/* SSSD
    openshift_auth.c - OpenShift provider authentication

    Copyright (C) 2019 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <security/pam_modules.h>
#include <jansson.h>

#include "providers/data_provider/dp.h"
#include "providers/data_provider.h"
#include "util/tev_curl.h"
#include "providers/openshift/openshift_private.h"
#include "providers/openshift/openshift_opts.h"

/*
 * The user and group names would be returned from the HTTP request
 * non-qualified, but SSSD stores both user and group names qualified
 * with the SSSD domain name. Turn a ocp_user_info structure with
 * raw names into one with names qualified based on a given domain.
 */
static struct ocp_user_info *ocp_user_domain_qualify(TALLOC_CTX *mem_ctx,
                                                     struct sss_domain_info *domain,
                                                     struct ocp_user_info *raw)
{
    errno_t ret;
    struct ocp_user_info *qualified = NULL;

    qualified = talloc_zero(mem_ctx, struct ocp_user_info);
    if (qualified == NULL) {
        return NULL;
    }

    qualified->name = sss_create_internal_fqname(qualified,
                                                 raw->name,
                                                 domain->name);
    if (qualified->name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    qualified->groups = talloc_zero_array(qualified,
                                          const char *,
                                          raw->ngroups + 1);
    if (qualified->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (size_t i = 0; i < raw->ngroups; i++) {
        qualified->groups[i] = sss_create_internal_fqname(qualified->groups,
                                                          raw->groups[i],
                                                          domain->name);
        if (qualified->groups[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }
    qualified->ngroups = raw->ngroups;

    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(qualified);
        return NULL;
    }
    return qualified;
}

/*
 * Adds a list of groups to the cache unless they already exist.
 *
 * The groups are added with the SYSDB_POSIX flag set to FALSE
 * meaning that the group are not expected to have a GID and therefore
 * not visible on the OS level. This is fine for the OCP groups
 * because a) we don't need them visible on the OS level and
 * b) each group would consume an ID from the range.
 *
 * All the group membership are needed for is access control later
 * on.
 */
static errno_t add_missing_groups(struct sss_domain_info *domain,
                                  char **add_groups)
{
    errno_t ret;
    int tret;
    bool in_transaction = false;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct sysdb_attrs *group_attrs;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    for (size_t i = 0; add_groups[i]; i++) {
        ret = sysdb_getgrnam(tmp_ctx, domain, add_groups[i], &res);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not get group %s [%d]: %s, ignoring\n",
                  add_groups[i], ret, sss_strerror(ret));
            continue;
        }

        if (res->count > 1) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Expected 1 groups, got %d\n", res->count);
            continue;
        } else if (res->count == 1) {
            DEBUG(SSSDBG_TRACE_LIBS, "Group %s already cached\n", add_groups[i]);
            continue;
        }

        /* Only res->count == 0 remains */
        if (group_attrs == NULL) {
            /* group_attrs is a singleton */
            group_attrs = sysdb_new_attrs(tmp_ctx);
            if (group_attrs == NULL) { DEBUG(SSSDBG_TRACE_LIBS, "sysdb_new_attrs failed.\n");
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_bool(group_attrs, SYSDB_POSIX, false);
            if (ret != EOK) {
                goto done;
            }
        }

        ret = sysdb_add_group(domain, add_groups[i],
                              0, group_attrs, 0, time(NULL));
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not add group %s [%d]: %s, ignoring\n",
                  add_groups[i], ret, sss_strerror(ret));
            continue;
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(domain->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * Given user information in struct ocp_user_info, make sure that their
 * group membership is accurately reflected in the cache: create groups
 * that do not exist and the user is a member of and link and unlink
 * the group membership links in the cache to reflect the server side
 * group membership.
 *
 * FIXME: While we do remove group membership from groups the user is
 * no longer a member of, we don't remove the orphaned grups. We should,
 * but let's do it past the POC stage.
 */
static errno_t populate_user_groups(struct ocp_user_info *user,
                                    struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    errno_t ret;
    const char **cache_group_list;
    size_t gi;
    int tret;
    bool in_transaction = false;
    char **add_groups;
    char **del_groups; /* FIXME: Unused at the moment. This is fine for POC */

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    /* Read the user entry from the cache.. */
    ret = sysdb_initgroups(tmp_ctx,
                           domain,
                           user->name,
                           &res);
    if (ret != EOK) {
        goto done;
    }

    cache_group_list = talloc_zero_array(tmp_ctx, const char *, res->count);
    if (cache_group_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* ..iterate over the group objects and read the name from each of them,
     * generating an array of groups the user is a member of
     *
     * Explicitly start counding from 1 because res->msgs[0] is the user
     * object
     */
    gi = 0;
    for (size_t i = 1; i < res->count; i++) {
        cache_group_list[gi] = ldb_msg_find_attr_as_string(res->msgs[i],
                                                           SYSDB_NAME,
                                                           NULL);
        if (cache_group_list[gi] == NULL) {
            continue;
        }
        gi++;
    }

    /* Find all the group differences */
    ret = diff_string_lists(tmp_ctx,
                            discard_const(user->groups),
                            discard_const(cache_group_list),
                            &add_groups, &del_groups, NULL);
    if (ret != EOK) {
        goto done;
    }

    /* Make sure that all the groups the user is a member of
     * are present in the cache, if not, create them
     */
    ret = add_missing_groups(domain, add_groups);
    if (ret != EOK) {
        goto done;
    }

    /* Sync the membership! */
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Updating memberships for %s\n", user->name);
    ret = sysdb_update_members(domain, user->name, SYSDB_MEMBER_USER,
                               (const char *const *) add_groups,
                               (const char *const *) del_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not update sysdb memberships for %s: %d [%s]\n",
              user->name, ret, sss_strerror(ret));
        goto done;
    }

    /* TODO: remove orphaned groups? */

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(domain->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

struct openshift_auth_state {
    struct sss_domain_info *dom;
    struct pam_data *pd;
};

static void openshift_auth_handler_done(struct tevent_req *subreq);

struct tevent_req *
openshift_auth_handler_send(TALLOC_CTX *mem_ctx,
                            struct openshift_auth_ctx *auth_ctx,
                            struct pam_data *pd,
                            struct dp_req_params *params)
{
    struct openshift_auth_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;

    req = tevent_req_create(mem_ctx, &state, struct openshift_auth_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->dom = find_domain_by_name(auth_ctx->be->domain, pd->domain, false);
    if (state->dom == NULL) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    state->pd = pd;
    state->pd->pam_status = PAM_SYSTEM_ERR;

    subreq = token_review_auth_send(state,
                                    auth_ctx->be->ev,
                                    auth_ctx->tc_ctx,
                                    dp_opt_get_cstring(auth_ctx->auth_opts,
                                                       API_SERVER_URL),
                                    pd->authtok);
    if (subreq == NULL) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }
    tevent_req_set_callback(subreq, openshift_auth_handler_done, req);

    return req;

immediately:
    tevent_req_done(req);
    tevent_req_post(req, params->ev);
    return req;
}

static void openshift_auth_handler_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct openshift_auth_state *state = NULL;
    struct tevent_req *req = NULL;
    struct ocp_user_info *raw_user_info = NULL;
    struct ocp_user_info *sss_user_info = NULL;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct openshift_auth_state);

    ret = token_review_auth_recv(state, subreq, &raw_user_info);
    talloc_free(subreq);
    if (ret != EOK) {
        /* http errors go here.. */
        goto done;
    }

    /* Turn the raw entry from the API endpoint into the format
     * that SSSD expects in its cache
     */
    sss_user_info = ocp_user_domain_qualify(state,
                                            state->dom,
                                            raw_user_info);
    if (sss_user_info == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Check if the username matches the requested user */
    if (strcmp(sss_user_info->name, state->pd->user) != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Username %s does not match the requested user %s\n",
              sss_user_info->name, state->pd->user);
        ret = ERR_AUTH_DENIED;
        goto done;
    }

    /* Populate groups for access control later.. */
    ret = populate_user_groups(sss_user_info, state->dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not add groups for %s, the user might be denied access\n",
              sss_user_info->name);
        /* non-fatal */
        ret = EOK;
    }

done:
    /*
     * The handler's interface are PAM status code, not SSSD status codes
     */
    switch (ret) {
    case EOK:
        state->pd->pam_status = PAM_SUCCESS;
        break;
    case ERR_AUTH_DENIED:
        state->pd->pam_status = PAM_PERM_DENIED;
        break;
    case ERR_AUTH_FAILED:
        state->pd->pam_status = PAM_AUTH_ERR;
        break;
    case ETIMEDOUT:
    case ERR_NETWORK_IO:
        state->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
        break;
    }
    tevent_req_done(req);
}

errno_t openshift_auth_handler_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct pam_data **_data)
{
    struct openshift_auth_state *state = NULL;

    state = tevent_req_data(req, struct openshift_auth_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
