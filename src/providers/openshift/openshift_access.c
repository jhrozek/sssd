/*
    SSSD

    openshift_access.c - Access control module of openshift provider

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

struct openshift_access_state {
    struct sss_domain_info *dom;
    struct pam_data *pd;
};


/*
 * Compare if the user who is trying to access the system
 * (pd->user) is cached and if their cache entry is a member
 * of some of the groups configured and stored in
 * access_ctx->allowed_groups
 */
static errno_t
ocp_access_check(struct openshift_access_ctx *access_ctx,
                 struct sss_domain_info *domain,
                 struct pam_data *pd)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    size_t gi;
    struct ldb_result *res;
    const char **cache_group_list;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* FIXME: code duplication with auth.c...*/
    /* Read the list of groups the user is a member of into
     * an array of strings
     */
    ret = sysdb_initgroups(tmp_ctx,
                           domain,
                           pd->user,
                           &res);
    if (ret != EOK) {
        goto done;
    }

    cache_group_list = talloc_zero_array(tmp_ctx, const char *, res->count);
    if (cache_group_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    gi = 0;
    /* start counting from 1 as 0 is the user entry */
    for (size_t i = 1; i < res->count; i++) {
        cache_group_list[gi] = ldb_msg_find_attr_as_string(res->msgs[i],
                                                           SYSDB_NAME,
                                                           NULL);
        if (cache_group_list[gi] == NULL) {
            /* Just carry on with failures, the worst thing is that the
             * user is a member of fewer groups and will be denied access
             */
            continue;
        }
        gi++;
    }

    if (cache_group_list[0] == NULL) {
        /* No groups? Go away */
        ret = ERR_ACCESS_DENIED;
        goto done;
    }

    if (access_ctx->allowed_groups == NULL
            || access_ctx->allowed_groups[0] == NULL) {
        /* Empty ACL? Go away */
        ret = ERR_ACCESS_DENIED;
        goto done;
    }

    /* Check if any of the groups the user is a member of are in the
     * allowed ACL
     */
    for (size_t i = 0; cache_group_list[i] != NULL; i++) {
        for (size_t ii = 0; access_ctx->allowed_groups[ii]; ii++) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Checking %s against %s\n",
                  cache_group_list[i],
                  access_ctx->allowed_groups[ii]);

                /* In theory we could just strcmp, but it might be better
                 * to presume case-insenstive domains where we might need
                 * to lowercase the string correctly, sss_string_equal
                 * does that
                 * FIXME: Use sss_string_equal() in the rest of the provider
                 */
                if (sss_string_equal(domain->case_sensitive,
                                     cache_group_list[i],
                                     access_ctx->allowed_groups[ii])) {
                    DEBUG(SSSDBG_TRACE_LIBS, "Access granted\n");
                    /* First match wins, we don't need to carry on */
                    ret = EOK;
                    goto done;
                }
        }
    }

    /* Nothing matched, deny access */
    DEBUG(SSSDBG_TRACE_LIBS, "Access denied\n");
    ret = ERR_ACCESS_DENIED;
done:
    talloc_free(tmp_ctx);
    return ret;
}

struct tevent_req *
openshift_access_handler_send(TALLOC_CTX *mem_ctx,
                              struct openshift_access_ctx *access_ctx,
                              struct pam_data *pd,
                              struct dp_req_params *params)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct openshift_access_state *state = NULL;

    req = tevent_req_create(mem_ctx, &state, struct openshift_access_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    /* pd->domain is a string, find the corresponding domain object. */
    /* This is really just future-proofing, currently be->domain is
     * the only domain object we support anyway
     */
    state->dom = find_domain_by_name(access_ctx->be->domain, pd->domain, false);
    if (state->dom == NULL) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    state->pd = pd;
    /* Defensive defaults, presume error */
    state->pd->pam_status = PAM_SYSTEM_ERR;

    /* Check if the user is a member of any of the groups in the ACL */
    ret = ocp_access_check(access_ctx, params->domain, pd);
    switch (ret) {
    case EOK:
        state->pd->pam_status = PAM_SUCCESS;
        break;
    case ERR_ACCESS_DENIED:
        state->pd->pam_status = PAM_PERM_DENIED;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
        break;
    }

immediately:
    tevent_req_done(req);
    tevent_req_post(req, params->ev);
    return req;
}

errno_t openshift_access_handler_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct pam_data **_data)
{
    struct openshift_access_state *state = NULL;

    state = tevent_req_data(req, struct openshift_access_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
