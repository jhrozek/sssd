/*
    SSSD

    openshift_id.c - Identity lookups for the openshift provider

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


#include "providers/data_provider/dp.h"
#include "providers/openshift/openshift_private.h"
#include "providers/openshift/openshift_opts.h"

#include "util/strtonum.h" /* strtouint32() */

struct openshift_account_info_handler_state {
    struct dp_reply_std reply;

    struct openshift_id_ctx *id_ctx;
};

struct ocp_user_removal_ctx {
    struct tevent_timer *timeout_handler;
    struct openshift_id_ctx *id_ctx;
    const char *name;
};

/* FIXME: We should also run this handler on startup to purge any stale entries since
 * service restart
 */
static void
ocp_user_removal_handler(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval tv,
                         void *pvt)
{
    struct ocp_user_removal_ctx *user_rm_ctx = talloc_get_type(pvt, struct ocp_user_removal_ctx);
    errno_t ret;
    struct ldb_result *res;
    const char *last_login;
    const char *attrs[] = {
        SYSDB_LAST_ONLINE_AUTH,
        NULL,
    };

    ret = sysdb_get_user_attr(user_rm_ctx,
                              user_rm_ctx->id_ctx->domain,
                              user_rm_ctx->name,
                              attrs,
                              &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not query cache for user %s: [%d]: %s\n",
              user_rm_ctx->name, ret, sss_strerror(ret));
        goto done;
    }

    switch (res->count) {
    case 0:
        /* No such user entry? Nothing to do except report.. */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "User %s vanished from cache\n",  user_rm_ctx->name);
        break;
    case 1:
        last_login = ldb_msg_find_attr_as_string(res->msgs[0],
                                                SYSDB_LAST_ONLINE_AUTH,
                                                NULL);
        if (last_login == NULL) {
            /* The user never logged in. Remove it. */
            ret = sysdb_delete_entry(user_rm_ctx->id_ctx->domain->sysdb,
                                     res->msgs[0]->dn,
                                     false);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Could not remove user %s\n", user_rm_ctx->name);
                goto done;
            }

            /* Signal nss to drop memcache */
            dp_sbus_reset_users_memcache(user_rm_ctx->id_ctx->be->provider);
        }
        break;
    default:
        /* Too many users? Nothing to do except report.. */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Found multiple records for user %s\n",  user_rm_ctx->name);
        break;
    }

done:
    talloc_free(user_rm_ctx);
}

static errno_t resolve_ocp_user(TALLOC_CTX *mem_ctx,
                                struct openshift_id_ctx *id_ctx,
                                const char *name)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_result *res = NULL;
    struct ldb_result *all_res = NULL;
    uid_t user_uid;
    struct timeval tv;
    struct ocp_user_removal_ctx  *user_rm_ctx;
    char *add_groups[2];

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* check if the user exists */
    ret = sysdb_getpwnam(tmp_ctx, id_ctx->domain, name, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not query cache for user %s: [%d]: %s\n",
              name, ret, sss_strerror(ret));
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Found multiple users named %s\n", name);
        ret = EIO;
        goto done;
    } else if (res->count == 1) {
        /* This is just a user refresh request */
        /* For now, don't do anything, we can later bump the
         * cache validity
         */
        DEBUG(SSSDBG_TRACE_FUNC, "User %s already exists\n", name);
        ret = EOK;
        goto done;
    }

    /* check if we have enough quota */
    ret = sysdb_enumpwent(tmp_ctx, id_ctx->domain, &all_res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not enumerate users: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (all_res->count > id_ctx->user_quota) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Quota %zu reached\n", id_ctx->user_quota);
        ret = E2BIG;        /* FIXME: Our own return code? */
        goto done;
    }

    /* Get user's UID */
    /* FIXME: We'll need to support rolling over the max_id limit */
    ret = sysdb_get_new_id(id_ctx->domain, &user_uid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not get the next ID [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* FIXME: transaction!! */

    /* create the user */
    ret = sysdb_store_user(id_ctx->domain,
                           name,
                           NULL,
                           user_uid,
                           user_uid,
                           NULL,
                           "/",
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           id_ctx->domain->user_timeout,
                           0);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not store the user %s [%d]: %s\n",
              name, ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_store_group(id_ctx->domain,
                            name,
                            user_uid,
                            NULL,
                            id_ctx->domain->group_timeout,
                            0);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not store the user group %s [%d]: %s\n",
              name, ret, sss_strerror(ret));
        /* Non fatal */
    }

    /*
     * Explicitly add the user into the additional group even before
     * authentication. This might not actually be needed, but some
     * clients might use the list of groups returned before auth as
     * canonical and if the group is only added during auth, it might
     * be missing from the effective list.
     */
    add_groups[0] = dp_opt_get_string(id_ctx->id_opts, OCP_ADDTL_GROUP);
    add_groups[1] = NULL;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Updating memberships for %s\n", name);
    ret = sysdb_update_members(id_ctx->domain, name, SYSDB_MEMBER_USER,
                               (const char *const *) add_groups,
                               NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not update sysdb memberships for %s: %d [%s]\n",
              name, ret, sss_strerror(ret));
        goto done;
    }

    /* start a timer to remove the user unless they authenticated */
    if (id_ctx->remove_user_timeout > 0) {

        user_rm_ctx = talloc_zero(id_ctx, struct ocp_user_removal_ctx);
        if (user_rm_ctx == NULL) {
            ret = ENOMEM;
            goto done;
        }
        user_rm_ctx->name = talloc_strdup(user_rm_ctx, name);
        if (user_rm_ctx->name == NULL) {
            ret = ENOMEM;
            goto done;
        }
        user_rm_ctx->id_ctx = id_ctx;

        tv = tevent_timeval_current_ofs(id_ctx->remove_user_timeout, 0);
        user_rm_ctx->timeout_handler = tevent_add_timer(id_ctx->be->ev,
                                                        user_rm_ctx,
                                                        tv,
                                                        ocp_user_removal_handler,
                                                        user_rm_ctx);
        if (user_rm_ctx->timeout_handler == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(user_rm_ctx);
    }
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * SSSD supports requesting objects by many 'keys', including by-name, by-ID,
 * by-certificate etc. The objects in openshift have no fixed schema that
 * would include other attributes than name, but on the system level, the users
 * also have an autogenerated ID which might own files. When an ID of a file
 * owned by an openshift user is requested (or another request by a key
 * different than a name comes, file resolution is just the most common one),
 * then the only option we have is to check if we already have the matching key
 * cached and extract the name from that object. Then we can use the name
 * to 'refresh' the entry, meaning that at least we'll be able to check
 * if the entry still exists in the openshift ID store.
 *
 * FIXME: This is not really useful while we autogenerate the users, but
 * will/might be used in the future, so jhrozek just coded it up now so
 * that he doesn't forget
 */
static const char *
get_request_name(TALLOC_CTX *mem_ctx,
                 struct sss_domain_info *domain,
                 struct dp_id_data *acct_req_data)
{
    uid_t uid;
    char *endptr;
    errno_t ret;
    struct ldb_result *res;
    const char *name;

    if (acct_req_data->filter_type == BE_FILTER_NAME) {
        /* By-name requests are easy, just use the provided key */
        return talloc_strdup(mem_ctx, acct_req_data->filter_value);
    } else if (acct_req_data->filter_type == BE_FILTER_IDNUM) {
        /* By-ID request: Check if that ID is cached, if yes, read the name
         * of that object so we can refresh it
         */
        uid = (uid_t) strtouint32(acct_req_data->filter_value, &endptr, 10);
        if (errno || *endptr || (acct_req_data->filter_value == endptr)) {
            ret = errno ? errno : EINVAL;
            return NULL;
        }

        ret = sysdb_getpwuid(mem_ctx, domain, uid, &res);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                    "Could not query cache for UID [%d]: %s\n",
                    ret, sss_strerror(ret));
            talloc_free(res);
            return NULL;
        }

        if (res->count != 1) {
            return NULL;
        }

        name = talloc_strdup(mem_ctx,
                             ldb_msg_find_attr_as_string(res->msgs[0],
                                                         SYSDB_NAME,
                                                         NULL));
        talloc_free(res);
        return name;
    }

    /* Other request types (by-SID, by-UUID, by-CERT) are not supported
     * now. We might add them later if it makes sense.
     */
    return NULL;
}

struct tevent_req *
openshift_account_info_handler_send(TALLOC_CTX *mem_ctx,
                                    struct openshift_id_ctx *id_ctx,
                                    struct dp_id_data *data,
                                    struct dp_req_params *params)
{
    errno_t ret;
    struct openshift_account_info_handler_state *state;
    struct tevent_req *req;
    const char *name;

    req = tevent_req_create(mem_ctx, &state,
                            struct openshift_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }
    state->id_ctx = id_ctx;

    /* This back end only processes user requests and groups-for-users
     * requests (initgroups). The latter is also just using the group
     * resolution request because the groups will only be populated
     * during auth when we actually have the user token
     */
    /* FIXME: the id handler will first just create any users you ask for. Later,
     * we'll try to use the client certificate that kubectl uses to actually
     * query for users.
     */
    switch (data->entry_type & BE_REQ_TYPE_MASK) {
    /* FIXME: without a way to talk to OCP, we can't find the groups before auth,
     * so initgroups just returns the user
     */
    case BE_REQ_USER:
    case BE_REQ_INITGROUPS:
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected entry type: %d\n", data->entry_type & BE_REQ_TYPE_MASK);
        ret = EINVAL;
        goto immediate;
    }

    /* Since there are no UIDs or GIDs in the openshift identity store, all
     * request types (by-ID typically) are translated to by-name requests.
     * If the request cannot be translated to a by-name, the provider just
     * returns 'I don't know'. This is fine it just means that a number won't
     * be translated to a name, so e.g. files might show up as having numerical
     * ownership if they were created by a user whose ID was recycled.
     */
    name = get_request_name(state, id_ctx->domain, data);
    if (name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Can't infer the request name\n");
        ret = ENOENT;
        goto immediate;
    }

    /* Perform a fake optimistic user resolution for now. If the user does
     * not exist and there is enough quota in the domain, return a user entry.
     *
     * If the user does not authenticate within id_ctx->remove_user_timeout
     * seconds, their entry will be removed to not take up quota and avoid
     * filling up the cache
     *
     * FIXME: In the future, we might use a true tevent request to actually
     * look up the entry using kubelet client certificate
     */
    ret = resolve_ocp_user(state, id_ctx, name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Can't look up user %s: [%d]: %s\n",
              name, ret, sss_strerror(ret));
        goto immediate;
    }

    ret = EOK;
immediate:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    tevent_req_post(req, params->ev);
    return req;
}

errno_t openshift_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                            struct tevent_req *req,
                                            struct dp_reply_std *data)
{
    struct openshift_account_info_handler_state *state = NULL;

    state = tevent_req_data(req, struct openshift_account_info_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;
    return EOK;
}
