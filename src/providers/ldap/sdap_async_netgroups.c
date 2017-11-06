/*
    SSSD

    Async LDAP Helper routines for netgroups

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/ldap/sdap_async_private.h"

static bool is_dn(const char *str)
{
    int ret;
    LDAPDN dn;

    ret = ldap_str2dn(str, &dn, LDAP_DN_FORMAT_LDAPV3);
    return (ret == LDAP_SUCCESS ? true : false);
}

static errno_t sdap_save_netgroup(TALLOC_CTX *memctx,
                                  struct sysdb_ctx *ctx,
                                  struct sdap_options *opts,
                                  struct sss_domain_info *dom,
                                  struct sysdb_attrs *attrs,
                                  char **_timestamp)
{
    struct ldb_message_element *el;
    struct sysdb_attrs *netgroup_attrs;
    const char *name = NULL;
    int ret;
    char *timestamp = NULL;
    size_t c;

    ret = sysdb_attrs_get_el(attrs,
                             opts->netgroup_map[SDAP_AT_NETGROUP_NAME].sys_name,
                             &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        ret = EINVAL;
        goto fail;
    }
    name = (const char *)el->values[0].data;

    netgroup_attrs = sysdb_new_attrs(memctx);
    if (!netgroup_attrs) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_attrs_get_el(attrs, SYSDB_ORIG_DN, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original DN is not available for [%s].\n", name));
    } else {
        DEBUG(7, ("Adding original DN [%s] to attributes of [%s].\n",
                  el->values[0].data, name));
        ret = sysdb_attrs_add_string(netgroup_attrs, SYSDB_ORIG_DN,
                                     (const char *)el->values[0].data);
        if (ret) {
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                         opts->netgroup_map[SDAP_AT_NETGROUP_MODSTAMP].sys_name,
                         &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original mod-Timestamp is not available for [%s].\n",
                  name));
    } else {
        ret = sysdb_attrs_add_string(netgroup_attrs,
                         opts->netgroup_map[SDAP_AT_NETGROUP_MODSTAMP].sys_name,
                         (const char*)el->values[0].data);
        if (ret) {
            goto fail;
        }
        timestamp = talloc_strdup(memctx, (const char*)el->values[0].data);
        if (!timestamp) {
            ret = ENOMEM;
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                           opts->netgroup_map[SDAP_AT_NETGROUP_TRIPLE].sys_name,
                           &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("No netgroup triples for netgroup [%s].\n", name));
    } else {
        for(c = 0; c < el->num_values; c++) {
            ret = sysdb_attrs_add_string(netgroup_attrs,
                           opts->netgroup_map[SDAP_AT_NETGROUP_TRIPLE].sys_name,
                            (const char*)el->values[c].data);
            if (ret) {
                goto fail;
            }
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                       opts->netgroup_map[SDAP_AT_NETGROUP_MEMBER].sys_name,
                       &el);
    if (ret != EOK) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("No original members for netgroup [%s]\n", name));

    } else {
        DEBUG(7, ("Adding original members to netgroup [%s]\n", name));
        for(c = 0; c < el->num_values; c++) {
            ret = sysdb_attrs_add_string(netgroup_attrs,
                       opts->netgroup_map[SDAP_AT_NETGROUP_MEMBER].sys_name,
                       (const char*)el->values[c].data);
            if (ret) {
                goto fail;
            }
        }
    }


    ret = sysdb_attrs_get_el(attrs, SYSDB_NETGROUP_MEMBER, &el);
    if (ret != EOK) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("No members for netgroup [%s]\n", name));

    } else {
        DEBUG(7, ("Adding members to netgroup [%s]\n", name));
        for(c = 0; c < el->num_values; c++) {
            ret = sysdb_attrs_add_string(netgroup_attrs, SYSDB_NETGROUP_MEMBER,
                                         (const char*)el->values[c].data);
            if (ret) {
                goto fail;
            }
        }
    }

    DEBUG(6, ("Storing info for netgroup %s\n", name));

    ret = sysdb_add_netgroup(ctx, dom, name, NULL, netgroup_attrs,
                             dp_opt_get_int(opts->basic,
                                            SDAP_ENTRY_CACHE_TIMEOUT));
    if (ret) goto fail;

    if (_timestamp) {
        *_timestamp = timestamp;
    }

    return EOK;

fail:
    DEBUG(2, ("Failed to save netgroup %s\n", name));
    return ret;
}

struct dn_item {
    const char *dn;
    struct sysdb_attrs *netgroup;
    char *cn;
    struct dn_item *next;
    struct dn_item *prev;
};

static errno_t update_dn_list(struct dn_item *dn_list, const size_t count,
                              struct ldb_message **res, bool *all_resolved)
{
    struct dn_item *dn_item;
    size_t c;
    const char *dn;
    const char *cn;
    bool not_resolved = false;

    *all_resolved = false;

    DLIST_FOR_EACH(dn_item, dn_list) {
        if (dn_item->cn != NULL) {
            continue;
        }

        for(c = 0; c < count; c++) {
            dn = ldb_msg_find_attr_as_string(res[c], SYSDB_ORIG_DN, NULL);
            if (dn == NULL) {
                DEBUG(1, ("Missing original DN.\n"));
                return EINVAL;
            }
            if (strcmp(dn, dn_item->dn) == 0) {
                DEBUG(9, ("Found matching entry for [%s].\n", dn_item->dn));
                cn = ldb_msg_find_attr_as_string(res[c], SYSDB_NAME, NULL);
                if (cn == NULL) {
                    DEBUG(1, ("Missing name.\n"));
                    return EINVAL;
                }
                dn_item->cn = talloc_strdup(dn_item, cn);
                break;
            }
        }

        not_resolved = true;
    }

    *all_resolved = !not_resolved;

    return EOK;
}

struct netgr_translate_members_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;

    struct sysdb_attrs **netgroups;
    size_t count;
    struct dn_item *dn_list;
    struct dn_item *dn_item;
    struct dn_item *dn_idx;
};

static errno_t netgr_translate_members_ldap_step(struct tevent_req *req);
static void netgr_translate_members_ldap_done(struct tevent_req *subreq);

struct tevent_req *netgr_translate_members_send(TALLOC_CTX *memctx,
                                                struct tevent_context *ev,
                                                struct sdap_options *opts,
                                                struct sdap_handle *sh,
                                                struct sss_domain_info *dom,
                                                struct sysdb_ctx *sysdb,
                                                const size_t count,
                                                struct sysdb_attrs **netgroups)
{
    struct tevent_req *req;
    struct netgr_translate_members_state *state;
    size_t c;
    size_t mc;
    const char **member_list;
    size_t sysdb_count;
    int ret;
    struct ldb_message **sysdb_res;
    struct dn_item *dn_item;
    char *dn_filter;
    char *sysdb_filter;
    struct ldb_dn *netgr_basedn;
    bool all_resolved;
    const char *cn_attr[] = { SYSDB_NAME, SYSDB_ORIG_DN, NULL };

    req = tevent_req_create(memctx, &state,
                            struct netgr_translate_members_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->sysdb = sysdb;
    state->netgroups = netgroups;
    state->count = count;
    state->dn_list = NULL;
    state->dn_item = NULL;
    state->dn_idx = NULL;

    for (c = 0; c < count; c++) {
        ret = sysdb_attrs_get_string_array(netgroups[c],
                                           SYSDB_ORIG_NETGROUP_MEMBER, state,
                                           &member_list);
        if (ret != EOK) {
            DEBUG(7, ("Missing netgroup members.\n"));
            continue;
        }

        for (mc = 0; member_list[mc] != NULL; mc++) {
            if (is_dn(member_list[mc])) {
                dn_item = talloc_zero(state, struct dn_item);
                if (dn_item == NULL) {
                    DEBUG(1, ("talloc failed.\n"));
                    ret = ENOMEM;
                    goto fail;
                }

                DEBUG(9, ("Adding [%s] to DN list.\n", member_list[mc]));
                dn_item->netgroup = netgroups[c];
                dn_item->dn = member_list[mc];
                DLIST_ADD(state->dn_list, dn_item);
            } else {
                ret = sysdb_attrs_add_string(netgroups[c], SYSDB_NETGROUP_MEMBER,
                                             member_list[mc]);
                if (ret != EOK) {
                    DEBUG(1, ("sysdb_attrs_add_string failed.\n"));
                    goto fail;
                }
            }
        }
    }

    if (state->dn_list == NULL) {
        DEBUG(9, ("No DNs found among netgroup members.\n"));
        tevent_req_done(req);
        tevent_req_post(req, ev);
        return req;
    }

    dn_filter = talloc_strdup(state, "(|");
    if (dn_filter == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        ret = ENOMEM;;
        goto fail;
    }

    DLIST_FOR_EACH(dn_item, state->dn_list) {
            dn_filter = talloc_asprintf_append(dn_filter, "(%s=%s)",
                                               SYSDB_ORIG_DN, dn_item->dn);
            if (dn_filter == NULL) {
                DEBUG(1, ("talloc_asprintf_append failed.\n"));
                ret = ENOMEM;
                goto fail;
            }
    }

    dn_filter = talloc_asprintf_append(dn_filter, ")");
    if (dn_filter == NULL) {
        DEBUG(1, ("talloc_asprintf_append failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    sysdb_filter = talloc_asprintf(state, "(&(%s)%s)", SYSDB_NC, dn_filter);
    if (sysdb_filter == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    netgr_basedn = sysdb_netgroup_base_dn(sysdb, state, dom->name);
    if (netgr_basedn == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_search_entry(state, sysdb, netgr_basedn, LDB_SCOPE_BASE,
                             sysdb_filter, cn_attr, &sysdb_count, &sysdb_res);
    talloc_zfree(netgr_basedn);
    talloc_zfree(sysdb_filter);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(1, ("sysdb_search_entry failed.\n"));
        goto fail;
    }

    if (ret == EOK) {
        ret = update_dn_list(state->dn_list, sysdb_count, sysdb_res,
                             &all_resolved);
        if (ret != EOK) {
            DEBUG(1, ("update_dn_list failed.\n"));
            goto fail;
        }

        if (all_resolved) {
            DLIST_FOR_EACH(dn_item, state->dn_list) {
                    ret = sysdb_attrs_add_string(dn_item->netgroup,
                                                 SYSDB_NETGROUP_MEMBER,
                                                 dn_item->cn);
                    if (ret != EOK) {
                        DEBUG(1, ("sysdb_attrs_add_string failed.\n"));
                        goto fail;
                    }
            }

            tevent_req_done(req);
            tevent_req_post(req, ev);
            return req;
        }
    }

    state->dn_idx = state->dn_list;
    ret = netgr_translate_members_ldap_step(req);
    if (ret != EOK && ret != EAGAIN) {
        DEBUG(1, ("netgr_translate_members_ldap_step failed.\n"));
        goto fail;
    }

    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    }
    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

/* netgr_translate_members_ldap_step() returns
 *   EOK: if everthing is translated, the caller can call tevent_req_done
 *   EAGAIN: if there are still members waiting to be translated, the caller
 *   should return to the mainloop
 *   Exyz: every other return code indicates an error and tevent_req_error
 *   should be called
 */
static errno_t netgr_translate_members_ldap_step(struct tevent_req *req)
{
    struct netgr_translate_members_state *state = tevent_req_data(req,
                                          struct netgr_translate_members_state);
    const char **cn_attr;
    struct tevent_req *subreq;
    int ret;

    DLIST_FOR_EACH(state->dn_item, state->dn_idx) {
        if (state->dn_item->cn == NULL) {
            break;
        }
    }
    if (state->dn_item == NULL) {
        DLIST_FOR_EACH(state->dn_item, state->dn_list) {
                ret = sysdb_attrs_add_string(state->dn_item->netgroup,
                                             SYSDB_NETGROUP_MEMBER,
                                             state->dn_item->cn);
                if (ret != EOK) {
                    DEBUG(1, ("sysdb_attrs_add_string failed.\n"));
                    tevent_req_error(req, ret);
                    return ret;
                }
        }

        return EOK;
    }

    cn_attr = talloc_array(state, const char *, 3);
    if (cn_attr == NULL) {
        DEBUG(1, ("talloc_array failed.\n"));
        return ENOMEM;
    }
    cn_attr[0] = state->opts->netgroup_map[SDAP_AT_NETGROUP_NAME].name;
    cn_attr[1] = "objectclass";
    cn_attr[2] = NULL;

    DEBUG(9, ("LDAP base search for [%s].\n", state->dn_item->dn));
    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   state->dn_item->dn, LDAP_SCOPE_BASE, NULL,
                                   cn_attr, state->opts->netgroup_map,
                                   SDAP_OPTS_NETGROUP,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (!subreq) {
        DEBUG(1, ("sdap_get_generic_send failed.\n"));
        return ENOMEM;
    }
    talloc_steal(subreq, cn_attr);

    tevent_req_set_callback(subreq, netgr_translate_members_ldap_done, req);
    return EAGAIN;
}

static void netgr_translate_members_ldap_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct netgr_translate_members_state *state = tevent_req_data(req,
                                          struct netgr_translate_members_state);
    int ret;
    size_t count;
    struct sysdb_attrs **netgroups;
    const char *str;

    ret = sdap_get_generic_recv(subreq, state, &count, &netgroups);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("sdap_get_generic request failed.\n"));
        goto fail;
    }

    switch (count) {
        case 0:
            DEBUG(0, ("sdap_get_generic_recv found no entry for [%s].\n",
                      state->dn_item->dn));
            break;
        case 1:
            ret = sysdb_attrs_get_string(netgroups[0], SYSDB_NAME, &str);
            if (ret != EOK) {
                DEBUG(1, ("sysdb_attrs_add_string failed.\n"));
                break;
            }
            state->dn_item->cn = talloc_strdup(state->dn_item, str);
            if (state->dn_item->cn == NULL) {
                DEBUG(1, ("talloc_strdup failed.\n"));
            }
            break;
        default:
            DEBUG(1, ("Unexpected number of results [%d] for base search.\n",
                      count));
    }

    if (state->dn_item->cn == NULL) {
        DEBUG(1, ("Failed to resolve netgroup name for DN [%s], using DN.\n",
                  state->dn_item->dn));
        state->dn_item->cn = talloc_strdup(state->dn_item, state->dn_item->dn);
    }

    state->dn_idx = state->dn_item->next;
    ret = netgr_translate_members_ldap_step(req);
    if (ret != EOK && ret != EAGAIN) {
        DEBUG(1, ("netgr_translate_members_ldap_step failed.\n"));
        goto fail;
    }

    if (ret == EOK) {
        tevent_req_done(req);
    }
    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static errno_t netgroup_translate_ldap_members_recv(struct tevent_req *req,
                                                TALLOC_CTX *mem_ctx,
                                                size_t *count,
                                                struct sysdb_attrs ***netgroups)
{
    struct netgr_translate_members_state *state = tevent_req_data(req,
                                          struct netgr_translate_members_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *count = state->count;
    *netgroups = talloc_steal(mem_ctx, state->netgroups);

    return EOK;
}

/* ==Search-Netgroups-with-filter============================================ */

struct sdap_get_netgroups_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    const char **attrs;
    const char *filter;

    char *higher_timestamp;
    struct sysdb_attrs **netgroups;
    size_t count;
};

static void sdap_get_netgroups_process(struct tevent_req *subreq);
static void netgr_translate_members_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_netgroups_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sss_domain_info *dom,
                                           struct sysdb_ctx *sysdb,
                                           struct sdap_options *opts,
                                           struct sdap_handle *sh,
                                           const char **attrs,
                                           const char *filter,
                                           int timeout)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_netgroups_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_netgroups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->sysdb = sysdb;
    state->filter = filter;
    state->attrs = attrs;
    state->higher_timestamp = NULL;
    state->netgroups =  NULL;
    state->count = 0;

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   dp_opt_get_string(state->opts->basic,
                                                     SDAP_NETGROUP_SEARCH_BASE),
                                   LDAP_SCOPE_SUBTREE,
                                   state->filter, state->attrs,
                                   state->opts->netgroup_map,
                                   SDAP_OPTS_NETGROUP, timeout, false);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_netgroups_process, req);

    return req;
}

static void sdap_get_netgroups_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_netgroups_state *state = tevent_req_data(req,
                                               struct sdap_get_netgroups_state);
    int ret;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->count, &state->netgroups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(6, ("Search for netgroups, returned %d results.\n", state->count));

    if (state->count == 0) {
        tevent_req_error(req, ENOENT);
        return;
    }

    subreq = netgr_translate_members_send(state, state->ev, state->opts,
                                          state->sh, state->dom, state->sysdb,
                                          state->count, state->netgroups);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, netgr_translate_members_done, req);

    return;

}

static void netgr_translate_members_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_netgroups_state *state = tevent_req_data(req,
                                               struct sdap_get_netgroups_state);
    int ret;
    size_t c;

    ret = netgroup_translate_ldap_members_recv(subreq, state, &state->count,
                                               &state->netgroups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    for (c = 0; c < state->count; c++) {
        ret = sdap_save_netgroup(state, state->sysdb,
                                 state->opts, state->dom,
                                 state->netgroups[c],
                                 &state->higher_timestamp);
        if (ret) {
            DEBUG(2, ("Failed to store netgroups.\n"));
            tevent_req_error(req, ret);
            return;
        }
    }

    DEBUG(9, ("Saving %d Netgroups - Done\n", state->count));

    tevent_req_done(req);
}

int sdap_get_netgroups_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx, char **timestamp,
                            size_t *reply_count,
                            struct sysdb_attrs ***reply)
{
    struct sdap_get_netgroups_state *state = tevent_req_data(req,
                                               struct sdap_get_netgroups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (timestamp) {
        *timestamp = talloc_steal(mem_ctx, state->higher_timestamp);
    }

    if (reply_count) {
        *reply_count = state->count;
    }

    if (reply) {
        *reply = talloc_steal(mem_ctx, state->netgroups);
    }

    return EOK;
}
