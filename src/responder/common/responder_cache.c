/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    Autofs responder: the responder server

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

#include <errno.h>
#include <talloc.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "responder/common/responder.h"
#include "responder/common/responder_cache.h"

struct cache_req_lookup {
    const char *ncache_str;
};

/* There are several basic kinds of requests, among them getXXXbyname and
 * getXXXbyid. These basic functions provide building blocks for requests
 * by name or ID that cache_req_* functions can use
 */
int cache_req_check_ncache(void)
{
    return EOK;
}

int creq_byname_dom_rep(struct cache_req *creq, struct sss_domain_info *dom,
                        union cache_input *in, union cache_input *out)
{
    char *name;

    if (out == NULL) return EINVAL;

    name = sss_get_cased_name(creq, in->str, dom->case_sensitive);
    if (!name) return ENOMEM;

    out->str = name;
    return EOK;
}

struct cache_req *
cache_req_new(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx, const char *domname)
{
    struct cache_req *creq;

    creq = talloc_zero(mem_ctx, struct cache_req);
    if (creq == NULL) return NULL;

    if (domname) {
        /* this is a search in one domain */
        creq->domain = responder_get_domain(rctx, domname);
        if (creq->domain == NULL) {
            talloc_free(creq);
            return NULL;
        }
        creq->check_next = false;
    } else {
        /* this is a multidomain search */
        creq->domain = rctx->domains;
        creq->check_next = true;
    }

    creq->rctx = rctx;
    creq->check_provider = NEED_CHECK_PROVIDER(creq->domain->provider);

    return creq;
}

int cache_req_search(struct cache_req *creq)
{
    struct sss_domain_info *dom = creq->domain;
    char *name;
    errno_t ret;

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
        * qualified names instead */
        while (dom && creq->check_next && dom->fqnames) {
            dom = get_next_domain(dom, false);
        }

        if (!dom) break;

        if (dom != creq->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            creq->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the cache_req if we changed domain */
        creq->domain = dom;

        talloc_free(name);
        name = sss_get_cased_name(creq, creq->inp.str, dom->case_sensitive);
        if (!name) return ENOMEM;

        /* verify this user has not yet been negatively cached,
        * or has been permanently filtered */
        ret = sss_ncache_check_user(creq->nctx,
                                    10, /*FIXME*/
                                    dom, name);
        /* if neg cached, return we didn't find it */
        if (ret == EEXIST) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  ("User [%s] does not exist in [%s]! (negative cache)\n",
                   name, dom->name));
            /* if a multidomain search, try with next */
            if (creq->check_next) {
                dom = get_next_domain(dom, false);
                continue;
            }

            /* There are no further domains or this was a
             * fully-qualified user request.
             */
            return ENOENT;
        }

        DEBUG(SSSDBG_FUNC_DATA,
              ("Requesting info for [%s@%s]\n", name, dom->name));

        ret = sysdb_getpwnam(creq, dom, name, &creq->res);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                   ("Failed to make request to our cache!\n"));
            return EIO;
        }

        if (creq->res->count > 1) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("getpwnam call returned more than one result !?!\n"));
            return ENOENT;
        }

        if (creq->res->count == 0 && creq->check_provider == false) {
            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_user(creq->nctx, false, dom, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, ("Cannot set negcache for %s@%s\n",
                      name, dom->name));
                /* Not fatal */
            }

            /* if a multidomain search, try with next */
            if (creq->check_next) {
                dom = get_next_domain(dom, false);
                if (dom) continue;
            }

            DEBUG(SSSDBG_TRACE_FUNC, ("No results for getpwnam call\n"));

            /* FIXME - make sure the caller deletes the entry from memcache */
            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
#if 0
        if (creq->check_provider) {
            ret = cache_req_check(creq, creq->res, SSS_DP_USER,
                                  nss_cmd_getby_dp_callback,
                                  0);          /* FIXME */
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }
#endif

        /* One result found */
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Returning info for user [%s@%s]\n", name, dom->name));
        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          ("No matching domain found for [%s], fail!\n", creq->inp.str));
    return ENOENT;
}

void cache_req_check_done(struct tevent_req *req);

int cache_req_check(struct cache_req *creq,
                    struct ldb_result *res,
                    int req_type,
                    sss_dp_callback_t callback,
                    unsigned int cache_refresh_percent,
                    void *pvt)
{
    uint64_t cache_expire = 0;
    int ret;
    struct tevent_req *req;
    struct dp_callback_ctx *cb_ctx = NULL;

    /* when searching for a user or netgroup, more than one reply is a
     * db error
     */
    if ((req_type == SSS_DP_USER || req_type == SSS_DP_NETGR) &&
            (res->count > 1)) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("getpwXXX call returned more than one result!"
               " DB Corrupted?\n"));
        return ENOENT;
    }

    /* if we have any reply let's check cache validity */
    if (res->count > 0) {
        if (req_type == SSS_DP_INITGROUPS) {
            cache_expire = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                       SYSDB_INITGR_EXPIRE, 1);
        }
        if (cache_expire == 0) {
            cache_expire = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                       SYSDB_CACHE_EXPIRE, 0);
        }

        /* if we have any reply let's check cache validity */
        ret = sss_cmd_check_cache(res->msgs[0], cache_refresh_percent,
                                  cache_expire);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC, ("Cached entry is valid, returning..\n"));
            return EOK;
        } else if (ret != EAGAIN && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Error checking cache: %d\n", ret));
            return ret;
        }
    } else {
        /* No replies */
        ret = ENOENT;
    }

    /* EAGAIN (off band) or ENOENT (cache miss) -> check cache */
    if (ret == EAGAIN) {
        /* No callback required
         * This was an out-of-band update. We'll return EOK
         * so the calling function can return the cached entry
         * immediately.
         */
        DEBUG(SSSDBG_TRACE_FUNC, ("Performing midpoint cache update\n"));

        req = sss_dp_get_account_send(creq, creq->rctx, creq->domain, true,
                                      req_type, creq->inp.str, 0,
                                      NULL);
        if (req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Out of memory sending out-of-band data provider "
                   "request\n"));
            /* This is non-fatal, so we'll continue here */
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, ("Updating cache out-of-band\n"));
        }

        /* We don't need to listen for a reply, so we will free the
         * request here.
         */
        talloc_zfree(req);
    } else {
       /* This is a cache miss. Or the cache is expired.
        * We need to get the updated user information before returning it.
        */

        /* dont loop forever :-) */
        creq->check_provider = false;

        /* keep around current data in case backend is offline */
        if (res->count) {
            creq->res = talloc_steal(creq, res);
        }

        req = sss_dp_get_account_send(creq, creq->rctx, creq->domain, true,
                                      req_type, creq->inp.str, 0,
                                      NULL);
        if (req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Out of memory sending data provider request\n"));
            return ENOMEM;
        }

        cb_ctx = talloc_zero(creq, struct dp_callback_ctx);
        if(!cb_ctx) {
            talloc_zfree(req);
            return ENOMEM;
        }
        cb_ctx->callback = callback;
        cb_ctx->ptr = pvt;
        cb_ctx->cctx = NULL;                /* FIXME */
        cb_ctx->mem_ctx = creq;

        tevent_req_set_callback(req, cache_req_check_done, cb_ctx);
        return EAGAIN;
    }

    return EOK;
}

void
cache_req_check_done(struct tevent_req *req)
{
    struct dp_callback_ctx *cb_ctx =
            tevent_req_callback_data(req, struct dp_callback_ctx);

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;

    ret = sss_dp_get_account_recv(cb_ctx->mem_ctx, req,
                                  &err_maj, &err_min,
                                  &err_msg);
    talloc_zfree(req);
    /* FIXME - how do we report ret? */

    cb_ctx->callback(err_maj, err_min, err_msg, cb_ctx->ptr);
}
