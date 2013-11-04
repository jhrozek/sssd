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

#ifndef __SSS_RESPONDER_CACHE_H__
#define __SSS_RESPONDER_CACHE_H__

#include "responder/common/negcache.h"
#include "responder/common/responder.h"

union cache_input {
    const char *str;
    uint32_t id;
    uint8_t *buf;
};

struct cache_req {
    union cache_input inp;

    struct sss_domain_info *domain;
    bool check_next;
    bool check_provider;

    /* FIXME - It must be OK to have no negcache. In that case, the ncache
     * functions will always return "not cached"
     */
    struct resp_ctx *rctx;
    struct sss_nc_ctx *nctx;
    struct ldb_result *res;
};

struct cache_req *
cache_req_new(TALLOC_CTX *mem_ctx,
              struct resp_ctx *rctx,
              const char *domname);

int cache_req_check(struct cache_req *creq,
                    struct ldb_result *res,
                    int req_type,
                    sss_dp_callback_t callback,
                    unsigned int cache_refresh_percent,
                    void *pvt);

#endif /* __SSS_RESPONDER_CACHE_H__ */
