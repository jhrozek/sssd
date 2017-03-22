/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <talloc.h>
#include <ldb.h>

#include "util/util.h"
#include "util/sss_nss.h"
#include "confdb/confdb.h"
#include "responder/common/responder.h"
#include "responder/nss/nss_private.h"

int sized_output_name(TALLOC_CTX *mem_ctx,
                      struct resp_ctx *rctx,
                      const char *orig_name,
                      struct sss_domain_info *name_dom,
                      struct sized_string **_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *name_str;
    struct sized_string *name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    name = talloc_zero(tmp_ctx, struct sized_string);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_nss_output_name(mem_ctx, name_dom, orig_name,
                              rctx->override_space, &name_str);
    if (ret != EOK) {
        goto done;
    }

    to_sized_string(name, name_str);
    *_name = talloc_steal(mem_ctx, name);
    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sized_member_name(TALLOC_CTX *mem_ctx,
                      struct resp_ctx *rctx,
                      const char *member_name,
                      struct sized_string **_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *domname;
    struct sss_domain_info *member_dom;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, member_name, NULL, &domname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_parse_internal_fqname failed\n");
        goto done;
    }

    if (domname == NULL) {
        ret = ERR_WRONG_NAME_FORMAT;
        goto done;
    }

    member_dom = find_domain_by_name(get_domains_head(rctx->domains),
                                     domname, true);
    if (member_dom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    ret = sized_output_name(mem_ctx, rctx, member_name,
                            member_dom, _name);
done:
    talloc_free(tmp_ctx);
    return ret;
}

const char *
nss_get_pwfield(struct nss_ctx *nctx,
               struct sss_domain_info *dom)
{
    if (dom->pwfield != NULL) {
        return dom->pwfield;
    }

    return nctx->pwfield;
}
