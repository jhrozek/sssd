/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include "util/util.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "tests/cmocka/common_mock.h"

struct sdap_id_ctx *mock_sdap_id_ctx(TALLOC_CTX *mem_ctx,
                                     struct be_ctx *be_ctx,
                                     struct sdap_options *sdap_opts)
{
    struct sdap_id_ctx *sdap_id_ctx;

    sdap_id_ctx = talloc_zero(mem_ctx, struct sdap_id_ctx);
    assert_non_null(sdap_id_ctx);

    sdap_id_ctx->be = be_ctx;
    sdap_id_ctx->opts = sdap_opts;

    return sdap_id_ctx;
}

struct sdap_options *mock_sdap_options(TALLOC_CTX *mem_ctx,
                                       struct sdap_attr_map *src_user_map,
                                       struct sdap_attr_map *src_group_map,
                                       struct dp_option *src_basic_opts)
{
    struct sdap_options *opts;
    errno_t ret;

    opts = talloc_zero(mem_ctx, struct sdap_options);
    assert_non_null(opts);

    ret = sdap_copy_map(opts, src_user_map,
                        SDAP_OPTS_USER, &opts->user_map);
    assert_int_equal(ret, ERR_OK);

    ret = sdap_copy_map(opts, src_group_map,
                        SDAP_OPTS_GROUP, &opts->group_map);
    assert_int_equal(ret, ERR_OK);

    ret = dp_copy_defaults(opts, src_basic_opts,
                           SDAP_OPTS_BASIC, &opts->basic);
    assert_int_equal(ret, ERR_OK);

    return opts;
}

struct sdap_options *mock_sdap_options_ldap(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            struct confdb_ctx *confdb_ctx,
                                            const char *conf_path)
{
    struct sdap_options *opts = NULL;
    errno_t ret;

    ret = ldap_get_options(mem_ctx, domain, confdb_ctx, conf_path, &opts);
    if (ret != EOK) {
        return NULL;
    }

    return opts;
}

struct sdap_handle *mock_sdap_handle(TALLOC_CTX *mem_ctx)
{
    struct sdap_handle *handle = talloc_zero(mem_ctx, struct sdap_handle);

    /* we will never connect to any LDAP server and any sdap API that
     * access sdap_handle should be mocked, thus returning empty structure
     * is enough */

    return handle;
}

