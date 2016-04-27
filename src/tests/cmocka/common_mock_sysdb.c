/*
    Copyright (C) 2016 Red Hat

    SSSD tests: Mocked a sysdb connection

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

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_sysdb.h"

int _setup_sysdb_tests(const char *domain_name,
                       const char *provider,
                       bool enumerate)
                       struct sysdb_test_ctx **ctx)
{
    struct sysdb_test_ctx *test_ctx;
    char *conf_db;
    int ret;

    const char *val[2];
    val[1] = NULL;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    assert_true(ret == 0 || errno == EEXIST);

    test_ctx = talloc_zero(global_talloc_context, struct sysdb_test_ctx);
    assert_non_null(test_ctx);

    /* Create an event context
     * It will not be used except in confdb_init and sysdb_init
     */
    test_ctx->ev = tevent_context_init(test_ctx);
    assert_non_null(test_ctx->ev);

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    assert_non_null(conf_db);
    DEBUG(SSSDBG_MINOR_FAILURE, "CONFDB: %s\n", conf_db);

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    assert_int_equal(ret, EOK);

    val[0] = "LOCAL";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    assert_int_equal(ret, EOK);

    val[0] = "local";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = enumerate ? "TRUE" : "FALSE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "enumerate", val);
    assert_int_equal(ret, EOK);

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "cache_credentials", val);
    assert_int_equal(ret, EOK);

    ret = sssd_domain_init(test_ctx, test_ctx->confdb, "local",
                           TESTS_PATH, &test_ctx->domain);
    assert_int_equal(ret, EOK);

    test_ctx->domain->has_views = true;
    test_ctx->sysdb = test_ctx->domain->sysdb;

    *ctx = test_ctx;
    return EOK;
}

