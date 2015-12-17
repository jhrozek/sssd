/*
    Copyright (C) 2015 Red Hat

    SSSD tests: Simple access provider tests

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
#include <tevent.h>
#include <errno.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_be.h"
#include "tests/cmocka/common_mock_resp.h"
#include "db/sysdb_private.h"   /* new_subdomain() */
#include "providers/simple/simple_access.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_simple_conf.ldb"
#define TEST_DOM_NAME "simple_test"
#define TEST_SUBDOM_NAME "test.subdomain"
#define TEST_ID_PROVIDER "ldap"

const char *ulist_1[] = {"u1", "u2", NULL};
const char *glist_1[] = {"g1", "g2", NULL};
const char *glist_1_case[] = {"G1", "G2", NULL};

int sssm_simple_access_init(struct be_ctx *bectx, struct bet_ops **ops,
                            void **pvt_data);

struct simple_test_ctx {
    struct sss_test_ctx *tctx;
    struct be_ctx *be_ctx;
    struct sss_domain_info *subdom;

    bool access_granted;
    struct simple_ctx *ctx;
};

static int test_simple_setup(struct sss_test_conf_param params[], void **state)
{
    struct simple_test_ctx *simple_test_ctx;
    int ret;

    simple_test_ctx = talloc_zero(NULL, struct simple_test_ctx);
    if (simple_test_ctx == NULL) {
        return ENOMEM;
    }

    simple_test_ctx->tctx = create_dom_test_ctx(simple_test_ctx, TESTS_PATH,
                                                TEST_CONF_DB, TEST_DOM_NAME,
                                                TEST_ID_PROVIDER, params);
    assert_non_null(simple_test_ctx->tctx);
    if (simple_test_ctx->tctx == NULL) {
        return ENOMEM;
    }

    ret = sss_names_init(simple_test_ctx, simple_test_ctx->tctx->confdb,
                         TEST_DOM_NAME, &simple_test_ctx->tctx->dom->names);
    if (ret != EOK) {
        return ENOMEM;
    }

    simple_test_ctx->be_ctx = mock_be_ctx(simple_test_ctx,
                                          simple_test_ctx->tctx);
    if (simple_test_ctx->be_ctx == NULL) {
        return ENOMEM;
    }

    *state = simple_test_ctx;
    return 0;
}

static int set_simple_lists(struct simple_test_ctx *test_ctx,
                            struct sss_domain_info *dom,
                            struct sss_test_conf_param params[])
{
    errno_t ret;
    const char *val[2] = { NULL, NULL };
    char *cdb_path;

    cdb_path = talloc_asprintf(test_ctx, CONFDB_DOMAIN_PATH_TMPL, dom->name);
    if (cdb_path == NULL) {
        return ENOMEM;
    }

    ret = EOK;

    if (params != NULL) {
        for (int i = 0; params[i].key != NULL; i++) {
            val[0] = params[i].value;
            ret = confdb_add_param(test_ctx->tctx->confdb,
                                   true, cdb_path, params[i].key, val);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add parameter %s [%d]: "
                      "%s\n", params[i].key, ret, sss_strerror(ret));
                break;
            }
        }
    }

    talloc_free(cdb_path);
    return ret;
}

static int setup_with_params(struct simple_test_ctx *test_ctx,
                             struct sss_domain_info *dom,
                             struct sss_test_conf_param params[])
{
    errno_t ret;
    struct bet_ops *ops;

    ret = set_simple_lists(test_ctx, dom, params);
    if (ret != EOK) {
        return ret;
    }

    ret = sssm_simple_access_init(test_ctx->be_ctx,
                                  &ops,
                                  (void **) &test_ctx->ctx);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static int simple_test_setup(void **state)
{
    test_dom_suite_setup(TESTS_PATH);
    return test_simple_setup(NULL, state);
}

static int simple_test_teardown(void **state)
{
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);

    /* make sure there are no leftovers from previous tests */
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    talloc_free(simple_test_ctx);
    return 0;
}

static void simple_access_check_done(struct tevent_req *req)
{
    struct simple_test_ctx *simple_test_ctx =
                        tevent_req_callback_data(req, struct simple_test_ctx);

    simple_test_ctx->tctx->error = simple_access_check_recv(req,
                                              &simple_test_ctx->access_granted);
    talloc_free(req);
    simple_test_ctx->tctx->done = true;
}

static void test_both_empty(void **state)
{
    errno_t ret;
    struct tevent_req *req;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);

    ret = setup_with_params(simple_test_ctx, simple_test_ctx->tctx->dom, NULL);
    assert_int_equal(ret, EOK);

    req = simple_access_check_send(simple_test_ctx, simple_test_ctx->tctx->ev,
                                   simple_test_ctx->ctx, "u1");
    assert_non_null(req);
    tevent_req_set_callback(req, simple_access_check_done, simple_test_ctx);

    ret = test_ev_loop(simple_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    assert_true(simple_test_ctx->access_granted);
}

static void test_allow_empty(void **state)
{
    errno_t ret;
    struct tevent_req *req;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_deny_users", "u1, u2" },
    };

    ret = setup_with_params(simple_test_ctx, simple_test_ctx->tctx->dom, params);
    assert_int_equal(ret, EOK);

    req = simple_access_check_send(simple_test_ctx, simple_test_ctx->tctx->ev,
                                   simple_test_ctx->ctx, "u1");
    assert_non_null(req);
    tevent_req_set_callback(req, simple_access_check_done, simple_test_ctx);

    ret = test_ev_loop(simple_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    assert_false(simple_test_ctx->access_granted);

    simple_test_ctx->tctx->done = false;

    req = simple_access_check_send(simple_test_ctx, simple_test_ctx->tctx->ev,
                                   simple_test_ctx->ctx, "u3");
    assert_non_null(req);
    tevent_req_set_callback(req, simple_access_check_done, simple_test_ctx);

    ret = test_ev_loop(simple_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    assert_true(simple_test_ctx->access_granted);
}

static void test_deny_empty(void **state)
{
    errno_t ret;
    struct tevent_req *req;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_users", "u1, u2" },
    };

    ret = setup_with_params(simple_test_ctx, simple_test_ctx->tctx->dom, params);
    assert_int_equal(ret, EOK);

    req = simple_access_check_send(simple_test_ctx, simple_test_ctx->tctx->ev,
                                   simple_test_ctx->ctx, "u1");
    assert_non_null(req);
    tevent_req_set_callback(req, simple_access_check_done, simple_test_ctx);

    ret = test_ev_loop(simple_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    assert_true(simple_test_ctx->access_granted);

    simple_test_ctx->tctx->done = false;

    req = simple_access_check_send(simple_test_ctx, simple_test_ctx->tctx->ev,
                                   simple_test_ctx->ctx, "u3");
    assert_non_null(req);
    tevent_req_set_callback(req, simple_access_check_done, simple_test_ctx);

    ret = test_ev_loop(simple_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    assert_false(simple_test_ctx->access_granted);
}

int main(int argc, const char *argv[])
{
    int rv;
    int no_cleanup = 0;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        /* FIXME - group fixtures? */
        cmocka_unit_test_setup_teardown(test_both_empty,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_allow_empty,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_deny_empty,
                                        simple_test_setup,
                                        simple_test_teardown),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old db to be sure */
    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    test_dom_suite_setup(TESTS_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }
    return rv;
}
