/*
    Copyright (C) 2015 Red Hat

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
#include "tests/cmocka/common_mock_sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/ad/ad_opts.h"
#include "util/crypto/sss_crypto.h"

/* Mock parsing search base without overlinking the test */
errno_t sdap_parse_search_base(TALLOC_CTX *mem_ctx,
                               struct dp_option *opts, int class,
                               struct sdap_search_base ***_search_bases)
{
    return EOK;
}

int ldap_get_options(TALLOC_CTX *memctx,
                     struct sss_domain_info *dom,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct sdap_options **_opts)
{
    return 0;
}

struct posix_test_state {
    struct sss_test_ctx *tctx;

    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sdap_search_base **search_bases;
};

static int posix_test_setup(void **state)
{

    struct posix_test_state *test_state;
    errno_t ret;

    assert_true(leak_check_setup());

    test_state = talloc_zero(global_talloc_context,
                           struct posix_test_state);
    assert_non_null(test_state);

    test_state->tctx = create_ev_test_ctx(test_state);
    assert_non_null(test_state->tctx);

    test_state->opts = mock_sdap_options(test_state,
                                         ad_2008r2_user_map,
                                         ad_2008r2_group_map,
                                         default_basic_opts);
    assert_non_null(test_state->opts);

    test_state->search_bases = talloc_array(test_state,
                                            struct sdap_search_base *, 2);
    assert_non_null(test_state->search_bases);
    test_state->search_bases[1] = NULL;

    ret = sdap_create_search_base(test_state,
                                  "cn=example,cn=com",
                                  LDAP_SCOPE_SUBTREE,
                                  NULL,
                                  &test_state->search_bases[0]);
    assert_int_equal(ret, EOK);
    test_state->sh = mock_sdap_handle(test_state);
    assert_non_null(test_state->sh);

    *state = test_state;
    return 0;
}

static int posix_test_teardown(void **state)
{
    struct posix_test_state *test_state = talloc_get_type_abort(*state,
                                               struct posix_test_state);
    assert_true(check_leaks_pop(test_state) == true);
    talloc_free(test_state);
    assert_true(leak_check_teardown());
    return 0;
}

static void sdap_posix_check_done(struct tevent_req *req);

static void test_posix_attrs(void **state)
{
    struct posix_test_state *test_ctx =
        talloc_get_type(*state, struct posix_test_state);
    struct tevent_req *req;
    errno_t ret;

    req = sdap_posix_check_send(test_ctx,
                                test_ctx->tctx->ev,
                                test_ctx->opts,
                                test_ctx->sh,
                                test_ctx->search_bases,
                                5);
    assert_non_null(req);

    tevent_req_set_callback(req, sdap_posix_check_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
}

static void sdap_posix_check_done(struct tevent_req *req)
{
    struct posix_test_state *test_ctx = \
        tevent_req_callback_data(req, struct posix_test_state);
    errno_t ret;

    ret = sdap_posix_check_recv(req, NULL);
    talloc_zfree(req);
    assert_int_equal(ret, ERR_OK);

    test_ctx->tctx->done = true;
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_posix_attrs,
                                        posix_test_setup,
                                        posix_test_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
