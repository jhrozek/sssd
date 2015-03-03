/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests: Unit tests for the IPA SELinux module

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

#include <popt.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "tests/common.h"

struct selinux_test_ctx {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
};

static int selinux_test_setup(void **state)
{
    struct selinux_test_ctx *test_ctx = NULL;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context,
                           struct selinux_test_ctx);
    assert_non_null(test_ctx);

    /* create be_ctx, only ev and offline field should be used */
    test_ctx->be_ctx = talloc_zero(test_ctx, struct be_ctx);
    assert_non_null(test_ctx->be_ctx);

    test_ctx->be_ctx->ev = tevent_context_init(test_ctx->be_ctx);
    assert_non_null(test_ctx->be_ctx->ev);

    *state = test_ctx;

    return 0;
}

static int selinux_test_teardown(void **state)
{
    struct selinux_test_ctx *test_ctx = \
                        talloc_get_type(*state, struct selinux_test_ctx);

    assert_true(leak_check_teardown());
    talloc_free(test_ctx);

    return 0;
}

static int test_user_context(void **state)
{
    (void) state; /* unused */

    return 0;
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
        cmocka_unit_test(test_user_context),
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

    tests_set_cwd();

    return cmocka_run_group_tests(tests,
                                  selinux_test_setup,
                                  selinux_test_teardown);
}
