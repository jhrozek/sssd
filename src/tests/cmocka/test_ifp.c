/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: InfoPipe responder

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

#include "db/sysdb.h"
#include "tests/cmocka/common_mock.h"
#include "responder/ifp/ifp_private.h"

static void assert_string_list_equal(const char **s1,
                                     const char **s2)
{
    int i;

    for (i=0; s1[i]; i++) {
        assert_non_null(s2[i]);
        assert_string_equal(s1[i], s2[i]);
    }

    assert_null(s2[i]);
}

static void attr_parse_test(const char *expected[], const char *input)
{
    const char **res;
    TALLOC_CTX *test_ctx;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    res = ifp_parse_attr_list(test_ctx, input);

    if (expected) {
        /* Positive test */
        assert_non_null(res);
        assert_string_list_equal(res, expected);
    } else {
        /* Negative test */
        assert_null(res);
    }

    talloc_free(test_ctx);
}

void test_attr_acl(void **state)
{
    /* Test defaults */
    const char *exp_defaults[] = { SYSDB_NAME, SYSDB_UIDNUM,
                                   SYSDB_GIDNUM, SYSDB_GECOS,
                                   SYSDB_HOMEDIR, SYSDB_SHELL,
                                   NULL };
    attr_parse_test(exp_defaults, NULL);

    /* Test adding some attributes to the defaults */
    const char *exp_add[] = { "telephoneNumber", "streetAddress",
                              SYSDB_NAME, SYSDB_UIDNUM,
                              SYSDB_GIDNUM, SYSDB_GECOS,
                              SYSDB_HOMEDIR, SYSDB_SHELL,
                              NULL };
    attr_parse_test(exp_add, "+telephoneNumber, +streetAddress");

    /* Test removing some attributes to the defaults */
    const char *exp_rm[] = { SYSDB_NAME,
                             SYSDB_GIDNUM, SYSDB_GECOS,
                             SYSDB_HOMEDIR,
                             NULL };
    attr_parse_test(exp_rm, "-"SYSDB_SHELL ",-"SYSDB_UIDNUM);

    /* Test both add and remove */
    const char *exp_add_rm[] = { "telephoneNumber",
                                 SYSDB_NAME, SYSDB_UIDNUM,
                                 SYSDB_GIDNUM, SYSDB_GECOS,
                                 SYSDB_HOMEDIR,
                                 NULL };
    attr_parse_test(exp_add_rm, "+telephoneNumber, -"SYSDB_SHELL);

    /* Test rm trumps add */
    const char *exp_add_rm_override[] = { SYSDB_NAME, SYSDB_UIDNUM,
                                          SYSDB_GIDNUM, SYSDB_GECOS,
                                          SYSDB_HOMEDIR, SYSDB_SHELL,
                                          NULL };
    attr_parse_test(exp_add_rm_override,
                    "+telephoneNumber, -telephoneNumber, +telephoneNumber");

    /* Remove all */
    const char *rm_all[] = { NULL };
    attr_parse_test(rm_all,  "-"SYSDB_NAME ", -"SYSDB_UIDNUM
                             ", -"SYSDB_GIDNUM ", -"SYSDB_GECOS
                             ", -"SYSDB_HOMEDIR ", -"SYSDB_SHELL);

    /* Malformed list */
    attr_parse_test(NULL,  "missing_plus_or_minus");
}

void test_attr_allowed(void **state)
{
    const char *whitelist[] = { "name", "gecos", NULL };
    const char *emptylist[] = { NULL };

    assert_true(ifp_attr_allowed(whitelist, "name"));
    assert_true(ifp_attr_allowed(whitelist, "gecos"));

    assert_false(ifp_attr_allowed(whitelist, "password"));

    assert_false(ifp_attr_allowed(emptylist, "name"));
    assert_false(ifp_attr_allowed(NULL, "name"));
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

    const UnitTest tests[] = {
        unit_test(test_attr_acl),
        unit_test(test_attr_allowed),
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

    DEBUG_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old db to be sure */
    tests_set_cwd();

    return run_tests(tests);
}
