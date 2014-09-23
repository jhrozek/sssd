/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: User switching

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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <popt.h>
#include "util/util.h"
#include "tests/cmocka/common_mock.h"

void test_get_user_num(void **state)
{
    uid_t uid;
    errno_t ret;

    ret = sss_user_from_string("123", &uid);
    assert_int_equal(ret, 0);
    assert_int_equal(uid, 123);
}

void test_get_user_str(void **state)
{
    uid_t uid;
    errno_t ret;

    ret = sss_user_from_string("sssd", &uid);
    assert_int_equal(ret, 0);
    assert_int_equal(uid, 123);
}

void test_get_group_num(void **state)
{
    gid_t gid;
    errno_t ret;

    ret = sss_group_from_string("123", &gid);
    assert_int_equal(ret, 0);
    assert_int_equal(gid, 123);
}

void test_get_group_str(void **state)
{
    gid_t gid;
    errno_t ret;

    ret = sss_group_from_string("sssd", &gid);
    assert_int_equal(ret, 0);
    assert_int_equal(gid, 123);
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
        unit_test(test_get_user_num),
        unit_test(test_get_user_str),
        unit_test(test_get_group_num),
        unit_test(test_get_group_str),
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

    return run_tests(tests);
}
