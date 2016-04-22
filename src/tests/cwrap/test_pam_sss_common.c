/*
    Copyright (C) 2015 Red Hat

    SSSD tests: PAM tests

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
#include <libpamtest.h>

#include "util/util.h"
#include "tests/cmocka/common_mock.h"

/* Correct testuser's authtok */
const char *authtoks[] = {
    "secret",
    NULL,
};

/* Correct testuser's old and two new authtoks */
const char *chauthtoks[] = {
    "secret",
    "new_secret",
    "new_secret",
    NULL,
};

const char *wrong_authtoks[] = {
    "wrong_secret",
    NULL,
};

/* First authtok is wrong, second one is correct */
const char *retry_authtoks[] = {
    "wrong_secret",
    "retried_secret",
    NULL,
};

const char *otp_authtoks[] = {
    "secret",
    "1234",
    NULL,
};

const char *otp_ssh_authtoks[] = {
    "secret1234",
    "secret1234",
    NULL,
};

const char *no_authtoks[] = {
    NULL,
};

void assert_pam_test(enum pamtest_err perr,
                     const enum pamtest_err perr_exp,
                     struct pam_testcase *tests)
{
    const struct pam_testcase *tc;

    if (perr != perr_exp) {
        tc = pamtest_failed_case(tests);
        if (tc == NULL) {
            /* Probably pam_start/pam_end failed..*/
            fail_msg("PAM test with pamtest err %d\n", perr);
        }

        /* FIXME - would be nice to print index..*/
        fail_msg("PAM test expected %d returned %d\n",
                 tc->expected_rv, tc->op_rv);
    }
}

enum pamtest_err pamtest_loc(const char *service,
                             const char *user,
                             const char *test_locale,
                             struct pamtest_conv_data *conv_data,
                             struct pam_testcase *test_cases,
                             size_t num_test_cases)
{
    char *old_locale;
    enum pamtest_err perr;

    old_locale = setlocale(LC_ALL, NULL);
    setlocale(LC_ALL, test_locale);
    perr = _pamtest(service, user, conv_data, test_cases, num_test_cases);
    setlocale(LC_ALL, old_locale);

    return perr;
}

void test_chpass_conv_loc(const char *service,
                          const char *user,
                          const char *test_locale,
                          int exp_opcode,
                          char *chpass_info_msg)
{
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    char *info_arr[] = {
        chpass_info_msg,
        NULL,
    };
    struct pam_testcase tests[] = {
        pam_test(PAMTEST_CHAUTHTOK, exp_opcode),
    };

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = no_authtoks;
    conv_data.out_info = info_arr;

    perr = pamtest_loc(service, user, test_locale,
                       &conv_data, tests, N_ELEMENTS(tests));
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}
