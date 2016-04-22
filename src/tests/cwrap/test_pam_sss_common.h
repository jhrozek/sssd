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

#ifndef TEST_PAM_SSS_COMMON_H
#define TEST_PAM_SSS_COMMON_H

#include <libpamtest.h>

/* Correct testuser's authtok */
extern const char *authtoks[];

/* Correct testuser's old and two new authtoks */
extern const char *chauthtoks[];

extern const char *wrong_authtoks[];

/* First authtok is wrong, second one is correct */
extern const char *retry_authtoks[];

extern const char *otp_authtoks[];

extern const char *otp_ssh_authtoks[];

extern const char *no_authtoks[];

void assert_pam_test(enum pamtest_err perr,
                     const enum pamtest_err perr_exp,
                     struct pam_testcase *tests);

enum pamtest_err pamtest_loc(const char *service,
                             const char *user,
                             const char *test_locale,
                             struct pamtest_conv_data *conv_data,
                             struct pam_testcase *test_cases,
                             size_t num_test_cases);

#define pamtest_c_loc(service, user, conv_data, test_cases, num_test_cases) \
        pamtest_loc(service, user, "C", conv_data, test_cases, num_test_cases)

void test_chpass_conv_loc(const char *service,
                          const char *user,
                          const char *test_locale,
                          int exp_opcode,
                          char *chpass_info_msg);


#endif  /* TEST_PAM_SSS_COMMON_H */
