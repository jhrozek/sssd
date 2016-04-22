#!/bin/sh

. $CWRAP_TEST_SRCDIR/pam_wrapper_test_setup.sh

exec ./pam_sss_wrapper-tests "$@"
