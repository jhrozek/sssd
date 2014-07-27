
AM_CPPFLAGS = \
    -Wall \
    -I$(top_srcdir)/src \
    -I. \
    $(DBUS_CFLAGS) \
    $(NULL)

AM_TESTS_ENVIRONMENT = \
    SSSD_SRCDIR=$(top_srcdir) \
	. $(top_srcdir)/src/tests/cwrap/cwrap_test_setup.sh; \
    $(NULL)

check_PROGRAMS = \
	become_user-tests \
	$(NULL)

check_LTLIBRARIES = \
    libsss_test_common.la

TESTS = $(check_PROGRAMS)

libsss_test_common_la_SOURCES = \
    ../common_tev.c \
    ../common_dom.c \
    ../leak_check.c \
    ../common.c
libsss_test_common_la_LIBADD = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS)

become_user_tests_SOURCES = \
    test_become_user.c \
    $(NULL)
become_user_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
become_user_tests_LDADD = \
    $(POPT_LIBS) \
    $(CMOCKA_LIBS) \
    $(abs_top_builddir)/libsss_debug.la \
    libsss_test_common.la \
    $(NULL)

tests: $(check_PROGRAMS)
