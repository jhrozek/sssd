
AM_CPPFLAGS = \
    -Wall \
    -I$(top_srcdir)/src \
    -I. \
    -DLOCALEDIR=\"$(localedir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    $(DBUS_CFLAGS) \
    $(GLIB2_CFLAGS) \
    $(NULL)

SSSD_LIBS = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(PCRE_LIBS) \
    $(INI_CONFIG_LIBS) \
    $(COLLECTION_LIBS) \
    $(DHASH_LIBS) \
    $(SSS_CRYPT_LIBS) \
    $(OPENLDAP_LIBS) \
    $(TDB_LIBS)

AM_TESTS_ENVIRONMENT = \
    SSSD_SRCDIR=$(top_srcdir) \
	. $(top_srcdir)/src/tests/cwrap/cwrap_test_setup.sh; \
    $(NULL)

check_PROGRAMS = \
	become_user-tests \
	server-tests \
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

server_tests_SOURCES = \
    test_server.c \
    ../../../src/util/server.c \
    ../../../src/util/become_user.c \
    ../../../src/util/backup_file.c \
    ../../../src/util/domain_info_utils.c \
    ../../../src/util/atomic_io.c \
    ../../../src/util/signal.c \
    ../../../src/util/util.c \
    ../../../src/util/strtonum.c \
    ../../../src/util/util_errors.c \
    ../../../src/util/safe-format-string.c \
    ../../../src/util/sss_tc_utf8.c \
    ../../../src/util/sss_utf8.c \
    ../../../src/util/usertools.c \
    ../../../src/confdb/confdb.c \
    ../../../src/db/sysdb.c \
    ../../../src/db/sysdb_upgrade.c \
    ../../../src/db/sysdb_ops.c \
    ../../../src/db/sysdb_search.c \
    ../../../src/db/sysdb_autofs.c \
    ../../../src/db/sysdb_services.c \
    $(NULL)
server_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(LIBCAPNG_CFLAGS) \
    -DTEST_DB_PATH=\"server_tests\" \
    -DTEST_PID_PATH=\"server_tests\" \
    -DUNIT_TESTING \
    $(NULL)
server_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(LIBCAPNG_LIBS) \
    $(UNICODE_LIBS) \
    $(SSSD_LIBS) \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_crypt.la \
    libsss_test_common.la \
    $(NULL)

tests: $(check_PROGRAMS)
