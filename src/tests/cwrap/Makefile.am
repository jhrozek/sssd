AM_CPPFLAGS = \
    -std=gnu99 \
    -Wall \
    -I$(top_srcdir)/src \
    -I. \
    -DLOCALEDIR=\"$(localedir)\" \
    -DLIBDIR=\"$(libdir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    -DSSS_STATEDIR=\"$(localstatedir)/lib/sss\" \
    -DSYSCONFDIR=\"$(sysconfdir)\" \
    -DBASE_FILE_STEM=\"$(*F)\" \
    $(DBUS_CFLAGS) \
    $(GLIB2_CFLAGS) \
    $(NULL)

TESTS_ENVIRONMENT = \
    CWRAP_TEST_SRCDIR=$(abs_srcdir) \
    . $(srcdir)/cwrap_test_setup.sh; \
    $(AUX_TESTS_ENVIRONMENT) \
    $(NULL)

dist_noinst_SCRIPTS = \
    cwrap_test_setup.sh \
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
    $(OPENLDAP_LIBS) \
    $(TDB_LIBS)

SSSD_INTERNAL_LTLIBS = \
    $(abs_top_builddir)/libsss_util.la \
    $(abs_top_builddir)/libsss_crypt.la \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_child.la \
    $(NULL)

SSSD_RESPONDER_OBJ = \
    ../../../src/responder/common/negcache_files.c \
    ../../../src/responder/common/negcache.c \
    ../../../src/responder/common/responder_cmd.c \
    ../../../src/responder/common/responder_common.c \
    ../../../src/responder/common/responder_dp.c \
    ../../../src/responder/common/responder_packet.c \
    ../../../src/responder/common/responder_get_domains.c \
    ../../../src/responder/common/responder_utils.c \
    ../../../src/responder/common/responder_cache_req.c \
    ../../../src/monitor/monitor_iface_generated.c \
    ../../../src/providers/data_provider_iface_generated.c \
    ../../../src/providers/data_provider_req.c

memberof_la_SOURCES = \
    ../../../src/ldb_modules/memberof.c \
    ../../../src/util/util.c
memberof_la_CFLAGS = \
    $(AM_CFLAGS)
memberof_la_LIBADD = \
    $(abs_top_builddir)/libsss_debug.la \
    $(LDB_LIBS) \
    $(DHASH_LIBS)
memberof_la_LDFLAGS = \
    -avoid-version \
    -module

ldblib_LTLIBRARIES = \
    memberof.la

dist_noinst_DATA = \
    group \
    passwd \
    $(NULL)

check_PROGRAMS =
if HAVE_CMOCKA
if HAVE_NSS_WRAPPER
if HAVE_UID_WRAPPER
check_PROGRAMS += \
    become_user-tests \
    server-tests \
    usertools-tests \
    responder_common-tests \
    negcache-tests \
    $(NULL)
endif # HAVE_UID_WRAPPER
endif # HAVE_NSS_WRAPPER
endif # HAVE_CMOCKA

TESTS = $(check_PROGRAMS)

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
    $(abs_top_builddir)/libsss_test_common.la \
    $(NULL)

server_tests_SOURCES = \
    test_server.c \
    ../../../src/util/server.c \
    $(NULL)
server_tests_CFLAGS = \
    $(AM_CFLAGS) \
    -DTEST_DB_PATH=\"server_tests\" \
    -DTEST_PID_PATH=\"server_tests\" \
    -DUNIT_TESTING \
    $(NULL)
server_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(abs_top_builddir)/libsss_util.la \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(NULL)

usertools_tests_SOURCES = \
    test_usertools.c \
    $(NULL)
usertools_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
usertools_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(abs_top_builddir)/libsss_util.la \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(NULL)

responder_common_tests_SOURCES =\
    test_responder_common.c \
    ../../../src/responder/common/negcache_files.c \
    ../../../src/responder/common/negcache.c \
    ../../../src/responder/common/responder_common.c \
    ../../../src/responder/common/responder_packet.c \
    ../../../src/responder/common/responder_cmd.c \
    $(NULL)
responder_common_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
responder_common_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SELINUX_LIBS) \
    $(abs_top_builddir)/libsss_util.la \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(NULL)

EXTRA_negcache_tests_DEPENDENCIES = \
    $(ldblib_LTLIBRARIES)
negcache_tests_SOURCES = \
    $(SSSD_RESPONDER_OBJ) \
    test_negcache.c
negcache_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(DHASH_CFLAGS)
negcache_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(abs_top_builddir)/libsss_test_common.la \
    $(abs_top_builddir)/libsss_idmap.la

tests: $(check_PROGRAMS)
