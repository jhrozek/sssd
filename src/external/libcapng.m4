dnl A macro to check presence of libcap-ng on the system
AC_DEFUN([AM_CHECK_LIBCAP_NG],
[
    PKG_CHECK_EXISTS(libcap-ng,
        dnl PKG_CHECK_EXISTS ACTION-IF-FOUND
        [ PKG_CHECK_MODULES([LIBCAPNG],
                            [libcap-ng],
                            [
                              have_libcap_ng="yes"
                              AC_DEFINE_UNQUOTED([HAVE_LIBCAPNG], 1,
                                                 [Use libcap-ng for privilege drop])
                            ])
        ],
        dnl PKG_CHECK_EXISTS ACTION-IF-NOT-FOUND
        [AC_MSG_WARN([No libcap-ng library found, falling back to our own privilege drop ipmlementation])]
    )
    AM_CONDITIONAL([HAVE_LIBCAPNG], [test x$have_libcap_ng = xyes])
])
