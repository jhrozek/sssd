dnl A macro to check presence of a cwrap wrapper on the system
dnl Usage:
dnl     AM_CHECK_WRAPPER(name, conditional)
dnl If the cwrap library is found, sets the HAVE_$name conditional
AC_DEFUN([AM_CHECK_WRAPPER],
[
    AC_MSG_CHECKING([for $1])
    PKG_CHECK_EXISTS([$1],
                     [
                        AC_MSG_RESULT([yes])
                        AC_SUBST([$2], [yes])
                     ],
                     [
                        AC_MSG_RESULT([no])
                        AC_SUBST([$2], [no])
                        AC_MSG_WARN([cwrap library $1 not found, some tests will not run])
                     ])

    AM_CONDITIONAL($2, [ test x$$2 = xyes])
])

AC_DEFUN([AM_CHECK_UID_WRAPPER],
[
    AM_CHECK_WRAPPER(uid_wrapper, HAVE_UID_WRAPPER)
])

AC_DEFUN([AM_CHECK_NSS_WRAPPER],
[
    AM_CHECK_WRAPPER(nss_wrapper, HAVE_NSS_WRAPPER)
])

AC_DEFUN([AM_CHECK_PAM_WRAPPER],
[
    AM_CHECK_WRAPPER(pam_wrapper, HAVE_PAM_WRAPPER)
])

AC_DEFUN([AM_CHECK_LIBPAMTEST],
[
    have_libpamtest="no"
    PKG_CHECK_EXISTS(libpamtest,
        dnl PKG_CHECK_EXISTS ACTION-IF-FOUND
        [PKG_CHECK_MODULES([PAMTEST], [libpamtest], [have_libpamtest="yes"])],
        dnl PKG_CHECK_EXISTS ACTION-IF-NOT-FOUND
        [AC_MSG_WARN([No libpamtest library found, some tests will not be built])]
    )
    AM_CONDITIONAL([HAVE_LIBPAMTEST], [test x$have_libpamtest = xyes])
])

AC_DEFUN([AM_CHECK_PWRAP_MODULES],
[
    PKG_CHECK_VAR([PAM_WRAPPER_MODULESDIR], [pam_wrapper], [modules])
    AC_MSG_CHECKING([pam_wrapper helper module path])
    if test x"$PAM_WRAPPER_MODULESDIR" = "x"; then
        AC_MSG_RESULT([no])
        AC_SUBST([PAM_WRAPPER_MODULESDIR])
        AC_MSG_WARN([No pam_wrapper helper modules found, some tests will not be built])
    else
        AC_MSG_RESULT([yes])
    fi

    AM_CONDITIONAL([HAVE_PWRAP_MODULES], [test x$PAM_WRAPPER_MODULESDIR != x])
])
