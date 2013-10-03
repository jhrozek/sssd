AC_PREREQ([2.69])
AC_INIT([cifs-idmap-sss-plugin], [0.1], [benjaminfranzke@googlemail.com])
AC_CONFIG_SRCDIR([cifs_idmap_sss.c])

AM_INIT_AUTOMAKE
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

PKG_CHECK_MODULES([SSS_IDMAP], [sss_idmap sss_nss_idmap])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([limits.h stdlib.h string.h cifsidmap.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strdup strerror])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
