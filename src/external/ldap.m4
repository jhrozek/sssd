dnl AC_SUBST(LDAP_LIBS)
dnl
dnl AC_CHECK_HEADERS(lber.h ldap.h, , AC_MSG_ERROR("could not locate ldap header files please install devel package"))
dnl
dnl AC_CHECK_LIB(lber, main, LDAP_LIBS="-llber $LDAP_LIBS")
dnl AC_CHECK_LIB(ldap, main, LDAP_LIBS="-lldap $LDAP_LIBS")
dnl
dnl ---------------------------------------------------------------------------
dnl - Check for Mozilla LDAP or OpenLDAP SDK
dnl ---------------------------------------------------------------------------

AC_CHECK_LIB(ldap, ldap_search, with_ldap=yes)
dnl Check for other libraries we need to link with to get the main routines.
test "$with_ldap" != "yes" && { AC_CHECK_LIB(ldap, ldap_open, [with_ldap=yes with_ldap_lber=yes], , -llber) }
test "$with_ldap" != "yes" && { AC_CHECK_LIB(ldap, ldap_open, [with_ldap=yes with_ldap_lber=yes with_ldap_krb=yes], , -llber -lkrb) }
test "$with_ldap" != "yes" && { AC_CHECK_LIB(ldap, ldap_open, [with_ldap=yes with_ldap_lber=yes with_ldap_krb=yes with_ldap_des=yes], , -llber -lkrb -ldes) }
dnl Recently, we need -lber even though the main routines are elsewhere,
dnl because otherwise be get link errors w.r.t. ber_pvt_opt_on.  So just
dnl check for that (it's a variable not a fun but that doesn't seem to
dnl matter in these checks)  and stick in -lber if so.  Can't hurt (even to
dnl stick it in always shouldn't hurt, I don't think) ... #### Someone who
dnl #### understands LDAP needs to fix this properly.
test "$with_ldap_lber" != "yes" && { AC_CHECK_LIB(lber, ber_pvt_opt_on, with_ldap_lber=yes) }

if test "$with_ldap" = "yes"; then
  if test "$with_ldap_des" = "yes" ; then
    OPENLDAP_LIBS="${OPENLDAP_LIBS} -ldes"
  fi
  if test "$with_ldap_krb" = "yes" ; then
    OPENLDAP_LIBS="${OPENLDAP_LIBS} -lkrb"
  fi
  if test "$with_ldap_lber" = "yes" ; then
    OPENLDAP_LIBS="${OPENLDAP_LIBS} -llber"
  fi
  OPENLDAP_LIBS="${OPENLDAP_LIBS} -lldap"
else
  AC_MSG_ERROR([OpenLDAP not found])
fi

AC_SUBST(OPENLDAP_LIBS)

SAVE_CFLAGS=$CFLAGS
SAVE_LIBS=$LIBS
CFLAGS="$CFLAGS $OPENLDAP_CFLAGS"
LIBS="$LIBS $OPENLDAP_LIBS"
AC_CHECK_FUNCS([ldap_control_create ldap_init_fd])
AC_CHECK_MEMBERS([struct ldap_conncb.lc_arg],
                 [AC_RUN_IFELSE(
                   [AC_LANG_PROGRAM(
                     [[ #include <ldap.h> ]],
                     [[
                       struct ldap_conncb cb;
                       return ldap_set_option(NULL, LDAP_OPT_CONNECT_CB, &cb);
                     ]] )],
                   [AC_DEFINE([HAVE_LDAP_CONNCB], [1],
                     [Define if LDAP connection callbacks are available])],
                   [AC_MSG_WARN([Found broken callback implementation])],
                   [])],
                 [], [[#include <ldap.h>]])

CFLAGS=$SAVE_CFLAGS
LIBS=$SAVE_LIBS

