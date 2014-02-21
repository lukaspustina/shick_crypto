AC_PREREQ([2.59])
AC_INIT([shick_crypto], [0.1], [lukas AT shickapp.com])

AC_CONFIG_SRCDIR([src/shick_crypto.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Werror foreign 1.9.6])

AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_AR
AC_PROG_LIBTOOL

AM_PATH_CHECK()
AC_SEARCH_LIBS(sodium_init, [sodium], [ ], AC_ERROR([libsodium not found]))

AC_ARG_ENABLE([gcov],
  [AS_HELP_STRING([--enable-gcov],
    [use Gcov to test the test suite])],
    [],
    [enable_gcov=no])
AM_CONDITIONAL([COND_GCOV],[test '!' "$enable_gcov" = no])

AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h])

AC_FUNC_MALLOC

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 tests/Makefile
                 examples/Makefile])

AC_OUTPUT

