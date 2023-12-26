AC_INIT([syscall_intercept], [1.0], [axtlos@disroot.org])
LT_INIT
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIRS([m4])
AC_PROG_CC
AC_CHECK_LIB
AC_HEADER_STDC
AM_PROG_AR
AC_CONFIG_COMMANDS([config.yml],
                   [./parse_config.sh > src/calls.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
