AC_INIT([syscall_interceptor], [1.0], [axtlos@disroot.org])
LT_INIT
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIRS([m4])
AC_PROG_CC
AC_CHECK_LIB
AC_HEADER_STDC
AC_CHECK_HEADERS([strings.h])
AC_CHECK_HEADERS([libsyscall_intercept_hook_point.h])
AC_CHECK_HEADER_STDBOOL
AC_FUNC_MALLOC
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_RANLIB
AM_PROG_AR
AC_CONFIG_COMMANDS([config.yml],
                   [python3 parse_config.py > src/calls.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
