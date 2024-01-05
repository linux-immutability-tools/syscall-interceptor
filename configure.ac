AC_PREREQ([2.71])
AC_INIT([syscall_interceptor], [1.0], [axtlos@disroot.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIRS([m4])

AC_CHECK_PROG([PYTHON3], [python3], ["yes"])
AS_IF([test "x$PYTHON3" != "xyes"], [
  AC_MSG_ERROR([Program python3 not found. Either install it or add it to PATH])
])

AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AM_PROG_AR

LT_INIT

AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([strings.h])
AC_CHECK_HEADERS([libsyscall_intercept_hook_point.h])
AC_CHECK_HEADER_STDBOOL

AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_FUNC_MALLOC
AC_CHECK_FUNCS([strstr])

AC_CONFIG_COMMANDS([config.yml],
                   [python3 parse_config.py > src/calls.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
