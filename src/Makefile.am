#bin_PROGRAMS = syscall_interceptor
#syscall_interceptor_SOURCES = main.c
#syscall_interceptor_CFLAGS = -lsyscall_intercept

lib_LTLIBRARIES = libsyscall_interceptor.la
libsyscall_interceptor_la_SOURCES = main.c
libsyscall_interceptor_la_CFLAGS = -fpic -lsyscall_intercept -Wall -Wextra
libsyscall_interceptor_la_LDFLAGS = -version-info 1:0:0

