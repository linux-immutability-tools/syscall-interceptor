#include <config.h>
#include <calls.h>
#include <limits.h>
#include <stdio.h>
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <errno.h>
#include <strings.h>

static int
hook (long syscall_number,
      long arg0, long arg1,
      long arg2, long arg3,
      long arg4, long arg5,
      long *result) {

  struct syscall *calls = get_calls();
  struct syscall *curr_call = calls;
  while(true) {
    if (curr_call->callnum == syscall_number) {
      //      puts ((char*) arg0);
      puts("here");
      *result = -ENOTSUP;
      return 0;
    }
    if (!curr_call->next) {
      return 1;
    }
    curr_call = curr_call->next;
  }
}

static __attribute__((constructor)) void
init(void) {
  intercept_hook_point = hook;
}

int
main (void)
{
  struct syscall *calls = get_calls();

  puts ("Hello World!");
  puts ("This is " PACKAGE_STRING ".");
  puts (LOG_FILE);
  //  printf ("%ld", calls->callnum);
  long *result = (long *) malloc(LONG_MAX);
  hook(SYS_umount2, 0, 0, 0, 0, 0, 0, result);
  printf("%ld", *result);
  return 0;
}
