/* copyright axtlos <axtlos@disroot.org>
 * SPDX-LICENSE: LGPL-3.0-ONLY */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <libsyscall_intercept_hook_point.h>
#include "calls.h"

inline bool
has_flag(long search_flag, long all_flags)
{
    return (all_flags & search_flag) == search_flag;
}

bool
argcmp(int matchtype, long config_arg_long, char *config_arg_char, long sys_arg)
{
    bool return_val = false;

    if (!config_arg_char && config_arg_long != -1)
        return_val = has_flag (config_arg_long, sys_arg);
    else if (config_arg_char)
        switch (matchtype)
        {
            case -1:
                if (strncmp (config_arg_char, (char *)sys_arg, strlen (config_arg_char)) == 0)
                    return_val = true;
                break;
            case 0:
                if (strcmp ((char *)sys_arg, config_arg_char) == 0)
                    return_val = true;
                break;
            case 1:
                if (strstr ((char *)sys_arg, config_arg_char) != NULL)
                    return_val = true;
                break;
            default:
                return_val = false;
        }

    return return_val;
}

/* Function origin:
 *
 * https://www.gnu.org/software/libc/manual/html_node/Symbolic-Links.html#index-readlink */
char *
readlink_malloc(const char *filename)
{
    size_t size = 50;
    char *buffer = NULL;

    while (true)
    {
        buffer = reallocarray (buffer, size, 2);
        if (buffer == 0)
        {
            puts ("Virtual memory exhausted");
            exit (1);
        }
        size *= 2;
        ssize_t nchars = readlink (filename, buffer, size);
        if (nchars < 0)
        {
            free (buffer);
            return NULL;
        }
        if ((unsigned)nchars < size)
            return buffer;
    }
}

char *
get_fdesc(long arg)
{
    char *linkname, *procstat;
    pid_t pid = getpid ();
    int proc = asprintf (&procstat, "/proc/%d/fd/%ld", pid, arg);

    if (proc < 0)
        linkname = NULL;
    else
        linkname = readlink_malloc (procstat);

    return linkname;
}

bool
match_args(conf_syscall * call, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    bool arg0_match = true, arg1_match = true, arg2_match = true, arg3_match = true,
         arg4_match = true, arg5_match = true;

    if (call->arg0 || call->arg0_long != -1)
    {
        long arg = arg0;
        if (call->arg0_fdesc == true)
        {
            arg = (long)get_fdesc (arg0);
            if (arg <= 0)
                goto arg1cmp;
        }
        arg0_match = argcmp (call->arg0_matchtype, call->arg0_long, call->arg0, arg);
    }
arg1cmp:
    if (call->arg1 || call->arg1_long != -1)
    {
        long arg = arg1;
        if (call->arg1_fdesc == true)
        {
            arg = (long)get_fdesc (arg1);
            if (arg <= 0)
                goto arg2cmp;
        }
        arg1_match = argcmp (call->arg1_matchtype, call->arg1_long, call->arg1, arg);
    }
arg2cmp:
    if (call->arg2 || call->arg2_long != -1)
    {
        long arg = arg2;
        if (call->arg2_fdesc == true)
        {
            arg = (long)get_fdesc (arg2);
            if (arg <= 0)
                goto arg3cmp;
        }
        arg2_match = argcmp (call->arg2_matchtype, call->arg2_long, call->arg2, arg);
    }
arg3cmp:
    if (call->arg3 || call->arg3_long != -1)
    {
        long arg = arg3;
        if (call->arg3_fdesc == true)
        {
            arg = (long)get_fdesc (arg3);
            if (arg <= 0)
                goto arg4cmp;
        }
        arg3_match = argcmp (call->arg3_matchtype, call->arg3_long, call->arg3, arg);
    }
arg4cmp:
    if (call->arg4 || call->arg4_long != -1)
    {
        long arg = arg4;
        if (call->arg4_fdesc == true)
        {
            arg = (long)get_fdesc (arg4);
            if (arg <= 0)
                goto arg5cmp;
        }
        arg4_match = argcmp (call->arg4_matchtype, call->arg4_long, call->arg4, arg);
    }
arg5cmp:
    if (call->arg5 || call->arg5_long != -1)
    {
        long arg = arg5;
        if (call->arg5_fdesc == true)
        {
            arg = (long)get_fdesc (arg5);
            if (arg <= 0)
                goto cmpfinish;
        }
        arg5_match = argcmp (call->arg5_matchtype, call->arg5_long, call->arg5, arg);
    }
cmpfinish:
    return arg0_match && arg1_match && arg2_match && arg3_match && arg4_match && arg5_match;
}

void
log_call(conf_syscall * call)
{
    FILE *log_file;
    time_t t = time (NULL);
    struct tm timestruc = *localtime (&t);

    log_file = fopen (LOG_FILE, "a");
    fprintf (log_file, "Intercepted call %s at %d-%02d-%02d %02d:%02d:%02d\n",
             call->name, timestruc.tm_year + 1900, timestruc.tm_mon + 1,
             timestruc.tm_mday, timestruc.tm_hour, timestruc.tm_min,
             timestruc.tm_sec);
    fclose (log_file);
}

static int
hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result)
{
    conf_syscall *call = get_calls ();
    while (true)
    {
        if (call->callnum == syscall_number && match_args (call, arg0, arg1, arg2, arg3, arg4, arg5))
        {
            if (call->log)
                log_call (call);
            if (call->block)
            {
                *result = -ENOTSUP;
                return 0;
            }
        }
        if (!call->next)
            return 1;

        call = call->next;
    }
}

static __attribute__ ((constructor))
void
init(void)
{
    intercept_hook_point = &hook;
}
