#include <config.h>
#include <calls.h>
#include <limits.h>
#include <stdio.h>
#include <libsyscall_intercept_hook_point.h>
#include <string.h>
#include <syscall.h>
#include <errno.h>
#include <strings.h>
#include <time.h>

bool
has_flag(long search_flag, long all_flags) {
    return (all_flags & search_flag) == search_flag;
}

bool
argcmp(int matchtype, long config_arg_long, char *config_arg_char, long sys_arg) {
    if (!config_arg_char && config_arg_long != -1) {
        return has_flag(config_arg_long, sys_arg);
    } else if (config_arg_char) {
        switch (matchtype) {
        case -1:
            return strncmp(config_arg_char, (char*)sys_arg, strlen(config_arg_char)) == 0;
        case 0:
            if (strcmp((char *)sys_arg, config_arg_char) == 0)
                return true;
            break;
        case 1:
            if (strstr((char *)sys_arg, config_arg_char) != NULL)
                return true;
            break;
        default:
            return false;
        }
    }
    return false;
}

bool
match_args(syscall *call, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
    bool arg0_match = true, arg1_match = true, arg2_match = true, arg3_match = true, arg4_match = true, arg5_match = true;
    if (call->arg0 || call->arg0_long != -1) {
        arg0_match = argcmp(call->arg0_matchtype, call->arg0_long, call->arg0, arg0);
    }
    if (call->arg1 || call->arg1_long != -1) {
        arg1_match = argcmp(call->arg1_matchtype, call->arg1_long, call->arg1, arg1);
    }
    if (call->arg2 || call->arg2_long != -1) {
        arg2_match = argcmp(call->arg2_matchtype, call->arg2_long, call->arg2, arg2);
    }
    if (call->arg3 || call->arg3_long != -1) {
        arg3_match = argcmp(call->arg3_matchtype, call->arg3_long, call->arg3, arg3);
    }
    if (call->arg4 || call->arg4_long != -1) {
        arg4_match = argcmp(call->arg4_matchtype, call->arg4_long, call->arg4, arg4);
    }
    if (call->arg5 || call->arg5_long != -1) {
        arg5_match = argcmp(call->arg5_matchtype, call->arg5_long, call->arg5, arg5);
    }

    return arg0_match && arg1_match && arg2_match && arg3_match && arg4_match && arg5_match;
}

void
log_call(syscall *call) {
    FILE *log_file;
    time_t t = time(NULL);
    struct tm timestruc = *localtime(&t);

    log_file = fopen(LOG_FILE, "a");
    fprintf(log_file, "Intercepted call %s at %d-%02d-%02d %02d:%02d:%02d\n", call->name, timestruc.tm_year+1900, timestruc.tm_mon+1, timestruc.tm_mday, timestruc.tm_hour, timestruc.tm_min, timestruc.tm_sec);
    fclose(log_file);
}

static int
hook (long syscall_number,
      long arg0, long arg1,
      long arg2, long arg3,
      long arg4, long arg5,
      long *result) {

    syscall *call = get_calls();
    while(true) {
        if (call->callnum == syscall_number
            && match_args(call, arg0, arg1, arg2, arg3, arg4, arg5))
        {
            if (call->log) {
                log_call(call);
            }
            if (call->block) {
                *result = -ENOTSUP;
                return 0;
            }
        }
        if (!call->next) {
            return 1;
        }
        call = call->next;
    }
}

static __attribute__((constructor)) void
init(void) {
    intercept_hook_point = &hook;
}
