# parse_config.py
# author: axtlos / axtloss <axtlos@disroot.org>
# SPDX-LICENSE: GPL-3.0-ONLY

# Converts a yaml syscall-intercept configuration to a
# header file to be used by syscall-intercept
import yaml


header_template = """
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/syscall.h>

#define LOG_FILE "{PYLOGFILE}"

struct syscall {{
  char *name;
  long callnum;
  bool log;
  bool block;
  char *arg0;
  long arg0_long;
  char *arg1;
  long arg1_long;
  char *arg2;
  long arg2_long;
  char *arg3;
  long arg3_long;
  char *arg4;
  long arg4_long;
  char *arg5;
  long arg5_long;

  struct syscall *next;
  struct syscall *prev;
}} syscall_default = {{NULL, -1, false, false, NULL, -1, NULL, -1, NULL, -1, NULL, -1, NULL, -1, NULL, -1, NULL, NULL}};

typedef struct syscall syscall;

syscall *
get_calls() {{
{PYSTRUCTBUILD}
return {FIRSTVARNAME};
}};
"""

structbuild_template = {
    "var_define": "syscall *{varname} = (struct syscall *) malloc(sizeof(syscall));\nmemcpy({varname}, &syscall_default, sizeof(syscall));\n",
    "set_name": '{varname}->name = (char *) malloc(strlen("{name}")+1);\nstrcpy({varname}->name, "{name}");\n{varname}->callnum = {name};\n',
    "set_log": "{varname}->log = {log};\n",
    "set_block": "{varname}->block = {block};\n",
    "set_arg_char": '{varname}->{argname} = (char *) malloc(strlen("{arg}")+1);\nstrcpy({varname}->{argname}, "{arg}");\n',
    "set_arg_long": '{varname}->{argname}_long = {arg};\n',
    "set_next": "{varname}->next = {nextcall};\n",
    "set_prev": "{varname}->prev = {prevcall};\n",
}


class Syscall:
    name: str
    log: bool
    block: bool
    arg0: str = ""
    arg_char: bool = True
    arg1: str = ""
    arg1_char: bool = True
    arg2: str = ""
    arg2_char: bool = True
    arg3: str = ""
    arg3_char: bool = True
    arg4: str = ""
    arg4_char: bool = True
    arg5: str = ""
    arg5_char: bool = True

    def __init__(
        self,
        name: str,
        log: bool,
        block: bool,
        arg0: str = "",
        arg0_char: bool = True,
        arg1: str = "",
        arg1_char: bool = True,
        arg2: str = "",
        arg2_char: bool = True,
        arg3: str = "",
        arg3_char: bool = True,
        arg4: str = "",
        arg4_char: bool = True,
        arg5: str = "",
        arg5_char: bool = True,
    ):
        self.name = name
        self.log = log
        self.block = block
        self.arg0 = arg0
        self.arg0_char = arg0_char
        self.arg1 = arg1
        self.arg1_char = arg1_char
        self.arg2 = arg2
        self.arg2_char = arg2_char
        self.arg3 = arg3
        self.arg3_char = arg3_char
        self.arg4 = arg4
        self.arg4_char = arg4_char
        self.arg5 = arg5
        self.arg5_char = arg5_char

    def build_c_code(self, varname: str) -> str:
        c_code = structbuild_template["var_define"].format(varname=varname)
        if self.name.startswith("SYS_"):
            c_code = c_code + structbuild_template["set_name"].format(
                varname=varname, name=self.name.lower()
            )
        else:
            c_code = c_code + structbuild_template["set_name"].format(
                varname=varname, name="SYS_"+self.name.lower()
            )


        c_code = c_code + structbuild_template["set_log"].format(
            varname=varname, log=str(self.log).lower()
        )
        c_code = c_code + structbuild_template["set_block"].format(
            varname=varname, block=str(self.block).lower()
        )
        if self.arg0 != "":
            if self.arg0_char:
                c_code = c_code + structbuild_template["set_arg_char"].format(
                    varname=varname, argname="arg0", arg=self.arg0
                )
            else:
                c_code = c_code + structbuild_template["set_arg_long"].format(
                    varname=varname, argname="arg0", arg=self.arg0
                )

        if self.arg1 != "":
            if self.arg1_char:
                c_code = c_code + structbuild_template["set_arg_char"].format(
                    varname=varname, argname="arg1", arg=self.arg1
                )
            else:
                c_code = c_code + structbuild_template["set_arg_long"].format(
                    varname=varname, argname="arg1", arg=self.arg1
                )

        if self.arg2 != "":
            if self.arg2_char:
                c_code = c_code + structbuild_template["set_arg_char"].format(
                    varname=varname, argname="arg2", arg=self.arg2
                )
            else:
                c_code = c_code + structbuild_template["set_arg_long"].format(
                    varname=varname, argname="arg2", arg=self.arg2
                )


        if self.arg3 != "":
            if self.arg3_char:
                c_code = c_code + structbuild_template["set_arg_char"].format(
                    varname=varname, argname="arg3", arg=self.arg3
                )
            else:
                c_code = c_code + structbuild_template["set_arg_long"].format(
                    varname=varname, argname="arg3", arg=self.arg3
                )

        if self.arg4 != "":
            if self.arg4_char:
                c_code = c_code + structbuild_template["set_arg_char"].format(
                    varname=varname, argname="arg4", arg=self.arg4
                )
            else:
                c_code = c_code + structbuild_template["set_arg_long"].format(
                    varname=varname, argname="arg4", arg=self.arg4
                )

        if self.arg5 != "":
            if self.arg5_char:
                c_code = c_code + structbuild_template["set_arg_char"].format(
                    varname=varname, argname="arg5", arg=self.arg5
                )
            else:
                c_code = c_code + structbuild_template["set_arg_long"].format(
                    varname=varname, argname="arg5", arg=self.arg5
                )
        return c_code

    @staticmethod
    def init_from_dict(parsed: dict):
        call = Syscall(name=next(iter(parsed)), log=True, block=False)
        parsed = parsed[next(iter(parsed))]
        if parsed.get("log") is not None:
            call.log = bool(parsed.get("log"))
        if parsed.get("block") is not None:
            call.block = bool(parsed.get("block"))
        if parsed.get("arg0") is not None:
            call.arg0 = str(parsed.get("arg0"))
            call.arg0_char = bool(parsed.get("arg0_char"))
        if parsed.get("arg1") is not None:
            call.arg1 = str(parsed.get("arg1"))
            call.arg1_char = bool(parsed.get("arg1_char"))
        if parsed.get("arg2") is not None:
            call.arg2 = str(parsed.get("arg2"))
            call.arg2_char = bool(parsed.get("arg2_char"))
        if parsed.get("arg3") is not None:
            call.arg3 = str(parsed.get("arg3"))
            call.arg3_char = bool(parsed.get("arg3_char"))
        if parsed.get("arg4") is not None:
            call.arg4 = str(parsed.get("arg4"))
            call.arg4_char = bool(parsed.get("arg4_char"))
        if parsed.get("arg5") is not None:
            call.arg5 = str(parsed.get("arg5"))
            call.arg5_char = bool(parsed.get("arg5_char"))
        return call


class Config:
    log_file: str = "/var/log/syscall-intercept.log"
    syscalls: list[Syscall]

    def __init__(self, log_file: str, syscalls: list[Syscall]):
        self.log_file = log_file
        self.syscalls = syscalls

    def build_c_code(self) -> str:
        i: int = len(self.syscalls)
        c_structs = ""
        for syscall in reversed(self.syscalls):
            c_structs = c_structs + syscall.build_c_code("call" + str(i))
            i = i - 1
            c_structs = c_structs + "\n"

        linked_list_setup = ""
        for i in range(1, len(self.syscalls) + 1):
            if i == 1:
                linked_list_setup = linked_list_setup + structbuild_template[
                    "set_next"
                ].format(varname="call" + str(i), nextcall="call" + str(i + 1))
                linked_list_setup = linked_list_setup + structbuild_template[
                    "set_prev"
                ].format(varname="call" + str(i), prevcall="NULL")
            elif i == len(self.syscalls):
                linked_list_setup = linked_list_setup + structbuild_template[
                    "set_prev"
                ].format(varname="call" + str(i), prevcall="call" + str(i - 1))
                linked_list_setup = linked_list_setup + structbuild_template[
                    "set_next"
                ].format(varname="call" + str(i), nextcall="NULL")
            else:
                linked_list_setup = linked_list_setup + structbuild_template[
                    "set_prev"
                ].format(varname="call" + str(i), prevcall="call" + str(i - 1))
                linked_list_setup = linked_list_setup + structbuild_template[
                    "set_next"
                ].format(varname="call" + str(i), nextcall="call" + str(i + 1))

        c_structs = c_structs + linked_list_setup
        argtypes: list[str] = []
        c_code = header_template.format(
            PYLOGFILE=self.log_file,
            PYSTRUCTBUILD=c_structs,
            FIRSTVARNAME="call1",
        )
        return c_code

    @staticmethod
    def init_from_dict(parsed: dict):
        config = Config(log_file="", syscalls=[])
        if parsed.get("log_file") is not None:
            config.log_file = str(parsed.get("log_file"))
        if parsed.get("syscalls") is not None:
            for syscall in list(parsed["syscalls"]):
                config.syscalls.append(Syscall.init_from_dict(syscall))
        return config


def main():
    config: dict
    with open("config.yml", "r") as conf:
        config = yaml.safe_load(conf)

    parsed_config = Config.init_from_dict(config)
    print(parsed_config.build_c_code())


if __name__ == "__main__":
    main()
