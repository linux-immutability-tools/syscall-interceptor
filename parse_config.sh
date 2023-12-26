#!/bin/sh
# parse_config.h
# author: axtlos / axtloss <axtlos@disroot.org>
# SPDX-LICENSE: GPL-3.0-ONLY

# Converts a yaml syscall-intercept configuration to a
# header file to be used by syscall-intercept
script=`cat $0 | tail -n +12`
python -c "$script"
exit
# PYTHON:
import yaml


header_template = """
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define LOG_FILE "{PYLOGFILE}"

struct syscall {{
  char *name; // TODO: change to long
  bool log;
  bool block;
  char *arg0;
  char *arg1;
  char *arg2;
  char *arg3;
  char *arg4;
  char *arg5;

  struct syscall *next;
  struct syscall *prev;
}};


struct syscall *
get_calls() {{
{PYSTRUCTBUILD}
return {FIRSTVARNAME};
}};
"""

structbuild_template = {
    "var_define": "struct syscall *{varname} = (struct syscall *) malloc(sizeof(struct syscall));\n",
    "set_name": '{varname}->name = (char *) malloc(strlen("{name}")+1);\nstrcpy({varname}->name, "{name}");\n',
    "set_log": "{varname}->log = {log};\n",
    "set_block": "{varname}->block = {block};\n",
    "set_arg": '{varname}->{argname} = (char *) malloc(strlen("{arg}")+1);\nstrcpy({varname}->{argname}, "{arg}");\n',
    "set_next": "{varname}->next = {nextcall};\n",
    "set_prev": "{varname}->prev = {prevcall};\n",
}


class Syscall:
    name: str
    log: bool
    block: bool
    arg0: str = ""
    arg1: str = ""
    arg2: str = ""
    arg3: str = ""
    arg4: str = ""
    arg5: str = ""

    def __init__(
        self,
        name: str,
        log: bool,
        block: bool,
        arg0: str = "",
        arg1: str = "",
        arg2: str = "",
        arg3: str = "",
        arg4: str = "",
        arg5: str = "",
    ):
        self.name = name
        self.log = log
        self.block = block
        self.arg0 = arg0
        self.arg1 = arg1
        self.arg2 = arg2
        self.arg3 = arg3
        self.arg4 = arg4
        self.arg5 = arg5

    def build_c_code(self, varname: str) -> str:
        c_code = structbuild_template["var_define"].format(varname=varname)
        c_code = c_code + structbuild_template["set_name"].format(
            varname=varname, name=self.name
        )
        c_code = c_code + structbuild_template["set_log"].format(
            varname=varname, log=self.log
        )
        c_code = c_code + structbuild_template["set_block"].format(
            varname=varname, block=self.block
        )
        if self.arg0 != "":
            c_code = c_code + structbuild_template["set_arg"].format(
                varname=varname, argname="arg0", arg=self.arg0
            )
        if self.arg1 != "":
            c_code = c_code + structbuild_template["set_arg"].format(
                varname=varname, argname="arg1", arg=self.arg1
            )
        if self.arg2 != "":
            c_code = c_code + structbuild_template["set_arg"].format(
                varname=varname, argname="arg2", arg=self.arg2
            )
        if self.arg3 != "":
            c_code = c_code + structbuild_template["set_arg"].format(
                varname=varname, argname="arg3", arg=self.arg3
            )
        if self.arg4 != "":
            c_code = c_code + structbuild_template["set_arg"].format(
                varname=varname, argname="arg4", arg=self.arg4
            )
        if self.arg5 != "":
            c_code = c_code + structbuild_template["set_arg"].format(
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
            call.block = bool(parsed.get("log"))
        if parsed.get("arg0") is not None:
            call.arg0 = str(parsed.get("arg0"))
        if parsed.get("arg1") is not None:
            call.arg1 = str(parsed.get("arg1"))
        if parsed.get("arg2") is not None:
            call.arg2 = str(parsed.get("arg2"))
        if parsed.get("arg3") is not None:
            call.arg3 = str(parsed.get("arg3"))
        if parsed.get("arg4") is not None:
            call.arg4 = str(parsed.get("arg4"))
        if parsed.get("arg5") is not None:
            call.arg5 = str(parsed.get("arg5"))
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
            elif i == len(self.syscalls):
                linked_list_setup = linked_list_setup + structbuild_template[
                    "set_prev"
                ].format(varname="call" + str(i), prevcall="call" + str(i - 1))
            else:
                linked_list_setup = linked_list_setup + structbuild_template[
                    "set_prev"
                ].format(varname="call" + str(i), prevcall="call" + str(i - 1))
                linked_list_setup = linked_list_setup + structbuild_template[
                    "set_next"
                ].format(varname="call" + str(i), nextcall="call" + str(i + 1))

        c_structs = c_structs + linked_list_setup
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
