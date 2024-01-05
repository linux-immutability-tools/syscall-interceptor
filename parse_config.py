# parse_config.py
# author: axtlos / axtloss <axtlos@disroot.org>
# SPDX-LICENSE: LGPL-3.0-ONLY

# Converts a yaml syscall-intercept configuration to a
# header file to be used by syscall-intercept
import yaml


header_template = """
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/syscall.h>

#define LOG_FILE "{PYLOGFILE}"

struct conf_syscall {{
  char *name;
  long callnum;
  bool log;
  bool block;
  char *arg0;
  long arg0_long;
  int arg0_matchtype;
  bool arg0_fdesc;
  char *arg1;
  long arg1_long;
  int arg1_matchtype;
  bool arg1_fdesc;
  char *arg2;
  long arg2_long;
  int arg2_matchtype;
  bool arg2_fdesc;
  char *arg3;
  long arg3_long;
  int arg3_matchtype;
  bool arg3_fdesc;
  char *arg4;
  long arg4_long;
  int arg4_matchtype;
  bool arg4_fdesc;
  char *arg5;
  long arg5_long;
  int arg5_matchtype;
  bool arg5_fdesc;

  struct conf_syscall *next;
  struct conf_syscall *prev;
}} syscall_default = {{NULL, -1, false, false, NULL, -1, 0, false, NULL, -1, 0, false, NULL, -1, 0, false, NULL, -1, 0, false, NULL, -1, 0, false, NULL, -1, 0, false, NULL, NULL}};

typedef struct conf_syscall conf_syscall;

conf_syscall *
get_calls() {{
{PYSTRUCTBUILD}
return {FIRSTVARNAME};
}};
"""

structbuild_template = {
    "var_define": "conf_syscall *{varname} = (struct conf_syscall *) malloc(sizeof(conf_syscall));\nmemcpy({varname}, &syscall_default, sizeof(conf_syscall));\n",
    "set_name": '{varname}->name = (char *) malloc(strlen("{name}")+1);\nstrcpy({varname}->name, "{name}");\n{varname}->callnum = {name};\n',
    "set_log": "{varname}->log = {log};\n",
    "set_block": "{varname}->block = {block};\n",
    "set_arg_char": '{varname}->{argname} = (char *) malloc(strlen("{arg}")+1);\nstrcpy({varname}->{argname}, "{arg}");\n',
    "set_arg_long": '{varname}->{argname}_long = {arg};\n',
    "set_arg_matchtype": '{varname}->{argname}_matchtype = {matchtype};\n',
    "set_arg_isfdesc": '{varname}->{argname}_fdesc = {isfdesc};\n',
    "set_next": "{varname}->next = {nextcall};\n",
    "set_prev": "{varname}->prev = {prevcall};\n",
}


class Argument:
    content: str = ""
    matchtype: str = "full"
    isChar: bool = True
    isFdesc: bool = False

    def __init__(self, content: str = "", matchtype: str = "full", isChar: bool = True, isFdesc: bool = False):
        self.content = content
        self.matchtype = matchtype
        self.isChar = isChar
        self.isFdesc = isFdesc

    def build_c_code(self, varname: str, argnum: str) -> str:
        c_code = ""
        if self.content != "" and self.isChar:
            c_code = c_code+structbuild_template["set_arg_char"].format(varname=varname, argname="arg"+argnum, arg=self.content)
            c_code = c_code+structbuild_template["set_arg_matchtype"].format(varname=varname, argname="arg"+argnum, matchtype=0 if self.matchtype == "full" else -1 if self.matchtype == "begins" else 1)
        elif self.content != "" and not self.isChar:
            c_code = c_code+structbuild_template["set_arg_long"].format(varname=varname, argname="arg"+argnum, arg=self.content)
        if self.isFdesc:
            c_code = c_code+structbuild_template["set_arg_isfdesc"].format(varname=varname, argname="arg"+argnum, isfdesc=self.isFdesc)
        return c_code

    @staticmethod
    def init_from_dict(parsed: dict):
        arg = Argument()
        if parsed.get("content") is not None:
            arg.content = str(parsed.get("content"))
        if parsed.get("matchtype") is not None:
            arg.matchtype = str(parsed.get("matchtype"))
        if parsed.get("isChar") is not None:
            arg.isChar = bool(parsed.get("isChar"))
        if parsed.get("isFdesc") is not None:
            arg.isFdesc = bool(parsed.get("isFdesc"))
        return arg

class Syscall:
    name: str
    log: bool
    block: bool
    arg0: Argument = Argument()
    arg1: Argument = Argument()
    arg2: Argument = Argument()
    arg3: Argument = Argument()
    arg4: Argument = Argument()
    arg5: Argument = Argument()

    def __init__(
        self,
        name: str,
        log: bool,
        block: bool,
        arg0: Argument = Argument(),
        arg1: Argument = Argument(),
        arg2: Argument = Argument(),
        arg3: Argument = Argument(),
        arg4: Argument = Argument(),
        arg5: Argument = Argument(),
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
        c_code = c_code + self.arg0.build_c_code(varname, "0")
        c_code = c_code + self.arg1.build_c_code(varname, "1")
        c_code = c_code + self.arg2.build_c_code(varname, "2")
        c_code = c_code + self.arg3.build_c_code(varname, "4")
        c_code = c_code + self.arg4.build_c_code(varname, "5")
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
            call.arg0 = Argument.init_from_dict(parsed["arg0"])
        if parsed.get("arg1") is not None:
            call.arg1 = Argument.init_from_dict(parsed["arg1"])
        if parsed.get("arg2") is not None:
            call.arg2 = Argument.init_from_dict(parsed["arg2"])
        if parsed.get("arg3") is not None:
            call.arg3 = Argument.init_from_dict(parsed["arg3"])
        if parsed.get("arg4") is not None:
            call.arg4 = Argument.init_from_dict(parsed["arg4"])
        if parsed.get("arg5") is not None:
            call.arg5 = Argument.init_from_dict(parsed["arg5"])
        return call


class Config:
    log_file: str = "/var/log/syscall-intercept.log"
    syscalls: list[Syscall]

    def __init__(self, log_file: str, syscalls: list[Syscall]):
        self.log_file = log_file
        self.syscalls = syscalls

    def build_c_code(self) -> str:
        i: int = len(self.syscalls)
        c_structs: str = ""
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
