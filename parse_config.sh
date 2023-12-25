#!/bin/sh
# script=`cat $0 | tail -n +5`
# python -c "$script"
# exit
# PYTHON:
import yaml


class Syscall:
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
        log: bool,
        block: bool,
        arg0: str = "",
        arg1: str = "",
        arg2: str = "",
        arg3: str = "",
        arg4: str = "",
        arg5: str = "",
    ):
        self.log = log
        self.block = block
        self.arg0 = arg0
        self.arg1 = arg1
        self.arg2 = arg2
        self.arg3 = arg3
        self.arg4 = arg4
        self.arg5 = arg5


class Config:
    log_file: str = "/var/log/syscall-intercept.log"
    syscalls: list[Syscall]

    def __init__(self, log_file: str, syscalls: list[Syscall]):
        self.log_file = log_file
        self.syscalls = syscalls


def main():
    


if __name_ == "__main__":
    main()
