# syscall-interceptor

A program that intercepts syscalls issued by other programs and logs/blocks them.

## Configuring:
The configuration is the `config.yml` file in the root of the repository.
It only requires the `syscalls` field, however the `log_file` field should also be configured.
An example configuration that blocks the `umount2(2)` syscall with the `MNT_DETACH` flag, which gets called when running `umount -l`:
```
log_file: /some/random/path
syscalls:
  - umount2
    log: true
    block: true
    arg0: 1
    arg0_char: false
```
the name of the object is what gets interpreted as the syscall name, here the name `umount2` is taken, but `SYS_umount2` would also be accepted.
each syscall object can have a total of 6 args, reaching from arg0 to arg5, each also having an Argo_char option, which needs to be set if the argN field is set.
The argN_char option tells the parser if the argument is a string argument, e.g. if its a path, or if it a long, e.g. flags that can be raised, like `MNT_DETACH`.
In the example, arg0 is set to a long of value 1, this corresponds to the `MNT_DETACH` flag, if, for example, the syscall should only be blocked if `MNT_DETACH` _and_ `MNT_FORCE` are set, then the result of a bitwise or (|=) with `MNT_DETACH` and `MNT_FORCE` (which is 3) should be set to arg0:
```
log_file: /some/random/path
syscalls:
  - umount2
    log: true
    block: true
    arg0: 3
    arg0_char: false
```

In the future an extra tool may be developed to either fully generate or at least assist with the generation of a configuration file.

## Building
Dependencies:
- gcc (or equivalent c compiler)
- autotools
- [syscall_intercept](https://github.com/pmem/syscall_intercept)

assuming `config.yml` has already been properly adjusted:
```
autoreconf --install
./configure
make
```
The resulting shared object file will be placed in `src/.libs`

## Usage
To activate syscall-interceptor, libsyscall_interceptor.so will have to be preloaded.
This can be done with the `LD_PRELOAD` environment variable:
`LD_PRELOAD=/path/to/libsyscall_interceptor.so <command>`
