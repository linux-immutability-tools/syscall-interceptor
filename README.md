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
    arg0:
        content: 1
        isChar: false
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
    arg0:
        content: "/some/path"
        isChar: true
        isFdesc: false
        matchtype: "begins"
```
In this example, syscall interceptor checks if the argument in the syscall begins with "/some/path", meaning that trying to call `umount2` on `/some/path` or `/some/path/nested` would be blocked.


  - umount2
    log: true
    block: true
    arg0:
        content: 3
        isChar: false
```
In the case, that the argument is a char pointer, it can be specified how the argument should be matched, possible options are "full", "begins" and "contains":
```
log_file: /some/random/path
syscalls:It is also possible that some syscalls (such as arg0 in mount_setattr) use file descriptors to access files, in this case it is not possible for syscall-interceptor to intercept a sycall based on a clear path, instead the `isFdesc` option has to be set to true:
```
log_file: /some/random/path
syscalls:
  - mount_setattr
    log: true
    block: true
    arg0:
        content: "/some/path"
        isChar: true
        isFdesc: true
        matchtype: "begins"
```

In the case where a syscall accepts both (also mount_setattr), two entries for the same syscall can be configured:
```
log_file: /some/random/path
syscalls:
  - mount_setattr
    log: true
    block: true
    arg0:
        content: "/some/path"
        isChar: true
        isFdesc: true
        matchtype: "begins"
  - mount_setattr
    log: true
    block: true
    arg1:
        content: "/some/path"
        isChar: true
        isFdesc: false
        matchtype: "begins"
```
In this case a `mount_setattr` syscall gets blocked if either the file descriptor in `arg0` points to `/some/path` or if `arg1` equals `/some/path`

In the future an extra tool may be developed to either fully generate or at least assist with the generation of a configuration file, for now `strace` can be used to check which syscalls a program uses.

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
