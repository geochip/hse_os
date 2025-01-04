
## fork(2)

```console
$ man 2 fork
```

```
...
VERSIONS
   C library/kernel differences
       Since  glibc  2.3.3,  rather  than invoking the kernel's fork() system call, the glibc fork() wrapper that is provided as part of the NPTL threading implementation invokes clone(2)
       with flags that provide the same effect as the traditional system call.  (A call to fork() is equivalent to a call to clone(2) specifying flags as just SIGCHLD.)  The glibc wrapper
       invokes any fork handlers that have been established using pthread_atfork(3).
...
```

## linux source code


### fork

Source: https://elixir.bootlin.com/linux/v6.12.6/source/kernel/fork.c#L2888

```c
...
	struct kernel_clone_args args = {
		.exit_signal = SIGCHLD,
	};

	return kernel_clone(&args);
...
```

### clone

Source: https://elixir.bootlin.com/linux/v6.12.6/source/kernel/fork.c#L2933

```c
...
	struct kernel_clone_args args = {
		.flags		= (lower_32_bits(clone_flags) & ~CSIGNAL),
		.pidfd		= parent_tidptr,
		.child_tid	= child_tidptr,
		.parent_tid	= parent_tidptr,
		.exit_signal	= (lower_32_bits(clone_flags) & CSIGNAL),
		.stack		= newsp,
		.tls		= tls,
	};

	return kernel_clone(&args);
...
```

### clone3

Source: https://elixir.bootlin.com/linux/v6.12.6/source/kernel/fork.c#L3089

```c
...
	kargs.set_tid = set_tid;

	err = copy_clone_args_from_user(&kargs, uargs, size);
	if (err)
		return err;

	if (!clone3_args_valid(&kargs))
		return -EINVAL;

	return kernel_clone(&kargs);
...
```

### implementation
- kernel_clone: https://elixir.bootlin.com/linux/v6.12.6/source/kernel/fork.c#L2765
- copy_process: https://elixir.bootlin.com/linux/v6.12.6/source/kernel/fork.c#L2138

## glibc

- __libc_fork: https://elixir.bootlin.com/glibc/glibc-2.38/source/posix/fork.c#L40
- _Fork: https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/nptl/_Fork.c#L23
- arch_fork: https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/unix/sysv/linux/arch-fork.h#L35

```c
/* Call the clone syscall with fork semantic.  The CTID address is used */
...
  ret = INLINE_SYSCALL_CALL (clone, flags, 0, NULL, ctid, 0);
...
```

### macro `INLINE_SYSCALL_CALL`

provided by `<sysdep.h>`

```c
#define INLINE_SYSCALL_CALL(...)                                              \
  __INLINE_SYSCALL_DISP (__INLINE_SYSCALL, __VA_ARGS__)

// Expands to
({
  long int sc_ret = ({

    unsigned long int resultvar;

    __typeof__ (((__typeof__ ((0) - (0))) (0)))                                  __arg5 = ((__typeof__ ((0) - (0))) (0));
    __typeof__ (((__typeof__ ((ctid) - (ctid))) (ctid)))                         __arg4 = ((__typeof__ ((ctid) - (ctid))) (ctid));
    __typeof__ (((__typeof__ ((((void *) 0)) - (((void *) 0)))) (((void *) 0)))) __arg3 = ((__typeof__ ((((void *) 0)) - (((void *) 0)))) (((void *) 0)));
    __typeof__ (((__typeof__ ((0) - (0))) (0)))                                  __arg2 = ((__typeof__ ((0) - (0))) (0));
    __typeof__ (((__typeof__ ((flags) - (flags))) (flags)))                      __arg1 = ((__typeof__ ((flags) - (flags))) (flags));

    register __typeof__ (((__typeof__ ((0) - (0))) (0)))                                  _a5 asm ("r8")  = __arg5;
    register __typeof__ (((__typeof__ ((ctid) - (ctid))) (ctid)))                         _a4 asm ("r10") = __arg4;
    register __typeof__ (((__typeof__ ((((void *) 0)) - (((void *) 0)))) (((void *) 0)))) _a3 asm ("rdx") = __arg3;
    register __typeof__ (((__typeof__ ((0) - (0))) (0)))                                  _a2 asm ("rsi") = __arg2;
    register __typeof__ (((__typeof__ ((flags) - (flags))) (flags)))                      _a1 asm ("rdi") = __arg1;

    asm volatile ("syscall\n\t"
		  : "=a"(resultvar)
		  : "0"(56), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5)
		  : "memory", "cc", "r11", "cx");

    (long int) resultvar;

  });
  __builtin_expect ((((unsigned long int) (sc_ret) > -4096UL)), 0) ? ({
    (__libc_errno = ((-(sc_ret))));
    -1L;
  })
        : sc_ret;
})
```

Get the list of syscalls and their numbers:

```console
$ printf '#include <sys/syscall.h>' | cpp -dM | grep -E '__NR_.* [0-9]+$' | sed -E 's/#define __NR_(.+) ([0-9]+)$/\1 \2/g' | sort -n -k 2
read 0
write 1
open 2
close 3
stat 4
fstat 5
...
```

Syscall number 56 is clone:

```console
$ printf '#include <sys/syscall.h>' | cpp -dM | grep -E '__NR_.* [0-9]+$' | sed -E 's/#define __NR_(.+) ([0-9]+)$/\1 \2/g' | sort -n -k 2 | grep ' 56'
clone 56
```

So glibc uses clone system call to implement fork()
