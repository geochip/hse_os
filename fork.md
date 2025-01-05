
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
- `kernel_clone`: https://elixir.bootlin.com/linux/v6.12.6/source/kernel/fork.c#L2765
- `copy_process`: https://elixir.bootlin.com/linux/v6.12.6/source/kernel/fork.c#L2138

## glibc

`fork()` and `__fork()` are actually aliases for `__libc_fork()`

```c
pid_t
__libc_fork (void)
{
...
}
weak_alias (__libc_fork, __fork)
libc_hidden_def (__fork)
weak_alias (__libc_fork, fork)
```

### `__libc_fork`

https://elixir.bootlin.com/glibc/glibc-2.38/source/posix/fork.c#L40

```c
...
  pid_t pid = _Fork ();
...
```

### `_Fork`

https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/nptl/_Fork.c#L23

```c
...
  pid_t pid = arch_fork (&THREAD_SELF->tid);
...
```

### `arch_fork`

https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/unix/sysv/linux/arch-fork.h#L35

```c
/* Call the clone syscall with fork semantic.  The CTID address is used */
...
  ret = INLINE_SYSCALL_CALL (clone, flags, 0, NULL, ctid, 0);
...
```

### macro `INLINE_SYSCALL_CALL`

https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/unix/sysv/linux/sysdep.h#L42

```c
#define INLINE_SYSCALL(name, nr, args...)				\
  ({									\
    long int sc_ret = INTERNAL_SYSCALL (name, nr, args);		\
    __glibc_unlikely (INTERNAL_SYSCALL_ERROR_P (sc_ret))		\
    ? SYSCALL_ERROR_LABEL (INTERNAL_SYSCALL_ERRNO (sc_ret))		\
    : sc_ret;								\
  })
```

#### macro `INTERNAL_SYSCALL(name, nr, args...)`

https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/unix/sysv/linux/x86_64/sysdep.h#L234

```c
#define INTERNAL_SYSCALL(name, nr, args...)				\
	internal_syscall##nr (SYS_ify (name), args)
```

#### macro `SYS_ify(syscall_name)`

 https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/unix/sysv/linux/x86_64/sysdep.h#L34

```c
#define SYS_ify(syscall_name)	__NR_##syscall_name
```

#### `<sys/syscall.h>`

```c
...
#define __NR_setsockopt 54
#define __NR_getsockopt 55
#define __NR_clone 56
#define __NR_fork 57
#define __NR_vfork 58
#define __NR_execve 59
#define __NR_exit 60
...
```

#### macro `internal_syscall5(number, arg1, arg2, arg3, arg4, arg5)`

https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/unix/sysv/linux/x86_64/sysdep.h#L322

```c
#define internal_syscall5(number, arg1, arg2, arg3, arg4, arg5)	\
({									\
    unsigned long int resultvar;					\
    TYPEFY (arg5, __arg5) = ARGIFY (arg5);			 	\
    TYPEFY (arg4, __arg4) = ARGIFY (arg4);			 	\
    TYPEFY (arg3, __arg3) = ARGIFY (arg3);			 	\
    TYPEFY (arg2, __arg2) = ARGIFY (arg2);			 	\
    TYPEFY (arg1, __arg1) = ARGIFY (arg1);			 	\
    register TYPEFY (arg5, _a5) asm ("r8") = __arg5;			\
    register TYPEFY (arg4, _a4) asm ("r10") = __arg4;			\
    register TYPEFY (arg3, _a3) asm ("rdx") = __arg3;			\
    register TYPEFY (arg2, _a2) asm ("rsi") = __arg2;			\
    register TYPEFY (arg1, _a1) asm ("rdi") = __arg1;			\
    asm volatile (							\
    "syscall\n\t"							\
    : "=a" (resultvar)							\
    : "0" (number), "r" (_a1), "r" (_a2), "r" (_a3), "r" (_a4),		\
      "r" (_a5)								\
    : "memory", REGISTERS_CLOBBERED_BY_SYSCALL);			\
    (long int) resultvar;						\
})
```

### Result

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

## glibc 2.3.2 (still uses `__NR_fork`)

### `__libc_fork`

https://elixir.bootlin.com/glibc/glibc-2.3.2/source/linuxthreads/sysdeps/unix/sysv/linux/fork.c#L37
https://elixir.bootlin.com/glibc/glibc-2.3.2/source/linuxthreads/sysdeps/pthread/bits/libc-lock.h#L110
https://elixir.bootlin.com/glibc/glibc-2.3.2/source/linuxthreads/pthread.c#L240

We start at `__libc_fork`. It calls either `__libc_pthread_functions.ptr_pthread_fork (&__fork_block)` or `ARCH_FORK ()`

```c
pid_t
__libc_fork (void)
{
  return __libc_maybe_call2 (pthread_fork, (&__fork_block), ARCH_FORK ());
}
weak_alias (__libc_fork, __fork)
weak_alias (__libc_fork, fork)
```

## `pthread_fork`

https://elixir.bootlin.com/glibc/glibc-2.3.2/source/linuxthreads/ptfork.c#L28

`pthread_fork` calls `ARCH_FORK`

```c
...
  pid = ARCH_FORK ();
...
```

### `ARCH_FORK`

- https://elixir.bootlin.com/glibc/glibc-2.3.2/source/linuxthreads/sysdeps/unix/sysv/linux/fork.h#L59
- https://elixir.bootlin.com/glibc/glibc-2.3.2/source/sysdeps/unix/sysv/linux/x86_64/sysdep.h#L201

`ARCH_FORK` make a syscall with number `__NR_fork` defined by linux kernel.

```c
# define ARCH_FORK() INLINE_SYSCALL (fork, 0)
```

```c
#define INLINE_SYSCALL(name, nr, args...) \
  ({									      \
    unsigned long resultvar = INTERNAL_SYSCALL (name, , nr, args);	      \
    if (__builtin_expect (INTERNAL_SYSCALL_ERROR_P (resultvar, ), 0))	      \
      {									      \
	__set_errno (INTERNAL_SYSCALL_ERRNO (resultvar, ));		      \
	resultvar = (unsigned long) -1;					      \
      }									      \
    (long) resultvar; })
```

```c
#define INTERNAL_SYSCALL(name, err, nr, args...) \
  ({									      \
    unsigned long resultvar;						      \
    LOAD_ARGS_##nr (args)						      \
    asm volatile (							      \
    "movq %1, %%rax\n\t"						      \
    "syscall\n\t"							      \
    : "=a" (resultvar)							      \
    : "i" (__NR_##name) ASM_ARGS_##nr : "memory", "cc", "r11", "cx");	      \
    (long) resultvar; })
```
