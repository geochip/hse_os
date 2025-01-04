#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdio.h>

int main() {
    int pid = syscall(SYS_fork);

    if (pid == 0) {
        printf("I am child! rc=%d\n", pid);
        syscall(SYS_exit, 11);
    } else {
        printf("I am parent! rc=%d\n", pid);
        // POSIX requires siginfo_t argument to be non-NULL
        // Linux allows it to be NULL
        siginfo_t siginfo = {};
        syscall(SYS_waitid, P_PID, pid, &siginfo, WEXITED, NULL);
        syscall(SYS_exit, 22);
    }
}
