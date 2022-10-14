#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    syscall(__NR_execve, "./exec_victim", NULL, NULL);
    return 1;
}
