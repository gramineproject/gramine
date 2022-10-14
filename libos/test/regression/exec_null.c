#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, const char** argv, const char** envp) {
    syscall(__NR_execve, "./exec_victim", NULL, NULL);
    return 1;
}
