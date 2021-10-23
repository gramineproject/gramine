#define _GNU_SOURCE
#include <err.h>
#include <stdlib.h>
#include <sys/syscall.h>

int main(int argc, char** argv) {
    const char buf[] = "Hello world\n";
    long ret = -1;
#ifdef __x86_64__
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(__NR_write), "D"(1), "S"(buf), "d"(sizeof(buf) - 1)
        : "memory", "cc", "rcx", "r11"
    );
#endif
    if (ret < 0)
        errx(EXIT_FAILURE, "write syscall: %ld", ret);

    return 0;
}
