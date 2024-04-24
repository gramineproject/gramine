#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    int ret;

    errno = 0;
    ret = eventfd(0, 0);
    if (ret != -1 && errno != ENOSYS)
        errx(1, "expected eventfd to fail with -ENOSYS but it returned ret=%d errno=%d", ret,
             errno);

    errno = 0;
    ret = fork();
    if (ret != -1 && errno != ENOSYS)
        errx(1, "expected fork to fail with -ENOSYS but it returned ret=%d errno=%d", ret, errno);

    errno = 0;
    ret = getpid();
    if (ret < 0)
        errx(1, "expected getpid to succeed but it returned ret=%d errno=%d", ret, errno);

    errno = 0;
    ret = gettid();
    if (ret < 0)
        errx(1, "expected gettid to succeed but it returned ret=%d errno=%d", ret, errno);

    puts("TEST OK");
    return 0;
}
