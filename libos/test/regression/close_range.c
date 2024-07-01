#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "common.h"

// These constants are inlined here (instead of using linux/close_range.h),
// so that we don't depend on relatively new versions of kernel headers.

#define CLOSE_RANGE_UNSHARE     (1U << 1)
#define CLOSE_RANGE_CLOEXEC     (1U << 2)

#ifndef __NR_close_range
#ifdef __x86_64__
#define __NR_close_range 436
#else
#error "unknown close_range syscall number for this architecture"
#endif
#endif

// Likewise, don't rely on the libc wrapper.

static int my_close_range(unsigned int start, unsigned int last, unsigned int flags) {
    return syscall(__NR_close_range, start, last, flags);
}

static void open_files(void) {
    for (int i = 3; i <= 9; i++) {
        int res;
        CHECK(res = open("/dev/null", O_RDONLY));
        if (res != i) {
            errx(1, "got unexpected fd %d, expected %d", res, i);
        }
    }
}

static void close_files(void) {
    CHECK(my_close_range(3, ~0u, 0));
}

static void check_closed(int fd) {
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) {
        errx(1, "file %d not closed", fd);
    }
}

static void check_cloexec(int fd) {
    int res;
    CHECK(res = fcntl(fd, F_GETFD));
    if (!(res & FD_CLOEXEC)) {
        errx(1, "file %d not cloexec", fd);
    }
}

static void check_nocloexec(int fd) {
    int res;
    CHECK(res = fcntl(fd, F_GETFD));
    if (res & FD_CLOEXEC) {
        errx(1, "file %d is cloexec", fd);
    }
}

static void* close_range_thread(void* arg) {
    int flags = *(int*)arg;
    CHECK(my_close_range(5, 7, flags));
    check_nocloexec(3);
    check_nocloexec(4);
    if (flags & CLOSE_RANGE_CLOEXEC) {
        check_cloexec(5);
        check_cloexec(6);
        check_cloexec(7);
    } else {
        check_closed(5);
        check_closed(6);
        check_closed(7);
    }
    check_nocloexec(8);
    check_nocloexec(9);
    return 0;
}

static void run_thread(int flags) {
    pthread_t thr;
    if ((errno = pthread_create(&thr, 0, close_range_thread, &flags))) {
        err(1, "pthread_create");
    }
    if ((errno = pthread_join(thr, 0))) {
        err(1, "pthread_join");
    }
}

static void test_close_range_plain(void) {
    open_files();
    run_thread(/*flags=*/0);
    check_nocloexec(3);
    check_nocloexec(4);
    check_closed(5);
    check_closed(6);
    check_closed(7);
    check_nocloexec(8);
    check_nocloexec(9);
    close_files();
}

static void test_close_range_cloexec(void) {
    open_files();
    run_thread(CLOSE_RANGE_CLOEXEC);
    check_nocloexec(3);
    check_nocloexec(4);
    check_cloexec(5);
    check_cloexec(6);
    check_cloexec(7);
    check_nocloexec(8);
    check_nocloexec(9);
    close_files();
}

static void test_close_range_plain_unshare(void) {
    open_files();
    run_thread(CLOSE_RANGE_UNSHARE);
    for (int i = 3; i <= 9; i++)
        check_nocloexec(i);
    close_files();
}

static void test_close_range_cloexec_unshare(void) {
    open_files();
    run_thread(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC);
    for (int i = 3; i <= 9; i++)
        check_nocloexec(i);
    close_files();
}

int main(void) {
    // Make sure all FDs from 3 upwards are closed on start.
    close_files();

    test_close_range_plain();
    test_close_range_cloexec();
    test_close_range_plain_unshare();
    test_close_range_cloexec_unshare();

    puts("TEST OK");

    return 0;
}
