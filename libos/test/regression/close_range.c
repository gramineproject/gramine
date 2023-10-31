#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

static void open_files(void) {
    for (int i = 3; i <= 9; i++) {
        int res = open("/dev/null", O_RDONLY);
        if (res < 0) {
            err(1, "open /dev/null");
        }
        if (res != i) {
            errx(1, "got unexpected fd %d, expected %d", res, i);
        }
    }
}

static void close_files(void) {
    if (close_range(3, ~0u, 0) == -1) {
        err(1, "close_range");
    }
}

static void check_closed(int fd) {
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) {
        errx(1, "file %d not closed", fd);
    }
}

static void check_cloexec(int fd) {
    int res = fcntl(fd, F_GETFD);
    if (res == -1) {
        err(1, "file %d not open", fd);
    }
    if (!(res & FD_CLOEXEC)) {
        errx(1, "file %d not cloexec", fd);
    }
}

static void check_open_nocloexec(int fd) {
    int res = fcntl(fd, F_GETFD);
    if (res == -1) {
        err(1, "file %d not open", fd);
    }
    if (res & FD_CLOEXEC) {
        errx(1, "file %d is cloexec", fd);
    }
}

static void* close_range_thread(void* arg) {
    int flags = *(int*)arg;
    if (close_range(5, 7, flags) == -1) {
        err(1, "close_range");
    }
    check_open_nocloexec(3);
    check_open_nocloexec(4);
    if (flags & CLOSE_RANGE_CLOEXEC) {
        check_cloexec(5);
        check_cloexec(6);
        check_cloexec(7);
    } else {
        check_closed(5);
        check_closed(6);
        check_closed(7);
    }
    check_open_nocloexec(8);
    check_open_nocloexec(9);
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
    check_open_nocloexec(3);
    check_open_nocloexec(4);
    check_closed(5);
    check_closed(6);
    check_closed(7);
    check_open_nocloexec(8);
    check_open_nocloexec(9);
    close_files();
}

static void test_close_range_cloexec(void) {
    open_files();
    run_thread(CLOSE_RANGE_CLOEXEC);
    check_open_nocloexec(3);
    check_open_nocloexec(4);
    check_cloexec(5);
    check_cloexec(6);
    check_cloexec(7);
    check_open_nocloexec(8);
    check_open_nocloexec(9);
    close_files();
}

static void test_close_range_plain_unshare(void) {
    open_files();
    run_thread(CLOSE_RANGE_UNSHARE);
    for (int i = 3; i <= 9; i++)
        check_open_nocloexec(i);
    close_files();
}

static void test_close_range_cloexec_unshare(void) {
    open_files();
    run_thread(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC);
    for (int i = 3; i <= 9; i++)
        check_open_nocloexec(i);
    close_files();
}

int main(void) {
    test_close_range_plain();
    test_close_range_cloexec();
    test_close_range_plain_unshare();
    test_close_range_cloexec_unshare();

    printf("TEST OK\n");

    return 0;
}
