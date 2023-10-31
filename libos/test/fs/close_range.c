#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/close_range.h>
#include <pthread.h>
#include <unistd.h>

#include "common.h"

static void open_files(void) {
    for (int i = 3; i <= 9; i += 1) {
        int res = open("/dev/null", O_RDONLY);
        if (res < 0) {
            fatal_error("Failed to open /dev/null: %s\n", strerror(errno));
        }
        if (res != i) {
            fatal_error("Got unexpected fd %d, expected %d\n", res, i);
        }
    }
}

static void close_files(void) {
    if (close_range(3, ~0u, 0)) {
        fatal_error("Failed to close_range: %s\n", strerror(errno));
    }
}

static void check_closed(int fd) {
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) {
        fatal_error("File %d not closed\n", fd);
    }
}

static void check_cloexec(int fd) {
    int res = fcntl(fd, F_GETFD);
    if (res == -1) {
        fatal_error("File %d not open\n", fd);
    }
    if (res != FD_CLOEXEC) {
        fatal_error("File %d not cloexec\n", fd);
    }
}

static void check_open_nocloexec(int fd) {
    int res = fcntl(fd, F_GETFD);
    if (res == -1) {
        fatal_error("File %d not open\n", fd);
    }
    if (res != 0) {
        fatal_error("File %d is cloexec\n", fd);
    }
}

static void* close_range_thread(void* arg) {
    int flags = *(int*)arg;
    if (close_range(5, 7, flags)) {
        fatal_error("Failed to close_range: %s\n", strerror(errno));
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
    int err;
    if ((err = pthread_create(&thr, 0, close_range_thread, &flags))) {
        fatal_error("failed to spawn thread: %s\n", strerror(err));
    }
    if ((err = pthread_join(thr, 0))) {
        fatal_error("failed to join thread: %s\n", strerror(err));
    }
}

static void close_range_plain(void) {
    open_files();
    run_thread(0);
    check_open_nocloexec(3);
    check_open_nocloexec(4);
    check_closed(5);
    check_closed(6);
    check_closed(7);
    check_open_nocloexec(8);
    check_open_nocloexec(9);
    close_files();
}

static void close_range_cloexec(void) {
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

static void close_range_plain_unshare(void) {
    open_files();
    run_thread(CLOSE_RANGE_UNSHARE);
    for (int i = 3; i <= 9; i++) check_open_nocloexec(i);
    close_files();
}

static void close_range_cloexec_unshare(void) {
    open_files();
    run_thread(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC);
    for (int i = 3; i <= 9; i++) check_open_nocloexec(i);
    close_files();
}

int main(void) {
    setup();

    close_range_plain();
    close_range_cloexec();
    close_range_plain_unshare();
    close_range_cloexec_unshare();

    return 0;
}