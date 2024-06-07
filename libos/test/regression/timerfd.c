/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/*
 * Single-process test for `timerfd` syscalls (`timerfd_create()`, `timerfd_settime()` and
 * `timerfd_gettime()`).
 *
 * The tests involve cases including reading a blocking/non-blocking timerfd, poll/epoll/select on
 * timerfds, setting up a relative/absolute/periodic timerfd and reading a timerfd from multiple
 * threads.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#define EXPECTED_EXPIRATIONS 1
#define EXPECTED_PERIODIC_TIMER_EXPIRATION_COUNT 5
#define NUM_FDS 2
#define NUM_THREADS 5
#define PERIODIC_INTERVAL 1
#define TIMEOUT_VALUE 2

static void set_timerfd_relative(int fd, bool periodic) {
    struct itimerspec new_value = {
        .it_value.tv_sec = TIMEOUT_VALUE,
        .it_interval.tv_sec = periodic ? PERIODIC_INTERVAL : 0,
    };

    CHECK(timerfd_settime(fd, 0, &new_value, NULL));
}

static void set_timerfds_relative(int fds[NUM_FDS], bool periodic) {
    for (int i = 0; i < NUM_FDS; i++)
        set_timerfd_relative(fds[i], periodic);
}

static void set_timerfd_absolute(int fd, struct timespec* abs_time) {
    struct itimerspec new_value;

    /* Set the timer to expire at the absolute time specified */
    new_value.it_value.tv_sec = abs_time->tv_sec;
    new_value.it_value.tv_nsec = abs_time->tv_nsec;
    new_value.it_interval.tv_sec = 0;
    new_value.it_interval.tv_nsec = 0;

    /* Set the timer to absolute time */
    CHECK(timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL));
}

static void create_timerfds(int fds[NUM_FDS]) {
    for (int i = 0; i < NUM_FDS; i++)
        fds[i] = CHECK(timerfd_create(CLOCK_REALTIME, 0));
}

static void close_timerfds(int fds[NUM_FDS]) {
    for (int i = 0; i < NUM_FDS; i++)
        CHECK(close(fds[i]));
}

static void test_select(int fds[NUM_FDS]) {
    fd_set rfds;
    int max_fd = 0;
    int ready_fds = 0;

    for (int i = 0; i < NUM_FDS; i++) {
        if (fds[i] > max_fd)
            max_fd = fds[i];
    }

    while (ready_fds < NUM_FDS) {
        FD_ZERO(&rfds);
        for (int i = 0; i < NUM_FDS; i++) {
            FD_SET(fds[i], &rfds);
        }

        int nfds = select(max_fd + 1, &rfds, NULL, NULL, NULL);
        if (nfds <= 0)
            err(1, "select on read event failed");

        for (int i = 0; i < NUM_FDS; i++) {
            if (FD_ISSET(fds[i], &rfds)) {
                uint64_t expirations;
                CHECK(read(fds[i], &expirations, sizeof(expirations)));
                if (expirations != EXPECTED_EXPIRATIONS) {
                    errx(1, "select: unexpected number of expirations (expected %d, got %lu)",
                         EXPECTED_EXPIRATIONS, expirations);
                }
                ready_fds++;
            }
        }
    }

    if (ready_fds != NUM_FDS)
        errx(1, "select: unexpected number of ready fds (expected %d, got %d)",
             NUM_FDS, ready_fds);
}

static void test_poll(int fds[NUM_FDS]) {
    struct pollfd pfds[NUM_FDS];
    int ready_fds = 0;

    for (int i = 0; i < NUM_FDS; i++) {
        pfds[i].fd = fds[i];
        pfds[i].events = POLLIN;
        pfds[i].revents = 0;
    }

    while (ready_fds < NUM_FDS) {
        int nfds = poll(pfds, NUM_FDS, -1);
        if (nfds <= 0)
            err(1, "poll with POLLIN failed");

        for (int i = 0; i < NUM_FDS; i++) {
            if (pfds[i].revents & POLLIN) {
                uint64_t expirations;
                CHECK(read(pfds[i].fd, &expirations, sizeof(expirations)));
                if (expirations != EXPECTED_EXPIRATIONS) {
                    errx(1, "poll: unexpected number of expirations (expected %d, got %lu)",
                         EXPECTED_EXPIRATIONS, expirations);
                }
                ready_fds++;
                pfds[i].revents = 0;
            }
        }
    }

    if (ready_fds != NUM_FDS)
        errx(1, "poll: unexpected number of ready fds (expected %d, got %d)",
             NUM_FDS, ready_fds);
}

static void test_epoll(int fds[NUM_FDS]) {
    int epfd = CHECK(epoll_create1(0));

    struct epoll_event ev;
    ev.events = EPOLLIN;
    for (int i = 0; i < NUM_FDS; i++) {
        ev.data.fd = fds[i];
        CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i], &ev));
    }

    struct epoll_event events[NUM_FDS];
    int ready_fds = 0;

    while (ready_fds < NUM_FDS) {
        int nfds = epoll_wait(epfd, events, NUM_FDS, -1);
        if (nfds <= 0)
            err(1, "epoll_wait with EPOLLIN failed");

        for (int i = 0; i < nfds; i++) {
            uint64_t expirations;
            CHECK(read(events[i].data.fd, &expirations, sizeof(expirations)));
            if (expirations != EXPECTED_EXPIRATIONS) {
                errx(1, "epoll_wait: unexpected number of expirations (expected %d, got %lu)",
                     EXPECTED_EXPIRATIONS, expirations);
            }
            ready_fds++;
        }
    }

    if (ready_fds != NUM_FDS)
        errx(1, "epoll_wait: unexpected number of ready fds (expected %d, got %d)",
             NUM_FDS, ready_fds);

    CHECK(close(epfd));
}

/* this test expects the timerfd (`fd`) to be a periodic timer */
static void test_epoll_modes(int fd) {
    int epfd = CHECK(epoll_create1(0));

    /* level-triggered mode */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev));

    struct epoll_event events[1];
    int nfds = CHECK(epoll_wait(epfd, events, 1, -1));
    if (nfds != 1)
        errx(1, "epoll: unexpected number of fds (expected 1, got %u)", nfds);

    /* waiting for another event without reading the expiration count */
    nfds = CHECK(epoll_wait(epfd, events, 1, /*timeout=*/PERIODIC_INTERVAL * 1000 * 2));
    if (nfds != 1)
        errx(1, "epoll: unexpected number of fds in level-triggered mode without reading "
             "(expected 1, got %u)", nfds);

    /* switch to edge-triggered mode */
    ev.events = EPOLLIN | EPOLLET;
    CHECK(epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev));

    nfds = CHECK(epoll_wait(epfd, events, 1, -1));
    if (nfds != 1)
        errx(1, "epoll: unexpected number of fds (expected 1, got %u)", nfds);

    /* waiting for another event without reading the expiration count: here, even though the timer
     * expired at least one, there is no event reported because we're in edge-triggered mode (which
     * does not "reset" the event since there was no read) */
    nfds = CHECK(epoll_wait(epfd, events, 1, /*timeout=*/PERIODIC_INTERVAL * 1000 * 2));
    if (nfds != 0)
        errx(1, "epoll: unexpected number of fds in edge-triggered mode without reading "
             "(expected 0, got %u)", nfds);

    CHECK(close(epfd));
}

static void test_periodic_timer(int fd) {
    uint64_t expirations;
    size_t total_expirations = 0;

    while (total_expirations < EXPECTED_PERIODIC_TIMER_EXPIRATION_COUNT) {
        CHECK(read(fd, &expirations, sizeof(expirations)));
        total_expirations += expirations;
    }
}

static void* timerfd_read_thread(void* arg) {
    int fd = *(int*)arg;
    uint64_t expirations;
    CHECK(read(fd, &expirations, sizeof(expirations)));
    if (expirations == 0)
        err(1, "threaded read: unexpected number of expirations");
    pthread_exit(NULL);
}

/* a periodic timer is required so that all NUM_THREADS threads have something to read */
static void test_periodic_timer_threaded_read(int fd) {
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        CHECK(pthread_create(&threads[i], NULL, timerfd_read_thread, &fd));
        /* wait for the thread to finish */
        CHECK(pthread_join(threads[i], NULL));
    }
}

static void test_timerfd_gettime(int fd) {
    struct itimerspec curr_value;
    CHECK(timerfd_gettime(fd, &curr_value));

    /* the timer should be set to expire close to 2 seconds */
    if (curr_value.it_value.tv_sec > 2 || curr_value.it_value.tv_sec < 1 ||
        curr_value.it_value.tv_nsec < 0 || curr_value.it_value.tv_nsec >= 1000000000) {
        errx(1, "timerfd_gettime: unexpected timer value (expected close to 2.0, got %ld.%09ld)",
             curr_value.it_value.tv_sec, curr_value.it_value.tv_nsec);
    }
}

static void test_disarm_timer(int fd) {
    struct itimerspec old_value;

    /* immediately disarm the timer and get the old value */
    struct itimerspec disarm_value = { 0 };
    CHECK(timerfd_settime(fd, 0, &disarm_value, &old_value));

    /* check that the old value is around 2 seconds */
    if (old_value.it_value.tv_sec > 2 || old_value.it_value.tv_sec < 1 ||
        old_value.it_value.tv_nsec < 0 || old_value.it_value.tv_nsec >= 1000000000) {
        errx(1, "disarm_timer: unexpected old timer value (expected close to 2.0, got %ld.%09ld)",
             old_value.it_value.tv_sec, old_value.it_value.tv_nsec);
    }

    /* test poll with a timeout to ensure the timer was disarmed */
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };
    int ret = poll(&pfd, 1, /*timeout=*/(TIMEOUT_VALUE + 1) * 1000);
    if (ret != 0)
        errx(1, "disarm_timer: poll returned %d, expected 0 (timeout)", ret);
}

static void test_absolute_time(int fd) {
    struct timespec now;
    struct timespec abs_time;
    uint64_t expirations;

    /* test timerfd with absolute time set in the future */
    CHECK(clock_gettime(CLOCK_REALTIME, &now));
    abs_time.tv_sec = now.tv_sec + TIMEOUT_VALUE;
    abs_time.tv_nsec = now.tv_nsec;

    set_timerfd_absolute(fd, &abs_time);

    CHECK(read(fd, &expirations, sizeof(expirations)));
    if (expirations != EXPECTED_EXPIRATIONS) {
        errx(1, "absolute_time future: unexpected number of expirations (expected %d, got %lu)",
             EXPECTED_EXPIRATIONS, expirations);
    }

    expirations = 0;
    memset(&now, 0, sizeof(struct timespec));
    memset(&abs_time, 0, sizeof(struct timespec));

    /* test timerfd with absolute time set in the past */
    CHECK(clock_gettime(CLOCK_REALTIME, &now));
    abs_time.tv_sec = now.tv_sec - TIMEOUT_VALUE;
    abs_time.tv_nsec = now.tv_nsec;

    set_timerfd_absolute(fd, &abs_time);

    CHECK(read(fd, &expirations, sizeof(expirations)));
    if (expirations != EXPECTED_EXPIRATIONS) {
        errx(1, "absolute_time past: unexpected number of expirations (expected %d, got %lu)",
             EXPECTED_EXPIRATIONS, expirations);
    }
}

/* This test must be executed twice: first reading from a non-periodic timerfd in blocking mode to
 * capture its expiration, and then switching to non-blocking mode for a second read, which
 * immediately returns with EAGAIN because the timer is disarmed and there are no new expiration
 * events. */
static void test_read(int fd, bool non_blocking) {
    if (non_blocking) {
        CHECK(fcntl(fd, F_SETFL, O_NONBLOCK));
    }

    uint64_t expirations;
    int retval = read(fd, &expirations, sizeof(expirations));

    if (non_blocking) {
        if (retval != -1 || errno != EAGAIN) {
            errx(1, "non-blocking read: read returned %d, errno %d, expected -1 and EAGAIN",
                 retval, errno);
        }
    } else {
        CHECK(retval);
        if (expirations != EXPECTED_EXPIRATIONS) {
            errx(1, "read: unexpected number of expirations (expected %d, got %lu)",
                 EXPECTED_EXPIRATIONS, expirations);
        }
    }
}

int main(void) {
    int fds[NUM_FDS];
    create_timerfds(fds);

    set_timerfds_relative(fds, /*periodic=*/false);
    test_select(fds);

    set_timerfds_relative(fds, /*periodic=*/false);
    test_poll(fds);

    set_timerfds_relative(fds, /*periodic=*/false);
    test_epoll(fds);

    set_timerfd_relative(fds[0], /*periodic=*/true);
    test_epoll_modes(fds[0]);

    set_timerfd_relative(fds[0], /*periodic=*/true);
    test_periodic_timer(fds[0]);

    set_timerfd_relative(fds[0], /*periodic=*/true);
    test_periodic_timer_threaded_read(fds[0]);

    set_timerfd_relative(fds[0], /*periodic=*/false);
    test_timerfd_gettime(fds[0]);

    set_timerfd_relative(fds[0], /*periodic=*/false);
    test_disarm_timer(fds[0]);

    set_timerfd_relative(fds[0], /*periodic=*/false);
    test_read(fds[0], /*non_blocking=*/false);
    test_read(fds[0], /*non_blocking=*/true);

    test_absolute_time(fds[1]);

    close_timerfds(fds);

    puts("TEST OK");
    return 0;
}
