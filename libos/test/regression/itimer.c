/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/* Test for syscalls that gets/sets value of an interval timer (`getitimer()`, `setitimer()`). */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "common.h"

#define EXPECTED_ITIMER_COUNT 5

static volatile int g_itimer_count = 0;
static int g_pipefds[2];

static void itimer_handler(int signum) {
    ++g_itimer_count;

    if (g_itimer_count >= EXPECTED_ITIMER_COUNT) {
        char c = 0;
        ssize_t x = CHECK(write(g_pipefds[1], &c, 1));
        if (x != sizeof(c))
            errx(1, "pipe write: %zd", x);
    }
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_handler = itimer_handler;
    CHECK(sigaction(SIGALRM, &sa, NULL));

    /* configure the timer to expire after 1 sec, and then every 1 sec */
    struct itimerval timer = {
        .it_value.tv_sec     = 1,
        .it_value.tv_usec    = 0,
        .it_interval.tv_sec  = 1,
        .it_interval.tv_usec = 0,
    };

    setitimer(ITIMER_REAL, &timer, NULL);

    CHECK(pipe(g_pipefds));

    char c = 0;
    ssize_t x = 0;
    while (g_itimer_count < EXPECTED_ITIMER_COUNT) {
        do {
            x = read(g_pipefds[0], &c, sizeof(c));
        } while (x == -1 && errno == EINTR);
        if (x == -1)
            err(1, "pipe read");
        if (x != sizeof(c))
            errx(1, "pipe read %ld bytes, expected %ld", x, sizeof(c));
        if (c != 0)
            errx(1, "pipe read byte %d, expected %d", (int)c, 0);
    }

    if (g_itimer_count != EXPECTED_ITIMER_COUNT)
        errx(1, "expected itimer count = %d, but got %d", EXPECTED_ITIMER_COUNT, g_itimer_count);

    puts("TEST OK");
    return 0;
}
