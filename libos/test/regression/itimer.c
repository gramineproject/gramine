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

#include "common.h"

#define TEST_MIN_ITIMER_COUNT 5
#define TEST_PERIODIC_INTERVAL_MS 100
#define TIME_US_IN_MS 1000ul
#define TIME_US_IN_S  1000000ul

static int g_itimer_count = 0;

static void itimer_handler(int signum) {
    __atomic_add_fetch(&g_itimer_count, 1, __ATOMIC_RELAXED);
}

int main(void) {
    struct sigaction sa = { .sa_handler = itimer_handler };
    CHECK(sigaction(SIGALRM, &sa, NULL));

    /* configure the timer to expire after a predefined time interval and then periodically at the
     * arrival of each time interval */
    suseconds_t periodic_interval_usec = TEST_PERIODIC_INTERVAL_MS * TIME_US_IN_MS;
    struct itimerval timer = {
        .it_value.tv_sec     = periodic_interval_usec / TIME_US_IN_S,
        .it_value.tv_usec    = periodic_interval_usec % TIME_US_IN_S,
        .it_interval.tv_sec  = periodic_interval_usec / TIME_US_IN_S,
        .it_interval.tv_usec = periodic_interval_usec % TIME_US_IN_S,
    };

    CHECK(setitimer(ITIMER_REAL, &timer, NULL));

    while (__atomic_load_n(&g_itimer_count, __ATOMIC_RELAXED) < TEST_MIN_ITIMER_COUNT)
        ;

    struct itimerval current_timer = {0};
    CHECK(getitimer(ITIMER_REAL, &current_timer));
    if (current_timer.it_interval.tv_sec != (time_t)(periodic_interval_usec / TIME_US_IN_S) ||
        current_timer.it_interval.tv_usec != (suseconds_t)(periodic_interval_usec % TIME_US_IN_S))
        errx(1, "getitimer: unexpected values");

    puts("TEST OK");
    return 0;
}
