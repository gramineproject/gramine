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

#define EXPECTED_ITIMER_COUNT 5

static int g_itimer_count = 0;

static void itimer_handler(int signum) {
    __atomic_add_fetch(&g_itimer_count, 1, __ATOMIC_RELAXED);
}

int main(void) {
    struct sigaction sa = { .sa_handler = itimer_handler };
    CHECK(sigaction(SIGALRM, &sa, NULL));

    /* configure the timer to expire after 1 sec, and then every 1 sec */
    struct itimerval timer = {
        .it_value.tv_sec     = 1,
        .it_value.tv_usec    = 0,
        .it_interval.tv_sec  = 1,
        .it_interval.tv_usec = 0,
    };

    CHECK(setitimer(ITIMER_REAL, &timer, NULL));

    while (__atomic_load_n(&g_itimer_count, __ATOMIC_RELAXED) < EXPECTED_ITIMER_COUNT)
        ;

    if (g_itimer_count != EXPECTED_ITIMER_COUNT)
        errx(1, "expected itimer count = %d, but got %d", EXPECTED_ITIMER_COUNT, g_itimer_count);

    struct itimerval current_timer = {0};
    CHECK(getitimer(ITIMER_REAL, &current_timer));
    if (current_timer.it_interval.tv_sec != 1 || current_timer.it_interval.tv_usec != 0)
        errx(1, "getitimer: unexpected values");

    puts("TEST OK");
    return 0;
}
