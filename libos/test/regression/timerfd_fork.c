/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/* Multi-process test for `timerfd` syscalls (`timerfd_create()`, `timerfd_settime()` and
 * `timerfd_gettime()`).
 *
 * Note that timerfd is currently only emulated in a secure single-process mode, so this test does
 * not work.
 */

#define _GNU_SOURCE
#include <err.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#define EXPECTED_EXPIRATIONS 1
#define TIMEOUT_VALUE 2

static void set_timerfd(int fd) {
    struct itimerspec new_value = { .it_value.tv_sec = TIMEOUT_VALUE };

    CHECK(timerfd_settime(fd, 0, &new_value, NULL));
}

static void test_multi_process(int fd) {
    pid_t pid = CHECK(fork());
    if (pid == 0) {
        uint64_t expirations;
        /* child: wait on a blocking read for the timer to expire */
        CHECK(read(fd, &expirations, sizeof(expirations)));
        if (expirations != EXPECTED_EXPIRATIONS) {
            errx(1, "child process: unexpected number of expirations (expected %d, got %lu)",
                 EXPECTED_EXPIRATIONS, expirations);
        }
        exit(0);
    } else {
        int status = 0;

        /* parent: do nothing and let the child process read the timerfd */
        /* wait for the child process to exit */
        CHECK(waitpid(pid, &status, 0));
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            errx(1, "child died with status: %#x", status);
        }
    }
}

int main(void) {
    int fd = CHECK(timerfd_create(CLOCK_REALTIME, 0));

    set_timerfd(fd);
    test_multi_process(fd);

    CHECK(close(fd));

    puts("TEST OK");
    return 0;
}
