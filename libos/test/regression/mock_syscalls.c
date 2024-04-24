/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>
 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <sched.h>
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
    ret = getppid();
    if (ret < 0)
        errx(1, "expected getppid to succeed but it returned ret=%d errno=%d", ret, errno);

    /* sched_yield must *not* appear in strace on the host; this case is added for manual testing */
    for (int i = 0; i < 100; i++) {
        errno = 0;
        ret = sched_yield();
        if (ret < 0) {
            errx(1, "expected sched_yield to succeed (no-op) but it returned ret=%d errno=%d",
                    ret, errno);
        }
    }

    /* vhangup was chosen as a syscall that will most certainly not be implemented in Gramine */
    errno = 0;
    ret = vhangup();
    if (ret != 123)
        errx(1, "expected vhangup to succeed (as a no-op, with dummy return value 123) but it "
                "returned ret=%d errno=%d", ret, errno);

    puts("TEST OK");
    return 0;
}
