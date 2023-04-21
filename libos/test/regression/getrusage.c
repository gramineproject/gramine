/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com>
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#define __USE_GNU
#include <sys/resource.h>

#include "common.h"

#define KERNEL_POINTER 0xffff000000000000
#define INVALID_WHO 999

int main(void) {
    int ret;
    struct rusage r_usage;
    struct test_cases {
        int who;
        struct rusage* usage;
        int expected_errno;
    } tc[] = {
        {.who = RUSAGE_SELF, .usage = &r_usage, .expected_errno = 0},
        {.who = RUSAGE_CHILDREN, .usage = &r_usage, .expected_errno = 0},
        {.who = RUSAGE_THREAD, .usage = &r_usage, .expected_errno = 0},
        {.who = INVALID_WHO, .usage = &r_usage, .expected_errno = EINVAL},
        {.who = RUSAGE_SELF, .usage = (struct rusage*)KERNEL_POINTER, .expected_errno = EFAULT},
    };

    for (size_t i = 0; i < ARRAY_LEN(tc); i++) {
        errno = 0;
        ret = getrusage(tc[i].who, tc[i].usage);
        if (errno != tc[i].expected_errno || (tc[i].expected_errno == 0 && ret != 0) ||
            (tc[i].expected_errno != 0 && ret == 0)) {
            errx(1, "test case %lu failed with incorrect errno or return value. Expected errno is "
                    "%d (%s), received errno %d (%s), expected return value is %d, received %d", i,
                    tc[i].expected_errno, strerror(tc[i].expected_errno), errno, strerror(errno),
                    tc[i].expected_errno == 0 ? 0 : -1, ret);
        }
    }
    puts("TEST OK");
}
