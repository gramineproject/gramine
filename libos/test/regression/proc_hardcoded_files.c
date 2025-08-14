/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com> */

/* Test description: this test reads the contents of the pseudo file /proc/sys/fs/pipe-max-size and
 * /proc/sys/fs/lease-break-time and then tries to match the read contents with the expected
 * contents. */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#define BUF_SZ 1024
/* The following values are defined in gramine/libos/src/fs/proc/fs.c */
#define PIPE_MAX_SIZE "1048576"
#define LEASE_BREAK_TIME "45"

int main(void) {
    struct test_cases {
        const char* path;
        const char* expected_value;
        ssize_t expected_length;
    } tc [] = {
        {
            "/proc/sys/fs/pipe-max-size",
            PIPE_MAX_SIZE,
            strlen(PIPE_MAX_SIZE)
        },
        {
            "/proc/sys/fs/lease-break-time",
            LEASE_BREAK_TIME,
            strlen(LEASE_BREAK_TIME)
        },
    };

    char buf[BUF_SZ];
    for (size_t i = 0; i < sizeof(tc)/sizeof(*tc); i++) {
        memset(buf, 0, sizeof(buf));
        int fd = open(tc[i].path, O_RDONLY);
        if (fd < 0)
            err(1, "opening file %s failed", tc[i].path);
        ssize_t read_bytes = read(fd, buf, sizeof(buf));
        if (read_bytes < 0)
            err(1, "reading file %s failed", tc[i].path);
        if (read_bytes != tc[i].expected_length) {
            errx(1, "Content length mismatch for file = %s. Expected %ld got %ld", tc[i].path,
                 tc[i].expected_length, read_bytes);
        }
        if (strcmp(tc[i].expected_value, buf)) {
            errx(1, "Content mismatch for file = %s. Expected %s got %s", tc[i].path,
                 tc[i].expected_value, buf);
        }

        struct stat sb;
        int ret = stat(tc[i].path, &sb);
        if (ret < 0)
            err(1, "stat failed for file %s", tc[i].path);
        if (!S_ISREG(sb.st_mode))
            errx(1, "Unexpected type for file = %s. Expected S_ISREG", tc[i].path);
        ret = close(fd);
        if (ret < 0)
            err(1, "close() failed for file %s", tc[i].path);
    }
    puts("TEST OK");
    return 0;
}
