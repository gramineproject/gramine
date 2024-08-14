/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

int main(void) {
    struct rlimit rlim;

    int dev_null_fd = CHECK(open("/dev/null", O_WRONLY, 0666));

    CHECK(getrlimit(RLIMIT_NOFILE, &rlim));
    printf("old RLIMIT_NOFILE soft limit: %d\n", (int)rlim.rlim_cur);
    int old_lim = (int)rlim.rlim_cur;

    /* make sure we can increase the current soft limit */
    if (old_lim <= 0 || old_lim >= (int)rlim.rlim_max)
        CHECK(-1);

    int good_dup_fd = dup2(dev_null_fd, old_lim - 1);
    CHECK(good_dup_fd);
    printf("(before setrlimit) opened fd: %d\n", good_dup_fd);
    CHECK(close(good_dup_fd));

    int fail_dup_fd = dup2(dev_null_fd, old_lim);
    if (fail_dup_fd != -1 || errno != EBADF)
        CHECK(-1);

    rlim.rlim_cur++;
    CHECK(setrlimit(RLIMIT_NOFILE, &rlim));
    printf("new RLIMIT_NOFILE soft limit: %d\n", (int)rlim.rlim_cur);

    good_dup_fd = dup2(dev_null_fd, old_lim);
    CHECK(good_dup_fd);
    printf("(after setrlimit) opened fd: %d\n", good_dup_fd);
    CHECK(close(good_dup_fd));

    CHECK(close(dev_null_fd));
    puts("TEST OK");
    return 0;
}
