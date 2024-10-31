/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

int main(void) {
    struct rlimit rlim;

    CHECK(getrlimit(RLIMIT_STACK, &rlim));
    printf("old RLIMIT_STACK soft limit: %lu\n", (uint64_t)rlim.rlim_cur);

    /* make sure we can increase the current soft limit */
    if (rlim.rlim_cur >= rlim.rlim_max)
        CHECK(-1);

    rlim.rlim_cur++;
    CHECK(setrlimit(RLIMIT_STACK, &rlim));
    printf("new RLIMIT_STACK soft limit: %lu\n", (uint64_t)rlim.rlim_cur);

    fflush(stdout);

    int pid = CHECK(fork());
    if (pid == 0) {
        /* verify that STACK limit is correctly migrated to the child process */
        CHECK(getrlimit(RLIMIT_STACK, &rlim));
        printf("(in child, after setrlimit) RLIMIT_STACK soft limit: %lu\n",
               (uint64_t)rlim.rlim_cur);

        /* NOTE: we currently don't test that the stack limit is indeed enforced */
        exit(0);
    }

    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status))
        errx(1, "child wait status: %#x", status);

    CHECK(getrlimit(RLIMIT_STACK, &rlim));
    printf("(in parent, after setrlimit) RLIMIT_STACK soft limit: %lu\n", (uint64_t)rlim.rlim_cur);

    /* NOTE: we currently don't test that the stack limit is indeed enforced */
    puts("TEST OK");
    return 0;
}
