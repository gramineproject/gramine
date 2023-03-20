/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "common.h"

int main(int argc, const char** argv) {
    if (argc != 2) {
        fprintf(stderr, "This test requires a file to test");
        return 1;
    }

    int fd = CHECK(open(argv[1], O_RDONLY));
    CHECK(close(fd));

    puts("TEST OK");
    return 0;
}
