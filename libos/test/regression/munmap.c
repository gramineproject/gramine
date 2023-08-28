/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "common.h"

int main(void) {
    setbuf(stdout, NULL);

    size_t page_size = getpagesize();
    char* ptr = mmap(NULL, 3 * page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
                     -1, 0);
    if (ptr == MAP_FAILED) {
        err(1, "mmap");
    }

    /* Unmap middle of a mmapped region. */
    CHECK(munmap(ptr + page_size, page_size));

    /* Ummap range of memory with a hole inside. */
    CHECK(munmap(ptr, 3 * page_size));

    puts("TEST OK");
    return 0;
}
