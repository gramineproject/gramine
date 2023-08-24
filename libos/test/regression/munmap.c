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

static void test_mmap_munmap(int prot, int flags) {
    size_t page_size = getpagesize();
    unsigned int magic_number = 0xdeadbeaf;
    char* ptr = mmap(NULL, 3 * page_size, prot, flags, -1, 0);
    if (ptr == MAP_FAILED) {
        err(1, "mmap");
    }

    /* Unmap middle of a mmapped region. */
    CHECK(munmap(ptr + page_size, page_size));

    if (prot & PROT_WRITE) {
        *(unsigned int*)(ptr) = magic_number;
    }

    if ((prot & PROT_READ) && (prot & PROT_WRITE)) {
        unsigned int read_value = *(unsigned int*)(ptr);
        if (read_value != magic_number) {
            errx(1, "wrong magic number: expected 0x%x, got 0x%x", magic_number, read_value);
        }
    }

    /* Ummap range of memory with a hole inside. */
    CHECK(munmap(ptr, 3 * page_size));
}

int main(void) {
    setbuf(stdout, NULL);

    test_mmap_munmap(PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE);

    test_mmap_munmap(PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE);

    puts("TEST OK");
    return 0;
}
