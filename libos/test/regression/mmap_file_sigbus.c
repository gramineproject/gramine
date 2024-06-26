/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

/*
 * Perform a 2-page file-backed mmap on a file with 1-page size. Verify the following:
 *
 *   - Behavior when accessing the mmapped regions 
 *     - accessing the first 1-page region succeeds
 *     - accessing the second 1-page region results in SIGBUS
 *
 *   - Behavior when using the mmapped regions as a buffer to a syscall
 *     - specifying the whole 2-page region succeeds (writes 1 page) (yes, that's how Linux works)
 *     - specifying the first 1-page region succeeds (writes 1 page)
 *     - specifying the second 1-page region results in -EFAULT
 *
 *   - Behavior when using the mmapped regions with madvise(MADV_DONTNEED)
 *     - madvise(MADV_DONTNEED) on the first 1-page region succeeds
 *     - madvise(MADV_DONTNEED) on the second 1-page region succeeds (yes, that's how Linux works)
 *     - accessing the first 1-page region succeeds
 *     - accessing the second 1-page region results in SIGBUS
 */

#define _GNU_SOURCE
#include <err.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#include "common.h"

#define TEST_DIR  "tmp"
#define TEST_READFILE "__mmaptestreadfile__"
#define TEST_WRITEFILE "__mmaptestfilewrite__"

/* this test can be augmented to run on any arch, but we currently only care about x86-64 */
#ifndef __x86_64__
#error Unsupported architecture
#endif

uint64_t mem_read(void* addr) __attribute__((visibility("internal")));
void ret(void) __attribute__((visibility("internal")));
__asm__ (
".pushsection .text\n"
".type mem_read, @function\n"
".type ret, @function\n"
"mem_read:\n"
    "movq (%rdi), %rax\n"
    "ret\n"
"ret:\n"
    "ret\n"
".popsection\n"
);

static int g_sigbus_triggered = 0;

static void sigbus_handler(int signum, siginfo_t* si, void* uc) {
    if (signum != SIGBUS) {
        /* we registered a SIGBUS handler but got another signal?! */
        _Exit(1);
    }

    uint64_t rip = ((ucontext_t*)uc)->uc_mcontext.gregs[REG_RIP];
    if (rip != (uint64_t)(mem_read))
        _Exit(1);

    g_sigbus_triggered++;

    ((ucontext_t*)uc)->uc_mcontext.gregs[REG_RAX] = 0xdeadbeef;
    ((ucontext_t*)uc)->uc_mcontext.gregs[REG_RIP] = (uint64_t)ret;
}

int main(void) {
    size_t page_size = getpagesize();

    struct sigaction sa = {
        .sa_sigaction = sigbus_handler,
        .sa_flags = SA_RESTART | SA_SIGINFO,
    };
    CHECK(sigaction(SIGBUS, &sa, NULL));

    /* we assume that Pytest creates the 1-page file before running this test; note that we can't
     * create the file and ftruncate it as it would require the file to be writable -- this won't
     * allow to test madvise(MADV_DONTNEED) as Gramine doesn't support it on writable files */
    int fd = CHECK(open(TEST_DIR "/" TEST_READFILE, O_RDONLY));

    struct stat st;
    CHECK(stat(TEST_DIR "/" TEST_READFILE, &st));
    if (st.st_size != (ssize_t)page_size)
        errx(1, "stat: got 0x%lx, expected 0x%lx", st.st_size, page_size);

    char* m = (char*)mmap(NULL, page_size * 2, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED)
        err(1, "mmap()");

    void* addr_page1 = &m[0];
    void* addr_page2 = &m[page_size];

    /* test 1: access memory regions (first page succeeds, second page raises SIGBUS) */
    g_sigbus_triggered = 0;

    uint64_t x;
    x = mem_read(addr_page1);
    if (x == 0xdeadbeef)
        errx(1, "unexpected value in successful read from file-backed mmap region: %lx", x);
    x = mem_read(addr_page2);
    if (x != 0xdeadbeef)
        errx(1, "unexpected value in failing read from file-backed mmap region: %lx", x);
    if (g_sigbus_triggered != 1)
        errx(1, "expected 1 SIGBUS, got %d", g_sigbus_triggered);

    /* test 2: specify memory regions as buffer to a syscall */
    int write_fd = CHECK(open(TEST_DIR "/" TEST_WRITEFILE, O_WRONLY | O_CREAT | O_TRUNC, 0660));

    ssize_t ret;
    ret = write(write_fd, addr_page1, page_size * 2);
    if (ret != (ssize_t)page_size)
        errx(1, "write(2 pages): expected 1-page write, got ret=%ld, errno=%d", ret, errno);
    ret = write(write_fd, addr_page1, page_size);
    if (ret != (ssize_t)page_size)
        errx(1, "write(valid page): expected 1-page write, got ret=%ld, errno=%d", ret, errno);
    ret = write(write_fd, addr_page2, page_size);
    if (ret != -1 || errno != EFAULT)
        errx(1, "write(invalid page): expected EFAULT, got ret=%ld, errno=%d", ret, errno);

    CHECK(close(write_fd));
    CHECK(unlink(TEST_DIR "/" TEST_WRITEFILE));

    /* test 3: specify memory regions in madvise(MADV_DONTNEED) and access them */
    ret = madvise(addr_page1, page_size, MADV_DONTNEED);
    if (ret != 0)
        errx(1, "madvise(valid page): expected success, got ret=%ld, errno=%d", ret, errno);
    ret = madvise(addr_page2, page_size, MADV_DONTNEED);
    if (ret != 0)
        errx(1, "madvise(invalid page): expected success, got ret=%ld, errno=%d", ret, errno);

    g_sigbus_triggered = 0;
    x = mem_read(addr_page1);
    if (x == 0xdeadbeef)
        errx(1, "unexpected value in successful read after madvise(MADV_DONTNEED): %lx", x);
    x = mem_read(addr_page2);
    if (x != 0xdeadbeef)
        errx(1, "unexpected value in failing read after madvise(MADV_DONTNEED): %lx", x);
    if (g_sigbus_triggered != 1)
        errx(1, "expected 1 SIGBUS, got %d", g_sigbus_triggered);

    /* done with all tests */
    CHECK(close(fd));
    puts("TEST OK");
    return 0;
}
