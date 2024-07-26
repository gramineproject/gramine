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
 *     - accessing the first 1-page region after madvise(MADV_DONTNEED) succeeds
 *     - accessing the second 1-page region after madvise(MADV_DONTNEED) results in SIGBUS
 *
 * This test can be run as single-process (last argument == "nofork") or as multi-process (last
 * argument == "fork"). In the latter case, mmap happens in the parent process and all tests happen
 * in the child process, i.e. the test verifies that mmaped region was correctly sent to child.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

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

static void run_tests(char* m, const char* write_path) {
    size_t page_size = getpagesize();

    void* addr_page1 = &m[0];
    void* addr_page2 = &m[page_size];

    /* test 1: access memory regions (first page succeeds, second page raises SIGBUS) */
    g_sigbus_triggered = 0;

    uint64_t x;
    x = mem_read(addr_page1);
    if (x == 0xdeadbeef)
        errx(1, "read returned value reserved for invalid accesses: %lx", x);
    if (g_sigbus_triggered != 0)
        errx(1, "expected no SIGBUS, got %d", g_sigbus_triggered);
    x = mem_read(addr_page2);
    if (x != 0xdeadbeef)
        errx(1, "read did not return value reserved for invalid accesses but instead: %lx", x);
    if (g_sigbus_triggered != 1)
        errx(1, "expected 1 SIGBUS, got %d", g_sigbus_triggered);

    /* test 2: specify memory regions as buffer to a syscall */
    int write_fd = CHECK(open(write_path, O_WRONLY | O_CREAT | O_TRUNC, 0660));

    ssize_t ret;
#if 0
    /*
     * FIXME: Linux writes until the first memory fault, i.e. until the second page. Gramine
     *        on SGX (with EDMM) doesn't currently comply with this behavior: this would require
     *        intercepting memory faults, realizing that we're inside a system call and that a
     *        user-supplied buffer raised this fault, and instructing the syscall to return a
     *        partial success. Instead, Gramine returns -EFAULT when a buffer with an invalid memory
     *        region is detected.
     *
     *        Note that Linux returns -EFAULT if the memory fault is raised before any data was
     *        written, see write(write_fd, addr_page2, page_size) below. This is similar to Gramine.
     *
     *        Also see https://yarchive.net/comp/linux/partial_reads_writes.html for Linux history.
     */
    ret = write(write_fd, addr_page1, page_size * 2);
    if (ret != (ssize_t)page_size)
        errx(1, "write(2 pages): expected 1-page write, got ret=%ld, errno=%d", ret, errno);
#endif
    ret = write(write_fd, addr_page1, page_size);
    if (ret != (ssize_t)page_size)
        errx(1, "write(valid page): expected 1-page write, got ret=%ld, errno=%d", ret, errno);
    ret = write(write_fd, addr_page2, page_size);
    if (ret != -1 || errno != EFAULT)
        errx(1, "write(invalid page): expected EFAULT, got ret=%ld, errno=%d", ret, errno);

    CHECK(close(write_fd));
    CHECK(unlink(write_path));

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
        errx(1, "(after madvise) read returned value reserved for invalid accesses: %lx", x);
    if (g_sigbus_triggered != 0)
        errx(1, "expected no SIGBUS, got %d", g_sigbus_triggered);
    x = mem_read(addr_page2);
    if (x != 0xdeadbeef)
        errx(1, "(after madvise) read did not return value reserved for invalid accesses but "
                "instead: %lx", x);
    if (g_sigbus_triggered != 1)
        errx(1, "expected 1 SIGBUS, got %d", g_sigbus_triggered);
}

int main(int argc, char** argv) {
    size_t page_size = getpagesize();

    if (argc != 4) {
        errx(1, "Usage: %s <path1: read-only file> <path2: write-only file> <fork|nofork>",
             argv[0]);
    }

    const char* path1 = argv[1];
    const char* path2 = argv[2];

    bool do_fork;
    if (strcmp(argv[3], "fork") == 0) {
        do_fork = true;
    } else if (strcmp(argv[3], "nofork") == 0) {
        do_fork = false;
    } else {
        errx(1, "Did not recognize 3rd argument (can be only fork/nofork, but got %s)", argv[3]);
    }

    struct sigaction sa = {
        .sa_sigaction = sigbus_handler,
        .sa_flags = SA_RESTART | SA_SIGINFO,
    };
    CHECK(sigaction(SIGBUS, &sa, NULL));

    /* we assume that Pytest creates the 1-page file before running this test; note that we can't
     * create the file and ftruncate it as it would require the file to be writable -- this won't
     * allow to test madvise(MADV_DONTNEED) as Gramine doesn't support it on writable files */
    int fd = CHECK(open(path1, O_RDONLY));

    struct stat st;
    CHECK(stat(path1, &st));
    if (st.st_size != (ssize_t)page_size)
        errx(1, "stat: got 0x%lx, expected 0x%lx", st.st_size, page_size);

    char* m = (char*)mmap(NULL, page_size * 2, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED)
        err(1, "mmap()");

    if (!do_fork) {
        /* single-process test: run all tests in this main (and only) process */
        run_tests(m, path2);
    } else {
        /* multi-process test: run all tests in the child process */
        int pid = CHECK(fork());
        if (pid == 0) {
            run_tests(m, path2);
            puts("CHILD OK");
        } else {
            int status = 0;
            CHECK(wait(&status));
            if (!WIFEXITED(status) || WEXITSTATUS(status))
                errx(1, "child wait status: %#x", status);
            puts("PARENT OK");
        }
    }

    CHECK(close(fd));
    puts("TEST OK");
    return 0;
}
