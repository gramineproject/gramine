#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define TEST_LENGTH  0x10000f000
#define TEST_LENGTH2 0x8000f000
#define TEST_LENGTH3 0x800f000

int main(void) {
    setbuf(stdout, NULL);
    const char expected_val = 0xff;

    /* test large anonymous mappings with `MAP_NORESERVE` */
    void* a = mmap(NULL, TEST_LENGTH, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (a == MAP_FAILED)
        err(1, "mmap 1");

    ((char*)a)[0x100000000] = expected_val;
    printf("large_mmap: mmap 1 (anonymous) completed OK\n");

    CHECK(munmap(a, TEST_LENGTH));

    /* test large anonymous mappings with `MAP_NORESERVE` on fork, we pick relatively small length
     * of mapping to avoid exceeding the maximum number of memory map areas of a process */
    a = mmap(NULL, TEST_LENGTH3, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (a == MAP_FAILED)
        err(1, "mmap 2");

    ((char*)a)[0x8000000] = expected_val;
    pid_t pid = CHECK(fork());
    if (pid == 0) {
        char data = ((char*)a)[0x8000000];
        if (data != expected_val)
            errx(1, "child: unexpected value read (expected: %x, actual: %x)", expected_val, data);
        exit(0);
    }
    if (pid > 0) {
        int status;
        CHECK(wait(&status));
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            errx(1, "child wait status: %#x", status);
    }
    printf("large_mmap: mmap 2 (anonymous) completed OK\n");

    CHECK(munmap(a, TEST_LENGTH3));

    /* test large file-backed mappings */
    FILE* fp = fopen("testfile", "a+");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    CHECK(ftruncate(fileno(fp), TEST_LENGTH));

    a = mmap(NULL, TEST_LENGTH2, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fp), 0);
    if (a == MAP_FAILED)
        err(1, "mmap 3");

    ((char*)a)[0x80000000] = expected_val;
    printf("large_mmap: mmap 3 (file-backed) completed OK\n");

    CHECK(munmap(a, TEST_LENGTH2));

#if 0
    /* The below fork tests sending of large checkpoints: at this point, the process allocated >4GB
     * of memory and must send it to the child. Thus, this fork stresses 32-bit/64-bit logic in
     * Gramine (especially on SGX PAL). However, for SGX enclaves, this takes several minutes to
     * execute on wimpy machines (with 128MB of EPC), so it is commented out by default. */

    a = mmap(NULL, TEST_LENGTH, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fp), 0);
    if (a == MAP_FAILED)
        err(1, "mmap 4");

    ((char*)a)[0x100000000] = expected_val;
    printf("large_mmap: mmap 4 (file-backed) completed OK\n");

    pid = CHECK(fork());
    if (pid > 0) {
        int status;
        CHECK(wait(&status));
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            errx(1, "child wait status: %#x", status);
    }

    CHECK(munmap(a, TEST_LENGTH));
#endif

    puts("TEST OK");
    return 0;
}
