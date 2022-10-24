#define _XOPEN_SOURCE 700
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define SHMNAME "/shm_test"
#define OPEN_MODE 00666
#define FILE_SIZE 4096 * 4

const char g_shared_text[] = "test_text";

static void write_shm(void) {
    int fd = -1;
    void *addr = NULL;

    fd = CHECK(shm_open(SHMNAME, O_RDWR | O_CREAT, OPEN_MODE));
    CHECK(ftruncate(fd, FILE_SIZE));

    addr = mmap(NULL, FILE_SIZE, PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
    if (NULL == addr) {
        errx(1, "mmap failed");
    }
    memcpy(addr, g_shared_text, sizeof(g_shared_text));

    CHECK(munmap(addr, FILE_SIZE));
}

static void read_shm(void) {
    int fd = -1;
    void *addr = NULL;

    fd = CHECK(shm_open(SHMNAME, O_RDONLY, OPEN_MODE));

    addr = mmap(NULL, FILE_SIZE, PROT_READ, MAP_SHARED, fd, SEEK_SET);
    if (NULL == addr) {
        errx(1, "mmap failed");
    }

    if (memcmp(addr, &g_shared_text, sizeof(g_shared_text))) {
        errx(1, "memcmp failed\n");
    }
    CHECK(munmap(addr, FILE_SIZE));
    CHECK(shm_unlink(SHMNAME));
}

int main(int argc, const char **argv, const char **envp) {

    pid_t p = CHECK(fork());
    if (p == 0) {
        write_shm();
        return 0;
    }

    /* parent waits for child termination */
    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        errx(1, "child wait status: %#x", status);
    }
    read_shm();

    puts("TEST OK");
    return 0;
}
