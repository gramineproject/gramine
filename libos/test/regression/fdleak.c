#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define OPEN_CLOSE_FILES_COUNT 1000
#define INITIAL_OPEN_FDS 10
#define SPAWN_CHILDREN_COUNT 10

static void test_open_close(const char* fname) {
    for (size_t i = 0; i < OPEN_CLOSE_FILES_COUNT; i++) {
        int fd = CHECK(open(fname, O_RDONLY));
        char buf[0x10];
        ssize_t ret = CHECK(read(fd, buf, sizeof(buf)));
        if (ret != sizeof(buf)) {
            errx(1, "short read on a file: %zd", ret);
        }
        CHECK(close(fd));
    }
}

static void test_open_fork(const char* fname) {
    int fds[INITIAL_OPEN_FDS];
    for (size_t i = 0; i < ARRAY_LEN(fds); i++) {
        fds[i] = CHECK(open(fname, O_RDONLY));
    }

    int pipefds[2];
    CHECK(pipe(pipefds));

    pid_t p = CHECK(fork());
    if (p == 0) {
        CHECK(close(pipefds[0]));

        for (size_t i = 0; i < SPAWN_CHILDREN_COUNT; i++) {
            p = CHECK(fork());
            if (p != 0) {
                /* Parent just exits. */
                exit(0);
            }
            /* Child continues and spawns the next child (nested forks). */
        }

        /* Last child done, inform the first process. */
        char c = 0;
        CHECK(write(pipefds[1], &c, sizeof(c)));
        exit(0);
    }

    CHECK(close(pipefds[1]));

    char c = 0;
    ssize_t ret = CHECK(read(pipefds[0], &c, sizeof(c)));
    if (ret != sizeof(c)) {
        errx(1, "confirmation message too short: %zd", ret);
    }
    CHECK(wait(NULL));

    for (size_t i = 0; i < ARRAY_LEN(fds); i++) {
        CHECK(close(fds[i]));
    }
}

int main(int argc, char** argv) {
    if (argc != 1) {
        errx(1, "unexpected argc: %d (expected 1)", argc);
    }

    test_open_close(argv[0]);

    test_open_fork(argv[0]);

    puts("TEST OK");
    return 0;
}
