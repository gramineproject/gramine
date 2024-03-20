#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

int main(void) {
    int efd = CHECK(eventfd(0, EFD_NONBLOCK));

    pid_t pid = CHECK(fork());

    if (pid == 0) {
        uint64_t count = 5;
        if (write(efd, &count, sizeof(count)) != sizeof(count)) {
            errx(1, "eventfd write failed");
        }
        CHECK(close(efd));
        exit(0);
    }

    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errx(1, "child died with status: %#x", status);
    }

    uint64_t count = 0;
    if (read(efd, &count, sizeof(count)) != sizeof(count)) {
        errx(1, "eventfd read failed");
    }
    if (count != 5) {
        errx(1, "eventfd read returned wrong count (expected %d, got %lu)", 5, count);
    }

    CHECK(close(efd));
    puts("TEST OK");
    return 0;
}

