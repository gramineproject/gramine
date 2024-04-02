#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define MAX_EFDS 3

#define EXIT_IF_ERROR(bytes, prefix)                              \
    do {                                                          \
        if ((bytes) != sizeof(uint64_t)) {                        \
            errx(1, "error at line %d (%s)\n", __LINE__, prefix); \
        }                                                         \
    } while (0)

int efds[MAX_EFDS] = {0};

static void* write_eventfd_thread(void* arg) {
    uint64_t count = 10;
    int* efds = (int*)arg;

    for (int i = 0; i < MAX_EFDS; i++) {
        printf("%s: efd: %d\n", __func__, efds[i]);
    }

    for (int i = 0; i < MAX_EFDS; i++) {
        if (write(efds[i], &count, sizeof(count)) != sizeof(count)) {
            errx(1, "write error");
        }
        count += 1;
    }

    return NULL;
}

static void eventfd_using_poll(void) {
    int ret;
    int nread_events = 0;

    struct pollfd pollfds[MAX_EFDS];

    for (int i = 0; i < MAX_EFDS; i++) {
        efds[i] = CHECK(eventfd(0, 0));
        printf("efd = %d\n", efds[i]);
        pollfds[i].fd     = efds[i];
        pollfds[i].events = POLLIN;
    }

    pthread_t tid;
    ret = pthread_create(&tid, NULL, write_eventfd_thread, efds);
    if (ret != 0) {
        errx(1, "error in thread creation");
    }

    while (1) {
        ret = CHECK(poll(pollfds, MAX_EFDS, 1000));

        if (ret == 0) {
            printf("Poll timed out. Exiting.\n");
            break;
        }

        for (int i = 0; i < MAX_EFDS; i++) {
            if (pollfds[i].revents & POLLIN) {
                pollfds[i].revents = 0;
                uint64_t count = 0;
                if (read(pollfds[i].fd, &count, sizeof(count)) != sizeof(count)) {
                    errx(1, "read error");
                }
                printf("fd set: %d\n", pollfds[i].fd);
                printf("efd: %d, count: %lu, errno: %d\n", pollfds[i].fd, count, errno);
                nread_events++;
            }
        }
    }

    if (nread_events != MAX_EFDS) {
        errx(1, "%s: nread_events: %d, MAX_EFDS: %d\n", __func__, nread_events, MAX_EFDS);
    }

    ret = pthread_join(tid, NULL);
    if (ret != 0) {
        errx(1, "pthread_join: %d\n", ret);
    }

    for (int i = 0; i < MAX_EFDS; i++)
        CHECK(close(efds[i]));

    printf("%s completed successfully\n", __func__);
}

static void eventfd_using_various_flags(void) {
    int eventfd_flags[] = {0, EFD_SEMAPHORE, EFD_NONBLOCK, EFD_CLOEXEC};

    for (unsigned int i = 0; i < sizeof(eventfd_flags) / sizeof(*eventfd_flags); i++) {
        printf("iteration %d, flags %d\n", i, eventfd_flags[i]);

        int efd = CHECK(eventfd(0, eventfd_flags[i]));

        uint64_t count;
        ssize_t bytes;

        count = 5;
        bytes = write(efd, &count, sizeof(count));
        EXIT_IF_ERROR(bytes, "write");

        bytes = write(efd, &count, sizeof(count));
        EXIT_IF_ERROR(bytes, "write");

        count = 0;
        if (eventfd_flags[i] & EFD_SEMAPHORE) {
            uint64_t prev_count = 0;
            bytes = read(efd, &prev_count, sizeof(prev_count));
            EXIT_IF_ERROR(bytes, "read");

            bytes = read(efd, &count, sizeof(count));
            EXIT_IF_ERROR(bytes, "read");

            if (prev_count != 1 || count != 1) {
                errx(1, "flag->EFD_SEMAPHORE, error, prev_count: %lu, new count: %lu\n",
                     prev_count, count);
            }
            CHECK(close(efd));
            continue;
        }

        count = 0;
        bytes = read(efd, &count, sizeof(count));
        EXIT_IF_ERROR(bytes, "read");
        if (count != 10) {
            errx(1, "%d: efd: %d, count: %lu, errno: %d\n", __LINE__, efd, count, errno);
        }

        /* calling the second read would block if flags doesn't have EFD_NONBLOCK */
        if (eventfd_flags[i] & EFD_NONBLOCK) {
            count = 0;
            ssize_t ret = read(efd, &count, sizeof(count));
            if (ret != -1 || errno != EAGAIN) {
                errx(1, "read that should return -1 with EAGAIN returned %ld with errno %d\n", ret,
                     errno);
            }
            printf("%d: efd: %d, count: %lu, errno: %d\n", __LINE__, efd, count, errno);
        }

        CHECK(close(efd));
    }

    printf("%s completed successfully\n", __func__);
}

int main(void) {
    eventfd_using_poll();
    eventfd_using_various_flags();

    puts("TEST OK");
    return 0;
}
