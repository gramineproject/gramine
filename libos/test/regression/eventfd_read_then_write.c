/* This tests a bug in LibOS that resulted in a hang (due to locking) of Gramine */

#define _POSIX_C_SOURCE 200112 /* for nanosleep */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#define TEST_TIMES 100 /* each iteration has a sleep for 10ms, so total test time is 1s */

static int g_efd;
static bool g_read_thread_ready = false;

static void pthread_check(int x) {
    if (x) {
        printf("pthread failed with %d (%s)\n", x, strerror(x));
        exit(1);
    }
}

static void write_thread_once(void) {
    /* wait until the other thread starts its blocking read and reset the status */
    while (true) {
        bool expected = true;
        if (__atomic_compare_exchange_n(&g_read_thread_ready, &expected, /*desired=*/false,
                                        /*weak=*/0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            break;
        }
    }

    /* unfortunately there's no way to figure out (without side effects) if the other thread called
     * blocking read() already, so use a sleep-for-a-bit heuristic */
    struct timespec ts = { .tv_nsec = 10 * 1000 * 1000 };
    if (nanosleep(&ts, NULL) < 0) {
        err(1, "nanosleep failed");
    }

    uint64_t val = 42;
    if (write(g_efd, &val, sizeof(val)) != sizeof(val))
        errx(1, "eventfd write failed");
}

static void read_thread_once(void) {
    __atomic_store_n(&g_read_thread_ready, true, __ATOMIC_SEQ_CST);

    /* blocking read */
    uint64_t val;
    if (read(g_efd, &val, sizeof(val)) != sizeof(val))
        errx(1, "eventfd read failed");

    /* blocking read was unblocked by a write from another thread */
    if (val != 42)
        errx(1, "unexpected value read (%lu)", val);
}

static void* write_thread(void* arg) {
    for (int i = 0; i < TEST_TIMES; i++) {
        write_thread_once();
    }
    return NULL;
}

static void* read_thread(void* arg) {
    for (int i = 0; i < TEST_TIMES; i++) {
        read_thread_once();
    }
    return NULL;
}

int main(void) {
    g_efd = CHECK(eventfd(0, 0));

    pthread_t th[2];
    pthread_check(pthread_create(&th[0], NULL, read_thread, NULL));
    pthread_check(pthread_create(&th[1], NULL, write_thread, NULL));

    pthread_check(pthread_join(th[0], NULL));
    pthread_check(pthread_join(th[1], NULL));

    CHECK(close(g_efd));
    puts("TEST OK");
    return 0;
}
