/* This tests a bug in LibOS that resulted in a hang (due to locking) of Gramine */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include "common.h"

static int g_efd;
static bool g_read_thread_started = false;

static void pthread_check(int x) {
    if (x) {
        printf("pthread failed with %d (%s)\n", x, strerror(x));
        exit(1);
    }
}

static void* write_thread(void* arg) {
    /* wait until the other thread starts its blocking read */
    while (__atomic_load_n(&g_read_thread_started, __ATOMIC_SEQ_CST) == false)
        ;
    sleep(1); /* make sure the other thread called the blocking read */

    uint64_t val = 42;
    if (write(g_efd, &val, sizeof(val)) != sizeof(val))
        errx(1, "eventfd write failed");
    return NULL;
}

static void* read_thread(void* arg) {
    __atomic_store_n(&g_read_thread_started, true, __ATOMIC_SEQ_CST);

    /* blocking read */
    uint64_t val;
    if (read(g_efd, &val, sizeof(val)) != sizeof(val))
        errx(1, "eventfd read failed");

    /* blocking read was unblocked by a write from another thread */
    if (val != 42)
        errx(1, "unexpected value read (%lu)", val);
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

