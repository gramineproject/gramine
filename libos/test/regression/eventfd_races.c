#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "common.h"

#define TEST_RUNS 10000
#define TEST_VAL  42

static int g_efd;
static uint64_t g_read_events;  /* atomic counter */
static uint64_t g_write_events; /* atomic counter */
static uint64_t g_total_events; /* atomic counter */

/* required to NOT increase the above counters on the "last read/write event to unblock the eventfd
 * consumers"; this is purely to avoid these counters incrementing past TEST_RUNS */
static bool g_stop_test;        /* atomic boolean */

static void pthread_check(int x) {
    if (x) {
        printf("pthread failed with %d (%s)\n", x, strerror(x));
        exit(1);
    }
}

static void* write_eventfd_thread(void* arg) {
    uint64_t val = TEST_VAL;
    for (int i = 0; i < TEST_RUNS; i++) {
        uint64_t curr_read_events = __atomic_load_n(&g_read_events, __ATOMIC_SEQ_CST);
        if (write(g_efd, &val, sizeof(val)) != sizeof(val))
            errx(1, "eventfd write failed");
        while (__atomic_load_n(&g_read_events, __ATOMIC_SEQ_CST) == curr_read_events)
            /* wait until some reader thread updates the read_events counter */;
    }
    /* send one last event to unblock the second reader */
    __atomic_store_n(&g_stop_test, true, __ATOMIC_SEQ_CST);
    if (write(g_efd, &val, sizeof(val)) != sizeof(val))
        errx(1, "eventfd write failed");
    return NULL;
}

static void* read_eventfd_thread(void* arg) {
    uint64_t val;
    uint64_t read_events_total = 0;
    while (true) {
        uint64_t curr_read_events = __atomic_load_n(&g_read_events, __ATOMIC_SEQ_CST);
        if (curr_read_events == TEST_RUNS)
            break;
        if (read(g_efd, &val, sizeof(val)) != sizeof(val) || val != TEST_VAL)
            errx(1, "eventfd read failed");
        if (__atomic_load_n(&g_stop_test, __ATOMIC_SEQ_CST))
            break;
        __atomic_add_fetch(&g_read_events, 1, __ATOMIC_SEQ_CST);
        read_events_total++;
    }
    printf("Read-only thread: read eventfd %lu times\n", read_events_total);
    __atomic_add_fetch(&g_total_events, read_events_total, __ATOMIC_SEQ_CST);
    return NULL;
}

static void* poll_then_read_eventfd_thread(void* arg) {
    struct pollfd pollfd = { .fd = g_efd, .events = POLLIN };

    uint64_t val;
    uint64_t poll_events_total = 0;
    uint64_t read_events_total = 0;
    while (true) {
        uint64_t curr_read_events = __atomic_load_n(&g_read_events, __ATOMIC_SEQ_CST);
        if (curr_read_events == TEST_RUNS)
            break;
        int ret = CHECK(poll(&pollfd, /*nfds=*/1, /*timeout=*/-1));
        poll_events_total++;
        if (!ret)
            continue;
        if (ret != 1)
            errx(1, "poll on eventfd returned more than 1 event (%d)", ret);
        if (!(pollfd.revents & POLLIN))
            continue;
        /* below read may block because of the race: another thread can read first and reset the
         * event value; we don't care as this is benign */
        if (read(g_efd, &val, sizeof(val)) != sizeof(val) || val != TEST_VAL)
            errx(1, "eventfd read failed");
        if (__atomic_load_n(&g_stop_test, __ATOMIC_SEQ_CST))
            break;
        __atomic_add_fetch(&g_read_events, 1, __ATOMIC_SEQ_CST);
        read_events_total++;
    }
    printf("Poll-then-read thread: polled eventfd %lu times\n", poll_events_total);
    printf("Poll-then-read thread: read eventfd %lu times\n", read_events_total);
    __atomic_add_fetch(&g_total_events, read_events_total, __ATOMIC_SEQ_CST);
    return NULL;
}

static void* blocking_write_eventfd_thread(void* arg) {
    uint64_t val = 1; /* must be `1` because of semaphore semantics -- reader decrements by 1 */
    uint64_t write_events_total = 0;
    while (true) {
        uint64_t curr_write_events = __atomic_load_n(&g_write_events, __ATOMIC_SEQ_CST);
        if (curr_write_events == TEST_RUNS)
            break;
        if (write(g_efd, &val, sizeof(val)) != sizeof(val))
            errx(1, "eventfd write failed");
        if (__atomic_load_n(&g_stop_test, __ATOMIC_SEQ_CST))
            break;
        __atomic_add_fetch(&g_write_events, 1, __ATOMIC_SEQ_CST);
        write_events_total++;
    }
    printf("Blocking write thread: wrote eventfd %lu times\n", write_events_total);
    __atomic_add_fetch(&g_total_events, write_events_total, __ATOMIC_SEQ_CST);
    return NULL;
}

static void* read_for_blocking_write_eventfd_thread(void* arg) {
    uint64_t val;
    for (int i = 0; i < TEST_RUNS; i++) {
        uint64_t curr_write_events = __atomic_load_n(&g_write_events, __ATOMIC_SEQ_CST);
        if (read(g_efd, &val, sizeof(val)) != sizeof(val) || val != 1)
            errx(1, "eventfd read failed");
        while (__atomic_load_n(&g_write_events, __ATOMIC_SEQ_CST) == curr_write_events)
            /* wait until some writer thread updates the write_events counter */;
    }
    /* get one last event to unblock the second writer */
    __atomic_store_n(&g_stop_test, true, __ATOMIC_SEQ_CST);
    if (read(g_efd, &val, sizeof(val)) != sizeof(val))
        errx(1, "eventfd read failed");
    return NULL;
}

static void eventfd_two_readers_doing_two_reads(void) {
    g_read_events = g_total_events = 0;
    g_stop_test = false;
    g_efd = CHECK(eventfd(0, 0)); /* a blocking non-semaphore eventfd */

    pthread_t th[3]; /* two readers (both do blocking reads) and one writer */
    pthread_check(pthread_create(&th[0], NULL, write_eventfd_thread, NULL));
    pthread_check(pthread_create(&th[1], NULL, read_eventfd_thread, NULL));
    pthread_check(pthread_create(&th[2], NULL, read_eventfd_thread, NULL));

    for (int i = 0; i < 3; i++) {
        pthread_check(pthread_join(th[i], NULL));
    }
    CHECK(close(g_efd));
    if (g_total_events != TEST_RUNS)
        errx(1, "total events for subtest is %lu (expected %d)", g_total_events, TEST_RUNS);
}

static void eventfd_two_readers_doing_read_and_poll(void) {
    g_read_events = g_total_events = 0;
    g_stop_test = false;
    g_efd = CHECK(eventfd(0, 0)); /* a blocking non-semaphore eventfd */

    pthread_t th[3]; /* two readers (one does blocking read, one does poll) and one writer */
    pthread_check(pthread_create(&th[0], NULL, write_eventfd_thread, NULL));
    pthread_check(pthread_create(&th[1], NULL, read_eventfd_thread, NULL));
    pthread_check(pthread_create(&th[2], NULL, poll_then_read_eventfd_thread, NULL));

    for (int i = 0; i < 3; i++) {
        pthread_check(pthread_join(th[i], NULL));
    }
    CHECK(close(g_efd));
    if (g_total_events != TEST_RUNS)
        errx(1, "total events for subtest is %lu (expected %d)", g_total_events, TEST_RUNS);
}

static void eventfd_two_readers_doing_two_polls(void) {
    g_read_events = g_total_events = 0;
    g_stop_test = false;
    g_efd = CHECK(eventfd(0, 0)); /* a blocking non-semaphore eventfd */

    pthread_t th[3]; /* two readers (both do poll) and one writer */
    pthread_check(pthread_create(&th[0], NULL, write_eventfd_thread, NULL));
    pthread_check(pthread_create(&th[1], NULL, poll_then_read_eventfd_thread, NULL));
    pthread_check(pthread_create(&th[2], NULL, poll_then_read_eventfd_thread, NULL));

    for (int i = 0; i < 3; i++) {
        pthread_check(pthread_join(th[i], NULL));
    }
    CHECK(close(g_efd));
    if (g_total_events != TEST_RUNS)
        errx(1, "total events for subtest is %lu (expected %d)", g_total_events, TEST_RUNS);
}

static void eventfd_two_writers(void) {
    g_write_events = g_total_events = 0;
    g_stop_test = false;
    /* a blocking semaphore eventfd (we don't want reads to reset value, so that writes block) */
    g_efd = CHECK(eventfd(0, EFD_SEMAPHORE));
    uint64_t val = UINT64_MAX - 1;
    if (write(g_efd, &val, sizeof(val)) != sizeof(val))
        errx(1, "initial eventfd write failed");

    pthread_t th[3]; /* two writers (both do blocking writes) and one reader */
    pthread_check(pthread_create(&th[0], NULL, blocking_write_eventfd_thread, NULL));
    pthread_check(pthread_create(&th[1], NULL, blocking_write_eventfd_thread, NULL));
    pthread_check(pthread_create(&th[2], NULL, read_for_blocking_write_eventfd_thread, NULL));

    for (int i = 0; i < 3; i++) {
        pthread_check(pthread_join(th[i], NULL));
    }
    CHECK(close(g_efd));
    if (g_total_events != TEST_RUNS)
        errx(1, "total events for subtest is %lu (expected %d)", g_total_events, TEST_RUNS);
}

int main(void) {
    setbuf(stdout, NULL);
    puts("------------------------");
    eventfd_two_readers_doing_two_reads();
    puts("------------------------");
    eventfd_two_readers_doing_read_and_poll();
    puts("------------------------");
    eventfd_two_readers_doing_two_polls();
    puts("------------------------");
    eventfd_two_writers();
    puts("TEST OK");
    return 0;
}
