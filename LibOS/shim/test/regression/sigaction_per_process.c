/*
 * Test that signal disposition is per-process: set SIGTERM handler in a child thread, but send
 * SIGTERM signal to the main thread specifically. Verify that signal handler was called in the
 * main thread and it was called only once.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static pid_t mygettid(void) {
    return syscall(SYS_gettid);
}

static int tkill(pid_t tid, int sig) {
    return syscall(SYS_tkill, tid, sig);
}

static _Atomic pid_t who1 = 0;
static _Atomic pid_t who2 = 0;

static void sigterm_handler(int signum) {
    pid_t v = 0;
    pid_t my_tid = mygettid();
    if (!atomic_compare_exchange_strong_explicit(&who1, &v, my_tid, memory_order_seq_cst,
                                                 memory_order_seq_cst)) {
        atomic_store_explicit(&who2, my_tid, memory_order_seq_cst);
    }
    printf("sigterm_handler called in: %d\n", my_tid);
}

static atomic_int sync_var = 0;

static void set(int x) {
    atomic_store_explicit(&sync_var, x, memory_order_seq_cst);
}

static void wait_for(int x) {
    while (atomic_load_explicit(&sync_var, memory_order_seq_cst) != x)
        ;
}

static void* f(void* x) {
    printf("thread id: %d\n", mygettid());

    struct sigaction action = {0};
    action.sa_handler = sigterm_handler;

    int ret = sigaction(SIGTERM, &action, NULL);
    if (ret < 0) {
        fprintf(stderr, "sigaction failed\n");
        exit(1);
    }

    set(1);
    wait_for(2);

    return x;
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    pthread_t th;

    if (pthread_create(&th, NULL, f, NULL)) {
        fprintf(stderr, "pthread_create failed: %m\n");
        return 1;
    }

    wait_for(1);

    pid_t tid = mygettid();

    printf("parent tid: %d\n", tid);

    /* the below dummy tkill (no signal is sent) is for sanity */
    if (tkill(tid, /*sig=*/0)) {
        fprintf(stderr, "tkill(sig=0) failed: %m\n");
        return 1;
    }

    if (tkill(tid, SIGTERM)) {
        fprintf(stderr, "tkill failed: %m\n");
        return 1;
    }

    set(2);

    if (pthread_join(th, NULL)) {
        fprintf(stderr, "pthread_join failed: %m\n");
        return 1;
    }

    pid_t w1 = atomic_load_explicit(&who1, memory_order_seq_cst);
    pid_t w2 = atomic_load_explicit(&who2, memory_order_seq_cst);

    if (w1 != tid || w2 != 0) {
        fprintf(stderr, "test failed: (%d, %d)\n", w1, w2);
        return 1;
    }

    puts("TEST OK!");

    return 0;
}
