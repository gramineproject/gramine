#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

static atomic_int counter = 0;

static void sigterm_handler(int signum) {
    atomic_fetch_add_explicit(&counter, 1, memory_order_seq_cst);
}

static atomic_int sync_var = 0;

static void set(int x) {
    atomic_store_explicit(&sync_var, x, memory_order_seq_cst);
}

static void wait_for(int x) {
    while (atomic_load_explicit(&sync_var, memory_order_seq_cst) != x) {
        sched_yield();
    }
}

static void* thread_func(void* x) {
    set(1);
    wait_for(2);
    return x;
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    struct sigaction action = {0};
    action.sa_handler = sigterm_handler;

    int ret = sigaction(SIGTERM, &action, NULL);
    if (ret < 0) {
        fprintf(stderr, "sigaction failed\n");
        return 1;
    }

    pthread_t th;

    if (pthread_create(&th, NULL, thread_func, NULL)) {
        fprintf(stderr, "pthread_create failed: %m\n");
        return 1;
    }

    wait_for(1);

    /* the below dummy kill (no signal is sent) is for sanity */
    if (kill(getpid(), /*sig=*/0)) {
        fprintf(stderr, "kill(sig=0) failed: %m\n");
        return 1;
    }

    if (kill(getpid(), SIGTERM)) {
        fprintf(stderr, "kill failed: %m\n");
        return 1;
    }

    /* Poor man's way of allowing the other thread to handle the signal, if it was delivered to it.
     * That thread calls sched_yield in a loop, so 1ms should be enough. */
    usleep(1000);

    set(2);

    if (pthread_join(th, NULL)) {
        fprintf(stderr, "pthread_join failed: %m\n");
        return 1;
    }

    int t = atomic_load_explicit(&counter, memory_order_seq_cst);
    if (t != 1) {
        fprintf(stderr, "test failed: sigerm_handler was run %d times\n", t);
        return 1;
    }

    puts("TEST OK!");

    return 0;
}
