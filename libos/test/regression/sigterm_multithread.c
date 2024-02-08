/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

#define _XOPEN_SOURCE 700
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

static bool thread_started = false;

static void pthread_check(int x) {
    if (x) {
        errx(1, "pthread failed with %d", x);
    }
}

static void ignore_signal(void) {
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    CHECK(sigprocmask(SIG_SETMASK, &blocked, NULL));
}

static void* thread_func(void* arg) {
    ignore_signal();
    __atomic_store_n(&thread_started, true, __ATOMIC_SEQ_CST);

    sigset_t waitset;
    sigemptyset(&waitset);
    sigaddset(&waitset, SIGTERM);
    int ret = sigwaitinfo(&waitset, /*info=*/NULL);
    if (ret != SIGTERM)
        errx(1, "expected SIGTERM but sigwaitinfo returned %d", ret);

    exit(0);
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    ignore_signal();

    pthread_t th;
    pthread_check(pthread_create(&th, NULL, thread_func, NULL));

    while (!__atomic_load_n(&thread_started, __ATOMIC_SEQ_CST))
        ;

    /* helper thread started and waits for SIGTERM; inform the wrapper shell script */
    puts("READY");

    /* emulate some processing; note that we can't use `sleep(100)` because in this case, both
     * threads would wait in blocking host syscalls indefinitely, and Gramine currently has a
     * limitation that signals are delivered when some thread returns from syscall to the app */
    for (int i = 0; i < 100; i++)
        sleep(1);
    return 0;
}
