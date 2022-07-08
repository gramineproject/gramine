/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "host_ecalls.h"

#include <asm/errno.h>
#include <linux/futex.h>
#include <linux/signal.h>

#include "host_internal.h"
#include "pal_ecall_types.h"
#include "pal_ocall_types.h"
#include "pal_rpc_queue.h"

extern sgx_ocall_fn_t ocall_table[OCALL_NR];

rpc_queue_t* g_rpc_queue = NULL; /* pointer to untrusted queue */

static int rpc_thread_loop(void* arg) {
    __UNUSED(arg);
    long mytid = DO_SYSCALL(gettid);

    /* block all signals except SIGUSR2 for RPC thread */
    __sigset_t mask;
    __sigfillset(&mask);
    __sigdelset(&mask, SIGUSR2);
    DO_SYSCALL(rt_sigprocmask, SIG_SETMASK, &mask, NULL, sizeof(mask));

    spinlock_lock(&g_rpc_queue->lock);
    g_rpc_queue->rpc_threads[g_rpc_queue->rpc_threads_cnt] = mytid;
    g_rpc_queue->rpc_threads_cnt++;
    spinlock_unlock(&g_rpc_queue->lock);

    static const uint64_t SPIN_ATTEMPTS_MAX = 10000;     /* rather arbitrary */
    static const uint64_t SLEEP_TIME_MAX    = 100000000; /* nanoseconds (0.1 seconds) */
    static const uint64_t SLEEP_TIME_STEP   = 1000000;   /* 100 steps before capped */

    /* no races possible since vars are thread-local and RPC threads don't receive signals */
    uint64_t spin_attempts = 0;
    uint64_t sleep_time    = 0;

    while (1) {
        rpc_request_t* req = rpc_dequeue(g_rpc_queue);
        if (!req) {
            if (spin_attempts == SPIN_ATTEMPTS_MAX) {
                if (sleep_time < SLEEP_TIME_MAX)
                    sleep_time += SLEEP_TIME_STEP;

                struct timespec tv = {.tv_sec = 0, .tv_nsec = sleep_time};
                (void)DO_SYSCALL(nanosleep, &tv, /*rem=*/NULL);
            } else {
                spin_attempts++;
                CPU_RELAX();
            }
            continue;
        }

        /* new request came, reset spin/sleep heuristics */
        spin_attempts = 0;
        sleep_time    = 0;

        /* call actual function and notify awaiting enclave thread when done */
        sgx_ocall_fn_t f = ocall_table[req->ocall_index];
        req->result = f(req->buffer);

        /* this code is based on Mutex 2 from Futexes are Tricky */
        int old_lock_state = __atomic_fetch_sub(&req->lock.lock, 1, __ATOMIC_ACQ_REL);
        if (old_lock_state == SPINLOCK_LOCKED_WITH_WAITERS) {
            /* must unlock and wake waiters */
            spinlock_unlock(&req->lock);
            int ret = DO_SYSCALL(futex, &req->lock.lock, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
            if (ret == -1)
                log_error("RPC thread failed to wake up enclave thread");
        }
    }

    /* NOTREACHED */
    return 0;
}

static int start_rpc(size_t threads_cnt) {
    g_rpc_queue = (rpc_queue_t*)DO_SYSCALL(mmap, NULL,
                                           ALIGN_UP(sizeof(rpc_queue_t), PRESET_PAGESIZE),
                                           PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
                                           -1, 0);
    if (IS_PTR_ERR(g_rpc_queue))
        return -ENOMEM;

    /* initialize g_rpc_queue just for sanity, it will be overwritten by in-enclave code */
    rpc_queue_init(g_rpc_queue);

    for (size_t i = 0; i < threads_cnt; i++) {
        void* stack = (void*)DO_SYSCALL(mmap, NULL, RPC_STACK_SIZE, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (IS_PTR_ERR(stack))
            return -ENOMEM;

        void* child_stack_top = stack + RPC_STACK_SIZE;
        child_stack_top = ALIGN_DOWN_PTR(child_stack_top, 16);

        int dummy_parent_tid_field = 0;
        int ret = clone(rpc_thread_loop, child_stack_top,
                        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM |
                        CLONE_THREAD | CLONE_SIGHAND | CLONE_PTRACE | CLONE_PARENT_SETTID,
                        /*arg=*/NULL, &dummy_parent_tid_field, /*tls=*/NULL, /*child_tid=*/NULL,
                        thread_exit);

        if (ret < 0) {
            DO_SYSCALL(munmap, stack, RPC_STACK_SIZE);
            return -ENOMEM;
        }
    }

    /* wait until all RPC threads are initialized in rpc_thread_loop */
    while (1) {
        spinlock_lock(&g_rpc_queue->lock);
        size_t n = g_rpc_queue->rpc_threads_cnt;
        spinlock_unlock(&g_rpc_queue->lock);
        if (n == g_pal_enclave.rpc_thread_num)
            break;
        DO_SYSCALL(sched_yield);
    }

    return 0;
}

int ecall_enclave_start(char* libpal_uri, char* args, size_t args_size, char* env,
                        size_t env_size, int parent_stream_fd, sgx_target_info_t* qe_targetinfo,
                        struct pal_topo_info* topo_info) {
    g_rpc_queue = NULL;

    if (g_pal_enclave.rpc_thread_num > 0) {
        int ret = start_rpc(g_pal_enclave.rpc_thread_num);
        if (ret < 0) {
            /* failed to create RPC threads */
            return ret;
        }
        /* after this point, g_rpc_queue != NULL */
    }

    ms_ecall_enclave_start_t ms;
    ms.ms_libpal_uri       = libpal_uri;
    ms.ms_libpal_uri_len   = strlen(ms.ms_libpal_uri);
    ms.ms_args             = args;
    ms.ms_args_size        = args_size;
    ms.ms_env              = env;
    ms.ms_env_size         = env_size;
    ms.ms_parent_stream_fd = parent_stream_fd;
    ms.ms_qe_targetinfo    = qe_targetinfo;
    ms.ms_topo_info        = topo_info;
    ms.rpc_queue           = g_rpc_queue;
    return sgx_ecall(ECALL_ENCLAVE_START, &ms);
}

int ecall_thread_start(void) {
    return sgx_ecall(ECALL_THREAD_START, NULL);
}

int ecall_thread_reset(void) {
    return sgx_ecall(ECALL_THREAD_RESET, NULL);
}
