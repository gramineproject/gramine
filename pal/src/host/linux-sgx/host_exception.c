/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 *               2020 Intel Labs
 */

/*
 * This file contains APIs to set up signal handlers.
 */

#include <stddef.h> /* needed by <linux/signal.h> for size_t */

#include "sigset.h" /* FIXME: this include can't be sorted, otherwise we get:
                     * In file included from sgx_exception.c:19:0:
                     * ../../../include/arch/x86_64/linux/ucontext.h:136:5: error: unknown type name ‘__sigset_t’
                     *      __sigset_t uc_sigmask;
                     */


#include <linux/signal.h>
#include <stdbool.h>

#include "api.h"
#include "assert.h"
#include "cpu.h"
#include "debug_map.h"
#include "gdb_integration/sgx_gdb.h"
#include "host_internal.h"
#include "host_syscall.h"
#include "pal_rpc_queue.h"
#include "pal_tcb.h"
#include "sigreturn.h"
#include "ucontext.h"

static const int ASYNC_SIGNALS[] = {SIGTERM, SIGCONT};

/*
 * If no SGX-stats reset is in flight, this variable is zero.
 *
 * Upon user-induced SIGUSR1 on some thread (below happens in signal handling context):
 *   1. If `g_stats_reset_leader_tid == 0`, then it is set to the TID of this thread -- this thread
 *      is designated to be the "leader" of SGX-stats reset flow, and it will broadcast SIGUSR1 to
 *      all other threads on the first AEX (since we can't do any complex logic in signal handling
 *      context, we postpone to the normal context which starts right-after an AEX event).
 *   2. If `g_stats_reset_leader_tid != 0`, then it means that an SGX-stats reset flow is in flight.
 *      Two cases are possible:
 *        a. If PID of sending process is the current PID, then the signal was sent by the "leader"
 *           and this thread is a "follower" -- it sets `reset_stats = true` in its TCB, so that
 *           this thread's statistics are dumped and reset on the next AEX.
 *        b. If PID of sending process is not the current PID, then the signal was sent by the user
 *           and this is a new "SGX-stats reset" event from the user. Since the previous flow is
 *           still in flight, the thread must ignore this signal.
 *
 * On each AEX, each thread checks (below happens in normal context):
 *   1. If `g_stats_reset_leader_tid == 0`, do nothing (no SGX-stats reset is in flight).
 *   2. If `g_stats_reset_leader_tid == gettid()`, then this is the "leader" thread and it must
 *      broadcast SIGUSR1 to all other threads and wait until they perform their SGX-stats resets.
 *      After all threads are done, the "leader" resets `g_stats_reset_leader_tid` to zero.
 *   3. Else, this is the "follower" thread and it must perform its SGX-stats reset.
 *
 * Application threads on Linux can never be 0, so this "no-op" default is safe.
 */
static int g_stats_reset_leader_tid = 0;

static int block_signal(int sig, bool block) {
    int how = block ? SIG_BLOCK : SIG_UNBLOCK;

    __sigset_t mask;
    __sigemptyset(&mask);
    __sigaddset(&mask, sig);

    int ret = DO_SYSCALL(rt_sigprocmask, how, &mask, NULL, sizeof(__sigset_t));
    return ret < 0 ? ret : 0;
}

static int set_signal_handler(int sig, void* handler) {
    struct sigaction action = {0};
    action.sa_handler  = handler;
    action.sa_flags    = SA_SIGINFO | SA_ONSTACK | SA_RESTORER;
    action.sa_restorer = syscall_rt_sigreturn;

    /* disallow nested asynchronous signals during enclave exception handling */
    __sigemptyset((__sigset_t*)&action.sa_mask);
    for (size_t i = 0; i < ARRAY_SIZE(ASYNC_SIGNALS); i++)
        __sigaddset((__sigset_t*)&action.sa_mask, ASYNC_SIGNALS[i]);

    int ret = DO_SYSCALL(rt_sigaction, sig, &action, NULL, sizeof(__sigset_t));
    if (ret < 0)
        return ret;

    return block_signal(sig, /*block=*/false);
}

int block_async_signals(bool block) {
    for (size_t i = 0; i < ARRAY_SIZE(ASYNC_SIGNALS); i++) {
        int ret = block_signal(ASYNC_SIGNALS[i], block);
        if (ret < 0)
            return ret;
    }
    return 0;
}

static enum pal_event signal_to_pal_event(int sig) {
    switch (sig) {
        case SIGFPE:
            return PAL_EVENT_ARITHMETIC_ERROR;
        case SIGSEGV:
        case SIGBUS:
            return PAL_EVENT_MEMFAULT;
        case SIGILL:
            return PAL_EVENT_ILLEGAL;
        case SIGTERM:
            return PAL_EVENT_QUIT;
        case SIGCONT:
            return PAL_EVENT_INTERRUPTED;
        default:
            BUG();
    }
}

static bool interrupted_in_enclave(struct ucontext* uc) {
    unsigned long rip = ucontext_get_ip(uc);

    /* in case of AEX, RIP can point to any instruction in the AEP/ERESUME trampoline code, i.e.,
     * RIP can point to anywhere in [async_exit_pointer, async_exit_pointer_end) interval */
    return rip >= (unsigned long)async_exit_pointer && rip < (unsigned long)async_exit_pointer_end;
}

static bool interrupted_in_aex_profiling(void) {
    return pal_get_host_tcb()->is_in_aex_profiling != 0;
}

static void handle_sync_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    enum pal_event event = signal_to_pal_event(signum);

    __UNUSED(info);

    /* send dummy signal to RPC threads so they interrupt blocked syscalls */
    if (g_rpc_queue)
        for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
            DO_SYSCALL(tkill, g_rpc_queue->rpc_threads[i], SIGUSR2);

    if (interrupted_in_enclave(uc)) {
        /* exception happened in app/LibOS/trusted PAL code, handle signal inside enclave */
        pal_get_host_tcb()->sync_signal_cnt++;
        sgx_raise(event);
        return;
    }

    /* exception happened in untrusted PAL code (during syscall handling): fatal in Gramine */

    unsigned long rip = ucontext_get_ip(uc);
    char buf[LOCATION_BUF_SIZE];
    pal_describe_location(rip, buf, sizeof(buf));

    const char* event_name;
    switch (signum) {
        case SIGSEGV:
            event_name = "segmentation fault (SIGSEGV)";
            break;

        case SIGILL:
            event_name = "illegal instruction (SIGILL)";
            break;

        case SIGFPE:
            event_name = "arithmetic exception (SIGFPE)";
            break;

        case SIGBUS:
            event_name = "memory mapping exception (SIGBUS)";
            break;

        default:
            event_name = "unknown exception";
            break;
    }

    log_error("Unexpected %s occurred inside untrusted PAL (%s)", event_name, buf);
    DO_SYSCALL(exit_group, 1);
    die_or_inf_loop();
}

static void handle_async_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    enum pal_event event = signal_to_pal_event(signum);

    __UNUSED(info);

    /* send dummy signal to RPC threads so they interrupt blocked syscalls */
    if (g_rpc_queue)
        for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
            DO_SYSCALL(tkill, g_rpc_queue->rpc_threads[i], SIGUSR2);

    if (interrupted_in_enclave(uc) || interrupted_in_aex_profiling()) {
        /* signal arrived while in app/LibOS/trusted PAL code or when handling another AEX, handle
         * signal inside enclave */
        pal_get_host_tcb()->async_signal_cnt++;
        sgx_raise(event);
        return;
    }

    assert(event == PAL_EVENT_INTERRUPTED || event == PAL_EVENT_QUIT);
    if (pal_get_host_tcb()->last_async_event != PAL_EVENT_QUIT) {
        /* Do not overwrite `PAL_EVENT_QUIT`. The only other possible event here is
         * `PAL_EVENT_INTERRUPTED`, which is basically a no-op (just makes sure that a thread
         * notices any new signals or other state changes, which also happens for other events). */
        pal_get_host_tcb()->last_async_event = event;
    }

    uint64_t rip = ucontext_get_ip(uc);
    if (rip == (uint64_t)&do_syscall_intr_after_check1
            || rip == (uint64_t)&do_syscall_intr_after_check2) {
        ucontext_set_ip(uc, (uint64_t)&do_syscall_intr_eintr);
    }
}

static void handle_dummy_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    __UNUSED(signum);
    __UNUSED(info);
    __UNUSED(uc);
    /* we need this handler to interrupt blocking syscalls in RPC threads */
}

static void handle_sigusr1(int signum, siginfo_t* info, struct ucontext* uc) {
    __UNUSED(signum);
    __UNUSED(info);
    __UNUSED(uc);

    if (g_sgx_enable_stats) {
        int expected_tid = 0;
        if (__atomic_compare_exchange_n(&g_stats_reset_leader_tid, &expected_tid,
                                        DO_SYSCALL(gettid), /*weak=*/false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED) == true) {
            /* first thread that gets SIGUSR1, the CAS above designated it as the "leader" */
            PAL_HOST_TCB* tcb = pal_get_host_tcb();
            tcb->reset_stats = true;
        } else {
            /* thread gets SIGUSR1, check if this is a signal from the "leader" */
            if (info->si_pid == g_host_pid) {
                PAL_HOST_TCB* tcb = pal_get_host_tcb();
                assert(!tcb->reset_stats);
                tcb->reset_stats = true;
            } else {
                log_warning("Received SIGUSR1 from user, but there is another SGX-stats reset "
                            "in flight; ignoring it");
            }
        }
    }

#ifdef DEBUG
    if (g_pal_enclave.profile_enable) {
        __atomic_store_n(&g_trigger_profile_reinit, true, __ATOMIC_RELEASE);
    }
#endif /* DEBUG */
}

int sgx_signal_setup(void) {
    int ret;

    /* SIGCHLD and SIGPIPE are emulated completely inside LibOS */
    ret = set_signal_handler(SIGPIPE, SIG_IGN);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGCHLD, SIG_IGN);
    if (ret < 0)
        goto err;

    /* register synchronous signals (exceptions) in host Linux */
    ret = set_signal_handler(SIGFPE, handle_sync_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGSEGV, handle_sync_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGBUS, handle_sync_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGILL, handle_sync_signal);
    if (ret < 0)
        goto err;

    /* register asynchronous signals in host Linux */
    ret = set_signal_handler(SIGTERM, handle_async_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGCONT, handle_async_signal);
    if (ret < 0)
        goto err;

    ret = set_signal_handler(SIGUSR1, handle_sigusr1);
    if (ret < 0)
        goto err;

    /* SIGUSR2 is reserved for Gramine usage: interrupting blocking syscalls in RPC threads.
     * We block SIGUSR2 in enclave threads; it is unblocked by each RPC thread explicitly. */
    ret = set_signal_handler(SIGUSR2, handle_dummy_signal);
    if (ret < 0)
        goto err;

    ret = block_signal(SIGUSR2, /*block=*/true);
    if (ret < 0)
        goto err;

    ret = 0;
err:
    return ret;
}

/* The below function is used by stack protector's __stack_chk_fail(), _FORTIFY_SOURCE's *_chk()
 * functions and by assert.h's assert() defined in the common library. Thus it might be called by
 * any PAL execution context, including this untrusted context. */
noreturn void pal_abort(void) {
    DO_SYSCALL(exit_group, 1);
    die_or_inf_loop();
}

void pal_describe_location(uintptr_t addr, char* buf, size_t buf_size) {
#ifdef DEBUG
    if (debug_describe_location(addr, buf, buf_size) == 0)
        return;
#endif
    default_describe_location(addr, buf, buf_size);
}

static size_t send_sigusr1_to_followers(pid_t leader_tid) {
    size_t followers_num = 0;

    /* we re-use DBGINFO_ADDR special variable (that is primarily used by GDB for debugging),
     * fortunately this variable is set up even in non-debug builds */
    for (size_t i = 0; i < MAX_DBG_THREADS; i++) {
        int follower_tid = ((struct enclave_dbginfo*)DBGINFO_ADDR)->thread_tids[i];
        if (!follower_tid || follower_tid == leader_tid)
            continue;

        DO_SYSCALL(tkill, follower_tid, SIGUSR1);
        followers_num++;
    }
    return followers_num;
}

/* called on each AEX and OCALL (in normal context), see host_entry.S */
void dump_and_reset_stats(void) {
    static size_t followers_visited_num = 0; /* note `static`, it is a global var */

    if (!g_sgx_enable_stats)
        return;

    int leader_tid = __atomic_load_n(&g_stats_reset_leader_tid, __ATOMIC_ACQUIRE);
    if (!leader_tid)
        return;

    PAL_HOST_TCB* tcb = pal_get_host_tcb();
    if (!tcb->reset_stats)
        return;

    if (DO_SYSCALL(gettid) == leader_tid) {
        log_always("----- DUMPING and RESETTING SGX STATS -----");
        size_t followers_num = send_sigusr1_to_followers(leader_tid);

        while ((__atomic_load_n(&followers_visited_num, __ATOMIC_ACQUIRE)) < followers_num)
            DO_SYSCALL(sched_yield);

        update_and_print_stats(/*process_wide=*/true);
        pal_host_tcb_reset_stats();
        __atomic_store_n(&followers_visited_num, 0, __ATOMIC_RELEASE);

        __atomic_store_n(&g_stats_reset_leader_tid, 0, __ATOMIC_RELEASE);
    } else {
        update_and_print_stats(/*process_wide=*/false);
        pal_host_tcb_reset_stats();
        __atomic_fetch_add(&followers_visited_num, 1, __ATOMIC_ACQ_REL);
    }
}
