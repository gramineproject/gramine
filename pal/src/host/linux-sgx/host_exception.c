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
#include "cpu.h"
#include "debug_map.h"
#include "host_internal.h"
#include "pal_rpc_queue.h"
#include "sigreturn.h"
#include "ucontext.h"

static const int ASYNC_SIGNALS[] = {SIGTERM, SIGCONT};

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

static bool interrupted_in_aex(void) {
    return pal_get_host_tcb()->is_in_aex != 0;
}

static void handle_sync_signal(int signum, siginfo_t* info, struct ucontext* uc) {
    enum pal_event event = signal_to_pal_event(signum);

    __UNUSED(info);

    /* send dummy signal to RPC threads so they interrupt blocked syscalls */
    if (g_rpc_queue)
        for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
            DO_SYSCALL(tkill, g_rpc_queue->rpc_threads[i], SIGUSR2);

    if (event == PAL_EVENT_MEMFAULT &&
            ucontext_get_ip(uc) == (unsigned long)&sgx_raise_eenter_instr) {
        /* this is #GP on EENTER instruction during sgx_raise() -- means that some async signal
         * arrived while the enclave thread executes in CSSA=1 (stage-1 exception handler); we
         * should ignore this fault by skipping EENTER, see also sgx_handle_aex_signal() */
        ucontext_set_ip(uc, ucontext_get_ip(uc) + /*sizeof(ENCLU)=*/3);
        return;
    }

    if (interrupted_in_enclave(uc)) {
        /* exception happened in app/LibOS/trusted PAL code, mark to handle signal inside enclave */
        assert(pal_get_host_tcb()->aex_sync_event == PAL_EVENT_NO_EVENT);
        pal_get_host_tcb()->aex_sync_event = event;
        pal_get_host_tcb()->sync_signal_cnt++;
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

    assert(event == PAL_EVENT_INTERRUPTED || event == PAL_EVENT_QUIT);

    if (interrupted_in_enclave(uc) || interrupted_in_aex()) {
        /* signal arrived while in app/LibOS/trusted PAL code or when handling another AEX, mark to
         * handle signal inside enclave */
        if (pal_get_host_tcb()->aex_async_event != PAL_EVENT_QUIT) {
            /* Do not overwrite `PAL_EVENT_QUIT`. See explanation below. */
            pal_get_host_tcb()->aex_async_event = event;
        }
        pal_get_host_tcb()->async_signal_cnt++;
        return;
    }

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

/* The handle_sync_signal() and handle_async_signal() functions, executed in signal-handling
 * context, added sync/async signals to process (that happened during enclave-thread execution)
 * -- now the regular context must inform the enclave about these events. This function is
 * potentially noreturn -- if there is at least one signal, and the enclave is ready to handle it,
 * then the call to sgx_raise() never returns. Only one of potentially two signals (one sync and
 * one async) will be added by this function, because sgx_raise() doesn't return; the hope is that
 * the second (async) signal will be added on some later AEX. Also note that new sync signals
 * cannot occur while in this function, but new async signals can occur (since we are in regular
 * context and cannot block async signals), thus handling async signals must be aware of concurrent
 * signal handling code. */
void sgx_handle_aex_signal(void) {
    if (pal_get_host_tcb()->aex_sync_event != PAL_EVENT_NO_EVENT) {
        /* sync event must always be consumed by the enclave (there is no scenario where in-enclave
         * stage-1 handling of another sync/async event would generate a sync event) */
        enum pal_event event = pal_get_host_tcb()->aex_sync_event;
        pal_get_host_tcb()->aex_sync_event = PAL_EVENT_NO_EVENT;
        sgx_raise(event);
        return;
    }

    enum pal_event event = __atomic_exchange_n(&pal_get_host_tcb()->aex_async_event,
            PAL_EVENT_NO_EVENT, __ATOMIC_RELAXED);
    if (event != PAL_EVENT_NO_EVENT) {
        /* if async event is consumed by the enclave, then below sgx_raise() does not return;
         * otherwise it means that the enclave was already in the middle of stage-1 handler and
         * could not consume this async event: simply ignore for now; the very next AEX will try to
         * raise this async event again */
        sgx_raise(event);
        enum pal_event no_event = PAL_EVENT_NO_EVENT;
        __atomic_compare_exchange_n(&pal_get_host_tcb()->aex_async_event, &no_event, event,
                                    /*weak=*/false, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
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
