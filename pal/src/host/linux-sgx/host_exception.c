/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 *               2020 Intel Labs
 */

/*
 * This file contains APIs to set up signal handlers.
 */

#include <stddef.h> /* needed by <linux/signal.h> for size_t */

#include <linux/signal.h>
#include <stdbool.h>

#include "api.h"
#include "cpu.h"
#include "debug_map.h"
#include "host_internal.h"
#include "pal_rpc_queue.h"
#include "pal_tcb.h"
#include "sigreturn.h"
#include "sigset.h"
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
    __UNUSED(info);

    enum pal_event event = signal_to_pal_event(signum);
    uint64_t rip = ucontext_get_ip(uc);

    /* send dummy signal to RPC threads so they interrupt blocked syscalls */
    if (g_rpc_queue)
        for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
            DO_SYSCALL(tkill, g_rpc_queue->rpc_threads[i], SIGUSR2);

    if (event == PAL_EVENT_MEMFAULT && interrupted_in_aex() && rip == (uint64_t)&eenter_pointer) {
        /*
         * This is a #GP on EENTER instruction inside sgx_raise(), called during AEX handling by
         * maybe_raise_pending_signal(). This implies that some async signal arrived and was
         * injected by AEX logic while the enclave thread is being executed in CSSA=1 (stage-1
         * exception handler).
         *
         * We ignore this #GP fault by skipping EENTER. This newly arrived async signal will be
         * delivered at some later AEX event, when the enclave thread starts executing in CSSA=0.
         *
         * Since last_async_event was reset to NO_EVENT before sgx_raise(), we must restore it to
         * this failed-to-deliver async signal. We extract async signal number from RDI register.
         * See also maybe_raise_pending_signal().
         */
        enum pal_event faulted_event = uc->uc_mcontext.rdi; /* convention, see .Lcssa1_exception */
        if (faulted_event != PAL_EVENT_INTERRUPTED && faulted_event != PAL_EVENT_QUIT) {
            log_error("#GP on EENTER instruction not because of async signal, impossible!");
            BUG();
        }
        if (pal_get_host_tcb()->last_async_event != PAL_EVENT_QUIT) {
            /* Do not overwrite `PAL_EVENT_QUIT`. For explanation, see handle_async_signal(). */
            pal_get_host_tcb()->last_async_event = faulted_event;
        }

        ucontext_set_ip(uc, rip + /*sizeof(ENCLU)=*/3); /* skip EENTER */
        return;
    }

    if (interrupted_in_enclave(uc)) {
        /*
         * Exception happened in app/LibOS/trusted PAL code, mark this sync signal as pending. This
         * singal will be delivered right after this untrusted-runtime signal handler returns
         * control to the AEX logic, which will call maybe_raise_pending_signal().
         *
         * We do not deliver the signal immediately to the enclave (but instead mark it as pending)
         * because we want to support AEX-Notify hardware feature in SGX. In particular, AEX-Notify
         * must execute in-enclave flows in regular context of the untrusted runtime, because
         * AEX-Notify uses EDECCSSA instruction to go from CSSA=1 context to CSSA=0 context (i.e.,
         * AEX-Notify does not exit the SGX enclave and thus does not give an opportunity to the
         * untrusted runtime to switch from signal-handling context to regular context).
         *
         * Therefore, we must execute the in-enclave stage-1 signal handler in regular context of
         * the untrusted runtime. This is achieved by interposing on the AEX flow (which executes
         * right after the host kernel handles control from this signal handler back to regular
         * context).
         *
         * We don't need to use atomics when accessing last_sync_event since we are in the
         * signal-handling context, and thus no other signal can arrive while we're here.
         */
        if (pal_get_host_tcb()->last_sync_event != PAL_EVENT_NO_EVENT) {
            log_error("Nested sync signal, impossible!");
            BUG();
        }
        pal_get_host_tcb()->last_sync_event = event;

        pal_get_host_tcb()->sync_signal_cnt++;
        return;
    }

    /* exception happened in untrusted PAL code (during syscall handling): fatal in Gramine */
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

    if (interrupted_in_enclave(uc))
        pal_get_host_tcb()->async_signal_cnt++;

    /* see comments in handle_sync_signal() on why we do not deliver the signal immediately to the
     * enclave (but instead mark it as pending) */

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

#ifdef DEBUG
static void handle_sigusr1(int signum, siginfo_t* info, struct ucontext* uc) {
    __UNUSED(signum);
    __UNUSED(info);
    __UNUSED(uc);

    if (g_sgx_enable_stats) {
        PAL_HOST_TCB* tcb = pal_get_host_tcb();
        __atomic_store_n(&tcb->reset_stats, true, __ATOMIC_RELAXED);
    }

    if (g_pal_enclave.profile_enable) {
        __atomic_store_n(&g_trigger_profile_reinit, true, __ATOMIC_RELEASE);
    }
}
#endif /* DEBUG */

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

#ifdef DEBUG
    ret = set_signal_handler(SIGUSR1, handle_sigusr1);
    if (ret < 0)
        goto err;
#endif /* DEBUG */

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

#ifdef DEBUG
/* called on each AEX and OCALL (in regular context), see host_entry.S */
void maybe_dump_and_reset_stats(void) {
    if (!g_sgx_enable_stats)
        return;

    PAL_HOST_TCB* tcb = pal_get_host_tcb();
    if (__atomic_exchange_n(&tcb->reset_stats, false, __ATOMIC_RELAXED) == true) {
        collect_and_print_sgx_stats();
    }
}
#endif

/*
 * The handle_sync_signal() and handle_async_signal() functions, executed in signal-handling
 * context, added pending sync/async signal to the thread -- now the AEX flow, executed in regular
 * context, must inform the enclave about these signals.
 *
 * This function is executed as part of the AEX flow, and may result in EENTER -> in-enclave stage-1
 * signal handler -> EEXIT (if there is any pending signal, and enclave is not in the middle of
 * another stage-1 signal handler). When the function returns, the AEX flow continues and ends up in
 * ERESUME, that resumes "regular context" inside the enclave (which may be stage-2 signal handler).
 *
 * Only one of potentially two signals (one sync and one async) will be injected into the enclave at
 * a time by this function. The hope is that the second (async) signal will be added at some later
 * AEX event.
 *
 * Note that async signals are special in Gramine, there are only two of them: SIGCONT (aka
 * PAL_EVENT_INTERRUPTED) which is dummy (can be ignored) and SIGTERM (aka PAL_EVENT_QUIT) which is
 * injected only once anyway. Thus we don't need a queue of pending async signals, and a single slot
 * for a pending async signal is sufficient (which is the `pal_get_host_tcb()->last_async_event`
 * variable).
 *
 * Also note that new sync signals cannot occur while in this function, but new async signals can
 * occur (since we are in regular context and cannot block async signals), thus handling async
 * signals must be aware of concurrent signal handling code, i.e., last_async_event must be accessed
 * atomically. We also access last_sync_event atomically, just for uniformity (though it is not
 * strictly required).
 */
void maybe_raise_pending_signal(void) {
    enum pal_event event;

    event = __atomic_exchange_n(&pal_get_host_tcb()->last_sync_event, PAL_EVENT_NO_EVENT,
                                __ATOMIC_RELAXED);
    if (event != PAL_EVENT_NO_EVENT) {
        /*
         * Sync event must always be consumed by the enclave. There is no scenario where the
         * in-enclave stage-1 handling of another sync/async event would generate a sync event.
         */
        sgx_raise(event);
        return;
    }

    event = __atomic_exchange_n(&pal_get_host_tcb()->last_async_event, PAL_EVENT_NO_EVENT,
                                __ATOMIC_RELAXED);
    if (event != PAL_EVENT_NO_EVENT) {
        /*
         * Async event may be *not* consumed by the enclave. This can happen if the enclave was
         * already in the middle of stage-1 handler and thus EENTER generates #GP (because this
         * EENTER would imply CSSA=2 which Gramine always programmes as prohibited in Intel SGX).
         * In such case, this async event is ignored and will be delivered on some later AEX.
         * See also handle_sync_signal().
         */
        sgx_raise(event);
        return;
    }
}
