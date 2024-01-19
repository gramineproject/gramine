/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "libos_fs_lock.h"
#include "libos_handle.h"
#include "libos_ipc.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_signal.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "libos_utils.h"
#include "pal.h"

static noreturn void libos_clean_and_exit(int exit_code, int term_signal) {
    shutdown_sync_client();

    struct libos_thread* async_thread = terminate_async_worker();
    if (async_thread) {
        /* TODO: wait for the thread to finish its tasks and exit in the host OS.
         * This is tracked by the following issue:
         * https://github.com/gramineproject/graphene/issues/440
         */
        put_thread(async_thread);
    }

    /*
     * At this point there should be only 2 threads running: this + IPC worker.
     * XXX: We release current thread's ID, yet we are still running. We never put the (possibly)
     * last reference to the current thread (from TCB) and there should be no other references to it
     * lying around, so nothing bad should happen™. Hopefully...
     */
    /*
     * We might still be a zombie in the parent process. In an unlikely case that the parent does
     * not wait for us for a long time and pids overflow (currently we can have 2**32 pids), IPC
     * leader could give this ID to somebody else. This could be a nasty conflict.
     * The problem is that solving this is hard: we would need to make the parent own (or at least
     * release) our pid, but that would require "reparenting" in case the parent dies before us.
     * Such solution would also have some nasty consequences: Gramine pid 1 (which I guess would
     * be the new parent) might not be expecting to have more children than it spawned (normal apps
     * do not expect that, init process is pretty special).
     */
    release_id(get_cur_thread()->tid);

    /* Terminate the IPC worker and wait until all child processes have also terminated. However,
     * if we received a SIGTERM then the IPC worker will be forcefully terminated without waiting
     * for child processes. Once we exit, all child proceses will then also exit.
     */
    terminate_ipc_worker(term_signal == SIGTERM);

    log_debug("process %u exited with status %d", g_process_ipc_ids.self_vmid, exit_code);

    /* TODO: We exit whole libos, but there are some objects that might need cleanup - we should do
     * a proper cleanup of everything. */
    PalProcessExit(exit_code);
}

noreturn void thread_exit(int error_code, int term_signal) {
    struct libos_thread* cur_thread = get_cur_thread();
    if (cur_thread->robust_list) {
        release_robust_list(cur_thread->robust_list);
        cur_thread->robust_list = NULL;
    }

    /* Remove current thread from the threads list. */
    if (!check_last_thread(/*mark_self_dead=*/true)) {
        if (cur_thread->pal_handle == g_pal_public_state->first_thread) {
            /*
             * Do not exit the main thread (and do not free its resources) if the main thread is not
             * the last one in the process. This is added to correctly handle the case of a non-main
             * thread performing `execve()`, even after the main thread is considered terminated.
             *
             * The main thread waits forever so that the host OS doesn't "lose track" of this
             * Gramine process. E.g. on Linux, if the main thread (aka leader thread) terminates,
             * then the process becomes a zombie, which may confuse some tools like `docker kill`.
             * This "waiting forever" leaks memory, but only once per process (as there is only one
             * main thread per process, even after several execve invocations).
             *
             * Linux solves this corner case differently: the leader thread is terminated, and the
             * non-main thread assumes its identity (in particular, its PID):
             *
             *   https://elixir.bootlin.com/linux/v6.0/source/fs/exec.c#L1078
             *
             * Gramine can't do the same because there is no way to ask the host OS to "rewire" the
             * identity of one thread to another thread. Thus this workaround of infinite wait.
             * Note that because the main thread was removed from the list of threads (thanks to
             * `mark_self_dead=true` above), the still-alive main thread will not prevent the
             * Gramine process from terminating later on. Also note that because this thread never
             * leaves LibOS/PAL context, it will not receive signals.
             *
             * TODO: "Rewire" the identity of the non-main thread inside Gramine, similarly to how
             *       Linux does it.
             */
            thread_prepare_wait();
            while (true)
                thread_wait(/*timeout_us=*/NULL, /*ignore_pending_signals=*/true);
            __builtin_unreachable();
        }

        /* ask async worker thread to cleanup this thread */
        cur_thread->clear_child_tid_pal = 1; /* any non-zero value suffices */
        /* We pass this ownership to `cleanup_thread`. */
        get_thread(cur_thread);
        int64_t ret = install_async_event(NULL, 0, &cleanup_thread, cur_thread);

        /* Take the reference to the current thread from the tcb. */
        lock(&cur_thread->lock);
        assert(cur_thread->libos_tcb->tp == cur_thread);
        cur_thread->libos_tcb->tp = NULL;
        unlock(&cur_thread->lock);
        put_thread(cur_thread);

        if (ret < 0) {
            log_error("failed to set up async cleanup_thread (exiting without clear child tid),"
                      " return code: %s", unix_strerror(ret));
            /* `cleanup_thread` did not get this reference, clean it. We have to be careful, as
             * this is most likely the last reference and will free this `cur_thread`. */
            put_thread(cur_thread);
            PalThreadExit(NULL);
            /* UNREACHABLE */
        }

        PalThreadExit(&cur_thread->clear_child_tid_pal);
        /* UNREACHABLE */
    }

    /* Clear file (POSIX) locks before we notify parent: after a successful `wait()` by parent, our
     * locks should already be gone. */
    int ret = file_lock_clear_pid(g_process.pid);
    if (ret < 0)
        log_warning("error clearing file (POSIX) locks: %s", unix_strerror(ret));

    detach_all_fds();

    /* This is the last thread of the process. Let parent know we exited. */
    ret = ipc_cld_exit_send(error_code, term_signal);
    if (ret < 0) {
        log_error("Sending IPC process-exit notification failed: %s", unix_strerror(ret));
    }

    /* At this point other threads might be still in the middle of an exit routine, but we don't
     * care since the below will call `exit_group` eventually. */
    libos_clean_and_exit(term_signal ? 128 + (term_signal & ~__WCOREDUMP_BIT) : error_code,
                         term_signal);
}

static int mark_thread_to_die(struct libos_thread* thread, void* arg) {
    if (thread == (struct libos_thread*)arg) {
        return 0;
    }

    bool need_wakeup = !__atomic_exchange_n(&thread->time_to_die, true, __ATOMIC_ACQ_REL);

    /* Now let's kick `thread`, so that it notices (in `handle_signal`) the flag `time_to_die`
     * set above (but only if we really set that flag). */
    if (need_wakeup) {
        thread_wakeup(thread);
        (void)PalThreadResume(thread->pal_handle); // There is nothing we can do on errors.
    }
    return 1;
}

bool kill_other_threads(void) {
    bool killed = false;
    /* Tell other threads to exit. Since `mark_thread_to_die` never returns an error, this call
     * cannot fail. */
    if (walk_thread_list(mark_thread_to_die, get_cur_thread(), /*one_shot=*/false) != -ESRCH) {
        killed = true;
    }
    PalThreadYieldExecution();

    /* Wait for all other threads to exit. */
    while (!check_last_thread(/*mark_self_dead=*/false)) {
        /* Tell other threads to exit again - the previous announcement could have been missed by
         * threads that were just being created. */
        if (walk_thread_list(mark_thread_to_die, get_cur_thread(), /*one_shot=*/false) != -ESRCH) {
            killed = true;
        }
        PalThreadYieldExecution();
    }

    return killed;
}

noreturn void process_exit(int error_code, int term_signal) {
    assert(!is_internal(get_cur_thread()));

    /* If process_exit is invoked multiple times, only a single invocation proceeds past this
     * point. */
    if (!FIRST_TIME()) {
        /* Just exit current thread. */
        thread_exit(error_code, term_signal);
    }

    (void)kill_other_threads();

    /* Now quit our thread. Since we are the last one, this will exit the whole LibOS. */
    thread_exit(error_code, term_signal);
}

long libos_syscall_exit_group(int error_code) {
    assert(!is_internal(get_cur_thread()));

    error_code &= 0xFF;

    log_debug("---- exit_group (returning %d)", error_code);

    process_exit(error_code, 0);
}

long libos_syscall_exit(int error_code) {
    assert(!is_internal(get_cur_thread()));

    error_code &= 0xFF;

    log_debug("---- exit (returning %d)", error_code);

    thread_exit(error_code, 0);
}
