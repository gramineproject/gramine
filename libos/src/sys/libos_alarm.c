/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "alarm", "setitmer" and "getitimer".
 */

#include <stdint.h>

#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_signal.h"
#include "libos_table.h"
#include "libos_utils.h"
#include "spinlock.h"

static void signal_current_proc(int signo) {
    siginfo_t info = {
        .si_signo = signo,
        .si_pid = g_process.pid,
        .si_code = SI_USER,
    };
    if (kill_current_proc(&info) < 0) {
        log_warning("signal_alarm: failed to deliver a signal");
    }
}

static void signal_alarm(IDTYPE caller, void* arg) {
    __UNUSED(caller);
    __UNUSED(arg);
    signal_current_proc(SIGALRM);
}

long libos_syscall_alarm(unsigned int seconds) {
    uint64_t usecs = 1000000ULL * seconds;

    int64_t ret = install_async_event(NULL, usecs, &signal_alarm, NULL);
    if (ret < 0)
        return ret;

    uint64_t usecs_left = (uint64_t)ret;
    int secs = usecs_left / 1000000ULL;
    if (usecs_left % 1000000ULL)
        secs++;
    return secs;
}

static struct {
    unsigned long timeout;
    unsigned long reset;
} g_real_itimer;

static spinlock_t g_real_itimer_lock = INIT_SPINLOCK_UNLOCKED;

static void signal_itimer(IDTYPE caller, void* arg) {
    // XXX: Can we simplify this code or streamline with the other callback?
    __UNUSED(caller);
    __UNUSED(arg);

    spinlock_lock(&g_real_itimer_lock);

    g_real_itimer.timeout += g_real_itimer.reset;
    uint64_t next_reset = g_real_itimer.reset;

    spinlock_unlock(&g_real_itimer_lock);

    if (next_reset) {
        int64_t ret = install_async_event(/*object=*/NULL, next_reset, &signal_itimer,
                                          /*arg=*/NULL);
        if (ret < 0) {
            log_error(
                "failed to re-enqueue the next timer event initially set up by 'setitimer()': %s",
                unix_strerror(ret));
            die_or_inf_loop();
        }
    }

    signal_current_proc(SIGALRM);
}

#ifndef ITIMER_REAL
#define ITIMER_REAL 0
#endif

long libos_syscall_setitimer(int which, struct __kernel_itimerval* value,
                             struct __kernel_itimerval* ovalue) {
    if (which != ITIMER_REAL)
        return -ENOSYS;

    /* Technically, as of v6.5.2, Linux supports value==NULL with a special meaning (setting timer
     * to 0), but it throws a warning that it will be removed in the future versions, so we probably
     * don't have to implement it. */
    if (!is_user_memory_readable(value, sizeof(*value)))
        return -EFAULT;
    if (ovalue && !is_user_memory_writable(ovalue, sizeof(*ovalue)))
        return -EFAULT;

    uint64_t setup_time = 0;
    int ret = PalSystemTimeQuery(&setup_time);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    uint64_t next_value = value->it_value.tv_sec * (uint64_t)1000000 + value->it_value.tv_usec;
    uint64_t next_reset = value->it_interval.tv_sec * (uint64_t)1000000
                          + value->it_interval.tv_usec;

    spinlock_lock(&g_real_itimer_lock);

    uint64_t current_timeout = g_real_itimer.timeout > setup_time
                               ? g_real_itimer.timeout - setup_time
                               : 0;
    uint64_t current_reset = g_real_itimer.reset;

    int64_t install_ret = install_async_event(NULL, next_value, &signal_itimer, /*arg=*/NULL);

    if (install_ret < 0) {
        spinlock_unlock(&g_real_itimer_lock);
        return install_ret;
    }

    g_real_itimer.timeout = setup_time + next_value;
    g_real_itimer.reset   = next_reset;

    spinlock_unlock(&g_real_itimer_lock);

    if (ovalue) {
        ovalue->it_interval.tv_sec  = current_reset / 1000000;
        ovalue->it_interval.tv_usec = current_reset % 1000000;
        ovalue->it_value.tv_sec     = current_timeout / 1000000;
        ovalue->it_value.tv_usec    = current_timeout % 1000000;
    }

    return 0;
}

long libos_syscall_getitimer(int which, struct __kernel_itimerval* value) {
    if (which != ITIMER_REAL)
        return -ENOSYS;

    if (!is_user_memory_writable(value, sizeof(*value)))
        return -EFAULT;

    uint64_t setup_time = 0;
    int ret = PalSystemTimeQuery(&setup_time);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    spinlock_lock(&g_real_itimer_lock);
    uint64_t current_timeout = g_real_itimer.timeout > setup_time
                               ? g_real_itimer.timeout - setup_time
                               : 0;
    uint64_t current_reset = g_real_itimer.reset;
    spinlock_unlock(&g_real_itimer_lock);

    value->it_interval.tv_sec  = current_reset / 1000000;
    value->it_interval.tv_usec = current_reset % 1000000;
    value->it_value.tv_sec     = current_timeout / 1000000;
    value->it_value.tv_usec    = current_timeout % 1000000;
    return 0;
}
