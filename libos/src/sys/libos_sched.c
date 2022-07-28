/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "sched_yield", "setpriority", "getpriority", "sched_setparam",
 * "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max",
 * "sched_get_priority_min", "sched_rr_get_interval", "sched_setaffinity", "sched_getaffinity",
 * "getcpu".
 */

#include <errno.h>
#include <linux/resource.h>
#include <linux/sched.h>

#include "api.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "pal.h"

long libos_syscall_sched_yield(void) {
    PalThreadYieldExecution();
    return 0;
}

/* dummy implementation: ignore user-supplied niceval and return success */
long libos_syscall_setpriority(int which, int who, int niceval) {
    __UNUSED(who);

    if (which != PRIO_PROCESS && which != PRIO_PGRP && which != PRIO_USER)
        return -EINVAL;

    if (niceval < 1 || niceval > 40)
        return -EACCES;

    return 0;
}

/* dummy implementation: always return the default nice value of 20 */
long libos_syscall_getpriority(int which, int who) {
    __UNUSED(who);

    if (which != PRIO_PROCESS && which != PRIO_PGRP && which != PRIO_USER)
        return -EINVAL;

    return 20; /* default nice value on Linux */
}

/* dummy implementation: ignore user-supplied param and return success */
long libos_syscall_sched_setparam(pid_t pid, struct __kernel_sched_param* param) {
    if (pid < 0 || param == NULL)
        return -EINVAL;

    return 0;
}

/* dummy implementation: always return sched_priority of 0 (implies non-real-time sched policy) */
long libos_syscall_sched_getparam(pid_t pid, struct __kernel_sched_param* param) {
    if (pid < 0 || param == NULL)
        return -EINVAL;

    param->__sched_priority = 0;
    return 0;
}

/* dummy implementation: ignore user-supplied policy & param and return success */
long libos_syscall_sched_setscheduler(pid_t pid, int policy, struct __kernel_sched_param* param) {
    policy &= ~SCHED_RESET_ON_FORK; /* ignore reset-on-fork flag */

    if (pid < 0 || param == NULL)
        return -EINVAL;

    /* fail on unrecognized policies */
    if (policy != SCHED_NORMAL && policy != SCHED_BATCH &&
            policy != SCHED_IDLE && /* non-real-time */
            policy != SCHED_FIFO && policy != SCHED_RR /* real-time */)
        return -EINVAL;

    /* non-real-time policies must have priority of 0 */
    if ((policy == SCHED_NORMAL || policy == SCHED_BATCH || policy == SCHED_IDLE) &&
            (param->__sched_priority != 0))
        return -EINVAL;

    /* real-time policies must have priority in range [1, 99] */
    if ((policy == SCHED_FIFO || policy == SCHED_RR) &&
            (param->__sched_priority < 1 || param->__sched_priority > 99))
        return -EINVAL;

    return 0;
}

/* dummy implementation: always return SCHED_NORMAL (default round-robin time-sharing policy) */
long libos_syscall_sched_getscheduler(pid_t pid) {
    if (pid < 0)
        return -EINVAL;

    return SCHED_NORMAL;
}

long libos_syscall_sched_get_priority_max(int policy) {
    /* fail on unrecognized policies */
    if (policy != SCHED_NORMAL && policy != SCHED_BATCH &&
            policy != SCHED_IDLE && /* non-real-time */
            policy != SCHED_FIFO && policy != SCHED_RR /* real-time */)
        return -EINVAL;

    /* real-time policies have max priority of 99 */
    if (policy == SCHED_FIFO || policy == SCHED_RR)
        return 99;

    /* non-real-time policies have max priority of 0 */
    return 0;
}

long libos_syscall_sched_get_priority_min(int policy) {
    /* fail on unrecognized policies */
    if (policy != SCHED_NORMAL && policy != SCHED_BATCH &&
            policy != SCHED_IDLE && /* non-real-time */
            policy != SCHED_FIFO && policy != SCHED_RR /* real-time */)
        return -EINVAL;

    /* real-time policies have min priority of 1 */
    if (policy == SCHED_FIFO || policy == SCHED_RR)
        return 1;

    /* non-real-time policies have min priority of 0 */
    return 0;
}

/* dummy implementation: always return 100 ms (default in Linux) */
long libos_syscall_sched_rr_get_interval(pid_t pid, struct timespec* interval) {
    if (pid < 0)
        return -EINVAL;

    if (!is_user_memory_writable(interval, sizeof(*interval)))
        return -EFAULT;

    interval->tv_sec  = 0;
    interval->tv_nsec = 100000000; /* default value of 100 ms in Linux */
    return 0;
}

long libos_syscall_sched_setaffinity(pid_t pid, unsigned int user_mask_size,
                                     unsigned long* user_mask_ptr) {
    if (!is_user_memory_readable(user_mask_ptr, user_mask_size)) {
        return -EFAULT;
    }

    struct libos_thread* thread;
    if (pid) {
        thread = lookup_thread(pid);
        if (!thread) {
            return -ESRCH;
        }
    } else {
        thread = get_cur_thread();
        get_thread(thread);
    }

    int ret;
    unsigned long* cpu_mask = calloc(GET_CPU_MASK_LEN(), sizeof(*cpu_mask));
    if (!cpu_mask) {
        ret = -ENOMEM;
        goto out;
    }

    memcpy(cpu_mask, user_mask_ptr, MIN(user_mask_size, GET_CPU_MASK_LEN() * sizeof(*cpu_mask)));

    bool seen_online = false;
    size_t threads_count = g_pal_public_state->topo_info.threads_cnt;
    /* Remove offline cores from mask. */
    for (size_t i = 0; i < GET_CPU_MASK_LEN(); i++) {
        for (size_t j = 0; j < BITS_IN_TYPE(__typeof__(*cpu_mask)); j++) {
            size_t thread_idx = i * BITS_IN_TYPE(__typeof__(*cpu_mask)) + j;
            if (thread_idx >= threads_count
                    || !g_pal_public_state->topo_info.threads[thread_idx].is_online) {
                cpu_mask[i] &= ~(1ul << j);
            }
            if (cpu_mask[i] & (1ul << j)) {
                seen_online = true;
            }
        }
    }

    if (!seen_online) {
        ret = -EINVAL;
        goto out;
    }

    lock(&thread->lock);
    ret = PalThreadSetCpuAffinity(thread->pal_handle, cpu_mask, GET_CPU_MASK_LEN());
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out_unlock;
    }

    memcpy(thread->cpu_affinity_mask, cpu_mask, GET_CPU_MASK_LEN() * sizeof(*cpu_mask));
    ret = 0;

out_unlock:
    unlock(&thread->lock);
out:
    free(cpu_mask);
    put_thread(thread);
    return ret;
}

long libos_syscall_sched_getaffinity(pid_t pid, unsigned int user_mask_size,
                                     unsigned long* user_mask_ptr) {
    if (!is_user_memory_writable(user_mask_ptr, user_mask_size)) {
        return -EFAULT;
    }

    if (user_mask_size % sizeof(unsigned long)) {
        return -EINVAL;
    }

    if (user_mask_size < GET_CPU_MASK_LEN() * sizeof(unsigned long)) {
        return -EINVAL;
    }

    struct libos_thread* thread;
    if (pid) {
        thread = lookup_thread(pid);
        if (!thread) {
            return -ESRCH;
        }
    } else {
        thread = get_cur_thread();
        get_thread(thread);
    }

    lock(&thread->lock);
    memcpy(user_mask_ptr, thread->cpu_affinity_mask, GET_CPU_MASK_LEN() * sizeof(unsigned long));
    unlock(&thread->lock);

    put_thread(thread);
    return GET_CPU_MASK_LEN() * sizeof(unsigned long);
}

/* dummy implementation: always return cpu0  */
long libos_syscall_getcpu(unsigned* cpu, unsigned* node, struct getcpu_cache* unused) {
    __UNUSED(unused);

    if (cpu) {
        if (!is_user_memory_writable(cpu, sizeof(*cpu))) {
            return -EFAULT;
        }
        *cpu = 0;
    }

    if (node) {
        if (!is_user_memory_writable(node, sizeof(*node))) {
            return -EFAULT;
        }
        *node = 0;
    }

    return 0;
}
