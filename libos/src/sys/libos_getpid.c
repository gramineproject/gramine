/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2023 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 *                    Kailun Qin <kailun.qin@intel.com>
 */

#include "libos_lock.h"
#include "libos_process.h"
#include "libos_rwlock.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "libos_types.h"

long libos_syscall_getpid(void) {
    return g_process.pid;
}

long libos_syscall_gettid(void) {
    /* `tid` is constant, no need to take a lock. */
    return get_cur_thread()->tid;
}

long libos_syscall_getppid(void) {
    return g_process.ppid;
}

long libos_syscall_set_tid_address(int* tidptr) {
    struct libos_thread* cur = get_cur_thread();
    lock(&cur->lock);
    cur->clear_child_tid = tidptr; // will be lazy-verified (before writing to it)
    unlock(&cur->lock);
    return cur->tid;
}

long libos_syscall_setpgid(pid_t pid, pid_t pgid) {
    if (pgid < 0) {
        return -EINVAL;
    }

    if (!pid || g_process.pid == (IDTYPE)pid) {
        /* TODO: Currently we do not support checking that:
         * - the target process group to be joined (specified by `pgid`) must exist;
         * - the process group of the joining process (specified by `pid`) and the target process
         *   group to be joined must have the same session ID. */

        rwlock_write_lock(&g_process_id_lock);
        g_process.pgid = (IDTYPE)pgid ?: g_process.pid;
        rwlock_write_unlock(&g_process_id_lock);

        /* TODO: inform parent about pgid change. */
        return 0;
    }

    /* TODO: Currently we do not support setting pgid of children processes. */
    return -ESRCH;
}

long libos_syscall_getpgid(pid_t pid) {
    if (!pid || g_process.pid == (IDTYPE)pid) {
        rwlock_read_lock(&g_process_id_lock);
        long ret = g_process.pgid;
        rwlock_read_unlock(&g_process_id_lock);

        return ret;
    }

    /* TODO: Currently we do not support getting pgid of other processes.
     * Implement child lookup once `libos_syscall_setpgid` sends info to the parent. */
    return -ESRCH;
}

long libos_syscall_getpgrp(void) {
    return libos_syscall_getpgid(0);
}

long libos_syscall_setsid(void) {
    rwlock_write_lock(&g_process_id_lock);

    IDTYPE current_pid = g_process.pid;
    IDTYPE current_pgid = g_process.pgid;

    /* Fail if the calling process is already a process group leader. */
    if (current_pid == current_pgid) {
        rwlock_write_unlock(&g_process_id_lock);
        return -EPERM;
    }

    /* TODO: Currently we do not fail if a process group ID already exists that equals the session
     * ID to be set (which is made the same as the process ID of the calling process). */

    /* The calling process is the leader of the new session and the process group leader of the new
     * process group. */
    g_process.sid = current_pid;
    g_process.pgid = current_pid;

    rwlock_write_unlock(&g_process_id_lock);

    return current_pid;
}

long libos_syscall_getsid(pid_t pid) {
    if (!pid || g_process.pid == (IDTYPE)pid) {
        rwlock_read_lock(&g_process_id_lock);
        long ret = g_process.sid;
        rwlock_read_unlock(&g_process_id_lock);

        return ret;
    }

    /* TODO: Currently we do not support getting sid of other processes. */
    return -ESRCH;
}
