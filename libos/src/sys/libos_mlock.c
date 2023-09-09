/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Integritee AG
 *                    Frieder Paape <frieder@integritee.network>
 */

/*
 * Implements mlock, mlock2, munlock, mlockall, munlockall (lock and unlock memory). These syscalls
 * are stubbed to always return success -- Gramine cannot guarantee that the host OS will perform
 * lock/unlock anyway, and a malicious OS can still swap pages anyway.
 *
 * This (dummy) functionality is required by .NET workloads.
 */

#include "api.h"
#include "libos_table.h"
#include "linux_abi/errors.h"
#include "linux_abi/memory.h"

long libos_syscall_mlock(unsigned long start, size_t len) {
    if (!access_ok((void*)start, len)) {
        return -EINVAL;
    }
    return 0;
}

long libos_syscall_munlock(unsigned long start, size_t len) {
    if (!access_ok((void*)start, len)) {
        return -EINVAL;
    }
    return 0;
}

long libos_syscall_mlockall(int flags) {
    int unknown = flags & ~(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT);
    if (unknown != 0) {
        log_warning("Syscall mlockall was called with unknown flag(s): %#x\n", unknown);
        return -EINVAL;
    }

    return 0;
}

long libos_syscall_munlockall(void) {
    return 0;
}

long libos_syscall_mlock2(unsigned long start, size_t len, int flags) {
    int unknown = flags & ~MLOCK_ONFAULT;
    if (unknown != 0) {
        log_warning("Syscall mlock2 was called with unknown flag(s): %#x\n", unknown);
        return -EINVAL;
    }

    if (!access_ok((void*)start, len)) {
        return -EINVAL;
    }

    return 0;
}
