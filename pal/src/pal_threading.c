/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to create, exit and yield a thread.
 */

#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

/* PAL call PalThreadCreate: create a thread inside the current process */
int PalThreadCreate(int (*callback)(void*), void* param, PAL_HANDLE* handle) {
    *handle = NULL;
    return _PalThreadCreate(handle, callback, param);
}

/* PAL call PalThreadYieldExecution. Yield the execution of the current thread. */
void PalThreadYieldExecution(void) {
    _PalThreadYieldExecution();
}

/* PAL call PalThreadExit: simply exit the current thread no matter what */
noreturn void PalThreadExit(int* clear_child_tid) {
    _PalThreadExit(clear_child_tid);
    /* UNREACHABLE */
}

/* PAL call PalThreadResume: resume the execution of a thread which is delayed before */
int PalThreadResume(PAL_HANDLE thread_handle) {
    if (!thread_handle || thread_handle->hdr.type != PAL_TYPE_THREAD) {
        return PAL_ERROR_INVAL;
    }

    return _PalThreadResume(thread_handle);
}

int PalThreadSetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    return _PalThreadSetCpuAffinity(thread, cpu_mask, cpu_mask_len);
}

int PalThreadGetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    memset(cpu_mask, 0, cpu_mask_len * sizeof(*cpu_mask));
    return _PalThreadGetCpuAffinity(thread, cpu_mask, cpu_mask_len);
}
