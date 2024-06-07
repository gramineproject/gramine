/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to create, exit and yield a thread.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

/* _PalThreadCreate for internal use. Create an internal thread inside the current process. The
 *  arguments callback and param specify the starting function and parameters. */
int _PalThreadCreate(PAL_HANDLE* handle, int (*callback)(void*), void* param) {
    return PAL_ERROR_NOTIMPLEMENTED;
}

/* PAL call PalThreadYieldExecution. Yield the execution
   of the current thread. */
void _PalThreadYieldExecution(void) {
    /* needs to be implemented */
}

/* _PalThreadExit for internal use: Thread exiting */
noreturn void _PalThreadExit(int* clear_child_tid) {
    /* needs to be implemented */
    die_or_inf_loop();
}

int _PalThreadResume(PAL_HANDLE thread_handle) {
    return PAL_ERROR_NOTIMPLEMENTED;
}

int _PalThreadSetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    return PAL_ERROR_NOTIMPLEMENTED;
}

int _PalThreadGetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    return PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops g_thread_ops = {
    /* nothing */
};
