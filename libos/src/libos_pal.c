/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 IBM Corporation */

#include "libos_checkpoint.h"
#include "libos_internal.h"
#include "pal.h"

pal_callback_t get_pct(void) {
    struct libos_thread* thread = get_cur_thread();
    if (!thread || is_internal(thread))
        return NULL;
    if ((thread->state & (THR_STATE_IN_SYSCALL | THR_STATE_MIGRATING)) == THR_STATE_IN_SYSCALL)
        return libos_pal_callback;
    return NULL;
}

void libos_pal_callback(enum pal_callback_type pct) {
    switch(pct) {
    case PAL_CALLBACK_BEFORE_SYSCALL:
        CHECKPOINT_RUNLOCK;
        break;
    case PAL_CALLBACK_AFTER_SYSCALL:
        CHECKPOINT_RLOCK;
        break;
    }
}
