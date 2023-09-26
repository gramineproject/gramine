/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#pragma once

#include <stdbool.h>

#include "assert.h"
#include "libos_thread.h"
#include "libos_types.h"
#include "pal.h"

static inline bool lock_created(struct libos_lock* l) {
    return l->lock != NULL;
}

static inline void clear_lock(struct libos_lock* l) {
    l->lock  = NULL;
    l->owner = 0;
}

static inline bool create_lock(struct libos_lock* l) {
    l->owner = 0;
    return PalEventCreate(&l->lock, /*init_signaled=*/true, /*auto_clear=*/true) == 0;
}

static inline void destroy_lock(struct libos_lock* l) {
    PalObjectDestroy(l->lock);
    clear_lock(l);
}

static inline void lock(struct libos_lock* l) {
    assert(l->lock);

    while (PalEventWait(l->lock, /*timeout=*/NULL) < 0)
        /* nop */;

    l->owner = get_cur_tid();
}

static inline void unlock(struct libos_lock* l) {
    assert(l->lock);
    l->owner = 0;
    PalEventSet(l->lock);
}

#ifdef DEBUG
static inline bool locked(struct libos_lock* l) {
    if (!l->lock) {
        return false;
    }
    return get_cur_tid() == l->owner;
}
#endif // DEBUG
