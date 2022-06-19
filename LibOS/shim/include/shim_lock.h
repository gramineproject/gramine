/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#ifndef SHIM_LOCK_H_
#define SHIM_LOCK_H_

#include <stdbool.h>

#include "assert.h"
#include "pal.h"
#include "shim_thread.h"
#include "shim_types.h"

static inline bool lock_created(struct shim_lock* l) {
    return l->lock != NULL;
}

static inline void clear_lock(struct shim_lock* l) {
    l->lock  = NULL;
    l->owner = 0;
}

static inline bool create_lock(struct shim_lock* l) {
    l->owner = 0;
    return DkEventCreate(&l->lock, /*init_signaled=*/true, /*auto_clear=*/true) == 0;
}

static inline void destroy_lock(struct shim_lock* l) {
    DkObjectClose(l->lock); // TODO: handle errors
    clear_lock(l);
}

static inline void lock(struct shim_lock* l) {
    assert(l->lock);

    while (DkEventWait(l->lock, /*timeout=*/NULL) < 0)
        /* nop */;

    l->owner = get_cur_tid();
}

static inline void unlock(struct shim_lock* l) {
    assert(l->lock);
    l->owner = 0;
    DkEventSet(l->lock);
}

static inline bool locked(struct shim_lock* l) {
    if (!l->lock) {
        return false;
    }
    return get_cur_tid() == l->owner;
}

#endif // SHIM_LOCK_H_
