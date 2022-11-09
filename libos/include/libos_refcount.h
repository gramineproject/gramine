/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#pragma once

#include "api.h"

/*
 * Reference counting API.
 *
 * `refcount_get` has acquire semantics, `refcount_set` - release.
 * `refcount_{inc,dec}` have both acquire and release semantics, which means they synchronize
 * between themselves and with `refcount_{get,set}`.
 */

typedef int64_t refcount_t;

static inline refcount_t refcount_get(refcount_t* ref) {
    return __atomic_load_n(ref, __ATOMIC_ACQUIRE);
}

static inline void refcount_set(refcount_t* ref, refcount_t count) {
    __atomic_store_n(ref, count, __ATOMIC_RELEASE);
}

static inline refcount_t refcount_inc(refcount_t* ref) {
    return __atomic_add_fetch(ref, 1, __ATOMIC_ACQ_REL);
}

static inline refcount_t _refcount_dec(refcount_t* ref, const char* fname, size_t line) {
    refcount_t new_count = __atomic_sub_fetch(ref, 1, __ATOMIC_ACQ_REL);
    if (new_count < 0) {
        log_error("Reference count dropped below 0 at %s:%zu", fname, line);
        BUG();
    }
    return new_count;
}

#define refcount_dec(ref) _refcount_dec((ref), __FILE_NAME__, __LINE__)
