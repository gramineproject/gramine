/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Readers-writer lock implementation.
 * Inspired by https://eli.thegreenplace.net/2019/implementing-reader-writer-locks/.
 *
 * High level description:
 * The most important part is the `state` variable, which tracks the number of active readers. It
 * also indicates whether a writer is active (waiting for the lock or already has it). Each reader
 * increments this variable on lock and decrements on unlock. A writer decrements it by a large
 * value (bigger than the maximal number of readers) on write lock, which also hints any incoming
 * readers that a writer is pending (so they must wait for the writer to finish).
 * Rest of the variables is used to signal waiting readers when the writer is finished and
 * the waiting writer when all the readers have released the lock.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "libos_lock.h"

struct libos_rwlock {
    /*
     * State of the lock:
     * = 0 - unlocked
     * < 0 - write locked or writer waiting for the lock
     * > 0 - read locked
     *
     * All accesses are acquire/release atomics, which also synchronize readers with writers.
     */
    int64_t state;
    /* Number of readers having the lock after writer tried to acquire it. */
    int64_t departing_readers;
    /* Semaphore for writer to wait on. */
    PAL_HANDLE writer_wait;
    /* Semaphore for readers to wait on. */
    PAL_HANDLE readers_wait;
    /* Number of readers waiting on `readers_wait` after writer releases the lock. */
    size_t waiting_readers;
    /* Mutex to prevent multiple writers. */
    struct libos_lock writers_lock;
};

/* This number must be greater than the maximal number of readers or writer starvation might
 * happen. */
#define WRITER_WEIGHT (1ul << 60)

bool rwlock_create(struct libos_rwlock* l);
void rwlock_destroy(struct libos_rwlock* l);

void rwlock_read_lock_slow_path(struct libos_rwlock* l);
void rwlock_read_unlock_slow_path(struct libos_rwlock* l);

static inline void rwlock_read_lock(struct libos_rwlock* l) {
    int64_t state = __atomic_fetch_add(&l->state, 1, __ATOMIC_ACQUIRE);
    if (state < 0) {
        rwlock_read_lock_slow_path(l);
    }
}

static inline void rwlock_read_unlock(struct libos_rwlock* l) {
    int64_t state = __atomic_sub_fetch(&l->state, 1, __ATOMIC_RELEASE);
    if (state < 0) {
        rwlock_read_unlock_slow_path(l);
    }
}

void rwlock_write_lock(struct libos_rwlock* l);
void rwlock_write_unlock(struct libos_rwlock* l);

#ifdef DEBUG
/*
 * These two functions are not complete and might return false positives, but there are no false
 * negatives. Creating a fully complete check (working in all cases) is very hard or even impossible
 * with the current implementation, so this should be good enough.
 */
static inline bool rwlock_is_read_locked(struct libos_rwlock* l) {
    return __atomic_load_n(&l->state, __ATOMIC_RELAXED) != 0;
}

static inline bool rwlock_is_write_locked(struct libos_rwlock* l) {
    return locked(&l->writers_lock) && __atomic_load_n(&l->state, __ATOMIC_RELAXED) < 0;
}
#endif // DEBUG
