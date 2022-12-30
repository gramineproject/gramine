/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Readers-writer lock implemenation.
 * Inspired by https://eli.thegreenplace.net/2019/implementing-reader-writer-locks/.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "cpu.h"
#include "libos_lock.h"
#include "pal.h"

/* TODO: describe implementation and list what synchronizes with what. */

struct libos_rwlock {
    /*
     * = 0 - unlocked
     * < 0 - write locked or writer waiting for the lock
     * > 0 - read locked
     */
    int64_t state;
    /* Number of readers having the lock after writer tried to acquire it. */
    int64_t departing_readers;
    /* Semaphore for writer to wait on. */
    PAL_HANDLE writer_wait;
    /* Semaphore for readers to wait on. */
    PAL_HANDLE readers_wait;
    /* Number of readers waiting on `readers_wait` after writer releases the lock. */
    size_t readers_waiting;
    /* Mutex to prevent multiple writers. */
    struct libos_lock writers_lock;
};

/* This number must be greater than the maximal number of readers or writer starvation might
 * happen. */
#define WRITER_WEIGHT (1ul << 60)

static inline bool create_rwlock(struct libos_rwlock* l) {
    l->state = 0;
    l->departing_readers = 0;
    if (PalEventCreate(&l->readers_wait, /*init_signaled=*/false, /*auto_clear=*/false) < 0) {
        return false;
    }
    if (PalEventCreate(&l->writer_wait, /*init_signaled=*/false, /*auto_clear=*/true) < 0) {
        PalObjectClose(l->readers_wait);
        return false;
    }
    l->readers_waiting = 0;
    if (!create_lock(&l->writers_lock)) {
        PalObjectClose(l->readers_wait);
        PalObjectClose(l->writer_wait);
        return false;
    }
    return true;
}

static inline void destroy_rwlock(struct libos_rwlock* l) {
    assert(__atomic_load_n(&l->state, __ATOMIC_ACQUIRE) == 0);
    assert(l->departing_readers == 0);
    assert(l->readers_waiting == 0);

    PalObjectClose(l->readers_wait);
    PalObjectClose(l->writer_wait);
    destroy_lock(&l->writers_lock);
}

static inline void rwlock_read_lock(struct libos_rwlock* l) {
    int64_t state = __atomic_fetch_add(&l->state, 1, __ATOMIC_ACQUIRE);
    if (state < 0) {
        while (PalEventWait(l->readers_wait, /*timeout=*/NULL) < 0)
            /* nop */;
        size_t readers_waiting = __atomic_sub_fetch(&l->readers_waiting, 1, __ATOMIC_RELAXED);
        if (readers_waiting == 0) {
             PalEventSet(l->writer_wait);
        }
        /* This prevents code hoisting. */
        (void)__atomic_load_n(&l->state, __ATOMIC_ACQUIRE);
    }
}

static inline void rwlock_read_unlock(struct libos_rwlock* l) {
    RMB();
    int64_t state = __atomic_sub_fetch(&l->state, 1, __ATOMIC_RELAXED);
    if (state < 0) {
        int64_t departing = __atomic_sub_fetch(&l->departing_readers, 1, __ATOMIC_RELAXED);
        if (departing == 0) {
            /* Last reader, wake up writer. */
            PalEventSet(l->writer_wait);
        }
    }
}

static inline void rwlock_write_lock(struct libos_rwlock* l) {
    lock(&l->writers_lock);

    int64_t state = __atomic_fetch_sub(&l->state, WRITER_WEIGHT, __ATOMIC_ACQUIRE);
    if (state > 0) {
        int64_t departing = __atomic_add_fetch(&l->departing_readers, state, __ATOMIC_RELAXED);
        if (departing != 0) {
            assert(departing > 0);
            while (PalEventWait(l->writer_wait, /*timeout=*/NULL) < 0)
                /* nop */;
        }
        /* This prevents code hoisting. */
        (void)__atomic_load_n(&l->state, __ATOMIC_ACQUIRE);
    }
}

static inline void rwlock_write_unlock(struct libos_rwlock* l) {
    int64_t state = __atomic_add_fetch(&l->state, WRITER_WEIGHT, __ATOMIC_RELEASE);
    assert(state >= 0);

    if (state) {
        __atomic_store_n(&l->readers_waiting, state, __ATOMIC_RELAXED);

        /* Wake up readers. */
        PalEventSet(l->readers_wait);

        /* Wait for all waiting readers to actually wake up... */
        while (PalEventWait(l->writer_wait, /*timeout=*/NULL) < 0)
            /* nop */;

        /* ...and unset the event. */
        PalEventClear(l->readers_wait);
    }

    unlock(&l->writers_lock);
}
