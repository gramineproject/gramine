/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Readers-writer lock implementation.
 * Inspired by https://eli.thegreenplace.net/2019/implementing-reader-writer-locks/.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "cpu.h"
#include "libos_lock.h"

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
    size_t waiting_readers;
    /* Mutex to prevent multiple writers. */
    struct libos_lock writers_lock;
};

/* This number must be greater than the maximal number of readers or writer starvation might
 * happen. */
#define WRITER_WEIGHT (1ul << 60)

bool create_rwlock(struct libos_rwlock* l);
void destroy_rwlock(struct libos_rwlock* l);

void rwlock_read_lock_cold(struct libos_rwlock* l);
void rwlock_read_unlock_cold(struct libos_rwlock* l);

static inline void rwlock_read_lock(struct libos_rwlock* l) {
    int64_t state = __atomic_fetch_add(&l->state, 1, __ATOMIC_ACQUIRE);
    if (state < 0) {
        rwlock_read_lock_cold(l);
    }
}

static inline void rwlock_read_unlock(struct libos_rwlock* l) {
    RMB();
    int64_t state = __atomic_sub_fetch(&l->state, 1, __ATOMIC_RELAXED);
    if (state < 0) {
        rwlock_read_unlock_cold(l);
    }
}

void rwlock_write_lock(struct libos_rwlock* l);
void rwlock_write_unlock(struct libos_rwlock* l);
