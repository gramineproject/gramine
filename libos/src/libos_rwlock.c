/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "libos_rwlock.h"
#include "pal.h"

bool rwlock_create(struct libos_rwlock* l) {
    l->state = 0;
    l->departing_readers = 0;
    if (PalEventCreate(&l->readers_wait, /*init_signaled=*/false, /*auto_clear=*/false) < 0) {
        return false;
    }
    if (PalEventCreate(&l->writer_wait, /*init_signaled=*/false, /*auto_clear=*/true) < 0) {
        PalObjectDestroy(l->readers_wait);
        return false;
    }
    l->waiting_readers = 0;
    if (!create_lock(&l->writers_lock)) {
        PalObjectDestroy(l->readers_wait);
        PalObjectDestroy(l->writer_wait);
        return false;
    }
    return true;
}

void rwlock_destroy(struct libos_rwlock* l) {
    assert(__atomic_load_n(&l->state, __ATOMIC_ACQUIRE) == 0);
    assert(l->departing_readers == 0);
    assert(l->waiting_readers == 0);

    PalObjectDestroy(l->readers_wait);
    PalObjectDestroy(l->writer_wait);
    destroy_lock(&l->writers_lock);
}

void rwlock_read_lock_slow_path(struct libos_rwlock* l) {
    while (PalEventWait(l->readers_wait, /*timeout=*/NULL) < 0)
        /* nop */;
    size_t waiting_readers = __atomic_sub_fetch(&l->waiting_readers, 1, __ATOMIC_RELAXED);
    if (waiting_readers == 0) {
        PalEventSet(l->writer_wait);
    }
    /* This prevents code hoisting. */
    (void)__atomic_load_n(&l->state, __ATOMIC_ACQUIRE);
}

void rwlock_read_unlock_slow_path(struct libos_rwlock* l) {
    int64_t departing = __atomic_sub_fetch(&l->departing_readers, 1, __ATOMIC_RELAXED);
    if (departing == 0) {
        /* Last reader, wake up writer. */
        PalEventSet(l->writer_wait);
    }
}

void rwlock_write_lock(struct libos_rwlock* l) {
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

void rwlock_write_unlock(struct libos_rwlock* l) {
    int64_t state = __atomic_add_fetch(&l->state, WRITER_WEIGHT, __ATOMIC_RELEASE);
    assert(state >= 0);

    if (state) {
        __atomic_store_n(&l->waiting_readers, state, __ATOMIC_RELAXED);

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
