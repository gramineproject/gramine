/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */
#pragma once

#include "pal.h"
#include "spinlock.h"

/*
 * These events have binary semaphore semantics:
 * - `set_pollable_event(e)` sets the semaphore to 1 (regardless of its current state),
 * - `clear_pollable_event(e)` sets the semaphore to 0 (regardless of its current state).
 * Additionally `e->read_handle` can be passed to `PalStreamsWaitEvents` (which is actually the only
 * purpose these events exist for).
 */

struct libos_pollable_event {
    PAL_HANDLE read_handle;
    PAL_HANDLE write_handle;
    spinlock_t read_lock;
    spinlock_t write_lock;
};

int create_pollable_event(struct libos_pollable_event* event);
void destroy_pollable_event(struct libos_pollable_event* event);
int set_pollable_event(struct libos_pollable_event* event);
int clear_pollable_event(struct libos_pollable_event* event);
