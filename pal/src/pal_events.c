/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "assert.h"
#include "pal.h"
#include "pal_internal.h"

int PalEventCreate(PAL_HANDLE* handle, bool init_signaled, bool auto_clear) {
    *handle = NULL;
    return _PalEventCreate(handle, init_signaled, auto_clear);
}

void PalEventSet(PAL_HANDLE handle) {
    assert(handle && handle->hdr.type == PAL_TYPE_EVENT);
    _PalEventSet(handle);
}

void PalEventClear(PAL_HANDLE handle) {
    assert(handle && handle->hdr.type == PAL_TYPE_EVENT);
    _PalEventClear(handle);
}

int PalEventWait(PAL_HANDLE handle, uint64_t* timeout_us) {
    assert(handle && handle->hdr.type == PAL_TYPE_EVENT);
    return _PalEventWait(handle, timeout_us);
}
