/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for closing or polling PAL handles.
 */

#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

void _PalObjectDestroy(PAL_HANDLE handle) {
    const struct handle_ops* ops = HANDLE_OPS(handle);
    assert(ops);

    /* close all associated resources on the host... */
    if (ops->close)
        ops->close(handle);

    /* ...and deallocate the handle */
    free(handle);
}

void PalObjectDestroy(PAL_HANDLE handle) {
    assert(handle);
    _PalObjectDestroy(handle);
}

int PalStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, pal_wait_flags_t* events,
                         pal_wait_flags_t* ret_events, uint64_t* timeout_us) {
    for (size_t i = 0; i < count; i++) {
        assert(!handle_array[i] || handle_array[i]->hdr.type < PAL_HANDLE_TYPE_BOUND);
    }

    return _PalStreamsWaitEvents(count, handle_array, events, ret_events, timeout_us);
}
