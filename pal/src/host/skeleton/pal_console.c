/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Labs */

/*
 * Operations to handle the console device.
 *
 * Note that some operations (like stat and truncate) are resolved in LibOS and don't have a
 * counterpart in PAL.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

static int console_open(PAL_HANDLE* handle, const char* type, const char* uri,
                        enum pal_access access, pal_share_flags_t share,
                        enum pal_create_mode create, pal_stream_options_t options) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t console_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t console_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static void console_destroy(PAL_HANDLE handle) {
    /* noop */
}

static int console_flush(PAL_HANDLE handle) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops g_console_ops = {
    .open           = &console_open,
    .read           = &console_read,
    .write          = &console_write,
    .destroy        = &console_destroy,
    .flush          = &console_flush,
};
