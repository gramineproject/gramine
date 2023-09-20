/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Labs */

/*
 * Operations to handle the console (stdin/stdout/stderr). Note that some operations (like stat and
 * truncate) are resolved in LibOS and don't have a counterpart in PAL.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "perm.h"

static int console_open(PAL_HANDLE* handle, const char* type, const char* uri,
                        enum pal_access access, pal_share_flags_t share,
                        enum pal_create_mode create, pal_stream_options_t options) {
    __UNUSED(uri);
    __UNUSED(share);
    __UNUSED(create);
    __UNUSED(options);

    if (strcmp(type, URI_TYPE_CONSOLE))
        return -PAL_ERROR_INVAL;

    if (access != PAL_ACCESS_RDONLY && access != PAL_ACCESS_WRONLY)
        return -PAL_ERROR_INVAL;

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(console));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    hdl->hdr.type = PAL_TYPE_CONSOLE;
    hdl->flags = access == PAL_ACCESS_RDONLY ? PAL_HANDLE_FD_READABLE : PAL_HANDLE_FD_WRITABLE;
    hdl->console.fd = access == PAL_ACCESS_RDONLY ? /*host stdin*/0 : /*host stdout*/1;

    *handle = hdl;
    return 0;
}

static int64_t console_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_READABLE) || handle->console.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int64_t bytes = ocall_read(handle->console.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int64_t console_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE) || handle->console.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int64_t bytes = ocall_write(handle->console.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int console_close(PAL_HANDLE handle) {
    /* do not close host stdin/stdout, to allow Gramine itself to use them (e.g. for logs) */
    handle->console.fd = PAL_IDX_POISON;
    return 0;
}

static int console_flush(PAL_HANDLE handle) {
    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE) || handle->console.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int ret = ocall_fsync(handle->console.fd);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

struct handle_ops g_console_ops = {
    .open           = &console_open,
    .read           = &console_read,
    .write          = &console_write,
    .close          = &console_close,
    .flush          = &console_flush,
};
