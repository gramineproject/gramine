/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Labs */

/*
 * Operations to handle the console device. In this PAL, the console is emulated via host process's
 * stdin and stdout streams. Note that the host process's stderr stream is used purely for Gramine's
 * internal messages (like logs), and the stderr stream of the application running inside Gramine is
 * multiplexed onto the host's stdout stream.
 *
 * Note that some operations (like stat and truncate) are resolved in LibOS and don't have a
 * counterpart in PAL.
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
    assert(handle->hdr.type == PAL_TYPE_CONSOLE);

    if (offset)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_READABLE))
        return -PAL_ERROR_DENIED;

    int64_t bytes = DO_SYSCALL(read, handle->console.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int64_t console_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    assert(handle->hdr.type == PAL_TYPE_CONSOLE);

    if (offset)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE))
        return -PAL_ERROR_DENIED;

    int64_t bytes = DO_SYSCALL(write, handle->console.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static void console_destroy(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_CONSOLE);

    /* do not close host stdin/stdout, to allow Gramine itself to use them (e.g. for logs) */

    free(handle);
}

static int console_flush(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_CONSOLE);

    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE))
        return -PAL_ERROR_DENIED;

    int ret = DO_SYSCALL(fsync, handle->console.fd);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

struct handle_ops g_console_ops = {
    .open           = &console_open,
    .read           = &console_read,
    .write          = &console_write,
    .destroy        = &console_destroy,
    .flush          = &console_flush,
};
