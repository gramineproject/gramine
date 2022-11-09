/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "api.h"
#include "libos_internal.h"
#include "libos_pollable_event.h"
#include "libos_utils.h"
#include "log.h"
#include "pal.h"

int create_pollable_event(struct libos_pollable_event* event) {
    char uri[PIPE_URI_SIZE];
    PAL_HANDLE srv_handle;
    int ret = create_pipe(/*name=*/NULL, uri, sizeof(uri), &srv_handle,
                          /*use_vmid_for_name=*/false);
    if (ret < 0) {
        log_error("create_pipe failed: %s", unix_strerror(ret));
        return ret;
    }

    PAL_HANDLE write_handle;
    do {
        ret = PalStreamOpen(uri, PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED,
                            PAL_OPTION_NONBLOCK, &write_handle);
    } while (ret == -PAL_ERROR_INTERRUPTED);
    if (ret < 0) {
        log_error("PalStreamOpen failed: %s", pal_strerror(ret));
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    PAL_HANDLE read_handle;
    do {
        ret = PalStreamWaitForClient(srv_handle, &read_handle, PAL_OPTION_NONBLOCK);
    } while (ret == -PAL_ERROR_INTERRUPTED);
    if (ret < 0) {
        log_error("PalStreamWaitForClient failed: %s", pal_strerror(ret));
        PalObjectClose(write_handle);
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    event->read_handle = read_handle;
    event->write_handle = write_handle;
    spinlock_init(&event->read_lock);
    spinlock_init(&event->write_lock);
    ret = 0;

out:;
    int tmp_ret = pal_to_unix_errno(PalStreamDelete(srv_handle, PAL_DELETE_ALL));
    PalObjectClose(srv_handle);
    if (!ret && tmp_ret) {
        PalObjectClose(read_handle);
        PalObjectClose(write_handle);
        /* Clearing just for sanity. */
        event->read_handle = NULL;
        event->write_handle = NULL;
    }
    return ret ?: tmp_ret;
}

void destroy_pollable_event(struct libos_pollable_event* event) {
    PalObjectClose(event->read_handle);
    PalObjectClose(event->write_handle);
}

int set_pollable_event(struct libos_pollable_event* event) {
    int ret;

    spinlock_lock(&event->write_lock);

    do {
        char c = 0;
        size_t size = sizeof(c);
        ret = PalStreamWrite(event->write_handle, /*offset=*/0, &size, &c);
        ret = pal_to_unix_errno(ret);
        if (ret == 0 && size == 0) {
            ret = -EINVAL;
        }
        if (ret == -EAGAIN) {
            /* Pipe full - event already set. */
            ret = 0;
        }
    } while (ret == -EINTR);

    spinlock_unlock(&event->write_lock);
    return ret;
}

int clear_pollable_event(struct libos_pollable_event* event) {
    int ret = 0;

    spinlock_lock(&event->read_lock);

    do {
        char buf[0x100];
        size_t size = sizeof(buf);
        int ret = PalStreamRead(event->read_handle, /*offset=*/0, &size, buf);
        ret = pal_to_unix_errno(ret);
        if (ret == 0 && size == 0) {
            ret = -EINVAL;
        }
        if (ret == -EAGAIN) {
            /* Event not set. */
            ret = 0;
        }
    } while (ret == -EINTR);

    spinlock_unlock(&event->read_lock);
    return ret;
}
