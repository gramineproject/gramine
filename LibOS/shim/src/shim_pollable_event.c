/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "api.h"
#include "log.h"
#include "pal.h"
#include "shim_internal.h"
#include "shim_pollable_event.h"
#include "shim_utils.h"

int create_pollable_event(struct shim_pollable_event* event) {
    char uri[PIPE_URI_SIZE];
    PAL_HANDLE srv_handle;
    int ret = create_pipe(/*name=*/NULL, uri, sizeof(uri), &srv_handle,
                          /*use_vmid_for_name=*/false);
    if (ret < 0) {
        log_error("%s: create_pipe failed: %d", __func__, ret);
        return ret;
    }

    PAL_HANDLE write_handle;
    ret = DkStreamOpen(uri, PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED,
                       PAL_OPTION_CLOEXEC, &write_handle);
    if (ret < 0) {
        log_error("%s: DkStreamOpen failed: %d", __func__, ret);
        goto out;
    }

    PAL_HANDLE read_handle;
    ret = DkStreamWaitForClient(srv_handle, &read_handle, PAL_OPTION_NONBLOCK);
    if (ret < 0) {
        log_error("%s: DkStreamWaitForClient failed: %d", __func__, ret);
        DkObjectClose(write_handle);
        goto out;
    }

    event->read_handle = read_handle;
    event->write_handle = write_handle;
    ret = 0;

out:;
    int tmp_ret = DkStreamDelete(srv_handle, PAL_DELETE_ALL);
    DkObjectClose(srv_handle);
    if (!ret && tmp_ret) {
        DkObjectClose(read_handle);
        DkObjectClose(write_handle);
        /* Clearing just for sanity. */
        event->read_handle = NULL;
        event->write_handle = NULL;
    }
    return ret ?: tmp_ret;
}

void destroy_pollable_event(struct shim_pollable_event* event) {
    DkObjectClose(event->read_handle);
    DkObjectClose(event->write_handle);
}

int set_pollable_event(struct shim_pollable_event* event, size_t n) {
    char buf[0x20] = { 0 };
    while (n > 0) {
        size_t size = MIN(sizeof(buf), n);
        int ret = DkStreamWrite(event->write_handle, /*offset=*/0, &size, buf, /*dest=*/NULL);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED) {
                continue;
            }
            return pal_to_unix_errno(ret);
        }
        if (size == 0) {
            return -EINVAL;
        }
        n -= size;
    }
    return 0;
}

int wait_pollable_event(struct shim_pollable_event* event) {
    int ret = 0;
    do {
        char c;
        size_t size = sizeof(c);
        ret = DkStreamRead(event->read_handle, /*offset=*/0, &size, &c, NULL, 0);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
        } else if (size == 0) {
            ret = -EINVAL;
        }
    } while (ret == -EINTR || ret == -EAGAIN);
    return ret;
}

int clear_pollable_event(struct shim_pollable_event* event) {
    while (1) {
        char buf[0x100];
        size_t size = sizeof(buf);
        int ret = DkStreamRead(event->read_handle, /*offset=*/0, &size, buf, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED) {
                continue;
            } else if (ret == -PAL_ERROR_TRYAGAIN) {
                /* Event not set. */
                break;
            }
            return pal_to_unix_errno(ret);
        }
        if (size == 0) {
            return -EINVAL;
        }
    }
    return 0;
}
