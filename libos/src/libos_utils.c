/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "libos_internal.h"
#include "libos_utils.h"
#include "pal.h"

int read_exact(PAL_HANDLE handle, void* buf, size_t size) {
    size_t read = 0;
    while (read < size) {
        size_t tmp_read = size - read;
        int ret = PalStreamRead(handle, /*offset=*/0, &tmp_read, (char*)buf + read);
        if (ret < 0) {
            if (ret == PAL_ERROR_INTERRUPTED || ret == PAL_ERROR_TRYAGAIN) {
                continue;
            }
            return pal_to_unix_errno(ret);
        } else if (tmp_read == 0) {
            return -ENODATA;
        }
        read += tmp_read;
    }
    return 0;
}

int write_exact(PAL_HANDLE handle, void* buf, size_t size) {
    size_t written = 0;
    while (written < size) {
        size_t tmp_written = size - written;
        int ret = PalStreamWrite(handle, /*offset=*/0, &tmp_written, (char*)buf + written);
        if (ret < 0) {
            if (ret == PAL_ERROR_INTERRUPTED || ret == PAL_ERROR_TRYAGAIN) {
                continue;
            }
            return pal_to_unix_errno(ret);
        } else if (tmp_written == 0) {
            return -EPIPE;
        }
        written += tmp_written;
    }
    return 0;
}
