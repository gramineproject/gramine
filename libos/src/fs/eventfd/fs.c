/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019 Intel Corporation */

/*
 * This file contains code for implementation of 'eventfd' filesystem.
 */

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "linux_abi/errors.h"
#include "pal.h"

static ssize_t eventfd_read(struct libos_handle* hdl, void* buf, size_t count, file_off_t* pos) {
    __UNUSED(pos);

    if (count < sizeof(uint64_t))
        return -EINVAL;

    size_t orig_count = count;
    int ret = PalStreamRead(hdl->pal_handle, 0, &count, buf);
    ret = pal_to_unix_errno(ret);
    maybe_epoll_et_trigger(hdl, ret, /*in=*/true, ret == 0 ? count < orig_count : false);
    if (ret < 0) {
        return ret;
    }

    return (ssize_t)count;
}

static ssize_t eventfd_write(struct libos_handle* hdl, const void* buf, size_t count,
                             file_off_t* pos) {
    __UNUSED(pos);

    if (count < sizeof(uint64_t))
        return -EINVAL;

    size_t orig_count = count;
    int ret = PalStreamWrite(hdl->pal_handle, 0, &count, (void*)buf);
    ret = pal_to_unix_errno(ret);
    maybe_epoll_et_trigger(hdl, ret, /*in=*/false, ret == 0 ? count < orig_count : false);
    if (ret < 0) {
        return ret;
    }

    return (ssize_t)count;
}

struct libos_fs_ops eventfd_fs_ops = {
    .read  = &eventfd_read,
    .write = &eventfd_write,
};

struct libos_fs eventfd_builtin_fs = {
    .name   = "eventfd",
    .fs_ops = &eventfd_fs_ops,
};
