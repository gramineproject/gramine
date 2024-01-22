/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019 Intel Corporation */

/*
 * This file contains code for passthrough-to-host implementation of 'eventfd' filesystem.
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

    int ret = PalStreamRead(hdl->pal_handle, /*offset=*/0, &count, buf);
    if (!ret && count != sizeof(uint64_t)) {
        /* successful read must return 8 bytes, otherwise it's an attack or host malfunction */
        return -EPERM;
    }
    ret = pal_to_unix_errno(ret);
    /* eventfd objects never perform partial reads, see also check above */
    maybe_epoll_et_trigger(hdl, ret, /*in=*/true, /*unused was_partial=*/false);
    return ret < 0 ? ret : (ssize_t)count;
}

static ssize_t eventfd_write(struct libos_handle* hdl, const void* buf, size_t count,
                             file_off_t* pos) {
    __UNUSED(pos);

    if (count < sizeof(uint64_t))
        return -EINVAL;

    int ret = PalStreamWrite(hdl->pal_handle, /*offset=*/0, &count, (void*)buf);
    if (!ret && count != sizeof(uint64_t)) {
        /* successful write must return 8 bytes, otherwise it's an attack or host malfunction */
        return -EPERM;
    }
    ret = pal_to_unix_errno(ret);
    /* eventfd objects never perform partial writes, see also check above */
    maybe_epoll_et_trigger(hdl, ret, /*in=*/false, /*unused was_partial=*/false);
    return ret < 0 ? ret : (ssize_t)count;
}

struct libos_fs_ops eventfd_fs_ops = {
    .read  = &eventfd_read,
    .write = &eventfd_write,
};

struct libos_fs eventfd_builtin_fs = {
    .name   = "eventfd",
    .fs_ops = &eventfd_fs_ops,
};
