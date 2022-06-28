/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "libos_fs.h"

static int hstat(struct libos_handle* handle, struct stat* buf) {
    if (!handle->inode) {
        return -EINVAL;
    }
    return generic_inode_hstat(handle, buf);
}

static struct libos_fs_ops path_fs_ops = {
    .hstat = hstat,
};

static struct libos_d_ops path_d_ops = {};

struct libos_fs path_builtin_fs = {
    .name = "path",
    .fs_ops = &path_fs_ops,
    .d_ops = &path_d_ops,
};
