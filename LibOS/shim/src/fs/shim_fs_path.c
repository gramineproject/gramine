/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "shim_fs.h"

static int hstat(struct shim_handle* handle, struct stat* buf) {
    if (!handle->inode) {
        return -EINVAL;
    }
    return generic_inode_hstat(handle, buf);
}

static struct shim_fs_ops path_fs_ops = {
    .hstat = hstat,
};

static struct shim_d_ops path_d_ops = {};

struct shim_fs path_builtin_fs = {
    .name = "path",
    .fs_ops = &path_fs_ops,
    .d_ops = &path_d_ops,
};
