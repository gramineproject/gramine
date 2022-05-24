/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "readv" and "writev".
 */

#include <errno.h>

#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_table.h"

long shim_do_readv(unsigned long fd, struct iovec* vec, unsigned long vlen) {
    if (!is_user_memory_readable(vec, sizeof(*vec) * vlen))
        return -EINVAL;

    for (size_t i = 0; i < vlen; i++) {
        if (vec[i].iov_base) {
            if (!access_ok(vec[i].iov_base, vec[i].iov_len))
                return -EINVAL;
            if (!is_user_memory_writable(vec[i].iov_base, vec[i].iov_len))
                return -EFAULT;
        }
    }

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    lock(&hdl->pos_lock);

    int ret = 0;

    if (hdl->is_dir) {
        ret = -EISDIR;
        goto out;
    }

    if (!(hdl->acc_mode & MAY_READ) || !hdl->fs || !hdl->fs->fs_ops) {
        ret = -EACCES;
        goto out;
    }

    if (hdl->fs->fs_ops->readv) {
        ret = hdl->fs->fs_ops->readv(hdl, vec, vlen, &hdl->pos);
        goto out;
    }

    if (!hdl->fs->fs_ops->read) {
        ret = -EACCES;
        goto out;
    }

    ssize_t bytes = 0;
    for (size_t i = 0; i < vlen; i++) {
        if (!vec[i].iov_base)
            continue;

        ssize_t b_vec = hdl->fs->fs_ops->read(hdl, vec[i].iov_base, vec[i].iov_len, &hdl->pos);
        if (b_vec < 0) {
            ret = bytes ?: b_vec;
            goto out;
        }

        bytes += b_vec;
    }

    ret = bytes;
out:
    unlock(&hdl->pos_lock);
    put_handle(hdl);
    if (ret == -EINTR) {
        ret = -ERESTARTSYS;
    }
    return ret;
}

long shim_do_writev(unsigned long fd, struct iovec* vec, unsigned long vlen) {
    if (!is_user_memory_readable(vec, sizeof(*vec) * vlen))
        return -EINVAL;

    for (size_t i = 0; i < vlen; i++) {
        if (vec[i].iov_base) {
            if (!access_ok(vec[i].iov_base, vec[i].iov_len))
                return -EINVAL;
            if (!is_user_memory_readable(vec[i].iov_base, vec[i].iov_len))
                return -EFAULT;
        }
    }

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    lock(&hdl->pos_lock);

    int ret = 0;

    if (hdl->is_dir) {
        ret = -EISDIR;
        goto out;
    }

    if (!(hdl->acc_mode & MAY_WRITE) || !hdl->fs || !hdl->fs->fs_ops) {
        ret = -EACCES;
        goto out;
    }

    if (hdl->fs->fs_ops->writev) {
        ret = hdl->fs->fs_ops->writev(hdl, vec, vlen, &hdl->pos);
        goto out;
    }

    if (!hdl->fs->fs_ops->write) {
        ret = -EACCES;
        goto out;
    }

    ssize_t bytes = 0;
    for (size_t i = 0; i < vlen; i++) {
        if (!vec[i].iov_base)
            continue;

        ssize_t b_vec = hdl->fs->fs_ops->write(hdl, vec[i].iov_base, vec[i].iov_len, &hdl->pos);
        if (b_vec < 0) {
            ret = bytes ?: b_vec;
            goto out;
        }

        bytes += b_vec;
    }

    ret = bytes;
out:
    unlock(&hdl->pos_lock);
    put_handle(hdl);
    if (ret == -EINTR) {
        ret = -ERESTARTSYS;
    }
    return ret;
}
