/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "getcwd", "chdir" and "fchdir".
 */

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "linux_abi/errors.h"
#include "stat.h"

#ifndef ERANGE
#define ERANGE 34
#endif

long libos_syscall_getcwd(char* buf, size_t buf_size) {
    if (!is_user_memory_writable(buf, buf_size))
        return -EFAULT;

    lock(&g_process.fs_lock);
    struct libos_dentry* cwd = g_process.cwd;
    get_dentry(cwd);
    unlock(&g_process.fs_lock);

    char* path = NULL;
    size_t size;
    int ret = dentry_abs_path(cwd, &path, &size);
    if (ret < 0)
        goto out;

    if (size > PATH_MAX) {
        ret = -ENAMETOOLONG;
    } else if (size > buf_size) {
        ret = -ERANGE;
    } else {
        ret = size;
        memcpy(buf, path, size);
    }

    free(path);

out:
    put_dentry(cwd);
    return ret;
}

long libos_syscall_chdir(const char* filename) {
    struct libos_dentry* dent = NULL;
    int ret;

    if (!is_user_string_readable(filename))
        return -EFAULT;

    if (strnlen(filename, PATH_MAX + 1) == PATH_MAX + 1)
        return -ENAMETOOLONG;

    lock(&g_dcache_lock);
    ret = path_lookupat(/*start=*/NULL, filename, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dent);
    unlock(&g_dcache_lock);
    if (ret < 0)
        return ret;

    if (!dent)
        return -ENOENT;

    lock(&g_process.fs_lock);
    put_dentry(g_process.cwd);
    g_process.cwd = dent;
    unlock(&g_process.fs_lock);
    return 0;
}

long libos_syscall_fchdir(int fd) {
    struct libos_thread* thread = get_cur_thread();
    struct libos_handle* hdl    = get_fd_handle(fd, NULL, thread->handle_map);
    if (!hdl)
        return -EBADF;

    struct libos_dentry* dent = hdl->dentry;

    if (!dent) {
        log_debug("FD=%d has no path in the filesystem", fd);
        return -ENOTDIR;
    }
    if (!dent->inode || dent->inode->type != S_IFDIR) {
        char* path = NULL;
        dentry_abs_path(dent, &path, /*size=*/NULL);
        log_debug("%s is not a directory", path);
        free(path);
        put_handle(hdl);
        return -ENOTDIR;
    }

    lock(&g_process.fs_lock);
    get_dentry(dent);
    put_dentry(g_process.cwd);
    g_process.cwd = dent;
    unlock(&g_process.fs_lock);
    put_handle(hdl);
    return 0;
}
