/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Implementation of system call "fcntl":
 *
 * - F_DUPFD, F_DUPFD_CLOEXEC (duplicate a file descriptor)
 * - F_GETFD, F_SETFD (file descriptor flags)
 * - F_GETFL, F_SETFL (file status flags)
 * - F_SETLK, F_SETLKW, F_GETLK (POSIX advisory locks)
 * - F_SETOWN (file descriptor owner): dummy implementation
 */

#include <errno.h>
#include <linux/fcntl.h>

#include "libos_fs.h"
#include "libos_fs_lock.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_table.h"
#include "libos_thread.h"

#define FCNTL_SETFL_MASK (O_APPEND | O_DIRECT | O_NOATIME | O_NONBLOCK)

static int generic_set_flags(struct libos_handle* handle, unsigned int flags, unsigned int mask) {
    /* TODO: DOES THIS WORK LOL
     * The old version of this code did this, but this seem to be incorrect. If a handle type allows
     * for setting some flags without actually doing anything with them immediately, it should have
     * a `setflags` callback implementation. */
    lock(&handle->lock);
    handle->flags = (handle->flags & ~mask) | flags;
    unlock(&handle->lock);
    return 0;
}

static int set_handle_flags(struct libos_handle* handle, unsigned int flags, unsigned int mask) {
    flags &= mask;
    if (handle->fs && handle->fs->fs_ops && handle->fs->fs_ops->setflags) {
        return handle->fs->fs_ops->setflags(handle, flags, mask);
    }
    return generic_set_flags(handle, flags, mask);
}

int set_handle_nonblocking(struct libos_handle* handle, bool on) {
    return set_handle_flags(handle, on ? O_NONBLOCK : 0, O_NONBLOCK);
}

/*
 * Convert user-mode `struct flock` into our `struct posix_lock`. This mostly means converting the
 * position parameters (l_whence, l_start, l_len) to an absolute inclusive range [start .. end]. See
 * `man fcntl` for details.
 *
 * We need to return -EINVAL for underflow (positions before start of file), and -EOVERFLOW for
 * positive overflow.
 */
static int flock_to_posix_lock(struct flock* fl, struct libos_handle* hdl, struct posix_lock* pl) {
    if (!(fl->l_type == F_RDLCK || fl->l_type == F_WRLCK || fl->l_type == F_UNLCK))
        return -EINVAL;

    int ret;

    struct libos_fs* fs = hdl->fs;
    assert(fs && fs->fs_ops);

    /* Compute the origin based on `l_start` and `l_whence`. Note that we cannot directly call
     * `seek(hdl, l_start, l_whence)`, because that would modify the handle position. Only
     * retrieving the current position (by calling `seek(hdl, 0, SEEK_CUR)`) is safe. */
    uint64_t origin;
    switch (fl->l_whence) {
        case SEEK_SET:
            origin = 0;
            break;
        case SEEK_CUR: {
            if (!fs->fs_ops->seek)
                return -EINVAL;

            file_off_t pos = fs->fs_ops->seek(hdl, 0, SEEK_CUR);
            if (pos < 0)
                return pos;
            origin = pos;
            break;
        }
        case SEEK_END: {
            if (!fs->fs_ops->hstat)
                return -EINVAL;

            struct stat stat;
            ret = fs->fs_ops->hstat(hdl, &stat);
            if (ret < 0)
                return ret;
            assert(stat.st_size >= 0);
            origin = stat.st_size;
            break;
        }
        default:
            return -EINVAL;
    }

    if (__builtin_add_overflow(origin, fl->l_start, &origin)) {
        return fl->l_start > 0 ? -EOVERFLOW : -EINVAL;
    }

    uint64_t start, end;
    if (fl->l_len > 0) {
        /* len > 0: the range is [origin .. origin + len - 1] */
        start = origin;
        if (__builtin_add_overflow(origin, fl->l_len - 1, &end))
            return -EOVERFLOW;
    } else if (fl->l_len < 0) {
        /* len < 0: the range is [origin + len .. origin - 1] */
        if (__builtin_add_overflow(origin, fl->l_len, &start))
            return -EINVAL;
        if (__builtin_add_overflow(origin, -1, &end))
            return -EINVAL;
    } else {
        /* len == 0: the range is [origin .. EOF] */
        start = origin;
        end = FS_LOCK_EOF;
    }

    pl->type = fl->l_type;
    pl->start = start;
    pl->end = end;
    pl->pid = g_process.pid;
    pl->handle_id = 0;
    return 0;
}

long libos_syscall_fcntl(int fd, int cmd, unsigned long arg) {
    int ret;
    int flags;

    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    assert(handle_map);

    struct libos_handle* hdl = get_fd_handle(fd, &flags, handle_map);
    if (!hdl)
        return -EBADF;
    hdl->id = 0;

    switch (cmd) {
        /* See `man fcntl` for the expected semantics of these commands. */

        /* F_DUPFD (int) */
        case F_DUPFD: {
            ret = set_new_fd_handle_above_fd(arg, hdl, flags, handle_map);
            break;
        }

        /* F_DUPFD_CLOEXEC (int) */
        case F_DUPFD_CLOEXEC: {
            flags |= FD_CLOEXEC;
            ret = set_new_fd_handle_above_fd(arg, hdl, flags, handle_map);
            break;
        }

        /* F_GETFD (int) */
        case F_GETFD:
            ret = flags & FD_CLOEXEC;
            break;

        /* F_SETFD (int) */
        case F_SETFD:
            lock(&handle_map->lock);
            if (HANDLE_ALLOCATED(handle_map->map[fd]))
                handle_map->map[fd]->flags = arg & FD_CLOEXEC;
            unlock(&handle_map->lock);
            ret = 0;
            break;

        /* F_GETFL (void) */
        case F_GETFL:
            lock(&hdl->lock);
            flags = hdl->flags;
            unlock(&hdl->lock);
            ret = flags;
            break;

        /* F_SETFL (int) */
        case F_SETFL:
            ret = set_handle_flags(hdl, arg, FCNTL_SETFL_MASK);
            break;

        /* F_SETLK, F_SETLKW (struct flock*): see `libos_fs_lock.h` for caveats */
        case F_SETLK:
        case F_SETLKW: {
            struct flock *fl = (struct flock*)arg;
            if (!is_user_memory_readable(fl, sizeof(*fl))) {
                ret = -EFAULT;
                break;
            }

            if (!hdl->dentry) {
                /* TODO: Linux allows locks on pipes etc. Our locks work only for "normal" files
                 * that have a dentry. */
                ret = -EINVAL;
                break;
            }

            if (fl->l_type == F_RDLCK && !(hdl->acc_mode & MAY_READ)) {
                ret = -EINVAL;
                break;
            }

            if (fl->l_type == F_WRLCK && !(hdl->acc_mode & MAY_WRITE)) {
                ret = -EINVAL;
                break;
            }

            struct posix_lock pl;
            ret = flock_to_posix_lock(fl, hdl, &pl);
            if (ret < 0)
                break;

            ret = posix_lock_set(hdl->dentry, &pl, /*wait=*/cmd == F_SETLKW);
            break;
        }

        /* F_GETLK (struct flock*): see `libos_fs_lock.h` for caveats */
        case F_GETLK: {
            struct flock *fl = (struct flock*)arg;
            if (!is_user_memory_readable(fl, sizeof(*fl))
                    || !is_user_memory_writable(fl, sizeof(*fl))) {
                ret = -EFAULT;
                break;
            }

            if (!hdl->dentry) {
                ret = -EINVAL;
                break;
            }

            struct posix_lock pl;
            ret = flock_to_posix_lock(fl, hdl, &pl);
            if (ret < 0)
                break;

            if (pl.type == F_UNLCK) {
                ret = -EINVAL;
                break;
            }

            struct posix_lock pl2;
            ret = posix_lock_get(hdl->dentry, &pl, &pl2);
            if (ret < 0)
                break;

            fl->l_type = pl2.type;
            if (pl2.type != F_UNLCK) {
                fl->l_whence = SEEK_SET;
                fl->l_start = pl2.start;
                if (pl2.end == FS_LOCK_EOF) {
                    /* range until EOF is encoded as len == 0 */
                    fl->l_len = 0;
                } else {
                    fl->l_len = pl2.end - pl2.start + 1;
                }
                fl->l_pid = pl2.pid;
            }
            ret = 0;
            break;
        }

        /* F_SETOWN (int): dummy implementation */
        case F_SETOWN:
            ret = 0;
            /* XXX: DUMMY for now */
            break;

        default:
            ret = -EINVAL;
            break;
    }

    put_handle(hdl);
    return ret;
}

long libos_syscall_flock(int fd, int operation) {
    int ret;

    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    assert(handle_map);

    struct libos_handle* hdl = get_fd_handle(fd, NULL, handle_map);
    if (!hdl)
        return -EBADF;

    struct flock fl;

    switch (operation & ~LOCK_NB) {
        case LOCK_EX:
            fl.l_type = F_WRLCK;
            break;
        case LOCK_SH:
            fl.l_type = F_RDLCK;
            break;
        case LOCK_UN:
            fl.l_type = F_UNLCK;
            break;
        default:
            ret = -EINVAL;
            goto out;
    }

    fl.l_whence = SEEK_SET;
    /* Lock the whole file. */
    fl.l_start = fl.l_len = 0L;

    struct posix_lock pl;
    ret = flock_to_posix_lock(&fl, hdl, &pl);
    if (ret < 0)
        goto out;

    pl.handle_id = hdl->id;
    ret = posix_lock_set(hdl->dentry, &pl, !(operation & LOCK_NB));

out:
    put_handle(hdl);
    return ret;
}
