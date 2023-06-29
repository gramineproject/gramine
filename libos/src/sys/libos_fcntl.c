/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Implementation of system calls "fcntl" and "flock".
 *
 * The "fcntl" syscall supports:
 *
 * - F_DUPFD, F_DUPFD_CLOEXEC (duplicate a file descriptor)
 * - F_GETFD, F_SETFD (file descriptor flags)
 * - F_GETFL, F_SETFL (file status flags)
 * - F_SETLK, F_SETLKW, F_GETLK (POSIX advisory locks)
 * - F_SETOWN (file descriptor owner): dummy implementation
 */

#include "libos_fs.h"
#include "libos_fs_lock.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "linux_abi/errors.h"
#include "linux_abi/fs.h"
#include "toml_utils.h"

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
 * Convert user-mode `struct flock` into our `struct libos_file_lock` (for POSIX locks only). This
 * mostly means converting the position parameters (l_whence, l_start, l_len) to an absolute
 * inclusive range [start .. end]. See `man fcntl` for details.
 *
 * We need to return -EINVAL for underflow (positions before start of file), and -EOVERFLOW for
 * positive overflow.
 */
static int flock_to_file_lock(struct flock* fl, struct libos_handle* hdl,
                              struct libos_file_lock* file_lock) {
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

    file_lock->family = FILE_LOCK_POSIX;
    file_lock->type = fl->l_type;
    file_lock->start = start;
    file_lock->end = end;
    file_lock->pid = g_process.pid;
    file_lock->handle_id = 0; /* unused in POSIX (fcntl) locks, unset for sanity */
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
            rwlock_write_lock(&handle_map->lock);
            if (HANDLE_ALLOCATED(handle_map->map[fd]))
                handle_map->map[fd]->flags = arg & FD_CLOEXEC;
            rwlock_write_unlock(&handle_map->lock);
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
            struct flock* fl = (struct flock*)arg;
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

            struct libos_file_lock file_lock;
            ret = flock_to_file_lock(fl, hdl, &file_lock);
            if (ret < 0)
                break;

            ret = file_lock_set(hdl->dentry, &file_lock, /*wait=*/cmd == F_SETLKW);
            break;
        }

        /* F_GETLK (struct flock*): see `libos_fs_lock.h` for caveats */
        case F_GETLK: {
            struct flock* fl = (struct flock*)arg;
            if (!is_user_memory_readable(fl, sizeof(*fl))
                    || !is_user_memory_writable(fl, sizeof(*fl))) {
                ret = -EFAULT;
                break;
            }

            if (!hdl->dentry) {
                ret = -EINVAL;
                break;
            }

            struct libos_file_lock file_lock;
            ret = flock_to_file_lock(fl, hdl, &file_lock);
            if (ret < 0)
                break;

            if (file_lock.type == F_UNLCK) {
                ret = -EINVAL;
                break;
            }

            struct libos_file_lock file_lock2;
            ret = file_lock_get(hdl->dentry, &file_lock, &file_lock2);
            if (ret < 0)
                break;

            fl->l_type = file_lock2.type;
            if (file_lock2.type != F_UNLCK) {
                fl->l_whence = SEEK_SET;
                fl->l_start = file_lock2.start;
                if (file_lock2.end == FS_LOCK_EOF) {
                    /* range until EOF is encoded as len == 0 */
                    fl->l_len = 0;
                } else {
                    fl->l_len = file_lock2.end - file_lock2.start + 1;
                }
                fl->l_pid = file_lock2.pid;
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

long libos_syscall_flock(unsigned int fd, unsigned int cmd) {
    int ret;

    /* support for LOCK_{MAND,READ,WRITE,RW} was removed from Linux; it simply ignores LOCK_MAND
     * requests so we do the same */
    if (cmd & LOCK_MAND) {
        log_warning("flock requests with LOCK_MAND are ignored");
        return 0;
    }

    /* TODO: temporary measure, remove it once flock implementation is thoroughly validated and
     * works on multi-process apps; see comments at `created_by_process` in `libos_handle.h` */
    assert(g_manifest_root);
    bool enable_flock;
    ret = toml_bool_in(g_manifest_root, "sys.experimental__enable_flock", /*defaultval=*/false,
                       &enable_flock);
    if (ret < 0) {
        log_error("Cannot parse 'sys.experimental__enable_flock' (the value must be `true` or "
                  "`false`)");
        return -ENOSYS;
    }
    if (!enable_flock) {
        /* flock is not explicitly allowed in manifest */
        if (FIRST_TIME()) {
            log_warning("The app tried to use flock, but it's turned off "
                        "(sys.experimental__enable_flock = false)");
        }

        return -ENOSYS;
    }


    struct libos_handle* hdl = get_fd_handle(fd, /*fd_flags=*/NULL, /*map=*/NULL);
    if (!hdl)
        return -EBADF;

    int lock_type;
    switch (cmd & ~LOCK_NB) {
        case LOCK_EX:
            lock_type = F_WRLCK;
            break;
        case LOCK_SH:
            lock_type = F_RDLCK;
            break;
        case LOCK_UN:
            lock_type = F_UNLCK;
            break;
        default:
            ret = -EINVAL;
            goto out;
    }

    struct libos_file_lock file_lock = {
        .family = FILE_LOCK_FLOCK,
        .type = lock_type,
        .handle_id = hdl->id,
    };
    ret = file_lock_set(hdl->dentry, &file_lock, !(cmd & LOCK_NB));
out:
    put_handle(hdl);
    return ret;
}
