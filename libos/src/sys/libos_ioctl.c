/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system call "ioctl".
 */

#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_process.h"
#include "libos_rwlock.h"
#include "libos_signal.h"
#include "libos_table.h"
#include "linux_abi/errors.h"
#include "linux_abi/ioctl.h"
#include "pal.h"
#include "stat.h"

static void signal_io(IDTYPE caller, void* arg) {
    __UNUSED(caller);
    __UNUSED(arg);
    /* TODO: fill these values e.g. by getting the handle in arg; this is completely unusable now */
    siginfo_t info = {
        .si_signo = SIGIO,
        .si_code = SI_SIGIO,
        .si_band = 0,
        .si_fd = 0,
    };
    if (kill_current_proc(&info) < 0) {
        log_warning("signal_io: failed to deliver a signal");
    }
}

long libos_syscall_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg) {
    int ret;

    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    assert(handle_map);

    struct libos_handle* hdl = get_fd_handle(fd, NULL, handle_map);
    if (!hdl)
        return -EBADF;

    lock(&g_dcache_lock);
    bool is_host_dev = hdl->type == TYPE_CHROOT && hdl->dentry->inode &&
        hdl->dentry->inode->type == S_IFCHR;
    unlock(&g_dcache_lock);

    if (is_host_dev) {
        int cmd_ret;
        ret = PalDeviceIoControl(hdl->pal_handle, cmd, arg, &cmd_ret);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }

        assert(ret == 0);
        ret = cmd_ret;
        goto out;
    }

    switch (cmd) {
        case TIOCGPGRP:
            if (!hdl->uri || strcmp(hdl->uri, URI_PREFIX_CONSOLE)) {
                ret = -ENOTTY;
                break;
            }

            if (!is_user_memory_writable((void*)arg, sizeof(int))) {
                ret = -EFAULT;
                break;
            }
            rwlock_read_lock(&g_process_id_lock);
            *(int*)arg = g_process.pgid;
            rwlock_read_unlock(&g_process_id_lock);
            ret = 0;
            break;
        case FIONBIO:
            if (!is_user_memory_readable((void*)arg, sizeof(int))) {
                ret = -EFAULT;
                break;
            }
            int nonblocking_on = *(int*)arg;
            ret = set_handle_nonblocking(hdl, !!nonblocking_on);
            break;
        case FIONCLEX:
            rwlock_write_lock(&handle_map->lock);
            if (HANDLE_ALLOCATED(handle_map->map[fd])) {
                handle_map->map[fd]->flags &= ~FD_CLOEXEC;
                ret = 0;
            } else {
                ret = -EBADF;
            }
            rwlock_write_unlock(&handle_map->lock);
            break;
        case FIOCLEX:
            rwlock_write_lock(&handle_map->lock);
            if (HANDLE_ALLOCATED(handle_map->map[fd])) {
                handle_map->map[fd]->flags |= FD_CLOEXEC;
                ret = 0;
            } else {
                ret = -EBADF;
            }
            rwlock_write_unlock(&handle_map->lock);
            break;
        case FIOASYNC:
            ret = install_async_event(hdl->pal_handle, 0, &signal_io, NULL);
            break;
        case FIONREAD: {
            if (!is_user_memory_writable((void*)arg, sizeof(int))) {
                ret = -EFAULT;
                break;
            }

            struct libos_fs* fs = hdl->fs;
            if (!fs || !fs->fs_ops) {
                ret = -ENOTTY;
                break;
            }

            if (fs->fs_ops->ioctl) {
                ret = fs->fs_ops->ioctl(hdl, cmd, arg);
                break;
            }

            /* TODO: the code below should be deleted and each handle type should have custom ioctl
             * handling. */
            int size = 0;
            if (fs->fs_ops->hstat) {
                struct stat stat;
                ret = fs->fs_ops->hstat(hdl, &stat);
                if (ret < 0)
                    break;
                size = stat.st_size;
            } else if (hdl->pal_handle) {
                PAL_STREAM_ATTR attr;
                ret = PalStreamAttributesQueryByHandle(hdl->pal_handle, &attr);
                if (ret < 0) {
                    ret = pal_to_unix_errno(ret);
                    break;
                }
                size = attr.pending_size;
            }

            int offset = 0;
            if (fs->fs_ops->seek) {
                ret = fs->fs_ops->seek(hdl, 0, SEEK_CUR);
                if (ret < 0)
                    break;
                offset = ret;
            }

            *(int*)arg = size - offset;
            ret = 0;
            break;
        }
        default: {
            struct libos_fs* fs = hdl->fs;
            if (!fs || !fs->fs_ops || !fs->fs_ops->ioctl) {
                ret = -ENOTTY;
                break;
            }
            ret = fs->fs_ops->ioctl(hdl, cmd, arg);
            break;
        }
    }

out:
    put_handle(hdl);
    if (ret == -EINTR) {
        ret = -ERESTARTSYS;
    }
    return ret;
}
