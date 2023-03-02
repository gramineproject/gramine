/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system call "ioctl".
 */

#include <asm/ioctls.h>

#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_process.h"
#include "libos_signal.h"
#include "libos_table.h"
#include "pal.h"

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
    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    assert(handle_map);

    struct libos_handle* hdl = get_fd_handle(fd, NULL, handle_map);
    if (!hdl)
        return -EBADF;

    int ret;
    switch (cmd) {
        case TIOCGPGRP:
            if (!hdl->uri || strcmp(hdl->uri, "dev:tty") != 0) {
                ret = -ENOTTY;
                break;
            }

            if (!is_user_memory_writable((void*)arg, sizeof(int))) {
                ret = -EFAULT;
                break;
            }
            lock(&g_process_id_lock);
            *(int*)arg = g_process.pgid;
            unlock(&g_process_id_lock);
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
            lock(&handle_map->lock);
            if (HANDLE_ALLOCATED(handle_map->map[fd])) {
                handle_map->map[fd]->flags &= ~FD_CLOEXEC;
                ret = 0;
            } else {
                ret = -EBADF;
            }
            unlock(&handle_map->lock);
            break;
        case FIOCLEX:
            lock(&handle_map->lock);
            if (HANDLE_ALLOCATED(handle_map->map[fd])) {
                handle_map->map[fd]->flags |= FD_CLOEXEC;
                ret = 0;
            } else {
                ret = -EBADF;
            }
            unlock(&handle_map->lock);
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
        default:
            ret = -ENOSYS;
            break;
    }

    put_handle(hdl);
    if (ret == -EINTR) {
        ret = -ERESTARTSYS;
    }
    return ret;
}
