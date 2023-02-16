/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * Implementation of system call "flock".
 */
#include <errno.h>

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_table.h"
#include "libos_thread.h"

long libos_syscall_flock(int fd, int operation) {
    int ret;

    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    assert(handle_map);

    struct libos_handle* hdl = get_fd_handle(fd, NULL, handle_map);
    if (!hdl)
        return -EBADF;

    if(!hdl->dentry || !hdl->fs || !hdl->fs->fs_ops || !hdl->fs->fs_ops->flock) {
        ret = -EINVAL;
        goto out;
    }

    ret = hdl->fs->fs_ops->flock(hdl, operation);

out:
    put_handle(hdl);
    return ret;
}