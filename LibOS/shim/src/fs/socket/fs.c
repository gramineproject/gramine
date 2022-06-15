/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <asm/fcntl.h>

#include "api.h"
#include "pal.h"
#include "perm.h"
#include "shim_fs.h"
#include "shim_lock.h"
#include "shim_socket.h"
#include "stat.h"

static int close(struct shim_handle* handle) {
    if (lock_created(&handle->info.sock.lock)) {
        destroy_lock(&handle->info.sock.lock);
    }
    if (lock_created(&handle->info.sock.recv_lock)) {
        destroy_lock(&handle->info.sock.recv_lock);
    }
    free(handle->info.sock.peek.buf);
    /* No need for atomics - we are releasing the last reference, nothing can access it anymore. */
    if (handle->info.sock.pal_handle) {
        DkObjectClose(handle->info.sock.pal_handle);
    }
    return 0;
}

static ssize_t read(struct shim_handle* handle, void* buf, size_t size, file_off_t* pos) {
    __UNUSED(pos);
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = size,
    };
    unsigned int flags = 0;
    return do_recvmsg(handle, &iov, /*iov_len=*/1, /*addr=*/NULL, /*addrlen=*/NULL, &flags);
}

static ssize_t write(struct shim_handle* handle, const void* buf, size_t size, file_off_t* pos) {
    __UNUSED(pos);
    struct iovec iov = {
        .iov_base = (void*)buf,
        .iov_len = size,
    };
    return do_sendmsg(handle, &iov, /*iov_len=*/1, /*addr=*/NULL, /*addrlen=*/0, /*flags=*/0);
}

static ssize_t readv(struct shim_handle* handle, struct iovec* iov, size_t iov_len,
                     file_off_t* pos) {
    __UNUSED(pos);
    unsigned int flags = 0;
    return do_recvmsg(handle, iov, iov_len, /*addr=*/NULL, /*addrlen=*/NULL, &flags);
}

static ssize_t writev(struct shim_handle* handle, struct iovec* iov, size_t iov_len,
                      file_off_t* pos) {
    __UNUSED(pos);
    return do_sendmsg(handle, iov, iov_len, /*addr=*/NULL, /*addrlen=*/0, /*flags=*/0);
}

static int hstat(struct shim_handle* handle, struct stat* stat) {
    __UNUSED(handle);
    assert(stat);

    memset(stat, 0, sizeof(*stat));

    /* XXX: maybe we should put something meaningful in `dev` and `ino`? */
    stat->st_dev = 0;
    stat->st_ino = 0;
    stat->st_mode = S_IFSOCK | PERM_rwxrwxrwx;
    stat->st_nlink = 1;
    stat->st_blksize = PAGE_SIZE;

    /* XXX: maybe set `st_size` - query PAL for pending size? Otoh nothing seems to be using it. */

    return 0;
}

static int setflags(struct shim_handle* handle, int flags) {
    if (!WITHIN_MASK(flags, O_NONBLOCK)) {
        return -EINVAL;
    }

    bool nonblocking = flags & O_NONBLOCK;

    PAL_HANDLE pal_handle = __atomic_load_n(&handle->info.sock.pal_handle, __ATOMIC_ACQUIRE);
    if (!pal_handle) {
        log_warning("Trying to set flags on not bound / not connected UNIX socket. This is not "
                    "supported in Gramine.");
        return -EINVAL;
    }

    PAL_STREAM_ATTR attr;
    int ret = DkStreamAttributesQueryByHandle(pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    assert(ret == 0);

    if (attr.nonblocking != nonblocking) {
        attr.nonblocking = nonblocking;
        ret = DkStreamAttributesSetByHandle(pal_handle, &attr);
    }

    return pal_to_unix_errno(ret);
}

static int checkout(struct shim_handle* handle) {
    struct shim_sock_handle* sock = &handle->info.sock;
    sock->ops = NULL;
    clear_lock(&sock->lock);
    clear_lock(&sock->recv_lock);
    /*
     * XXX: this should actually copy the data, but:
     * - `handle` is a copy of the original handle (let's call it `orig_handle`),
     * - to copy the `orig_handle->info.sock.peek.buf` data, we need to acquire
     *   `orig_handle->info.sock.recv_lock`, but we already hold `orig_handle->lock` (and have no
     *   access to `orig_handle` anyway),
     * - moreover, we have no way of allocating memory in the checkpointing blob here for this data.
     */
    sock->peek.buf = NULL;
    sock->peek.buf_size = 0;
    sock->peek.data_size = 0;
    return 0;
}

static int checkin(struct shim_handle* handle) {
    struct shim_sock_handle* sock = &handle->info.sock;
    switch (sock->domain) {
        case AF_UNIX:
            sock->ops = &sock_unix_ops;
            break;
        case AF_INET:
        case AF_INET6:
            sock->ops = &sock_ip_ops;
            break;
        default:
            BUG();
    }
    if (!create_lock(&sock->lock) || !create_lock(&sock->recv_lock)) {
        return -ENOMEM;
    }
    return 0;
}

static struct shim_fs_ops socket_fs_ops = {
    .close    = close,
    .read     = read,
    .write    = write,
    .readv    = readv,
    .writev   = writev,
    .hstat    = hstat,
    .setflags = setflags,
    .checkout = checkout,
    .checkin  = checkin,
};

struct shim_fs socket_builtin_fs = {
    .name   = "socket",
    .fs_ops = &socket_fs_ops,
};
