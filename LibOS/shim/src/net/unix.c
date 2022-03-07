/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Implementation of UNIX domain sockets.
 * Currently only stream-oriented sockets are supported (i.e. `SOCK_STREAM`).
 */

// TODO: Pathname UNIX sockets are not visible on the filesystem. Is that a problem?
// Possibly unlink might be...

#include "crypto.h"
#include "hex.h"
#include "pal.h"
#include "shim_fs.h"
#include "shim_internal.h"
#include "shim_socket.h"

static int unaddr_to_sockname(void* _addr, size_t addrlen, char* sock_name, size_t sock_name_size) {
    struct sockaddr_un* addr = _addr;
    if (addrlen > sizeof(*addr)) {
        addrlen = sizeof(*addr);
    }
    if (addrlen < offsetof(struct sockaddr_un, sun_path) + 1) {
        return -EINVAL;
    }
    if (addr->sun_family != AF_UNIX) {
        return -EAFNOSUPPORT;
    }

    const char* path = addr->sun_path;
    size_t pathlen = addrlen - offsetof(struct sockaddr_un, sun_path);
    assert(pathlen >= 1);
    if (path[0]) {
        /* Named UNIX socket. */
        pathlen = strnlen(path, pathlen);
    }

    uint8_t hash[32];
    LIB_SHA256_CONTEXT hash_context;
    int ret = lib_SHA256Init(&hash_context);
    if (ret < 0) {
        return -ENOMEM;
    }
    ret = lib_SHA256Update(&hash_context, (const uint8_t*)path, pathlen);
    if (ret < 0) {
        return -ENOMEM;
    }
    ret = lib_SHA256Final(&hash_context, hash);
    if (ret < 0) {
        return -ENOMEM;
    }
    assert(sock_name_size >= 2 * sizeof(hash) + 1);
    BYTES2HEXSTR(hash, sock_name, sock_name_size);
    return 0;
}

static void fixup_sockaddr_un_path(struct sockaddr_storage* ss_addr, size_t* addrlen) {
    /* This does not violate the strict aliasing rule, because we never dereference `ss_addr`. */
    struct sockaddr_un* addr = (void*)ss_addr;
    /* We know the addr is valid, but it might not contain the ending nullbyte or contain some
     * unnecessary garbage after it. */
    assert(*addrlen <= sizeof(*addr));
    assert(offsetof(struct sockaddr_un, sun_path) < *addrlen);
    assert(sizeof(*addr) < sizeof(*ss_addr));
    assert(*addrlen < sizeof(*ss_addr));

    char* path = addr->sun_path;
    size_t pathlen = *addrlen - offsetof(struct sockaddr_un, sun_path);
    assert(pathlen >= 1);
    if (!path[0]) {
        /* Abstract UNIX socket - nothing to do. */
        return;
    }

    pathlen = strnlen(path, pathlen);

    /* Clean unnecessary garbage, if any. */
    assert(sizeof(*ss_addr) - offsetof(struct sockaddr_un, sun_path) - pathlen > 0);
    memset(path + pathlen, 0, sizeof(*ss_addr) - offsetof(struct sockaddr_un, sun_path) - pathlen);

    *addrlen = offsetof(struct sockaddr_un, sun_path) + pathlen + 1;
    assert(*addrlen <= sizeof(*ss_addr));
}

static int create(struct shim_handle* handle) {
    assert(handle->info.sock.domain == AF_UNIX);
    assert(handle->info.sock.type == SOCK_STREAM || handle->info.sock.type == SOCK_DGRAM);

    if (handle->info.sock.type == SOCK_DGRAM) {
        /* We do not support datagram UNIX sockets. */
        return -EPROTONOSUPPORT;
    }
    if (handle->info.sock.protocol != 0) {
        return -EPROTONOSUPPORT;
    }

    handle->info.sock.pal_handle = NULL;
    return 0;
}

static int bind(struct shim_handle* handle, void* addr, size_t addrlen) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    char pipe_name[static_strlen(URI_PREFIX_PIPE_SRV) + 64 + 1] = URI_PREFIX_PIPE_SRV;
    int ret = unaddr_to_sockname(addr, addrlen,
                                 pipe_name + static_strlen(URI_PREFIX_PIPE_SRV),
                                 sizeof(pipe_name) - static_strlen(URI_PREFIX_PIPE_SRV));
    if (ret < 0) {
        return ret;
    }

    lock(&handle->lock);
    pal_stream_options_t options = handle->flags & O_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    unlock(&handle->lock);

    PAL_HANDLE pal_handle = NULL;
    ret = DkStreamOpen(pipe_name, PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED, options,
                       &pal_handle);
    if (ret < 0) {
        return (ret == -PAL_ERROR_STREAMEXIST) ? -EADDRINUSE : pal_to_unix_errno(ret);
    }

    __atomic_store_n(&handle->info.sock.pal_handle, pal_handle, __ATOMIC_RELEASE);

    static_assert(sizeof(struct sockaddr_un) < sizeof(sock->local_addr),
                  "need additional space for a nullbyte");
    sock->local_addrlen = MIN(addrlen, sizeof(struct sockaddr_un));
    memcpy(&sock->local_addr, addr, sock->local_addrlen);
    /* The address was verified in `unaddr_to_sockname`, so this is safe to call. */
    fixup_sockaddr_un_path(&sock->local_addr, &sock->local_addrlen);

    interrupt_epolls(handle);
    return 0;
}

static int listen(struct shim_handle* handle, unsigned int backlog) {
    /* PAL pipes don't have changeable wait queue size. */
    __UNUSED(backlog);
    if (handle->info.sock.type != SOCK_STREAM) {
        return -EOPNOTSUPP;
    }
    /* This socket is already listening - it must have been bound before. */
    assert(handle->info.sock.state == SOCK_BOUND || handle->info.sock.state == SOCK_LISTENING);
    return 0;
}

static int accept(struct shim_handle* handle, bool is_nonblocking,
                  struct shim_handle** client_ptr) {
    pal_stream_options_t options = is_nonblocking ? PAL_OPTION_NONBLOCK : 0;
    PAL_HANDLE pal_handle = __atomic_load_n(&handle->info.sock.pal_handle, __ATOMIC_ACQUIRE);
    /* Since this socket is listening, it must have a PAL handle. */
    assert(pal_handle);
    PAL_HANDLE client_pal_handle;
    int ret = DkStreamWaitForClient(pal_handle, &client_pal_handle, options);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    struct shim_handle* client_handle = get_new_handle();
    if (!client_handle) {
        DkObjectClose(client_pal_handle);
        return -ENOMEM;
    }

    client_handle->type = TYPE_SOCK;
    client_handle->fs = &socket_builtin_fs;
    client_handle->flags = is_nonblocking ? O_NONBLOCK : 0;
    client_handle->acc_mode = MAY_READ | MAY_WRITE;

    struct shim_sock_handle* client_sock = &client_handle->info.sock;
    client_sock->pal_handle = client_pal_handle;
    client_sock->state = SOCK_CONNECTED;
    client_sock->ops = handle->info.sock.ops;
    client_sock->domain = handle->info.sock.domain;
    client_sock->type = handle->info.sock.type;
    client_sock->protocol = handle->info.sock.protocol;
    client_sock->was_bound = false;
    client_sock->read_shutdown = false;
    client_sock->write_shutdown = false;

    if (!create_lock(&client_sock->lock)) {
        put_handle(client_handle);
        return -ENOMEM;
    }

    client_sock->remote_addr.ss_family = AF_UNIX;
    client_sock->remote_addrlen = sizeof(client_sock->remote_addr.ss_family);

    lock(&handle->info.sock.lock);
    client_sock->local_addrlen = handle->info.sock.local_addrlen;
    memcpy(&client_sock->local_addr, &handle->info.sock.local_addr, client_sock->local_addrlen);
    unlock(&handle->info.sock.lock);

    *client_ptr = client_handle;
    return 0;
}

static int connect(struct shim_handle* handle, void* addr, size_t addrlen) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    if (sock->state != SOCK_NEW) {
        log_warning("Gramine does not support connect on already bound UNIX socket");
        return -EINVAL;
    }

    char pipe_name[static_strlen(URI_PREFIX_PIPE) + 64 + 1] = URI_PREFIX_PIPE;
    int ret = unaddr_to_sockname(addr, addrlen,
                                 pipe_name + static_strlen(URI_PREFIX_PIPE),
                                 sizeof(pipe_name) - static_strlen(URI_PREFIX_PIPE));
    if (ret < 0) {
        return ret;
    }

    lock(&handle->lock);
    pal_stream_options_t options = handle->flags & O_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    unlock(&handle->lock);

    PAL_HANDLE pal_handle = NULL;
    ret = DkStreamOpen(pipe_name, PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED, options,
                       &pal_handle);
    if (ret < 0) {
        return (ret == -PAL_ERROR_CONNFAILED) ? -ENOENT : pal_to_unix_errno(ret);
    }

    assert(sock->pal_handle == NULL);
    __atomic_store_n(&sock->pal_handle, pal_handle, __ATOMIC_RELEASE);

    static_assert(sizeof(struct sockaddr_un) < sizeof(sock->remote_addr),
                  "need additional space for a nullbyte");
    sock->remote_addrlen = MIN(addrlen, sizeof(struct sockaddr_un));
    memcpy(&sock->remote_addr, addr, sock->remote_addrlen);
    /* The address was verified in `unaddr_to_sockname`, so this is safe to call. */
    fixup_sockaddr_un_path(&sock->remote_addr, &sock->remote_addrlen);

    if (sock->state != SOCK_BOUND) {
        assert(sock->state == SOCK_NEW);
        sock->local_addr.ss_family = AF_UNIX;
        sock->local_addrlen = sizeof(sock->local_addr.ss_family);
    }

    interrupt_epolls(handle);
    return 0;
}

static int disconnect(struct shim_handle* handle) {
    __UNUSED(handle);
    /* We do not support disconnecting UNIX sockets. */
    return -EINVAL;
}

static int setsockopt(struct shim_handle* handle, int level, int optname, void* optval,
                      size_t len) {
    /* Nothing to do here. */
    __UNUSED(handle);
    __UNUSED(level);
    __UNUSED(optname);
    __UNUSED(optval);
    __UNUSED(len);
    return -ENOPROTOOPT;
}

static int getsockopt(struct shim_handle* handle, int level, int optname, void* optval,
                      size_t* len) {
    /* Nothing to do here. */
    __UNUSED(handle);
    __UNUSED(level);
    __UNUSED(optname);
    __UNUSED(optval);
    __UNUSED(len);
    return -ENOPROTOOPT;
}

static int send(struct shim_handle* handle, struct iovec* iov, size_t iov_len, size_t* size_out,
                void* addr, size_t addrlen) {
    __UNUSED(addr);
    __UNUSED(addrlen);

    if (handle->info.sock.type == SOCK_DGRAM) {
        /* We do not support datagram UNIX sockets. */
        BUG();
    }

    PAL_HANDLE pal_handle = __atomic_load_n(&handle->info.sock.pal_handle, __ATOMIC_ACQUIRE);
    if (!pal_handle) {
        return -ENOTCONN;
    }

    void* buf;
    size_t size;
    char* backing_buf = NULL;
    if (iov_len == 1) {
        /* Common case - no need for copying. */
        buf = iov[0].iov_base;
        size = iov[0].iov_len;
    } else {
        size = 0;
        for (size_t i = 0; i < iov_len; ++i) {
            size += iov[i].iov_len;
        }
        backing_buf = malloc(size);
        if (!backing_buf) {
            return -ENOMEM;
        }
        size = 0;
        for (size_t i = 0; i < iov_len; ++i) {
            memcpy(backing_buf + size, iov[i].iov_base, iov[i].iov_len);
            size += iov[i].iov_len;
        }
        buf = backing_buf;
        /* `size` already correct. */
    }

    int ret = DkStreamWrite(pal_handle, /*offset=*/0, &size, buf, NULL);
    free(backing_buf);
    if (ret < 0) {
        return (ret == -PAL_ERROR_TOOLONG) ? -EMSGSIZE : pal_to_unix_errno(ret);
    }
    *size_out = size;
    return 0;
}

static int recv(struct shim_handle* handle, struct iovec* iov, size_t iov_len, size_t* size_out,
                void* addr, size_t* addrlen) {
    __UNUSED(addr);
    __UNUSED(addrlen);

    if (handle->info.sock.type == SOCK_DGRAM) {
        /* We do not support datagram UNIX sockets. */
        BUG();
    }

    PAL_HANDLE pal_handle = __atomic_load_n(&handle->info.sock.pal_handle, __ATOMIC_ACQUIRE);
    if (!pal_handle) {
        return -ENOTCONN;
    }

    void* buf;
    size_t size;
    char* backing_buf = NULL;
    if (iov_len == 1) {
        /* Common simple case. */
        buf = iov[0].iov_base;
        size = iov[0].iov_len;
    } else {
        size = 0;
        for (size_t i = 0; i < iov_len; ++i) {
            size += iov[i].iov_len;
        }
        backing_buf = malloc(size);
        if (!backing_buf) {
            return -ENOMEM;
        }
        buf = backing_buf;
        /* `size` already correct. */
    }

    int ret = DkStreamRead(pal_handle, /*offset=*/0, &size, buf, NULL, 0);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
    } else {
        *size_out = size;
        if (backing_buf) {
            /* Need to copy back to user buffers. */
            size_t copied = 0;
            for (size_t i = 0; i < iov_len && copied < size; ++i) {
                size_t this_size = MIN(size - copied, iov[i].iov_len);
                memcpy(iov[i].iov_base, buf + copied, this_size);
                copied += this_size;
            }
            assert(copied == size);
        }
        ret = 0;
    }
    free(backing_buf);
    return ret;
}

struct shim_sock_ops sock_unix_ops = {
    .create = create,
    .bind = bind,
    .listen = listen,
    .accept = accept,
    .connect = connect,
    .disconnect = disconnect,
    .getsockopt = getsockopt,
    .setsockopt = setsockopt,
    .send = send,
    .recv = recv,
};
