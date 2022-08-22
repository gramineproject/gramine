/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Implementation of UNIX domain sockets.
 * Currently only stream-oriented sockets are supported (i.e. `SOCK_STREAM`).
 */

/*
 * TODO: Currently pathname UNIX domain sockets are not visible on the Gramine filesystem (they
 * do not have a corresponding dentry). This shouldn't be hard to implement, but leaving this as
 * a todo for now - nothing seemed to require it, at least so far.
 */

#include "crypto.h"
#include "hex.h"
#include "libos_fs.h"
#include "libos_internal.h"
#include "libos_socket.h"
#include "pal.h"

/*!
 * \brief Verify UNIX socket address and convert it to a unique socket name.
 *
 * \param         addr            The socket address to convert.
 * \param[in,out] addrlen         Pointer to the size of \p addr. Always updated to the actual size
 *                                of the address (but it's never extended).
 * \param[out]    sock_name       Buffer for the output socket name. On success contains a null
 *                                terminated string.
 * \param         sock_name_size  Size of \p sock_name.
 */
static int unaddr_to_sockname(void* addr, size_t* addrlen, char* sock_name, size_t sock_name_size) {
    if (*addrlen > sizeof(struct sockaddr_un)) {
        /* Cap the address at the maximal possible size - rest of the input buffer (if any) is
         * ignored. */
        *addrlen = sizeof(struct sockaddr_un);
    }
    if (*addrlen < offsetof(struct sockaddr_un, sun_path) + 1) {
        return -EINVAL;
    }
    static_assert(offsetof(struct sockaddr_un, sun_family) < offsetof(struct sockaddr_un, sun_path),
                  "ops");
    unsigned short family;
    memcpy(&family, (char*)addr + offsetof(struct sockaddr_un, sun_family), sizeof(family));
    if (family != AF_UNIX) {
        return -EAFNOSUPPORT;
    }

    const char* path = (char*)addr + offsetof(struct sockaddr_un, sun_path);
    size_t pathlen = *addrlen - offsetof(struct sockaddr_un, sun_path);
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
    bytes2hex(hash, sizeof(hash), sock_name, sock_name_size);
    return 0;
}

static void fixup_sockaddr_un_path(struct sockaddr_storage* ss_addr, size_t* addrlen) {
    /* We know the addr is valid, but it might not contain the ending nullbyte or contain some
     * unnecessary garbage after it. */
    assert(*addrlen <= sizeof(struct sockaddr_un));
    assert(offsetof(struct sockaddr_un, sun_path) < *addrlen);
    assert(sizeof(struct sockaddr_un) < sizeof(*ss_addr));
    assert(*addrlen < sizeof(*ss_addr));

    char* path = (char*)ss_addr + offsetof(struct sockaddr_un, sun_path);
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

static int create(struct libos_handle* handle) {
    assert(handle->info.sock.domain == AF_UNIX);
    assert(handle->info.sock.type == SOCK_STREAM || handle->info.sock.type == SOCK_DGRAM);

    if (handle->info.sock.type == SOCK_DGRAM) {
        /* We use PAL pipes to emulate UNIX sockets. Pipes are streams by their nature, so we have
         * no infrastructure to preserve message (datagram) boundaries - hence datagram UNIX sockets
         * are not supported. */
        return -EPROTONOSUPPORT;
    }
    if (handle->info.sock.protocol != 0) {
        return -EPROTONOSUPPORT;
    }

    handle->info.sock.pal_handle = NULL;
    return 0;
}

static int bind(struct libos_handle* handle, void* addr, size_t addrlen) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    char pipe_name[static_strlen(URI_PREFIX_PIPE_SRV) + 64 + 1] = URI_PREFIX_PIPE_SRV;
    int ret = unaddr_to_sockname(addr, &addrlen,
                                 pipe_name + static_strlen(URI_PREFIX_PIPE_SRV),
                                 sizeof(pipe_name) - static_strlen(URI_PREFIX_PIPE_SRV));
    if (ret < 0) {
        return ret;
    }

    lock(&handle->lock);
    /* `setflags` in "fs/socket/fs.c" is the only way to change this flag and it takes `sock->lock`,
     * so using `options` after releasing the lock below is race-free. */
    pal_stream_options_t options = handle->flags & O_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    unlock(&handle->lock);

    PAL_HANDLE pal_handle = NULL;
    ret = PalStreamOpen(pipe_name, PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED, options,
                        &pal_handle);
    if (ret < 0) {
        return (ret == -PAL_ERROR_STREAMEXIST) ? -EADDRINUSE : pal_to_unix_errno(ret);
    }

    __atomic_store_n(&handle->info.sock.pal_handle, pal_handle, __ATOMIC_RELEASE);

    static_assert(sizeof(struct sockaddr_un) < sizeof(sock->local_addr),
                  "need additional space for a nullbyte");
    sock->local_addrlen = addrlen;
    memcpy(&sock->local_addr, addr, sock->local_addrlen);
    /* The address was verified in `unaddr_to_sockname`, so this is safe to call. */
    fixup_sockaddr_un_path(&sock->local_addr, &sock->local_addrlen);

    interrupt_epolls(handle);
    return 0;
}

static int listen(struct libos_handle* handle, unsigned int backlog) {
    /* PAL pipes don't have changeable wait queue size. */
    __UNUSED(backlog);
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    if (sock->type != SOCK_STREAM) {
        return -EOPNOTSUPP;
    }
    /* This socket is already listening - it must have been bound before. */
    assert(sock->state == SOCK_BOUND || sock->state == SOCK_LISTENING);
    return 0;
}

static int accept(struct libos_handle* handle, bool is_nonblocking,
                  struct libos_handle** out_client) {
    pal_stream_options_t options = is_nonblocking ? PAL_OPTION_NONBLOCK : 0;
    PAL_HANDLE pal_handle = __atomic_load_n(&handle->info.sock.pal_handle, __ATOMIC_ACQUIRE);
    /* Since this socket is listening, it must have a PAL handle. */
    assert(pal_handle);
    PAL_HANDLE client_pal_handle;
    int ret = PalStreamWaitForClient(pal_handle, &client_pal_handle, options);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    struct libos_handle* client_handle = get_new_socket_handle(handle->info.sock.domain,
                                                               handle->info.sock.type,
                                                               handle->info.sock.protocol,
                                                               is_nonblocking);
    if (!client_handle) {
        PalObjectClose(client_pal_handle);
        return -ENOMEM;
    }

    struct libos_sock_handle* client_sock = &client_handle->info.sock;
    client_sock->state = SOCK_CONNECTED;
    client_sock->pal_handle = client_pal_handle;
    client_sock->can_be_read = true;
    client_sock->can_be_written = true;
    assert(client_sock->ops == &sock_unix_ops);

    client_sock->remote_addr.ss_family = AF_UNIX;
    client_sock->remote_addrlen = sizeof(client_sock->remote_addr.ss_family);

    lock(&handle->info.sock.lock);
    client_sock->local_addrlen = handle->info.sock.local_addrlen;
    memcpy(&client_sock->local_addr, &handle->info.sock.local_addr, client_sock->local_addrlen);
    unlock(&handle->info.sock.lock);

    *out_client = client_handle;
    return 0;
}

static int connect(struct libos_handle* handle, void* addr, size_t addrlen) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    if (sock->state != SOCK_NEW) {
        log_warning("Gramine does not support connect on already bound UNIX socket");
        return -EINVAL;
    }

    char pipe_name[static_strlen(URI_PREFIX_PIPE) + 64 + 1] = URI_PREFIX_PIPE;
    int ret = unaddr_to_sockname(addr, &addrlen,
                                 pipe_name + static_strlen(URI_PREFIX_PIPE),
                                 sizeof(pipe_name) - static_strlen(URI_PREFIX_PIPE));
    if (ret < 0) {
        return ret;
    }

    lock(&handle->lock);
    /* `setflags` in "fs/socket/fs.c" is the only way to change this flag and it takes `sock->lock`,
     * so using `options` after releasing the lock below is race-free. */
    pal_stream_options_t options = handle->flags & O_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    unlock(&handle->lock);

    PAL_HANDLE pal_handle = NULL;
    ret = PalStreamOpen(pipe_name, PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED, options,
                        &pal_handle);
    if (ret < 0) {
        return (ret == -PAL_ERROR_CONNFAILED) ? -ENOENT : pal_to_unix_errno(ret);
    }

    assert(sock->pal_handle == NULL);
    __atomic_store_n(&sock->pal_handle, pal_handle, __ATOMIC_RELEASE);

    static_assert(sizeof(struct sockaddr_un) < sizeof(sock->remote_addr),
                  "need additional space for a nullbyte");
    sock->remote_addrlen = addrlen;
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

static int disconnect(struct libos_handle* handle) {
    __UNUSED(handle);
    /* We do not support disconnecting UNIX sockets. */
    return -EINVAL;
}

static int set_socket_option(struct libos_handle* handle, int optname, void* optval, size_t len) {
    /* All currently supported options use `int`. */
    int val;
    if (len < sizeof(val)) {
        return -EINVAL;
    }
    memcpy(&val, optval, sizeof(val));

    switch (optname) {
        case SO_REUSEADDR:
            /* This option has no effect on UNIX sockets (we just save the value). */
            handle->info.sock.reuseaddr = !!val;
            break;
        default:
            return -ENOPROTOOPT;
    }
    return 0;
}

static int setsockopt(struct libos_handle* handle, int level, int optname, void* optval,
                      size_t len) {
    assert(locked(&handle->info.sock.lock));

    switch (level) {
        case SOL_SOCKET:
            return set_socket_option(handle, optname, optval, len);
        default:
            return -ENOPROTOOPT;
    }
}

static int getsockopt(struct libos_handle* handle, int level, int optname, void* optval,
                      size_t* len) {
    /* Nothing to do here. */
    __UNUSED(handle);
    __UNUSED(level);
    __UNUSED(optname);
    __UNUSED(optval);
    __UNUSED(len);
    return -ENOPROTOOPT;
}

static int send(struct libos_handle* handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                void* addr, size_t addrlen, bool force_nonblocking) {
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

    if (force_nonblocking) {
        lock(&handle->lock);
        bool handle_is_nonblocking = handle->flags & O_NONBLOCK;
        unlock(&handle->lock);
        if (!handle_is_nonblocking) {
            /* XXX: `PalStreamWrite` has no way of making one-time nonblocking write, so we have no
             * other option but to fail. */
            return -EINVAL;
        }
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
        for (size_t i = 0; i < iov_len; i++) {
            size += iov[i].iov_len;
        }
        backing_buf = malloc(size);
        if (!backing_buf) {
            return -ENOMEM;
        }
        size = 0;
        for (size_t i = 0; i < iov_len; i++) {
            memcpy(backing_buf + size, iov[i].iov_base, iov[i].iov_len);
            size += iov[i].iov_len;
        }
        buf = backing_buf;
        /* `size` is already correct. */
    }

    int ret = PalStreamWrite(pal_handle, /*offset=*/0, &size, buf);
    free(backing_buf);
    if (ret < 0) {
        return (ret == -PAL_ERROR_TOOLONG) ? -EMSGSIZE : pal_to_unix_errno(ret);
    }
    *out_size = size;
    return 0;
}

static int recv(struct libos_handle* handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                void* addr, size_t* addrlen, bool force_nonblocking) {
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

    if (force_nonblocking) {
        lock(&handle->lock);
        bool handle_is_nonblocking = handle->flags & O_NONBLOCK;
        unlock(&handle->lock);
        if (!handle_is_nonblocking) {
            /* XXX: `PalStreamRead` has no way of making one-time nonblocking read, so we have no
             * other option but to fail. */
            return -EINVAL;
        }
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
        for (size_t i = 0; i < iov_len; i++) {
            size += iov[i].iov_len;
        }
        backing_buf = malloc(size);
        if (!backing_buf) {
            return -ENOMEM;
        }
        buf = backing_buf;
        /* `size` is already correct. */
    }

    int ret = PalStreamRead(pal_handle, /*offset=*/0, &size, buf);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
    } else {
        *out_size = size;
        if (backing_buf) {
            /* Need to copy back to user buffers. */
            size_t copied = 0;
            for (size_t i = 0; i < iov_len && copied < size; i++) {
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

struct libos_sock_ops sock_unix_ops = {
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
