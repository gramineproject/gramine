/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Implementation of IPv4 and IPv6 sockets.
 * `handle->info.sock.pal_handle` is always set, hence does not need atomicity on accesses.
 */

#include "pal.h"
#include "shim_fs.h"
#include "shim_socket.h"
#include "socket_utils.h"

static int create(struct shim_handle* handle) {
    assert(handle->info.sock.domain == AF_INET || handle->info.sock.domain == AF_INET6);
    assert(handle->info.sock.type == SOCK_STREAM || handle->info.sock.type == SOCK_DGRAM);

    enum pal_socket_domain pal_domain;
    switch (handle->info.sock.domain) {
        case AF_INET:
            pal_domain = IPV4;
            break;
        case AF_INET6:
            pal_domain = IPV6;
            break;
        default:
            BUG();
    }

    enum pal_socket_type pal_type;
    switch (handle->info.sock.type) {
        case SOCK_STREAM:
            pal_type = PAL_SOCKET_TCP;
            switch (handle->info.sock.protocol) {
                case IPPROTO_IP:
                case IPPROTO_TCP:
                    break;
                default:
                    return -EPROTONOSUPPORT;
            }
            break;
        case SOCK_DGRAM:
            pal_type = PAL_SOCKET_UDP;
            switch (handle->info.sock.protocol) {
                case IPPROTO_IP:
                case IPPROTO_UDP:
                    break;
                default:
                    return -EPROTONOSUPPORT;
            }
            /* UDP sockets are ready for communication instantly. */
            handle->info.sock.read_shutdown = false;
            handle->info.sock.write_shutdown = false;
            break;
        default:
            BUG();
    }

    /* We don't need to take the lock - handle was just created. */
    pal_stream_options_t options = handle->flags & O_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    PAL_HANDLE pal_handle = NULL;
    int ret = DkSocketCreate(pal_domain, pal_type, options, &pal_handle);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    handle->info.sock.pal_handle = pal_handle;
    return 0;
}

static int bind(struct shim_handle* handle, void* _addr, size_t addrlen) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    switch (sock->domain) {
        case AF_INET:;
            struct sockaddr_in* addr = _addr;
            if (addrlen < sizeof(*addr)) {
                return -EINVAL;
            }
            addrlen = sizeof(*addr);
            if (addr->sin_family != AF_INET) {
                return -EAFNOSUPPORT;
            }
            break;
        case AF_INET6:;
            struct sockaddr_in6* addr6 = _addr;
            if (addrlen < sizeof(*addr6)) {
                return -EINVAL;
            }
            addrlen = sizeof(*addr6);
            if (addr6->sin6_family != AF_INET6) {
                return -EAFNOSUPPORT;
            }
            break;
        default:
            __builtin_unreachable();
    }

    struct pal_socket_addr pal_ip_addr;
    linux_to_pal_sockaddr(_addr, &pal_ip_addr);

    int ret = DkSocketBind(sock->pal_handle, &pal_ip_addr);
    if (ret < 0) {
        return (ret == -PAL_ERROR_STREAMEXIST) ? -EADDRINUSE : pal_to_unix_errno(ret);
    }

    pal_to_linux_sockaddr(&pal_ip_addr, &sock->local_addr, &sock->local_addrlen);
    return 0;
}

static int listen(struct shim_handle* handle, unsigned int backlog) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    if (sock->type != SOCK_STREAM) {
        return -EOPNOTSUPP;
    }

    return pal_to_unix_errno(DkSocketListen(sock->pal_handle, backlog));
}

static int accept(struct shim_handle* handle, bool is_nonblocking,
                  struct shim_handle** client_ptr) {
    PAL_HANDLE client_pal_handle;
    struct pal_socket_addr pal_ip_addr = { 0 };
    int ret = DkSocketAccept(handle->info.sock.pal_handle, is_nonblocking ? PAL_OPTION_NONBLOCK : 0,
                             &client_pal_handle, &pal_ip_addr);
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

    if (!create_lock(&client_sock->lock) || !create_lock(&client_sock->recv_lock)) {
        put_handle(client_handle);
        return -ENOMEM;
    }

    size_t len = 0;
    pal_to_linux_sockaddr(&pal_ip_addr, &client_sock->remote_addr, &len);
    client_sock->remote_addrlen = len;

    lock(&handle->info.sock.lock);
    client_sock->local_addrlen = handle->info.sock.local_addrlen;
    memcpy(&client_sock->local_addr, &handle->info.sock.local_addr, client_sock->local_addrlen);
    unlock(&handle->info.sock.lock);

    *client_ptr = client_handle;
    return 0;
}

static int connect(struct shim_handle* handle, void* _addr, size_t addrlen) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    switch (sock->domain) {
        case AF_INET:;
            struct sockaddr_in* addr = _addr;
            if (addrlen < sizeof(*addr)) {
                return -EINVAL;
            }
            addrlen = sizeof(*addr);
            if (addr->sin_family != AF_INET) {
                return -EAFNOSUPPORT;
            }
            break;
        case AF_INET6:;
            struct sockaddr_in6* addr6 = _addr;
            if (addrlen < sizeof(*addr6)) {
                return -EINVAL;
            }
            addrlen = sizeof(*addr6);
            if (addr6->sin6_family != AF_INET6) {
                return -EAFNOSUPPORT;
            }
            break;
        default:
            __builtin_unreachable();
    }

    struct pal_socket_addr pal_ip_addr;
    linux_to_pal_sockaddr(_addr, &pal_ip_addr);
    struct pal_socket_addr pal_local_addr;

    int ret = DkSocketConnect(sock->pal_handle, &pal_ip_addr, &pal_local_addr);
    if (ret < 0) {
        return ret == -PAL_ERROR_CONNFAILED ? -ECONNREFUSED : pal_to_unix_errno(ret);
    }

    memcpy(&sock->remote_addr, _addr, addrlen);
    sock->remote_addrlen = addrlen;
    if (sock->state != SOCK_BOUND) {
        assert(sock->state == SOCK_NEW);
        assert(!sock->was_bound);
        pal_to_linux_sockaddr(&pal_local_addr, &sock->local_addr, &sock->local_addrlen);
    }
    return 0;
}

static int disconnect(struct shim_handle* handle) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    struct pal_socket_addr pal_ip_addr = {
        .domain = PAL_DISCONNECT,
    };
    int ret = DkSocketConnect(sock->pal_handle, &pal_ip_addr, /*local_addr=*/NULL);
    return pal_to_unix_errno(ret);
}

static int set_sock_tcp_option(struct shim_handle* handle, int optname, void* optval, size_t len) {
    PAL_STREAM_ATTR attr;
    int ret = DkStreamAttributesQueryByHandle(handle->info.sock.pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(attr.handle_type == PAL_TYPE_SOCKET);

    if (len < sizeof(int)) {
        /* All currently supported options use `int`. */
        return -EINVAL;
    }

    switch (optname) {
        case TCP_CORK:
            attr.socket.tcp_cork = *(int*)optval;
            break;
        case TCP_NODELAY:
            attr.socket.tcp_nodelay = *(int*)optval;
            break;
        default:
            return -ENOPROTOOPT;
    }

    ret = DkStreamAttributesSetByHandle(handle->info.sock.pal_handle, &attr);
    return pal_to_unix_errno(ret);
}

static int set_sock_ipv6_option(struct shim_handle* handle, int optname, void* optval, size_t len) {
    PAL_STREAM_ATTR attr;
    int ret = DkStreamAttributesQueryByHandle(handle->info.sock.pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(attr.handle_type == PAL_TYPE_SOCKET);

    if (len < sizeof(int)) {
        /* All currently supported options use `int`. */
        return -EINVAL;
    }

    switch (optname) {
        case IPV6_V6ONLY:
            if (handle->info.sock.state != SOCK_NEW) {
                return -EINVAL;
            }
            attr.socket.ipv6_v6only = !!*(int*)optval;
            break;
        default:
            return -ENOPROTOOPT;
    }

    ret = DkStreamAttributesSetByHandle(handle->info.sock.pal_handle, &attr);
    return pal_to_unix_errno(ret);
}

// TODO: maybe inline all functions used here? or at least join them into one - they contain
// some common boilerplate
static int setsockopt(struct shim_handle* handle, int level, int optname, void* optval,
                      size_t len) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    switch (level) {
        case IPPROTO_IP:
            if (sock->domain != AF_INET) {
                return -EOPNOTSUPP;
            }
            /* No option supported at the moment. */
            return -ENOPROTOOPT;
        case IPPROTO_IPV6:
            if (sock->domain != AF_INET6) {
                return -EOPNOTSUPP;
            }
            return set_sock_ipv6_option(handle, optname, optval, len);
        case SOL_TCP:
            if (sock->type != SOCK_STREAM) {
                return -EOPNOTSUPP;
            }
            return set_sock_tcp_option(handle, optname, optval, len);
        default:
            return -ENOPROTOOPT;
    }
}

static int get_sock_tcp_option(struct shim_handle* handle, int optname, void* optval, size_t* len) {
    PAL_STREAM_ATTR attr;
    int ret = DkStreamAttributesQueryByHandle(handle->info.sock.pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(attr.handle_type == PAL_TYPE_SOCKET);

    int val;
    switch (optname) {
        case TCP_CORK:
            val = attr.socket.tcp_cork ? 1 : 0;
            break;
        case TCP_NODELAY:
            val = attr.socket.tcp_nodelay ? 1 : 0;
            break;
        default:
            return -ENOPROTOOPT;
    }

    if (*len > sizeof(val)) {
        *len = sizeof(val);
    }
    memcpy(optval, &val, *len);
    return 0;
}

static int get_sock_ipv6_option(struct shim_handle* handle, int optname, void* optval,
                                size_t* len) {
    PAL_STREAM_ATTR attr;
    int ret = DkStreamAttributesQueryByHandle(handle->info.sock.pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(attr.handle_type == PAL_TYPE_SOCKET);

    int val;
    switch (optname) {
        case IPV6_V6ONLY:
            val = attr.socket.ipv6_v6only ? 1 : 0;
            break;
        default:
            return -ENOPROTOOPT;
    }

    if (*len > sizeof(val)) {
        *len = sizeof(val);
    }
    memcpy(optval, &val, *len);
    return 0;
}

// TODO: maybe inline all functions used here? or at least join them into one - they contain
// some common boilerplate
static int getsockopt(struct shim_handle* handle, int level, int optname, void* optval,
                      size_t* len) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    switch (level) {
        case IPPROTO_IP:
            if (sock->domain != AF_INET) {
                return -EOPNOTSUPP;
            }
            /* No option supported at the moment. */
            return -ENOPROTOOPT;
        case IPPROTO_IPV6:
            if (sock->domain != AF_INET6) {
                return -EOPNOTSUPP;
            }
            return get_sock_ipv6_option(handle, optname, optval, len);
        case SOL_TCP:
            if (sock->type != SOCK_STREAM) {
                return -EOPNOTSUPP;
            }
            return get_sock_tcp_option(handle, optname, optval, len);
        default:
            return -EOPNOTSUPP;
    }
}

static int send(struct shim_handle* handle, struct iovec* iov, size_t iov_len, size_t* size_out,
                void* _addr, size_t addrlen) {
    assert(handle->type == TYPE_SOCK);

    struct shim_sock_handle* sock = &handle->info.sock;
    struct sockaddr_storage sock_addr;

    switch (sock->type) {
        case SOCK_STREAM:
            /* TCP sockets ignore destionation address - they must have been connected. */
            _addr = NULL;
            addrlen = 0;
            break;
        case SOCK_DGRAM:
            if (!_addr) {
                lock(&sock->lock);
                if (sock->remote_addr.ss_family == AF_UNSPEC) {
                    /* Not connected. */
                    unlock(&sock->lock);
                    return -ENOTCONN;
                }
                addrlen = sock->remote_addrlen;
                assert(addrlen <= sizeof(sock_addr));
                memcpy(&sock_addr, &sock->remote_addr, addrlen);
                _addr = &sock_addr;
                unlock(&sock->lock);
            }
            break;
        default:
            __builtin_unreachable();
    }

    struct pal_socket_addr pal_ip_addr;
    if (_addr) {
        switch (sock->domain) {
            case AF_INET:;
                struct sockaddr_in* addr = _addr;
                if (addrlen < sizeof(*addr)) {
                    return -EINVAL;
                }
                if (addr->sin_family != AF_INET) {
                    return -EAFNOSUPPORT;
                }
                break;
            case AF_INET6:;
                struct sockaddr_in6* addr6 = _addr;
                if (addrlen < sizeof(*addr6)) {
                    return -EINVAL;
                }
                if (addr6->sin6_family != AF_INET6) {
                    return -EAFNOSUPPORT;
                }
                break;
            default:
                __builtin_unreachable();
        }
        linux_to_pal_sockaddr(_addr, &pal_ip_addr);
    }

    struct pal_iovec* pal_iov = malloc(iov_len * sizeof(*pal_iov));
    if (!pal_iov) {
        return -ENOMEM;
    }
    for (size_t i = 0; i < iov_len; ++i) {
        pal_iov[i].iov_base = iov[i].iov_base;
        pal_iov[i].iov_len = iov[i].iov_len;
    }

    int ret = DkSocketSend(sock->pal_handle, pal_iov, iov_len, size_out,
                           _addr ? &pal_ip_addr : NULL);
    ret = (ret == -PAL_ERROR_TOOLONG) ? -EMSGSIZE : pal_to_unix_errno(ret);
    free(pal_iov);
    return ret;
}

static int recv(struct shim_handle* handle, struct iovec* iov, size_t iov_len, size_t* size_out,
                void* _addr, size_t* addrlen, bool is_nonblocking) {
    assert(handle->type == TYPE_SOCK);

    switch (handle->info.sock.type) {
        case SOCK_STREAM:
            /* TCP - not interested in remote address (we know it already). */
            _addr = NULL;
            addrlen = 0;
            break;
        case SOCK_DGRAM:
            break;
        default:
            __builtin_unreachable();
    }

    struct pal_iovec* pal_iov = malloc(iov_len * sizeof(*pal_iov));
    if (!pal_iov) {
        return -ENOMEM;
    }
    for (size_t i = 0; i < iov_len; ++i) {
        pal_iov[i].iov_base = iov[i].iov_base;
        pal_iov[i].iov_len = iov[i].iov_len;
    }

    struct pal_socket_addr pal_ip_addr;
    int ret = DkSocketRecv(handle->info.sock.pal_handle, pal_iov, iov_len, size_out,
                           _addr ? &pal_ip_addr : NULL, is_nonblocking);
    free(pal_iov);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    if (_addr) {
        struct sockaddr_storage linux_addr;
        size_t linux_addr_len = sizeof(linux_addr);
        pal_to_linux_sockaddr(&pal_ip_addr, &linux_addr, &linux_addr_len);
        memcpy(_addr, &linux_addr, MIN(*addrlen, linux_addr_len));
        *addrlen = linux_addr_len;
    }
    return 0;
}

struct shim_sock_ops sock_ip_ops = {
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
