/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Implementation of IPv4 and IPv6 sockets.
 * For such sockets `handle->info.sock.pal_handle` is always set, hence does not need atomicity on
 * accesses.
 */

#include "libos_fs.h"
#include "libos_socket.h"
#include "pal.h"
#include "socket_utils.h"

static int verify_sockaddr(int expected_family, void* addr, size_t* addrlen) {
    unsigned short family;
    switch (expected_family) {
        case AF_INET:
            if (*addrlen < sizeof(struct sockaddr_in)) {
                return -EINVAL;
            }
            memcpy(&family, (char*)addr + offsetof(struct sockaddr_in, sin_family), sizeof(family));
            if (family != AF_INET) {
                return -EAFNOSUPPORT;
            }
            /* Cap the address at the maximal possible size - rest of the input buffer (if any) is
             * ignored. */
            *addrlen = sizeof(struct sockaddr_in);
            break;
        case AF_INET6:
            if (*addrlen < sizeof(struct sockaddr_in6)) {
                return -EINVAL;
            }
            memcpy(&family, (char*)addr + offsetof(struct sockaddr_in6, sin6_family),
                   sizeof(family));
            if (family != AF_INET6) {
                return -EAFNOSUPPORT;
            }
            /* Cap the address at the maximal possible size - rest of the input buffer (if any) is
             * ignored. */
            *addrlen = sizeof(struct sockaddr_in6);
            break;
        default:
            BUG();
    }
    return 0;
}

static bool is_linux_sockaddr_any(const void* linux_addr) {
    unsigned short family;
    memcpy(&family, linux_addr, sizeof(family));

    switch (family) {
        case AF_INET:;
            struct sockaddr_in sa_ipv4;
            memcpy(&sa_ipv4, linux_addr, sizeof(sa_ipv4));
            if (sa_ipv4.sin_addr.s_addr == __htonl(INADDR_ANY)) {
                return true;
            }
            break;
        case AF_INET6:;
            struct sockaddr_in6 sa_ipv6;
            memcpy(&sa_ipv6, linux_addr, sizeof(sa_ipv6));
            if (memcmp(&sa_ipv6.sin6_addr, &(struct in6_addr){ 0 },
                       sizeof(sa_ipv6.sin6_addr)) == 0) {
                return true;
            }
            break;
        default:
            BUG();
     };
     return false;
}

static int create(struct libos_handle* handle) {
    assert(handle->info.sock.domain == AF_INET || handle->info.sock.domain == AF_INET6);
    assert(handle->info.sock.type == SOCK_STREAM || handle->info.sock.type == SOCK_DGRAM);

    enum pal_socket_domain pal_domain;
    switch (handle->info.sock.domain) {
        case AF_INET:
            pal_domain = PAL_IPV4;
            break;
        case AF_INET6:
            pal_domain = PAL_IPV6;
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
            handle->info.sock.can_be_read = true;
            handle->info.sock.can_be_written = true;
            break;
        default:
            BUG();
    }

    /* We don't need to take the lock - handle was just created. */
    pal_stream_options_t options = handle->flags & O_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    PAL_HANDLE pal_handle = NULL;
    int ret = PalSocketCreate(pal_domain, pal_type, options, &pal_handle);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    handle->info.sock.pal_handle = pal_handle;
    return 0;
}

static int bind(struct libos_handle* handle, void* addr, size_t addrlen) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    int ret = verify_sockaddr(sock->domain, addr, &addrlen);
    if (ret < 0) {
        return ret;
    }

    struct pal_socket_addr pal_ip_addr;
    linux_to_pal_sockaddr(addr, &pal_ip_addr);

    ret = PalSocketBind(sock->pal_handle, &pal_ip_addr);
    if (ret < 0) {
        return (ret == -PAL_ERROR_STREAMEXIST) ? -EADDRINUSE : pal_to_unix_errno(ret);
    }

    pal_to_linux_sockaddr(&pal_ip_addr, &sock->local_addr, &sock->local_addrlen);
    return 0;
}

static int listen(struct libos_handle* handle, unsigned int backlog) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    if (sock->type != SOCK_STREAM) {
        return -EOPNOTSUPP;
    }

    return pal_to_unix_errno(PalSocketListen(sock->pal_handle, backlog));
}

static int accept(struct libos_handle* handle, bool is_nonblocking,
                  struct libos_handle** out_client) {
    PAL_HANDLE client_pal_handle;
    struct pal_socket_addr pal_ip_addr = { 0 };
    struct pal_socket_addr pal_local_ip_addr = { 0 };
    int ret = PalSocketAccept(handle->info.sock.pal_handle, is_nonblocking ? PAL_OPTION_NONBLOCK : 0,
                              &client_pal_handle, &pal_ip_addr, &pal_local_ip_addr);
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
    assert(client_sock->ops == &sock_ip_ops);

    size_t len = 0;
    pal_to_linux_sockaddr(&pal_ip_addr, &client_sock->remote_addr, &len);
    client_sock->remote_addrlen = len;

    lock(&handle->info.sock.lock);
    if (is_linux_sockaddr_any(&handle->info.sock.local_addr)) {
        pal_to_linux_sockaddr(&pal_local_ip_addr, &client_sock->local_addr, &len);
        client_sock->local_addrlen = len;
    } else {
        client_sock->local_addrlen = handle->info.sock.local_addrlen;
        memcpy(&client_sock->local_addr, &handle->info.sock.local_addr, client_sock->local_addrlen);
    }
    unlock(&handle->info.sock.lock);

    *out_client = client_handle;
    return 0;
}

static int connect(struct libos_handle* handle, void* addr, size_t addrlen) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    int ret = verify_sockaddr(sock->domain, addr, &addrlen);
    if (ret < 0) {
        return ret;
    }

    struct pal_socket_addr pal_remote_addr;
    linux_to_pal_sockaddr(addr, &pal_remote_addr);
    struct pal_socket_addr pal_local_addr;

    /* XXX: this connect is always blocking (regardless of actual setting of nonblockingness on
     * `sock->pal_handle`. See also the comment in tcp connect implementation in Linux PAL. */
    ret = PalSocketConnect(sock->pal_handle, &pal_remote_addr, &pal_local_addr);
    if (ret < 0) {
        return ret == -PAL_ERROR_CONNFAILED ? -ECONNREFUSED : pal_to_unix_errno(ret);
    }

    memcpy(&sock->remote_addr, addr, addrlen);
    sock->remote_addrlen = addrlen;
    if (sock->state != SOCK_BOUND) {
        assert(sock->state == SOCK_NEW);
        assert(!sock->was_bound);
        pal_to_linux_sockaddr(&pal_local_addr, &sock->local_addr, &sock->local_addrlen);
    }
    return 0;
}

static int disconnect(struct libos_handle* handle) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    struct pal_socket_addr pal_ip_addr = {
        .domain = PAL_DISCONNECT,
    };
    int ret = PalSocketConnect(sock->pal_handle, &pal_ip_addr, /*local_addr=*/NULL);
    return pal_to_unix_errno(ret);
}

static int set_tcp_option(struct libos_handle* handle, int optname, void* optval, size_t len) {
    PAL_STREAM_ATTR attr;
    int ret = PalStreamAttributesQueryByHandle(handle->info.sock.pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(attr.handle_type == PAL_TYPE_SOCKET);

    /* All currently supported options use `int`. */
    size_t required_len = sizeof(int);
    if (len < required_len) {
        return -EINVAL;
    }

    union {
        int i;
    } value = { 0 };
    memcpy(&value, optval, required_len);

    switch (optname) {
        case TCP_CORK:
            attr.socket.tcp_cork = value.i;
            break;
        case TCP_KEEPIDLE:
            if (value.i < 1 || value.i > MAX_TCP_KEEPIDLE) {
                return -EINVAL;
            }
            attr.socket.tcp_keepidle = value.i;
            break;
        case TCP_KEEPINTVL:
            if (value.i < 1 || value.i > MAX_TCP_KEEPINTVL) {
                return -EINVAL;
            }
            attr.socket.tcp_keepintvl = value.i;
            break;
        case TCP_KEEPCNT:
            if (value.i < 1 || value.i > MAX_TCP_KEEPCNT) {
                return -EINVAL;
            }
            attr.socket.tcp_keepcnt = value.i;
            break;
        case TCP_NODELAY:
            attr.socket.tcp_nodelay = value.i;
            break;
        case TCP_USER_TIMEOUT:
            if (value.i < 0) {
                return -EINVAL;
            }
            attr.socket.tcp_user_timeout = value.i;
            break;
        default:
            return -ENOPROTOOPT;
    }

    ret = PalStreamAttributesSetByHandle(handle->info.sock.pal_handle, &attr);
    return pal_to_unix_errno(ret);
}

static int set_ipv4_option(struct libos_handle* handle, int optname, void* optval, size_t len) {
    __UNUSED(handle);
    __UNUSED(optval);
    if (optname == IP_RECVERR) {
        if (len < sizeof(int)) {
            return -EINVAL;
        }
        /* We ignore this option. Full support would require handling `MSG_ERRQUEUE` in `recvmsg`
         * syscall (which now fails with `-EOPNOTSUPP` if this flag is passed), which would be hard
         * to implement. This basically defers the moment the app notices this error reporting
         * mechanism is not supported from `setsockopt` call to when actual error condition on
         * the socket happens (which might be never). */
        return 0;
    }

    /* No other option supported at the moment. */
    return -ENOPROTOOPT;
}

static int set_ipv6_option(struct libos_handle* handle, int optname, void* optval, size_t len) {
    PAL_STREAM_ATTR attr;
    int ret = PalStreamAttributesQueryByHandle(handle->info.sock.pal_handle, &attr);
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
        case IPV6_RECVERR:
            /* See the comment in `set_ipv4_option` for why we handle it this way. */
            return 0;
        default:
            return -ENOPROTOOPT;
    }

    ret = PalStreamAttributesSetByHandle(handle->info.sock.pal_handle, &attr);
    return pal_to_unix_errno(ret);
}

static int set_socket_option(struct libos_handle* handle, int optname, void* optval, size_t len) {
    struct libos_sock_handle* sock = &handle->info.sock;
    PAL_STREAM_ATTR attr;
    int ret = PalStreamAttributesQueryByHandle(sock->pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(attr.handle_type == PAL_TYPE_SOCKET);

    size_t required_len;
    switch (optname) {
        case SO_KEEPALIVE:
            required_len = sizeof(int);
            break;
        case SO_LINGER:
            required_len = sizeof(struct linger);
            break;
        case SO_RCVBUF:
            required_len = sizeof(int);
            break;
        case SO_SNDBUF:
            required_len = sizeof(int);
            break;
        case SO_RCVTIMEO:
            required_len = sizeof(struct timeval);
            break;
        case SO_SNDTIMEO:
            required_len = sizeof(struct timeval);
            break;
        case SO_REUSEADDR:
            required_len = sizeof(int);
            break;
        case SO_REUSEPORT:
            required_len = sizeof(int);
            break;
        case SO_BROADCAST:
            required_len = sizeof(int);
            break;
        default:
            return -ENOPROTOOPT;
    }

    if (len < required_len) {
        return -EINVAL;
    }

    union {
        int i;
        struct linger linger;
        struct timeval tv;
    } value = { 0 };
    memcpy(&value, optval, required_len);

    bool need_pal_set = true;
    switch (optname) {
        case SO_KEEPALIVE:
            attr.socket.keepalive = value.i;
            break;
        case SO_LINGER:
            if (value.linger.l_onoff) {
                if (value.linger.l_linger < 0) {
                    return -EINVAL;
                }
                attr.socket.linger = value.linger.l_linger;
            } else {
                attr.socket.linger = 0;
            }
            break;
        case SO_RCVBUF:
            if (value.i < 0) {
                return -EINVAL;
            }
            /* The Linux kernel doubles this value. */
            value.i = MIN(value.i, INT_MAX / 2);
            value.i *= 2;
            attr.socket.recv_buf_size = value.i;
            break;
        case SO_SNDBUF:
            if (value.i < 0) {
                return -EINVAL;
            }
            /* The Linux kernel doubles this value. */
            value.i = MIN(value.i, INT_MAX / 2);
            value.i *= 2;
            attr.socket.send_buf_size = value.i;
            break;
        case SO_RCVTIMEO:
            if (value.tv.tv_sec < 0 || value.tv.tv_usec < 0
                    || (unsigned long)value.tv.tv_usec >= TIME_US_IN_S) {
                return -EINVAL;
            }
            attr.socket.receivetimeout_us = value.tv.tv_sec * TIME_US_IN_S + value.tv.tv_usec;
            break;
        case SO_SNDTIMEO:
            if (value.tv.tv_sec < 0 || value.tv.tv_usec < 0
                    || (unsigned long)value.tv.tv_usec >= TIME_US_IN_S) {
                return -EINVAL;
            }
            attr.socket.sendtimeout_us = value.tv.tv_sec * TIME_US_IN_S + value.tv.tv_usec;
            break;
        case SO_REUSEADDR:
            attr.socket.reuseaddr = value.i;
            break;
        case SO_REUSEPORT:
            attr.socket.reuseport = value.i;
            break;
        case SO_BROADCAST:
            if (sock->type == SOCK_STREAM) {
                /* This option has no effect on stream-oriented sockets. */
                need_pal_set = false;
            }
            attr.socket.broadcast = value.i;
            break;
    }

    if (need_pal_set) {
        ret = PalStreamAttributesSetByHandle(sock->pal_handle, &attr);
        if (ret < 0) {
            return pal_to_unix_errno(ret);
        }
    }

    /* Cache values in LibOS. */
    switch (optname) {
        case SO_REUSEADDR:
            sock->reuseaddr = attr.socket.reuseaddr;
            break;
        case SO_REUSEPORT:
            sock->reuseport = attr.socket.reuseport;
            break;
        case SO_BROADCAST:
            sock->broadcast = attr.socket.broadcast;
            break;
        case SO_RCVTIMEO:
            sock->receivetimeout_us = attr.socket.receivetimeout_us;
            break;
        case SO_SNDTIMEO:
            sock->sendtimeout_us = attr.socket.sendtimeout_us;
            break;
    }
    return 0;
}

static int setsockopt(struct libos_handle* handle, int level, int optname, void* optval,
                      size_t len) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    switch (level) {
        case SOL_SOCKET:
            return set_socket_option(handle, optname, optval, len);
        case IPPROTO_IP:
            if (sock->domain != AF_INET) {
                return -EOPNOTSUPP;
            }
            return set_ipv4_option(handle, optname, optval, len);
        case IPPROTO_IPV6:
            if (sock->domain != AF_INET6) {
                return -EOPNOTSUPP;
            }
            return set_ipv6_option(handle, optname, optval, len);
        case SOL_TCP:
            if (sock->type != SOCK_STREAM) {
                return -EOPNOTSUPP;
            }
            return set_tcp_option(handle, optname, optval, len);
        default:
            return -ENOPROTOOPT;
    }
}

static int get_tcp_option(struct libos_handle* handle, int optname, void* optval, size_t* len) {
    PAL_STREAM_ATTR attr;
    int ret = PalStreamAttributesQueryByHandle(handle->info.sock.pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(attr.handle_type == PAL_TYPE_SOCKET);

    int val;
    switch (optname) {
        case TCP_CORK:
            val = attr.socket.tcp_cork;
            break;
        case TCP_KEEPIDLE:
            val = attr.socket.tcp_keepidle;
            break;
        case TCP_KEEPINTVL:
            val = attr.socket.tcp_keepintvl;
            break;
        case TCP_KEEPCNT:
            val = attr.socket.tcp_keepcnt;
            break;
        case TCP_NODELAY:
            val = attr.socket.tcp_nodelay;
            break;
        case TCP_USER_TIMEOUT:
            val = attr.socket.tcp_user_timeout;
            break;
        default:
            return -ENOPROTOOPT;
    }

    if (*len > sizeof(val)) {
        /* Cap the buffer size to the option size. */
        *len = sizeof(val);
    }
    memcpy(optval, &val, *len);
    return 0;
}

static int get_ipv6_option(struct libos_handle* handle, int optname, void* optval, size_t* len) {
    PAL_STREAM_ATTR attr;
    int ret = PalStreamAttributesQueryByHandle(handle->info.sock.pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(attr.handle_type == PAL_TYPE_SOCKET);

    int val;
    switch (optname) {
        case IPV6_V6ONLY:
            val = attr.socket.ipv6_v6only;
            break;
        default:
            return -ENOPROTOOPT;
    }

    if (*len > sizeof(val)) {
        /* Cap the buffer size to the option size. */
        *len = sizeof(val);
    }
    memcpy(optval, &val, *len);
    return 0;
}

static int get_socket_option(struct libos_handle* handle, int optname, void* optval, size_t* len) {
    struct libos_sock_handle* sock = &handle->info.sock;
    PAL_STREAM_ATTR attr;
    int ret = PalStreamAttributesQueryByHandle(sock->pal_handle, &attr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(attr.handle_type == PAL_TYPE_SOCKET);

    union {
        int i;
        struct linger linger;
    } value = { 0 };
    size_t value_len = sizeof(int);

    switch (optname) {
        case SO_KEEPALIVE:
            value.i = attr.socket.keepalive;
            break;
        case SO_LINGER:
            value.linger.l_onoff = attr.socket.linger ? 1 : 0;
            value.linger.l_linger = attr.socket.linger;
            value_len = sizeof(value.linger);
            break;
        case SO_RCVBUF:
            value.i = attr.socket.recv_buf_size;
            break;
        case SO_SNDBUF:
            value.i = attr.socket.send_buf_size;
            break;
        default:
            return -ENOPROTOOPT;
    }

    if (*len > value_len) {
        *len = value_len;
    }
    memcpy(optval, &value, *len);
    return 0;
}

static int getsockopt(struct libos_handle* handle, int level, int optname, void* optval,
                      size_t* len) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    switch (level) {
        case SOL_SOCKET:
            return get_socket_option(handle, optname, optval, len);
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
            return get_ipv6_option(handle, optname, optval, len);
        case SOL_TCP:
            if (sock->type != SOCK_STREAM) {
                return -EOPNOTSUPP;
            }
            return get_tcp_option(handle, optname, optval, len);
        default:
            return -EOPNOTSUPP;
    }
}

static int send(struct libos_handle* handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                void* addr, size_t addrlen, bool force_nonblocking) {
    assert(handle->type == TYPE_SOCK);

    struct libos_sock_handle* sock = &handle->info.sock;
    struct sockaddr_storage sock_addr;

    switch (sock->type) {
        case SOCK_STREAM:
            /* TCP sockets ignore destination address - they must have been connected. */
            addr = NULL;
            addrlen = 0;
            break;
        case SOCK_DGRAM:
            if (!addr) {
                lock(&sock->lock);
                if (sock->remote_addr.ss_family == AF_UNSPEC) {
                    /* Not connected. */
                    unlock(&sock->lock);
                    return -ENOTCONN;
                }
                addrlen = sock->remote_addrlen;
                assert(addrlen <= sizeof(sock_addr));
                memcpy(&sock_addr, &sock->remote_addr, addrlen);
                addr = &sock_addr;
                unlock(&sock->lock);
            }
            break;
        default:
            __builtin_unreachable();
    }

    struct pal_socket_addr pal_ip_addr;
    if (addr) {
        int ret = verify_sockaddr(sock->domain, addr, &addrlen);
        if (ret < 0) {
            return ret;
        }
        linux_to_pal_sockaddr(addr, &pal_ip_addr);
    }

    int ret = PalSocketSend(sock->pal_handle, iov, iov_len, out_size, addr ? &pal_ip_addr : NULL,
                            force_nonblocking);
    ret = (ret == -PAL_ERROR_TOOLONG) ? -EMSGSIZE : pal_to_unix_errno(ret);
    return ret;
}

static int recv(struct libos_handle* handle, struct iovec* iov, size_t iov_len,
                size_t* out_total_size, void* addr, size_t* addrlen, bool force_nonblocking) {
    assert(handle->type == TYPE_SOCK);

    switch (handle->info.sock.type) {
        case SOCK_STREAM:
            /* TCP - not interested in remote address (we know it already). */
            addr = NULL;
            addrlen = NULL;
            break;
        case SOCK_DGRAM:
            break;
        default:
            __builtin_unreachable();
    }

    struct pal_socket_addr pal_ip_addr;
    int ret = PalSocketRecv(handle->info.sock.pal_handle, iov, iov_len, out_total_size,
                            addr ? &pal_ip_addr : NULL, force_nonblocking);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    if (addr) {
        struct sockaddr_storage linux_addr;
        size_t linux_addr_len = sizeof(linux_addr);
        pal_to_linux_sockaddr(&pal_ip_addr, &linux_addr, &linux_addr_len);
        /* If the user provided buffer is too small, the address is truncated, but we report
         * the actual address size in `addrlen`. */
        memcpy(addr, &linux_addr, MIN(*addrlen, linux_addr_len));
        *addrlen = linux_addr_len;
    }
    return 0;
}

struct libos_sock_ops sock_ip_ops = {
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
