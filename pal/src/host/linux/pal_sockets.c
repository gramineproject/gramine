/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <asm/ioctls.h>
#include <asm/poll.h>
#include <limits.h>
#include <linux/time.h>

#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "socket_utils.h"

static struct handle_ops g_tcp_handle_ops;
static struct handle_ops g_udp_handle_ops;
static struct socket_ops g_tcp_sock_ops;
static struct socket_ops g_udp_sock_ops;

static size_t g_default_recv_buf_size = 0;
static size_t g_default_send_buf_size = 0;

static PAL_HANDLE create_sock_handle(int fd, enum pal_socket_domain domain,
                                     enum pal_socket_type type, struct handle_ops* handle_ops,
                                     struct socket_ops* ops, bool is_nonblocking) {
    PAL_HANDLE handle = calloc(1, sizeof(*handle));
    if (!handle) {
        return NULL;
    }

    handle->hdr.type = PAL_TYPE_SOCKET;
    handle->hdr.ops = handle_ops;
    handle->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    handle->sock.fd = fd;
    handle->sock.domain = domain;
    handle->sock.type = type;
    handle->sock.ops = ops;

    handle->sock.recv_buf_size = __atomic_load_n(&g_default_recv_buf_size, __ATOMIC_RELAXED);
    if (!handle->sock.recv_buf_size) {
        int val = 0;
        int len = sizeof(val);
        int ret = DO_SYSCALL(getsockopt, fd, SOL_SOCKET, SO_RCVBUF, &val, &len);
        if (ret < 0) {
            log_error("getsockopt SO_RCVBUF failed: %s", unix_strerror(ret));
            free(handle);
            return NULL;
        }
        handle->sock.recv_buf_size = val;
        __atomic_store_n(&g_default_recv_buf_size, val, __ATOMIC_RELAXED);
    }

    handle->sock.send_buf_size = __atomic_load_n(&g_default_send_buf_size, __ATOMIC_RELAXED);
    if (!handle->sock.send_buf_size) {
        int val = 0;
        int len = sizeof(val);
        int ret = DO_SYSCALL(getsockopt, fd, SOL_SOCKET, SO_SNDBUF, &val, &len);
        if (ret < 0) {
            log_error("getsockopt SO_SNDBUF failed: %s", unix_strerror(ret));
            free(handle);
            return NULL;
        }
        handle->sock.send_buf_size = val;
        __atomic_store_n(&g_default_send_buf_size, val, __ATOMIC_RELAXED);
    }

    handle->sock.linger = 0;
    handle->sock.recvtimeout_us = 0;
    handle->sock.sendtimeout_us = 0;
    handle->sock.is_nonblocking = is_nonblocking;
    handle->sock.reuseaddr = false;
    handle->sock.reuseport = false;
    handle->sock.broadcast = false;
    handle->sock.keepalive = false;
    handle->sock.tcp_cork = false;
    handle->sock.tcp_keepidle = DEFAULT_TCP_KEEPIDLE;
    handle->sock.tcp_keepintvl = DEFAULT_TCP_KEEPINTVL;
    handle->sock.tcp_keepcnt = DEFAULT_TCP_KEEPCNT;
    handle->sock.tcp_user_timeout = DEFAULT_TCP_USER_TIMEOUT;
    handle->sock.tcp_nodelay = false;
    handle->sock.ipv6_v6only = false;

    return handle;
}

int _PalSocketCreate(enum pal_socket_domain domain, enum pal_socket_type type,
                     pal_stream_options_t options, PAL_HANDLE* out_handle) {
    int linux_domain;
    int linux_type;
    switch (domain) {
        case PAL_IPV4:
            linux_domain = AF_INET;
            break;
        case PAL_IPV6:
            linux_domain = AF_INET6;
            break;
        default:
            BUG();
    }
    struct handle_ops* handle_ops = NULL;
    struct socket_ops* sock_ops = NULL;
    switch (type) {
        case PAL_SOCKET_TCP:
            linux_type = SOCK_STREAM;
            handle_ops = &g_tcp_handle_ops;
            sock_ops = &g_tcp_sock_ops;
            break;
        case PAL_SOCKET_UDP:
            linux_type = SOCK_DGRAM;
            handle_ops = &g_udp_handle_ops;
            sock_ops = &g_udp_sock_ops;
            break;
        default:
            BUG();
    }

    if (options & PAL_OPTION_NONBLOCK) {
        linux_type |= SOCK_NONBLOCK;
    }
    linux_type |= SOCK_CLOEXEC;

    int fd = DO_SYSCALL(socket, linux_domain, linux_type, 0);
    if (fd < 0) {
        return unix_to_pal_error(fd);
    }

    PAL_HANDLE handle = create_sock_handle(fd, domain, type, handle_ops, sock_ops,
                                           !!(options & PAL_OPTION_NONBLOCK));
    if (!handle) {
        int ret = DO_SYSCALL(close, fd);
        if (ret < 0) {
            log_error("closing socket fd failed: %s", unix_strerror(ret));
        }
        return -PAL_ERROR_NOMEM;
    }

    *out_handle = handle;
    return 0;
}

static void destroy(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    int ret = DO_SYSCALL(close, handle->sock.fd);
    if (ret < 0) {
        log_error("closing socket host fd %d failed: %s", handle->sock.fd, unix_strerror(ret));
        /* We cannot do anything about it anyway... */
    }

    free(handle);
}

static int do_getsockname(int fd, struct sockaddr_storage* sa_storage) {
    int linux_addrlen_int = sizeof(*sa_storage);
    int ret = DO_SYSCALL(getsockname, fd, sa_storage, &linux_addrlen_int);
    return unix_to_pal_error(ret);
}

static int bind(PAL_HANDLE handle, struct pal_socket_addr* addr) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    if (addr->domain != handle->sock.domain) {
        return -PAL_ERROR_INVAL;
    }

    union {
        struct sockaddr_storage sa_storage;
        struct sockaddr_in addr_ipv4;
        struct sockaddr_in6 addr_ipv6;
    } linux_addr;
    size_t linux_addrlen;
    pal_to_linux_sockaddr(addr, &linux_addr.sa_storage, &linux_addrlen);
    assert(linux_addrlen <= INT_MAX);

    int ret = DO_SYSCALL(bind, handle->sock.fd, &linux_addr.sa_storage, (int)linux_addrlen);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    switch (addr->domain) {
        case PAL_IPV4:
            if (!addr->ipv4.port) {
                ret = do_getsockname(handle->sock.fd, &linux_addr.sa_storage);
                if (ret < 0) {
                    /* This should never happen, but we have to handle it somehow. Socket was bound,
                     * but something is wrong... */
                    return ret;
                }
                assert(linux_addr.addr_ipv4.sin_family == AF_INET);
                addr->ipv4.port = linux_addr.addr_ipv4.sin_port;
            }
            break;
        case PAL_IPV6:
            if (!addr->ipv6.port) {
                ret = do_getsockname(handle->sock.fd, &linux_addr.sa_storage);
                if (ret < 0) {
                    /* This should never happen, but we have to handle it somehow. Socket was bound,
                     * but something is wrong... */
                    return ret;
                }
                assert(linux_addr.addr_ipv6.sin6_family == AF_INET6);
                addr->ipv6.port = linux_addr.addr_ipv6.sin6_port;
            }
            break;
        default:
            BUG();
    }
    return 0;
}

static int tcp_listen(PAL_HANDLE handle, unsigned int backlog) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    int ret = DO_SYSCALL(listen, handle->sock.fd, backlog);
    return unix_to_pal_error(ret);
}

static int tcp_accept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                      struct pal_socket_addr* out_client_addr,
                      struct pal_socket_addr* out_local_addr) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    struct sockaddr_storage client_addr = { 0 };
    int client_addrlen = sizeof(client_addr);
    int flags = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;
    flags |= SOCK_CLOEXEC;

    int fd = DO_SYSCALL(accept4, handle->sock.fd, &client_addr, &client_addrlen, flags);
    if (fd < 0) {
        return unix_to_pal_error(fd);
    }

    PAL_HANDLE client = create_sock_handle(fd, handle->sock.domain, handle->sock.type,
                                           handle->hdr.ops, handle->sock.ops,
                                           !!(options & PAL_OPTION_NONBLOCK));
    if (!client) {
        int ret = DO_SYSCALL(close, fd);
        if (ret < 0) {
            log_error("closing socket fd failed: %s", unix_strerror(ret));
        }
        return -PAL_ERROR_NOMEM;
    }

    if (out_local_addr) {
        struct sockaddr_storage local_addr = { 0 };
        int ret = do_getsockname(fd, &local_addr);
        if (ret < 0) {
            /* This should never happen, but we have to handle it somehow. */
            _PalObjectDestroy(client);
            return ret;
        }
        linux_to_pal_sockaddr(&local_addr, out_local_addr);
        assert(out_local_addr->domain == client->sock.domain);
    }

    *out_client = client;
    if (out_client_addr) {
        linux_to_pal_sockaddr(&client_addr, out_client_addr);
        assert(out_client_addr->domain == client->sock.domain);
    }

    return 0;
}

static int connect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                   struct pal_socket_addr* out_local_addr, bool* out_inprogress) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    if (addr->domain != PAL_DISCONNECT && addr->domain != handle->sock.domain) {
        return -PAL_ERROR_INVAL;
    }

    struct sockaddr_storage sa_storage;
    size_t linux_addrlen;
    pal_to_linux_sockaddr(addr, &sa_storage, &linux_addrlen);
    assert(linux_addrlen <= INT_MAX);

    int ret = DO_SYSCALL(connect, handle->sock.fd, &sa_storage, (int)linux_addrlen);
    if (ret < 0 && ret != -EINPROGRESS) {
        return unix_to_pal_error(ret);
    }

    /* Connect succeeded or in progress (EINPROGRESS); in both cases retrieve local name -- host
     * Linux binds the socket to address even in case of EINPROGRESS */
    if (out_local_addr) {
        int getsockname_ret = do_getsockname(handle->sock.fd, &sa_storage);
        if (getsockname_ret < 0) {
            /* This should never happen, but we have to handle it somehow. */
            return getsockname_ret;
        }
        linux_to_pal_sockaddr(&sa_storage, out_local_addr);
    }

    /* POSIX/Linux have an unusual semantics for EINPROGRESS: the connect operation is considered
     * successful, but the return value is -EINPROGRESS error code. We don't want to replicate this
     * oddness in Gramine, so we return `0` and set a special variable. */
    *out_inprogress = (ret == -EINPROGRESS);
    return 0;
}

static int attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    memset(attr, 0, sizeof(*attr));

    attr->handle_type = PAL_TYPE_SOCKET;
    attr->nonblocking = handle->sock.is_nonblocking;

    int val = 0;
    int ret = DO_SYSCALL(ioctl, handle->sock.fd, FIONREAD, &val);
    attr->pending_size = ret >= 0 && val >= 0 ? val : 0;

    attr->socket.linger = handle->sock.linger;
    attr->socket.recv_buf_size = handle->sock.recv_buf_size;
    attr->socket.send_buf_size = handle->sock.send_buf_size;
    attr->socket.receivetimeout_us = handle->sock.recvtimeout_us;
    attr->socket.sendtimeout_us = handle->sock.sendtimeout_us;
    attr->socket.reuseaddr = handle->sock.reuseaddr;
    attr->socket.reuseport = handle->sock.reuseport;
    attr->socket.broadcast = handle->sock.broadcast;
    attr->socket.keepalive = handle->sock.keepalive;
    attr->socket.tcp_cork = handle->sock.tcp_cork;
    attr->socket.tcp_keepidle = handle->sock.tcp_keepidle;
    attr->socket.tcp_keepintvl = handle->sock.tcp_keepintvl;
    attr->socket.tcp_keepcnt = handle->sock.tcp_keepcnt;
    attr->socket.tcp_nodelay = handle->sock.tcp_nodelay;
    attr->socket.tcp_user_timeout = handle->sock.tcp_user_timeout;
    attr->socket.ipv6_v6only = handle->sock.ipv6_v6only;

    return 0;
};

/* Warning: if this is used to change two fields and the second set fails, the first set is not
 * undone. */
static int attrsetbyhdl_common(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    if (attr->handle_type != PAL_TYPE_SOCKET) {
        return -PAL_ERROR_INVAL;
    }

    if (attr->nonblocking != handle->sock.is_nonblocking) {
        int ret = DO_SYSCALL(fcntl, handle->sock.fd, F_GETFL);
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        int flags = ret;
        if (attr->nonblocking) {
            flags |= O_NONBLOCK;
        } else {
            flags &= ~O_NONBLOCK;
        }
        ret = DO_SYSCALL(fcntl, handle->sock.fd, F_SETFL, flags);
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.is_nonblocking = attr->nonblocking;
    }

    if (attr->socket.linger != handle->sock.linger) {
        if (attr->socket.linger > INT_MAX) {
            return -PAL_ERROR_INVAL;
        }
        struct linger linger = {
            .l_onoff = attr->socket.linger ? 1 : 0,
            .l_linger = attr->socket.linger,
        };
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_LINGER, &linger,
                             sizeof(linger));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.linger = attr->socket.linger;
    }

    if (attr->socket.recv_buf_size != handle->sock.recv_buf_size) {
        if (attr->socket.recv_buf_size > INT_MAX || attr->socket.recv_buf_size % 2) {
            return -PAL_ERROR_INVAL;
        }
        /* The Linux kernel will double this value. */
        int val = attr->socket.recv_buf_size / 2;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.recv_buf_size = attr->socket.recv_buf_size;
    }

    if (attr->socket.send_buf_size != handle->sock.send_buf_size) {
        if (attr->socket.send_buf_size > INT_MAX || attr->socket.send_buf_size % 2) {
            return -PAL_ERROR_INVAL;
        }
        /* The Linux kernel will double this value. */
        int val = attr->socket.send_buf_size / 2;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.send_buf_size = attr->socket.send_buf_size;
    }

    if (attr->socket.receivetimeout_us != handle->sock.recvtimeout_us) {
        struct timeval tv = {
            .tv_sec = attr->socket.receivetimeout_us / TIME_US_IN_S,
            .tv_usec = attr->socket.receivetimeout_us % TIME_US_IN_S,
        };
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.recvtimeout_us = attr->socket.receivetimeout_us;
    }

    if (attr->socket.sendtimeout_us != handle->sock.sendtimeout_us) {
        struct timeval tv = {
            .tv_sec = attr->socket.sendtimeout_us / TIME_US_IN_S,
            .tv_usec = attr->socket.sendtimeout_us % TIME_US_IN_S,
        };
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.sendtimeout_us = attr->socket.sendtimeout_us;
    }

    if (attr->socket.keepalive != handle->sock.keepalive) {
        int val = attr->socket.keepalive;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_KEEPALIVE, &val,
                             sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.keepalive = attr->socket.keepalive;
    }

    if (attr->socket.reuseaddr != handle->sock.reuseaddr) {
        int val = attr->socket.reuseaddr;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_REUSEADDR, &val,
                             sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.reuseaddr = attr->socket.reuseaddr;
    }

    if (attr->socket.reuseport != handle->sock.reuseport) {
        int val = attr->socket.reuseport;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_REUSEPORT, &val,
                             sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.reuseport = attr->socket.reuseport;
    }

    if (attr->socket.broadcast != handle->sock.broadcast) {
        int val = attr->socket.broadcast;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_BROADCAST, &val,
                             sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.broadcast = attr->socket.broadcast;
    }

    if (attr->socket.ipv6_v6only != handle->sock.ipv6_v6only) {
        int val = attr->socket.ipv6_v6only;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                             sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.ipv6_v6only = attr->socket.ipv6_v6only;
    }

    return 0;
}

static int attrsetbyhdl_tcp(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(handle->sock.type == PAL_SOCKET_TCP);

    int ret = attrsetbyhdl_common(handle, attr);
    if (ret < 0) {
        return ret;
    }

    if (attr->socket.tcp_cork != handle->sock.tcp_cork) {
        int val = attr->socket.tcp_cork;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_TCP, TCP_CORK, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.tcp_cork = attr->socket.tcp_cork;
    }

    if (attr->socket.tcp_keepidle != handle->sock.tcp_keepidle) {
        assert(attr->socket.tcp_keepidle >= 1 && attr->socket.tcp_keepidle <= MAX_TCP_KEEPIDLE);
        int val = attr->socket.tcp_keepidle;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.tcp_keepidle = attr->socket.tcp_keepidle;
    }

    if (attr->socket.tcp_keepintvl != handle->sock.tcp_keepintvl) {
        assert(attr->socket.tcp_keepintvl >= 1 && attr->socket.tcp_keepintvl <= MAX_TCP_KEEPINTVL);
        int val = attr->socket.tcp_keepintvl;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.tcp_keepintvl = attr->socket.tcp_keepintvl;
    }

    if (attr->socket.tcp_keepcnt != handle->sock.tcp_keepcnt) {
        assert(attr->socket.tcp_keepcnt >= 1 && attr->socket.tcp_keepcnt <= MAX_TCP_KEEPCNT);
        int val = attr->socket.tcp_keepcnt;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.tcp_keepcnt = attr->socket.tcp_keepcnt;
    }

    if (attr->socket.tcp_nodelay != handle->sock.tcp_nodelay) {
        int val = attr->socket.tcp_nodelay;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.tcp_nodelay = attr->socket.tcp_nodelay;
    }

    if (attr->socket.tcp_user_timeout != handle->sock.tcp_user_timeout) {
        assert(attr->socket.tcp_user_timeout <= INT_MAX);
        int val = attr->socket.tcp_user_timeout;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_TCP, TCP_USER_TIMEOUT, &val,
                             sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.tcp_user_timeout = attr->socket.tcp_user_timeout;
    }

    return 0;
}

static int attrsetbyhdl_udp(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(handle->sock.type == PAL_SOCKET_UDP);

    return attrsetbyhdl_common(handle, attr);
}

static int send(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                struct pal_socket_addr* addr, bool force_nonblocking) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    struct sockaddr_storage sa_storage;
    size_t linux_addrlen = 0;
    if (addr) {
        if (addr->domain != handle->sock.domain) {
            return -PAL_ERROR_INVAL;
        }
        pal_to_linux_sockaddr(addr, &sa_storage, &linux_addrlen);
        assert(linux_addrlen <= INT_MAX);
    }

    unsigned int flags = force_nonblocking ? MSG_DONTWAIT : 0;
    struct msghdr msg = {
        .msg_name = addr ? &sa_storage : NULL,
        .msg_namelen = linux_addrlen,
        .msg_iov = iov,
        .msg_iovlen = iov_len,
    };
    int ret = DO_SYSCALL(sendmsg, handle->sock.fd, &msg, flags);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }
    *out_size = ret;
    return 0;
}

static int recv(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_total_size,
                struct pal_socket_addr* addr, bool force_nonblocking) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    struct sockaddr_storage sa_storage;

    unsigned int flags = force_nonblocking ? MSG_DONTWAIT : 0;
    if (handle->sock.type == PAL_SOCKET_UDP) {
        /* Reads from PAL UDP sockets always return the full packed length. See also the definition
         * of `PalSocketRecv`. */
        flags |= MSG_TRUNC;
    }
    struct msghdr msg = {
        .msg_name = addr ? &sa_storage : NULL,
        .msg_namelen = addr ? sizeof(sa_storage) : 0,
        .msg_iov = iov,
        .msg_iovlen = iov_len,
    };
    int ret = DO_SYSCALL(recvmsg, handle->sock.fd, &msg, flags);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }
    *out_total_size = ret;
    if (addr) {
        linux_to_pal_sockaddr(&sa_storage, addr);
    }
    return 0;
}

static int delete_tcp(PAL_HANDLE handle, enum pal_delete_mode mode) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    int how;
    switch (mode) {
        case PAL_DELETE_ALL:
            how = SHUT_RDWR;
            break;
        case PAL_DELETE_READ:
            how = SHUT_RD;
            break;
        case PAL_DELETE_WRITE:
            how = SHUT_WR;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    int ret = DO_SYSCALL(shutdown, handle->sock.fd, how);
    return unix_to_pal_error(ret);
}

static int delete_udp(PAL_HANDLE handle, enum pal_delete_mode mode) {
    __UNUSED(handle);
    __UNUSED(mode);
    return 0;
}

static struct socket_ops g_tcp_sock_ops = {
    .bind = bind,
    .listen = tcp_listen,
    .accept = tcp_accept,
    .connect = connect,
    .send = send,
    .recv = recv,
};

static struct socket_ops g_udp_sock_ops = {
    .bind = bind,
    .connect = connect,
    .send = send,
    .recv = recv,
};

static struct handle_ops g_tcp_handle_ops = {
    .attrquerybyhdl = attrquerybyhdl,
    .attrsetbyhdl = attrsetbyhdl_tcp,
    .delete = delete_tcp,
    .destroy = destroy,
};

static struct handle_ops g_udp_handle_ops = {
    .attrquerybyhdl = attrquerybyhdl,
    .attrsetbyhdl = attrsetbyhdl_udp,
    .delete = delete_udp,
    .destroy = destroy,
};

void fixup_socket_handle_after_deserialization(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    switch (handle->sock.type) {
        case PAL_SOCKET_TCP:
            handle->sock.ops = &g_tcp_sock_ops;
            handle->hdr.ops = &g_tcp_handle_ops;
            break;
        case PAL_SOCKET_UDP:
            handle->sock.ops = &g_udp_sock_ops;
            handle->hdr.ops = &g_udp_handle_ops;
            break;
        default:
            BUG();
    }
}

int _PalSocketBind(PAL_HANDLE handle, struct pal_socket_addr* addr) {
    if (!handle->sock.ops->bind) {
        return -PAL_ERROR_NOTSUPPORT;
    }

    return handle->sock.ops->bind(handle, addr);
}

int _PalSocketListen(PAL_HANDLE handle, unsigned int backlog) {
    if (!handle->sock.ops->listen) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->listen(handle, backlog);
}

int _PalSocketAccept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                     struct pal_socket_addr* out_client_addr,
                     struct pal_socket_addr* out_local_addr) {
    if (!handle->sock.ops->accept) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->accept(handle, options, out_client, out_client_addr, out_local_addr);
}

int _PalSocketConnect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                      struct pal_socket_addr* out_local_addr, bool* out_inprogress) {
    if (!handle->sock.ops->connect) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->connect(handle, addr, out_local_addr, out_inprogress);
}

int _PalSocketSend(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                   struct pal_socket_addr* addr, bool force_nonblocking) {
    if (!handle->sock.ops->send) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->send(handle, iov, iov_len, out_size, addr, force_nonblocking);
}

int _PalSocketRecv(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_total_size,
                   struct pal_socket_addr* addr, bool force_nonblocking) {
    if (!handle->sock.ops->recv) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->recv(handle, iov, iov_len, out_total_size, addr, force_nonblocking);
}
