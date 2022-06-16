/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <asm/ioctls.h>
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

/* Default values on a modern Linux kernel. */
static size_t g_default_recv_buf_size = 0x20000;
static size_t g_default_send_buf_size = 0x4000;

static size_t sanitize_size(size_t size) {
    if (size > (1ull << 47)) {
        /* Some random approximation of what is a valid size. */
        return 0;
    }
    return size;
}

static int verify_ip_addr(enum pal_socket_domain domain, struct sockaddr_storage* addr,
                          size_t addrlen) {
    if (addrlen < offsetof(struct sockaddr_storage, ss_family) + sizeof(addr->ss_family)) {
        return -PAL_ERROR_DENIED;
    }
    switch (domain) {
        case PAL_IPV4:
            if (addr->ss_family != AF_INET) {
                return -PAL_ERROR_DENIED;
            }
            if (addrlen != sizeof(struct sockaddr_in)) {
                return -PAL_ERROR_DENIED;
            }
            break;
        case PAL_IPV6:
            if (addr->ss_family != AF_INET6) {
                return -PAL_ERROR_DENIED;
            }
            if (addrlen != sizeof(struct sockaddr_in6)) {
                return -PAL_ERROR_DENIED;
            }
            break;
        default:
            BUG();
    }
    return 0;
}

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
    handle->sock.recv_buf_size = g_default_recv_buf_size;
    handle->sock.send_buf_size = g_default_send_buf_size;
    handle->sock.linger = 0;
    handle->sock.recvtimeout_us = 0;
    handle->sock.sendtimeout_us = 0;
    handle->sock.is_nonblocking = is_nonblocking;
    handle->sock.reuseaddr = false;
    handle->sock.keepalive = false;
    handle->sock.tcp_cork = false;
    handle->sock.tcp_nodelay = false;
    handle->sock.ipv6_v6only = false;

    return handle;
}

int _DkSocketCreate(enum pal_socket_domain domain, enum pal_socket_type type,
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

    int fd = ocall_socket(linux_domain, linux_type, 0);
    if (fd < 0) {
        return unix_to_pal_error(fd);
    }

    PAL_HANDLE handle = create_sock_handle(fd, domain, type, handle_ops, sock_ops,
                                           !!(options & PAL_OPTION_NONBLOCK));
    if (!handle) {
        int ret = ocall_close(fd);
        if (ret < 0) {
            log_error("%s:%d closing socket fd failed: %d", __func__, __LINE__, ret);
        }
        return -PAL_ERROR_NOMEM;
    }

    *out_handle = handle;
    return 0;
}

static int close(PAL_HANDLE handle) {
    int ret = ocall_close(handle->sock.fd);
    if (ret < 0) {
        log_error("%s: closing socket fd failed: %d", __func__, ret);
        /* We cannot do anything about it anyway... */
    }
    return 0;
}

static int bind(PAL_HANDLE handle, struct pal_socket_addr* addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    if (addr->domain != handle->sock.domain) {
        return -PAL_ERROR_INVAL;
    }

    struct sockaddr_storage sa_storage;
    size_t linux_addrlen;
    pal_to_linux_sockaddr(addr, &sa_storage, &linux_addrlen);
    assert(linux_addrlen <= INT_MAX);
    uint16_t new_port = 0;

    int ret = ocall_bind(handle->sock.fd, &sa_storage, linux_addrlen, &new_port);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    switch (addr->domain) {
        case PAL_IPV4:
            if (!addr->ipv4.port) {
                addr->ipv4.port = new_port;
            }
            break;
        case PAL_IPV6:
            if (!addr->ipv6.port) {
                addr->ipv6.port = new_port;
            }
            break;
        default:
            BUG();
    }
    return 0;
}

static int tcp_listen(PAL_HANDLE handle, unsigned int backlog) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    int ret = ocall_listen_simple(handle->sock.fd, backlog);
    return unix_to_pal_error(ret);
}

static int tcp_accept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                      struct pal_socket_addr* out_client_addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);

    struct sockaddr_storage sa_storage = { 0 };
    size_t linux_addrlen = sizeof(sa_storage);
    int flags = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;
    flags |= SOCK_CLOEXEC;

    int fd = ocall_accept(handle->sock.fd, (void*)&sa_storage, &linux_addrlen, flags);
    if (fd < 0) {
        return unix_to_pal_error(fd);
    }

    PAL_HANDLE client = create_sock_handle(fd, handle->sock.domain, handle->sock.type,
                                           handle->hdr.ops, handle->sock.ops,
                                           !!(options & PAL_OPTION_NONBLOCK));
    if (!client) {
        int ret = ocall_close(fd);
        if (ret < 0) {
            log_error("%s:%d closing socket fd failed: %d", __func__, __LINE__, ret);
        }
        return -PAL_ERROR_NOMEM;
    }

    if (out_client_addr) {
        int ret = verify_ip_addr(client->sock.domain, &sa_storage, linux_addrlen);
        if (ret < 0) {
            _DkObjectClose(client);
            return ret;
        }

        linux_to_pal_sockaddr(&sa_storage, out_client_addr);
        assert(out_client_addr->domain == client->sock.domain);
    }

    *out_client = client;
    return 0;
}

static int connect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                   struct pal_socket_addr* out_local_addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    if (addr->domain != PAL_DISCONNECT && addr->domain != handle->sock.domain) {
        return -PAL_ERROR_INVAL;
    }

    struct sockaddr_storage sa_storage;
    size_t linux_addrlen;
    pal_to_linux_sockaddr(addr, &sa_storage, &linux_addrlen);
    assert(linux_addrlen <= INT_MAX);

    int ret = ocall_connect_simple(handle->sock.fd, &sa_storage, &linux_addrlen);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    if (out_local_addr) {
        ret = verify_ip_addr(handle->sock.domain, &sa_storage, linux_addrlen);
        if (ret < 0) {
            return ret;
        }
        linux_to_pal_sockaddr(&sa_storage, out_local_addr);
    }
    return 0;
}

static int attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);

    memset(attr, 0, sizeof(*attr));

    attr->handle_type = PAL_TYPE_SOCKET;
    attr->nonblocking = handle->sock.is_nonblocking;

    int ret = ocall_fionread(handle->sock.fd);
    attr->pending_size = ret >= 0 ? sanitize_size(ret) : 0;

    attr->socket.linger = handle->sock.linger;
    attr->socket.recv_buf_size = handle->sock.recv_buf_size;
    attr->socket.send_buf_size = handle->sock.send_buf_size;
    attr->socket.receivetimeout_us = handle->sock.recvtimeout_us;
    attr->socket.sendtimeout_us = handle->sock.sendtimeout_us;
    attr->socket.reuseaddr = handle->sock.reuseaddr;
    attr->socket.keepalive = handle->sock.keepalive;
    attr->socket.tcp_cork = handle->sock.tcp_cork;
    attr->socket.tcp_nodelay = handle->sock.tcp_nodelay;
    attr->socket.ipv6_v6only = handle->sock.ipv6_v6only;

    return 0;
};

/* Warning: if this is used to change two fields and the second set fails, the first set is not
 * undone. */
static int attrsetbyhdl_common(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    if (attr->handle_type != PAL_TYPE_SOCKET) {
        return -PAL_ERROR_INVAL;
    }

    if (attr->nonblocking != handle->sock.is_nonblocking) {
        int ret = ocall_fsetnonblock(handle->sock.fd, attr->nonblocking);
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
        int ret = ocall_setsockopt(handle->sock.fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
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
        int ret = ocall_setsockopt(handle->sock.fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
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
        int ret = ocall_setsockopt(handle->sock.fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
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
        int ret = ocall_setsockopt(handle->sock.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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
        int ret = ocall_setsockopt(handle->sock.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.sendtimeout_us = attr->socket.sendtimeout_us;
    }

    if (attr->socket.keepalive != handle->sock.keepalive) {
        int val = attr->socket.keepalive;
        int ret = ocall_setsockopt(handle->sock.fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.keepalive = attr->socket.keepalive;
    }

    if (attr->socket.reuseaddr != handle->sock.reuseaddr) {
        int val = attr->socket.reuseaddr;
        int ret = ocall_setsockopt(handle->sock.fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.reuseaddr = attr->socket.reuseaddr;
    }

    if (attr->socket.ipv6_v6only != handle->sock.ipv6_v6only) {
        int val = attr->socket.ipv6_v6only;
        int ret = ocall_setsockopt(handle->sock.fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
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
        int ret = ocall_setsockopt(handle->sock.fd, SOL_TCP, TCP_CORK, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.tcp_cork = attr->socket.tcp_cork;
    }

    if (attr->socket.tcp_nodelay != handle->sock.tcp_nodelay) {
        int val = attr->socket.tcp_nodelay;
        int ret = ocall_setsockopt(handle->sock.fd, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.tcp_nodelay = attr->socket.tcp_nodelay;
    }

    return 0;
}

static int attrsetbyhdl_udp(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(handle->sock.type == PAL_SOCKET_UDP);

    return attrsetbyhdl_common(handle, attr);
}

static int send(PAL_HANDLE handle, struct pal_iovec* pal_iov, size_t iov_len, size_t* out_size,
                struct pal_socket_addr* addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);

    struct sockaddr_storage sa_storage;
    size_t linux_addrlen = 0;
    if (addr) {
        if (addr->domain != handle->sock.domain) {
            return -PAL_ERROR_INVAL;
        }
        pal_to_linux_sockaddr(addr, &sa_storage, &linux_addrlen);
        assert(linux_addrlen <= INT_MAX);
    }

    struct iovec* iov = malloc(iov_len * sizeof(*iov));
    if (!iov) {
        return -PAL_ERROR_NOMEM;
    }
    for (size_t i = 0; i < iov_len; i++) {
        iov[i].iov_base = pal_iov[i].iov_base;
        iov[i].iov_len = pal_iov[i].iov_len;
    }

    ssize_t ret = ocall_send(handle->sock.fd, iov, iov_len, addr ? &sa_storage : NULL,
                             linux_addrlen, /*control=*/NULL, /*controllen=*/0);
    free(iov);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }
    *out_size = ret;
    return 0;
}

static int recv(PAL_HANDLE handle, struct pal_iovec* pal_iov, size_t iov_len,
                size_t* out_total_size, struct pal_socket_addr* addr, bool force_nonblocking) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);

    struct sockaddr_storage sa_storage;
    size_t linux_addrlen = addr ? sizeof(sa_storage) : 0;

    struct iovec* iov = malloc(iov_len * sizeof(*iov));
    if (!iov) {
        return -PAL_ERROR_NOMEM;
    }
    for (size_t i = 0; i < iov_len; i++) {
        iov[i].iov_base = pal_iov[i].iov_base;
        iov[i].iov_len = pal_iov[i].iov_len;
    }

    unsigned int flags = force_nonblocking ? MSG_DONTWAIT : 0;
    if (handle->sock.type == PAL_SOCKET_UDP) {
        /* Reads from PAL UDP sockets always return the full packed length. See also the definition
         * of `DkSocketRecv`. */
        flags |= MSG_TRUNC;
    }
    ssize_t ret = ocall_recv(handle->sock.fd, iov, iov_len, addr ? &sa_storage : NULL,
                             &linux_addrlen, /*control=*/NULL, /*controllenptr=*/NULL, flags);
    free(iov);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }
    size_t size = ret;
    if (addr) {
        ret = verify_ip_addr(handle->sock.domain, &sa_storage, linux_addrlen);
        if (ret < 0) {
            return ret;
        }
        linux_to_pal_sockaddr(&sa_storage, addr);
    }
    *out_total_size = size;
    return 0;
}

static int delete_tcp(PAL_HANDLE handle, enum pal_delete_mode mode) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
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

    int ret = ocall_shutdown(handle->sock.fd, how);
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
    .close = close,
};

static struct handle_ops g_udp_handle_ops = {
    .attrquerybyhdl = attrquerybyhdl,
    .attrsetbyhdl = attrsetbyhdl_udp,
    .delete = delete_udp,
    .close = close,
};

void fixup_socket_handle_after_deserialization(PAL_HANDLE handle) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
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

int _DkSocketBind(PAL_HANDLE handle, struct pal_socket_addr* addr) {
    if (!handle->sock.ops->bind) {
        return -PAL_ERROR_NOTSUPPORT;
    }

    return handle->sock.ops->bind(handle, addr);
}

int _DkSocketListen(PAL_HANDLE handle, unsigned int backlog) {
    if (!handle->sock.ops->listen) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->listen(handle, backlog);
}

int _DkSocketAccept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                    struct pal_socket_addr* out_client_addr) {
    if (!handle->sock.ops->accept) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->accept(handle, options, out_client, out_client_addr);
}

int _DkSocketConnect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                     struct pal_socket_addr* out_local_addr) {
    if (!handle->sock.ops->connect) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->connect(handle, addr, out_local_addr);
}

int _DkSocketSend(PAL_HANDLE handle, struct pal_iovec* iov, size_t iov_len, size_t* out_size,
                  struct pal_socket_addr* addr) {
    if (!handle->sock.ops->send) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->send(handle, iov, iov_len, out_size, addr);
}

int _DkSocketRecv(PAL_HANDLE handle, struct pal_iovec* iov, size_t iov_len, size_t* out_total_size,
                  struct pal_socket_addr* addr, bool force_nonblocking) {
    if (!handle->sock.ops->recv) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->recv(handle, iov, iov_len, out_total_size, addr, force_nonblocking);
}
