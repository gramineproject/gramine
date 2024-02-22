/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */


#include "api.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_process.h"
#include "libos_signal.h"
#include "libos_socket.h"
#include "libos_table.h"
#include "linux_abi/errors.h"

/*
 * Sockets can be in 5 states: NEW, BOUND, LISTENING, CONNECTING and CONNECTED.
 *
 *                                                        +------------------+
 *                                                        |                  |
 *                                                        |                  |
 *               bind()                     listen()      V       accept()   old socket
 *  +--> NEW --------------------> BOUND -------------> LISTEN --------------+
 *  |     |                        |   ^                                     new socket
 *  |     |                        |   |                                     |
 *  |     |                        |   +------------------------+            |
 *  |     |              connect() |           disconnect()     |            |
 *  |     |                        |         (if it was bound)  |            |
 *  |     | connect()              |                            |            |
 *  |     |                        |         select()/poll()/   |            |
 *  |     |                        V            epoll()         |            |
 *  |     +---------------------> CONNECTING ---------------> CONNECTED <----+
 *  |                             (only for                     |
 *  |                        non-blocking sockets)              |
 *  |                                                           |
 *  |                                         disconnect()      |
 *  |                                     (if it was not bound) |
 *  +-----------------------------------------------------------+
 *
 */

/* Creates a socket handle with default settings. */
struct libos_handle* get_new_socket_handle(int family, int type, int protocol,
                                           bool is_nonblocking) {
    struct libos_handle* handle = get_new_handle();
    if (!handle) {
        return NULL;
    }

    handle->type = TYPE_SOCK;
    handle->fs = &socket_builtin_fs;
    handle->flags = O_RDWR | (is_nonblocking ? O_NONBLOCK : 0);
    handle->acc_mode = MAY_READ | MAY_WRITE;

    struct libos_sock_handle* sock = &handle->info.sock;
    sock->state = SOCK_NEW;
    sock->domain = family;
    sock->type = type;
    sock->protocol = protocol;
    sock->remote_addr.ss_family = AF_UNSPEC;
    sock->remote_addrlen = sizeof(sock->remote_addr.ss_family);
    sock->local_addr.ss_family = AF_UNSPEC;
    sock->local_addrlen = sizeof(sock->local_addr.ss_family);
    sock->was_bound = false;
    sock->can_be_read = false;
    sock->can_be_written = false;
    sock->reuseaddr = false;
    sock->reuseport = false;
    sock->broadcast = false;
    switch (family) {
        case AF_UNIX:
            sock->ops = &sock_unix_ops;
            break;
        case AF_INET:
        case AF_INET6:
            sock->ops = &sock_ip_ops;
            break;
    }

    if (!create_lock(&sock->lock) || !create_lock(&sock->recv_lock)) {
        put_handle(handle);
        return NULL;
    }

    return handle;
}

void check_connect_inprogress_on_poll(struct libos_handle* handle, bool error_event) {
    /*
     * Special case of a non-blocking socket that is INPROGRESS (connecting): must check if error or
     * success of connecting. If error, then set SO_ERROR (last_error). If success, then move to
     * SOCK_CONNECTED state and clear SO_ERROR. See `man 2 connect`, EINPROGRESS case.
     *
     * We first fetch `connecting_in_progress` instead of a proper lock on the handle to speed up
     * the common case of an already-connected socket doing recv/send.
     */
    assert(handle->type == TYPE_SOCK);

    bool inprog = __atomic_load_n(&handle->info.sock.connecting_in_progress, __ATOMIC_ACQUIRE);
    if (!inprog)
        return;

    struct libos_sock_handle* sock = &handle->info.sock;
    lock(&sock->lock);

    if (sock->state != SOCK_CONNECTING) {
        /* data race: another thread could have done another select/poll on this socket and
         * modified the state; there's nothing left to be done */
        goto out;
    }

    if (error_event) {
        sock->last_error = ECONNREFUSED;
        goto out;
    }

    sock->last_error = 0;
    sock->can_be_read = true;
    sock->can_be_written = true;
    __atomic_store_n(&sock->connecting_in_progress, false, __ATOMIC_RELEASE);
    sock->state = SOCK_CONNECTED;
out:
    unlock(&sock->lock);
}

long libos_syscall_socket(int family, int type, int protocol) {
    switch (family) {
        case AF_UNIX:
        case AF_INET:
        case AF_INET6:
            break;
        default:
            log_warning("unsupported socket domain %d", family);
            return -EAFNOSUPPORT;
    }

    int flags = type & ~SOCK_TYPE_MASK;
    bool is_nonblocking = flags & SOCK_NONBLOCK;
    bool is_cloexec = flags & SOCK_CLOEXEC;
    if (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) {
        return -EINVAL;
    }

    type &= SOCK_TYPE_MASK;
    switch (type) {
        case SOCK_STREAM:
        case SOCK_DGRAM:
            break;
        default:
            log_warning("unsupported socket type %d", type);
            return -EPROTONOSUPPORT;
    }

    struct libos_handle* handle = get_new_socket_handle(family, type, protocol, is_nonblocking);
    if (!handle) {
        return -ENOMEM;
    }

    int ret = handle->info.sock.ops->create(handle);
    if (ret == 0) {
        ret = set_new_fd_handle(handle, is_cloexec ? FD_CLOEXEC : 0, NULL);
    }
    put_handle(handle);
    return ret;
}

long libos_syscall_socketpair(int family, int type, int protocol, int* sv) {
    if (family != AF_UNIX) {
        return -EAFNOSUPPORT;
    }

    int flags = type & ~SOCK_TYPE_MASK;
    bool is_nonblocking = flags & SOCK_NONBLOCK;
    bool is_cloexec = flags & SOCK_CLOEXEC;
    if (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) {
        return -EINVAL;
    }

    type &= SOCK_TYPE_MASK;
    if (type != SOCK_STREAM) {
        log_warning("unsupported socket type %d", type);
        return -EPROTONOSUPPORT;
    }

    if (protocol != 0) {
        return -EPROTONOSUPPORT;
    }

    if (!is_user_memory_writable(sv, 2 * sizeof(*sv))) {
        return -EFAULT;
    }

    int ret;
    struct libos_handle* handle1 = NULL;
    struct libos_handle* handle2 = NULL;
    struct libos_handle* handle3 = NULL;
    handle1 = get_new_socket_handle(family, type, protocol, /*is_nonblocking=*/false);
    if (!handle1) {
        ret = -ENOMEM;
        goto out;
    }
    handle2 = get_new_socket_handle(family, type, protocol, /*is_nonblocking=*/false);
    if (!handle2) {
        ret = -ENOMEM;
        goto out;
    }

    /* This is around 107 random bytes - no way we collide with an existing socket. */
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    /* We leave first byte as 0 - abstract UNIX socket. */
    ret = PalRandomBitsRead(&addr.sun_path[1], sizeof(addr.sun_path) - 1);
    if (ret < 0) {
        ret = -EAGAIN;
        goto out;
    }

    struct libos_sock_handle* sock1 = &handle1->info.sock;
    struct libos_sock_handle* sock2 = &handle2->info.sock;

    lock(&sock1->lock);
    ret = sock1->ops->create(handle1);
    if (ret < 0) {
        unlock(&sock1->lock);
        goto out;
    }
    ret = sock1->ops->bind(handle1, &addr, sizeof(addr));
    if (ret < 0) {
        unlock(&sock1->lock);
        goto out;
    }
    sock1->state = SOCK_BOUND;
    ret = sock1->ops->listen(handle1, 1);
    if (ret < 0) {
        unlock(&sock1->lock);
        goto out;
    }
    sock1->state = SOCK_LISTENING;
    sock1->can_be_read = true;
    /* Socketpair UNIX sockets have no meaningful addresses, but correct domain. */
    sock1->remote_addr.ss_family = AF_UNIX;
    sock1->remote_addrlen = sizeof(sock1->remote_addr.ss_family);
    sock1->local_addr.ss_family = AF_UNIX;
    sock1->local_addrlen = sizeof(sock1->local_addr.ss_family);
    unlock(&sock1->lock);

    lock(&sock2->lock);
    ret = sock2->ops->create(handle2);
    if (ret < 0) {
        unlock(&sock2->lock);
        goto out;
    }
    bool inprogress_unused;
    ret = sock2->ops->connect(handle2, &addr, sizeof(addr), &inprogress_unused);
    if (ret < 0) {
        unlock(&sock2->lock);
        goto out;
    }
    sock2->state = SOCK_CONNECTED;
    sock2->can_be_read = true;
    sock2->can_be_written = true;
    /* Socketpair UNIX sockets have no meaningful addresses, but correct domain. */
    sock2->remote_addr.ss_family = AF_UNIX;
    sock2->remote_addrlen = sizeof(sock2->remote_addr.ss_family);
    sock2->local_addr.ss_family = AF_UNIX;
    sock2->local_addrlen = sizeof(sock2->local_addr.ss_family);
    unlock(&sock2->lock);

    ret = sock1->ops->accept(handle1, is_nonblocking, &handle3);
    if (ret < 0) {
        goto out;
    }

    if (is_nonblocking) {
        ret = set_handle_nonblocking(handle2, is_nonblocking);
        if (ret < 0) {
            goto out;
        }
    }

    int fd1 = set_new_fd_handle(handle2, is_cloexec ? FD_CLOEXEC : 0, NULL);
    if (fd1 < 0) {
        ret = fd1;
        goto out;
    }
    int fd2 = set_new_fd_handle(handle3, is_cloexec ? FD_CLOEXEC : 0, NULL);
    if (fd2 < 0) {
        struct libos_handle* tmp = detach_fd_handle(fd1, NULL, NULL);
        assert(tmp == handle2);
        put_handle(tmp);
        ret = fd2;
        goto out;
    }

    sv[0] = fd1;
    sv[1] = fd2;
    ret = 0;

out:
    if (ret == -EINTR) {
        ret = -ERESTARTSYS;
    }
    if (handle1) {
        put_handle(handle1);
    }
    if (handle2) {
        put_handle(handle2);
    }
    if (handle3) {
        put_handle(handle3);
    }
    return ret;
}

long libos_syscall_bind(int fd, void* addr, int _addrlen) {
    int ret;

    if (_addrlen < 0) {
        return -EINVAL;
    }
    size_t addrlen = _addrlen;
    if (!is_user_memory_readable(addr, addrlen)) {
        return -EFAULT;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    if (handle->type != TYPE_SOCK) {
        put_handle(handle);
        return -ENOTSOCK;
    }

    struct libos_sock_handle* sock = &handle->info.sock;

    lock(&sock->lock);

    if (sock->state != SOCK_NEW) {
        ret = -EINVAL;
        goto out;
    }

    ret = sock->ops->bind(handle, addr, addrlen);
    if (ret < 0) {
        goto out;
    }

    sock->state = SOCK_BOUND;
    sock->was_bound = true;
    ret = 0;

out:
    unlock(&sock->lock);
    put_handle(handle);
    return ret;
}

long libos_syscall_listen(int fd, int backlog) {
    int ret;

    if ((unsigned int)backlog > LIBOS_SOCK_MAX_PENDING_CONNS) {
        /* Linux kernel caps `backlog` this way. */
        backlog = LIBOS_SOCK_MAX_PENDING_CONNS;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    if (handle->type != TYPE_SOCK) {
        put_handle(handle);
        return -ENOTSOCK;
    }

    struct libos_sock_handle* sock = &handle->info.sock;

    lock(&sock->lock);

    switch (sock->state) {
        case SOCK_BOUND:
        case SOCK_LISTENING:
            break;
        case SOCK_NEW:
            /* Gramine does not support auto binding in listen. */
        default:
            ret = -EINVAL;
            goto out;
    }

    ret = sock->ops->listen(handle, backlog);
    if (ret < 0) {
        goto out;
    }

    sock->state = SOCK_LISTENING;
    sock->can_be_read = true;
    ret = 0;

out:
    unlock(&sock->lock);
    put_handle(handle);
    return ret;
}

static int do_accept(int fd, void* addr, int* addrlen_ptr, int flags) {
    if (!WITHIN_MASK(flags, SOCK_NONBLOCK | SOCK_CLOEXEC)) {
        return -EINVAL;
    }

    size_t addrlen = 0;
    if (addr) {
        if (!is_user_memory_readable(addrlen_ptr, sizeof(*addrlen_ptr))
                || !is_user_memory_writable(addrlen_ptr, sizeof(*addrlen_ptr))) {
            return -EFAULT;
        }
        if (*addrlen_ptr < 0) {
            return -EINVAL;
        }
        addrlen = *addrlen_ptr;
        if (!is_user_memory_writable(addr, addrlen)) {
            return -EFAULT;
        }
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    int ret = 0;
    if (handle->type != TYPE_SOCK) {
        put_handle(handle);
        return -ENOTSOCK;
    }

    struct libos_handle* client_handle = NULL;
    bool has_recvtimeout_set = false;
    struct libos_sock_handle* sock = &handle->info.sock;

    lock(&sock->lock);
    if (sock->state != SOCK_LISTENING) {
        ret = -EINVAL;
    } else if (!sock->can_be_read) {
        ret = -EINVAL;
    } else {
        has_recvtimeout_set = !!sock->receivetimeout_us;
    }
    unlock(&sock->lock);
    if (ret) {
        goto out;
    }

    ret = sock->ops->accept(handle, !!(flags & SOCK_NONBLOCK), &client_handle);
    maybe_epoll_et_trigger(handle, ret, /*in=*/true, /*was_partial=*/false);
    if (ret < 0) {
        goto out;
    }

    if (addr) {
        assert(client_handle->type == TYPE_SOCK);
        lock(&client_handle->info.sock.lock);

        /* If the user provided buffer is too small, the address is truncated, but we report
         * the actual address size in `addrlen_ptr`. */
        memcpy(addr, &client_handle->info.sock.remote_addr,
               MIN(addrlen, client_handle->info.sock.remote_addrlen));
        *addrlen_ptr = client_handle->info.sock.remote_addrlen;

        unlock(&client_handle->info.sock.lock);
    }

    ret = set_new_fd_handle(client_handle, flags & SOCK_CLOEXEC ? FD_CLOEXEC : 0, NULL);

out:
    if (ret == -EINTR) {
        /* Timeout could have been changed in the meantime, but it should not matter - this is
         * a peculiar corner case that nothing should really care about. */
        if (has_recvtimeout_set) {
            ret = -ERESTARTNOHAND;
        } else {
            ret = -ERESTARTSYS;
        }
    }
    put_handle(handle);
    if (client_handle) {
        put_handle(client_handle);
    }
    return ret;
}

long libos_syscall_accept(int fd, void* addr, int* addrlen) {
    return do_accept(fd, addr, addrlen, 0);
}

long libos_syscall_accept4(int fd, void* addr, int* addrlen, int flags) {
    return do_accept(fd, addr, addrlen, flags);
}

long libos_syscall_connect(int fd, void* addr, int _addrlen) {
    int ret;

    if (_addrlen < 0) {
        return -EINVAL;
    }
    size_t addrlen = _addrlen;
    if (!is_user_memory_readable(addr, addrlen)) {
        return -EFAULT;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    if (handle->type != TYPE_SOCK) {
        put_handle(handle);
        return -ENOTSOCK;
    }

    struct libos_sock_handle* sock = &handle->info.sock;

    /* We need to take `recv_lock` just in case we free `peek` buffer in `disconnect` case.
     * This should not hurt though - nothing should be calling `recv` concurrently anyway. */
    lock(&sock->recv_lock);
    lock(&sock->lock);

    switch (sock->state) {
        case SOCK_NEW:
        case SOCK_BOUND:
        case SOCK_CONNECTING:
        case SOCK_CONNECTED:
            break;
        default:
            ret = -EINVAL;
            goto out;
    }

    if (sock->state == SOCK_CONNECTING) {
        assert(handle->flags & O_NONBLOCK);
        ret = -EALREADY;
        goto out;
    }

    if (sock->state == SOCK_CONNECTED) {
        unsigned short addr_family;
        if (addrlen < sizeof(addr_family)) {
            ret = -EINVAL;
            goto out;
        }
        memcpy(&addr_family, addr, sizeof(addr_family));

        if (addr_family == AF_UNSPEC) {
            ret = sock->ops->disconnect(handle);
            if (ret < 0) {
                goto out;
            }

            if (sock->was_bound) {
                sock->state = SOCK_BOUND;
            } else {
                sock->state = SOCK_NEW;
                sock->local_addr.ss_family = AF_UNSPEC;
                sock->local_addrlen = sizeof(sock->local_addr.ss_family);
            }

            sock->remote_addr.ss_family = AF_UNSPEC;
            sock->remote_addrlen = sizeof(sock->remote_addr.ss_family);

            sock->can_be_read = false;
            sock->can_be_written = false;

            free(sock->peek.buf);
            sock->peek.buf = NULL;
            sock->peek.buf_size = 0;
            sock->peek.data_size = 0;

            ret = 0;
            goto out;
        }

        ret = -EISCONN;
        goto out;
    }

    bool inprogress;
    ret = sock->ops->connect(handle, addr, addrlen, &inprogress);
    maybe_epoll_et_trigger(handle, ret, /*in=*/false, /*was_partial=*/false);
    if (ret < 0) {
        goto out;
    }

    if (inprogress) {
        sock->state = SOCK_CONNECTING;
        __atomic_store_n(&sock->connecting_in_progress, true, __ATOMIC_RELEASE);
        sock->last_error = EINPROGRESS;
        ret = -((int)sock->last_error);
    } else {
        sock->state = SOCK_CONNECTED;
        sock->can_be_read = true;
        sock->can_be_written = true;
        ret = 0;
    }

out:
    if (ret == -EINTR) {
        if (sock->sendtimeout_us) {
            ret = -ERESTARTNOHAND;
        } else {
            ret = -ERESTARTSYS;
        }
    }
    unlock(&sock->lock);
    unlock(&sock->recv_lock);
    put_handle(handle);
    return ret;
}

static int check_msghdr(struct msghdr* user_msg, bool is_recv) {
    if (!is_user_memory_readable(user_msg, sizeof(*user_msg))) {
        return -EFAULT;
    }
    size_t size;
    if (__builtin_mul_overflow(user_msg->msg_iovlen, sizeof(*user_msg->msg_iov), &size)) {
        return -EMSGSIZE;
    }
    if (!is_user_memory_readable(user_msg->msg_iov, size)) {
        return -EFAULT;
    }
    bool (*check_access_func)(const void*, size_t) = is_recv ? is_user_memory_writable
                                                             : is_user_memory_readable;
    for (size_t i = 0; i < user_msg->msg_iovlen; i++) {
        if (!check_access_func(user_msg->msg_iov[i].iov_base, user_msg->msg_iov[i].iov_len)) {
            return -EFAULT;
        }
    }
    if (user_msg->msg_control && user_msg->msg_controllen) {
        if (!check_access_func(user_msg->msg_control, user_msg->msg_controllen)) {
            return -EFAULT;
        }
    }
    if (user_msg->msg_name) {
        if (user_msg->msg_namelen < 0) {
            return -EINVAL;
        }
        if (!check_access_func(user_msg->msg_name, user_msg->msg_namelen)) {
            return -EFAULT;
        }
        if (is_recv) {
            if (!is_user_memory_writable(&user_msg->msg_namelen, sizeof(user_msg->msg_namelen))) {
                return -EFAULT;
            }
        }
    }
    if (is_recv) {
        if (!is_user_memory_writable(&user_msg->msg_flags, sizeof(user_msg->msg_flags))) {
            return -EFAULT;
        }
    }
    return 0;
}

/* We return the size directly (contrary to the usual out argument) for simplicity - this function
 * is called directly from syscall handlers, which return values in such a way. */
ssize_t do_sendmsg(struct libos_handle* handle, struct iovec* iov, size_t iov_len,
                   void* msg_control, size_t msg_controllen, void* addr, size_t addrlen,
                   unsigned int flags) {
    ssize_t ret = 0;
    if (handle->type != TYPE_SOCK) {
        return -ENOTSOCK;
    }
    if (!WITHIN_MASK(flags, MSG_NOSIGNAL | MSG_DONTWAIT | MSG_MORE)) {
        return -EOPNOTSUPP;
    }

    /* Note this only indicates whether this operation was requested to be nonblocking. If it's
     * `false`, but the handle is in nonblocking mode, this send won't block. */
    bool force_nonblocking = flags & MSG_DONTWAIT;
    struct libos_sock_handle* sock = &handle->info.sock;

    if (flags & MSG_MORE) {
        if (sock->type != SOCK_STREAM) {
            log_warning("MSG_MORE on non-TCP sockets is not supported");
            return -EOPNOTSUPP;
        }
        if (FIRST_TIME())
            log_debug("MSG_MORE on TCP sockets is ignored");
    }

    lock(&sock->lock);
    if (sock->state == SOCK_CONNECTING) {
        unlock(&sock->lock);
        return -EAGAIN;
    }

    bool has_sendtimeout_set = !!sock->sendtimeout_us;

    ret = -((ssize_t)sock->last_error);
    sock->last_error = 0;

    if (!ret && !sock->can_be_written) {
        ret = -EPIPE;
    }

    unlock(&sock->lock);

    if (ret < 0) {
        goto out;
    }

    size_t total_size = 0;
    for (size_t i = 0; i < iov_len; i++) {
        total_size += iov[i].iov_len;
    }

    size_t size = 0;
    ret = sock->ops->send(handle, iov, iov_len, msg_control, msg_controllen, &size, addr, addrlen,
                          force_nonblocking);
    maybe_epoll_et_trigger(handle, ret, /*in=*/false, !ret ? size < total_size : false);
    if (!ret) {
        ret = size;
    }

out:
    if (ret == -EPIPE && !(flags & MSG_NOSIGNAL)) {
        siginfo_t info = {
            .si_signo = SIGPIPE,
            .si_pid = g_process.pid,
            .si_code = SI_USER,
        };
        if (kill_current_proc(&info) < 0) {
            log_error("failed to deliver a signal");
        }
    }
    if (ret == -EINTR) {
        /* Timeout could have been changed in the meantime, but it should not matter - this is
         * a peculiar corner case that nothing should really care about. */
        if (has_sendtimeout_set) {
            ret = -ERESTARTNOHAND;
        } else {
            ret = -ERESTARTSYS;
        }
    }
    return ret;
}

long libos_syscall_sendto(int fd, void* buf, size_t len, unsigned int flags, void* addr,
                          int addrlen) {
    if (addr) {
        if (addrlen < 0) {
            return -EINVAL;
        }
        if (!is_user_memory_readable(addr, addrlen)) {
            return -EFAULT;
        }
    }

    if (!is_user_memory_readable(buf, len)) {
        return -EFAULT;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    struct iovec iov = {
        .iov_base = buf,
        .iov_len = len,
    };
    ssize_t ret = do_sendmsg(handle, &iov, 1, /*msg_control=*/NULL, /*msg_controllen=*/0, addr,
                             addr ? addrlen : 0, flags);
    put_handle(handle);
    return ret;
}

long libos_syscall_sendmsg(int fd, struct msghdr* msg, unsigned int flags) {
    ssize_t ret = check_msghdr(msg, /*is_recv=*/false);
    if (ret < 0) {
        return ret;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    size_t addrlen = msg->msg_name ? msg->msg_namelen : 0;
    ret = do_sendmsg(handle, msg->msg_iov, msg->msg_iovlen, msg->msg_control, msg->msg_controllen,
                     msg->msg_name, addrlen, flags);
    put_handle(handle);
    return ret;
}

long libos_syscall_sendmmsg(int fd, struct mmsghdr* msg, unsigned int vlen, unsigned int flags) {
    for (size_t i = 0; i < vlen; i++) {
        int ret = check_msghdr(&msg[i].msg_hdr, /*is_recv=*/false);
        if (ret < 0) {
            return ret;
        }
        if (!is_user_memory_writable(&msg[i].msg_len, sizeof(msg[i].msg_len))) {
            return -EFAULT;
        }
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    ssize_t ret;
    for (size_t i = 0; i < vlen; i++) {
        struct msghdr* hdr = &msg[i].msg_hdr;
        size_t addrlen = hdr->msg_name ? hdr->msg_namelen : 0;
        ret = do_sendmsg(handle, hdr->msg_iov, hdr->msg_iovlen, hdr->msg_control,
                         hdr->msg_controllen, hdr->msg_name, addrlen, flags);
        if (ret < 0) {
            if (i == 0) {
                /* Return error directly. */
                goto out;
            }
            if (!is_eintr_like(ret) && ret != -EAGAIN && ret != -EPIPE) {
                lock(&handle->info.sock.lock);
                /* Since `i > 0`, `do_sendmsg` has already verified that `handle` is a socket. */
                handle->info.sock.last_error = -ret;
                unlock(&handle->info.sock.lock);
            }
            ret = i;
            goto out;
        }
        msg[i].msg_len = ret;
    }

    ret = vlen;

out:
    put_handle(handle);
    return ret;
}

/* We return the size directly (contrary to the usual out argument) for simplicity - this function
 * is called directly from syscall handlers, which return values in such a way. */
ssize_t do_recvmsg(struct libos_handle* handle, struct iovec* iov, size_t iov_len,
                   void* msg_control, size_t* msg_controllen_ptr, void* addr, size_t* addrlen_ptr,
                   unsigned int* flags, bool emulate_recv_error_semantics) {
    ssize_t ret = 0;
    if (handle->type != TYPE_SOCK) {
        return -ENOTSOCK;
    }
    if (!WITHIN_MASK(*flags, MSG_PEEK | MSG_DONTWAIT | MSG_TRUNC)) {
        return -EOPNOTSUPP;
    }

    /* Note this only indicates whether this operation was requested to be nonblocking. If it's
     * `false`, but the handle is in nonblocking mode, this read won't block. */
    bool force_nonblocking = *flags & MSG_DONTWAIT;
    struct libos_sock_handle* sock = &handle->info.sock;

    lock(&sock->lock);
    if (sock->state == SOCK_CONNECTING) {
        unlock(&sock->lock);
        return -EAGAIN;
    }

    bool has_recvtimeout_set = !!sock->receivetimeout_us;

    ret = -((ssize_t)sock->last_error);
    sock->last_error = 0;
    unlock(&sock->lock);

    if (ret < 0) {
        return ret;
    }

    /* We ignore `sock->can_be_read` here - there might be some pending data in the host OS. */

    size_t total_size = 0;
    for (size_t i = 0; i < iov_len; i++) {
        /* This cannot overflow - we have already checked that all of this memory is present so it
         * must fit in `size_t`. */
        total_size += iov[i].iov_len;
    }

    if (!total_size && !emulate_recv_error_semantics) {
        /*
         * In Linux, read() and readv() -- i.e. not recv*() syscalls -- have a "match SYS5 behavior"
         * corner case: 0 is returned if the requested number of bytes to receive is 0. The
         * rationale for this behavior is unclear and lost in history. The relevant Linux code:
         * https://github.com/torvalds/linux/blob/99bd3cb0d12e85/net/socket.c#L1136-L1136
         *
         * Apparently some applications/libraries rely on this behavior. Without this corner case,
         * these apps would hang (if the socket is blocking) or unexpectedly return -EAGAIN (if the
         * socket is non-blocking). Note that the underlying PalSocketRecv() uses `recvmsg()`
         * syscall, at least on Linux-based PALs, so a simple fall-through to PAL would change the
         * semantics of `read()`/`readv()` issued by the app.
         */
        return 0;
    }

    /*
     * Taking this lock (and potentially blocking until other thread releases it) should be fine
     * in most cases, regardless of whether this read is blocking or not. If it is blocking, then
     * sleeping on the lock is fine. If it's nonblocking, then all other operations on this handle
     * are also non blocking, so the lock will be released soon and we won't block indefinitely.
     * There is a case though, that can cause this to block for arbitrary long periods: one thread
     * does a blocking read, then another one does a nonblocking read (either by specifying
     * `MSG_DONTWAIT` flag or using `fcntl` to add `O_NONBLOCK`) - whether `MSG_PEEK` is set is
     * irrelevant here. Hopefully no app depends on it and if it does for some reason, it should
     * not result in a deadlock - hopefully some data arrives (or the socket is closed from
     * the remote side) and unlocks the first blocked thread.
     */
    lock(&sock->recv_lock);

    if (*flags & MSG_PEEK) {
        if (sock->type != SOCK_STREAM) {
            log_warning("MSG_PEEK on non stream sockets is not supported");
            ret = -EOPNOTSUPP;
            goto out;
        }

        if (sock->peek.data_size < total_size) {
            /* Try getting more data. */
            if (sock->peek.buf_size < total_size) {
                /* Reallocate the buffer. */
                void* peek_buf = malloc(total_size);
                if (!peek_buf) {
                    ret = -ENOMEM;
                    goto out;
                }
                memcpy(peek_buf, sock->peek.buf, sock->peek.data_size);
                free(sock->peek.buf);
                sock->peek.buf = peek_buf;
                sock->peek.buf_size = total_size;
            }

            struct iovec tmp_iov = {
                .iov_base = sock->peek.buf + sock->peek.data_size,
                .iov_len = sock->peek.buf_size - sock->peek.data_size,
            };
            if (sock->peek.data_size) {
                /* We already have some data - should not block regardless of other settings. */
                force_nonblocking = true;
            }

            ret = sock->ops->recv(handle, &tmp_iov, 1, /*msg_control=*/NULL,
                                  /*msg_controllen_ptr=*/NULL, &tmp_iov.iov_len, /*addr=*/NULL,
                                  /*addrlen_ptr=*/NULL, force_nonblocking);
            if (ret == -EAGAIN && sock->peek.data_size) {
                /* We will just return what we have already. */
                ret = 0;
                tmp_iov.iov_len = 0;
            }
            if (ret < 0) {
                goto out;
            }
            assert(tmp_iov.iov_len <= sock->peek.buf_size - sock->peek.data_size);
            sock->peek.data_size += tmp_iov.iov_len;
        }

        if (sock->peek.data_size == 0) {
            /* No data to return. */
            ret = 0;
            goto out;
        }
    }

    if (sock->peek.data_size) {
        /* Copy what we have to the user app. */
        size_t size = 0;
        for (size_t i = 0; i < iov_len && size < sock->peek.data_size; i++) {
            size_t this_size = MIN(sock->peek.data_size - size, iov[i].iov_len);
            memcpy(iov[i].iov_base, sock->peek.buf + size, this_size);
            size += this_size;
        }

        if (!(*flags & MSG_PEEK)) {
            sock->peek.data_size -= size;
            memmove(sock->peek.buf, sock->peek.buf + size, sock->peek.data_size);
        }

        /* If this is not a peek recv, we could also query PAL for more data, but it's cumbersome
         * to implement. Instead just let the user app handle the partial read. */
        ret = size;
        goto out;
    }

    assert(!(*flags & MSG_PEEK));

    size_t size = 0;
    ret = sock->ops->recv(handle, iov, iov_len, msg_control, msg_controllen_ptr, &size, addr,
                          addrlen_ptr, force_nonblocking);
    maybe_epoll_et_trigger(handle, ret, /*in=*/true, !ret ? size < total_size : false);
    if (!ret) {
        ret = *flags & MSG_TRUNC ? size : MIN(size, total_size);
        *flags = size > total_size ? MSG_TRUNC : 0;
    }

out:
    unlock(&sock->recv_lock);
    if (ret == -EINTR) {
        /* Timeout could have been changed in the meantime, but it should not matter - this is
         * a peculiar corner case that nothing should really care about. */
        if (has_recvtimeout_set) {
            ret = -ERESTARTNOHAND;
        } else {
            ret = -ERESTARTSYS;
        }
    }
    return ret;
}

long libos_syscall_recvfrom(int fd, void* buf, size_t len, unsigned int flags, void* addr,
                            int* _addrlen) {
    size_t addrlen = 0;
    if (addr) {
        if (!is_user_memory_readable(_addrlen, sizeof(*_addrlen))) {
            return -EFAULT;
        }
        if (*_addrlen < 0) {
            return -EINVAL;
        }
        addrlen = *_addrlen;
        if (!is_user_memory_writable(addr, addrlen)) {
            return -EFAULT;
        }
    }

    if (!is_user_memory_writable(buf, len)) {
        return -EFAULT;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    struct iovec iov = {
        .iov_base = buf,
        .iov_len = len,
    };
    ssize_t ret = do_recvmsg(handle, &iov, 1, /*msg_control=*/NULL, /*msg_controllen_ptr=*/NULL,
                             addr, &addrlen, &flags, /*emulate_recv_error_semantics=*/true);
    if (ret >= 0 && addr) {
        *_addrlen = addrlen;
    }
    put_handle(handle);
    return ret;
}

long libos_syscall_recvmsg(int fd, struct msghdr* msg, unsigned int flags) {
    ssize_t ret = check_msghdr(msg, /*is_recv=*/true);
    if (ret < 0) {
        return ret;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    size_t addrlen = msg->msg_name ? msg->msg_namelen : 0;
    ret = do_recvmsg(handle, msg->msg_iov, msg->msg_iovlen, msg->msg_control, &msg->msg_controllen,
                     msg->msg_name, &addrlen, &flags, /*emulate_recv_error_semantics=*/true);
    if (ret >= 0) {
        if (msg->msg_name) {
            msg->msg_namelen = addrlen;
        }
        msg->msg_flags = flags;
    }
    put_handle(handle);
    return ret;
}

long libos_syscall_recvmmsg(int fd, struct mmsghdr* msg, unsigned int vlen, unsigned int flags,
                            struct __kernel_timespec* timeout) {
    if (timeout) {
        if (!is_user_memory_readable(timeout, sizeof(*timeout))) {
            return -EFAULT;
        }
        if (timeout->tv_sec < 0 || timeout->tv_nsec < 0
                || (uint64_t)timeout->tv_nsec >= TIME_NS_IN_S) {
            return -EINVAL;
        }
        log_warning("timeout argument to recvmmsg is broken, hence unsupported in Gramine");
        return -EINVAL;
    }

    for (size_t i = 0; i < vlen; i++) {
        int ret = check_msghdr(&msg[i].msg_hdr, /*is_recv=*/true);
        if (ret < 0) {
            return ret;
        }
        if (!is_user_memory_writable(&msg[i].msg_len, sizeof(msg[i].msg_len))) {
            return -EFAULT;
        }
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    ssize_t ret;
    for (size_t i = 0; i < vlen; i++) {
        struct msghdr* hdr = &msg[i].msg_hdr;
        size_t addrlen = hdr->msg_name ? hdr->msg_namelen : 0;
        unsigned int this_flags = flags;
        ret = do_recvmsg(handle, hdr->msg_iov, hdr->msg_iovlen, hdr->msg_control,
                         &hdr->msg_controllen, hdr->msg_name, &addrlen, &this_flags,
                         /*emulate_recv_error_semantics=*/true);
        if (ret < 0) {
            if (i == 0) {
                /* Return error directly. */
                goto out;
            }
            if (!is_eintr_like(ret) && ret != -EAGAIN) {
                lock(&handle->info.sock.lock);
                /* Since `i > 0`, `do_recvmsg` has already verified that `handle` is a socket. */
                handle->info.sock.last_error = -ret;
                unlock(&handle->info.sock.lock);
            }
            ret = i;
            goto out;
        }
        if (hdr->msg_name) {
            hdr->msg_namelen = addrlen;
        }
        hdr->msg_flags = this_flags;
        msg[i].msg_len = ret;
    }

    ret = vlen;

out:
    put_handle(handle);
    return ret;
}

long libos_syscall_shutdown(int fd, int how) {
    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    if (handle->type != TYPE_SOCK) {
        put_handle(handle);
        return -ENOTSOCK;
    }

    int ret;
    struct libos_sock_handle* sock = &handle->info.sock;

    lock(&sock->lock);

    switch (sock->state) {
        case SOCK_CONNECTED:
        case SOCK_LISTENING:
            break;
        default:
            ret = -ENOTCONN;
            goto out;
    }
    /* Connected and listening sockets must have `pal_handle` already set. */
    assert(sock->pal_handle);

    enum pal_delete_mode mode;
    switch (how) {
        case SHUT_RD:
            mode = PAL_DELETE_READ;
            break;
        case SHUT_WR:
            mode = PAL_DELETE_WRITE;
            break;
        case SHUT_RDWR:
            mode = PAL_DELETE_ALL;
            break;
        default:
            ret = -EINVAL;
            goto out;
    }

    ret = PalStreamDelete(sock->pal_handle, mode);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    switch (how) {
        case SHUT_RD:
            sock->can_be_read = false;
            break;
        case SHUT_WR:
            sock->can_be_written = false;
            break;
        case SHUT_RDWR:
            sock->can_be_read = false;
            sock->can_be_written = false;
            break;
    }
    ret = 0;

out:
    unlock(&sock->lock);
    put_handle(handle);
    return ret;
}

long libos_syscall_getsockname(int fd, void* addr, int* _addrlen) {
    if (!is_user_memory_readable(_addrlen, sizeof(*_addrlen))) {
        return -EFAULT;
    }
    if (*_addrlen < 0) {
        return -EINVAL;
    }
    size_t addrlen = *_addrlen;
    if (!is_user_memory_writable(addr, addrlen)) {
        return -EFAULT;
    }
    if (!is_user_memory_writable(_addrlen, sizeof(*_addrlen))) {
        return -EFAULT;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    int ret;
    if (handle->type != TYPE_SOCK) {
        ret = -ENOTSOCK;
        goto out;
    }

    struct libos_sock_handle* sock = &handle->info.sock;

    lock(&sock->lock);

    /* If the user provided buffer is too small, the address is truncated, but we report the actual
     * address size in `_addrlen`. */
    addrlen = MIN(addrlen, sock->local_addrlen);
    memcpy(addr, &sock->local_addr, addrlen);
    *_addrlen = sock->local_addrlen;

    unlock(&sock->lock);
    ret = 0;

out:
    put_handle(handle);
    return ret;
}

long libos_syscall_getpeername(int fd, void* addr, int* _addrlen) {
    if (!is_user_memory_readable(_addrlen, sizeof(*_addrlen))) {
        return -EFAULT;
    }
    if (*_addrlen < 0) {
        return -EINVAL;
    }
    size_t addrlen = *_addrlen;
    if (!is_user_memory_writable(addr, addrlen)) {
        return -EFAULT;
    }
    if (!is_user_memory_writable(_addrlen, sizeof(*_addrlen))) {
        return -EFAULT;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    if (handle->type != TYPE_SOCK) {
        put_handle(handle);
        return -ENOTSOCK;
    }

    int ret;
    struct libos_sock_handle* sock = &handle->info.sock;

    lock(&sock->lock);

    if (sock->state != SOCK_CONNECTED) {
        ret = -ENOTCONN;
        goto out;
    }

    /* If the user provided buffer is too small, the address is truncated, but we report the actual
     * address size in `_addrlen`. */
    addrlen = MIN(addrlen, sock->remote_addrlen);
    memcpy(addr, &sock->remote_addr, addrlen);
    *_addrlen = sock->remote_addrlen;

    ret = 0;

out:
    unlock(&sock->lock);
    put_handle(handle);
    return ret;
}

static int set_socket_option(struct libos_handle* handle, int optname, char* optval, size_t len) {
    __UNUSED(handle);
    __UNUSED(optval);
    __UNUSED(len);
    assert(locked(&handle->info.sock.lock));

    switch (optname) {
        case SO_ACCEPTCONN:
        case SO_DOMAIN:
        case SO_TYPE:
        case SO_PROTOCOL:
        case SO_ERROR:
            return -EPERM;
        default:
            return -ENOPROTOOPT;
    }
}

long libos_syscall_setsockopt(int fd, int level, int optname, char* optval, int optlen) {
    int ret;
    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }
    if (handle->type != TYPE_SOCK) {
        ret = -ENOTSOCK;
        goto out;
    }
    if (optlen < 0) {
        ret = -EINVAL;
        goto out;
    }
    size_t len = optlen;
    if (!is_user_memory_readable(optval, len)) {
        ret = -EFAULT;
        goto out;
    }

    struct libos_sock_handle* sock = &handle->info.sock;

    lock(&sock->lock);
    switch (level) {
        case SOL_SOCKET:
            ret = set_socket_option(handle, optname, optval, len);
            if (ret != -ENOPROTOOPT) {
                break;
            }
            /* Maybe the callback can handle this option. */
            /* Fallthrough. */
        default:
            if (!sock->ops->setsockopt) {
                ret = -EOPNOTSUPP;
            } else {
                ret = sock->ops->setsockopt(handle, level, optname, optval, len);
            }
            break;
    }
    unlock(&sock->lock);

out:
    put_handle(handle);
    return ret;
}

static int get_socket_option(struct libos_handle* handle, int optname, char* optval, size_t* len) {
    struct libos_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    union {
        int i;
        struct timeval timeval;
    } value = { 0 };
    size_t value_len = sizeof(int);

    switch (optname) {
        case SO_ACCEPTCONN:
            value.i = sock->state == SOCK_LISTENING;
            break;
        case SO_DOMAIN:
            value.i = sock->domain;
            break;
        case SO_TYPE:
            value.i = sock->type;
            break;
        case SO_PROTOCOL:
            value.i = sock->protocol;
            break;
        case SO_ERROR:
            value.i = sock->last_error;
            break;
        case SO_RCVTIMEO:
            value.timeval.tv_sec = sock->receivetimeout_us / TIME_US_IN_S;
            value.timeval.tv_usec = sock->receivetimeout_us % TIME_US_IN_S;
            value_len = sizeof(value.timeval);
            break;
        case SO_SNDTIMEO:
            value.timeval.tv_sec = sock->sendtimeout_us / TIME_US_IN_S;
            value.timeval.tv_usec = sock->sendtimeout_us % TIME_US_IN_S;
            value_len = sizeof(value.timeval);
            break;
        case SO_REUSEADDR:
            value.i = sock->reuseaddr;
            break;
        case SO_REUSEPORT:
            value.i = sock->reuseport;
            break;
        case SO_BROADCAST:
            value.i = sock->broadcast;
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

long libos_syscall_getsockopt(int fd, int level, int optname, char* optval, int* optlen) {
    int ret;
    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }
    if (handle->type != TYPE_SOCK) {
        ret = -ENOTSOCK;
        goto out;
    }

    if (!is_user_memory_readable(optlen, sizeof(*optlen))) {
        ret = -EFAULT;
        goto out;
    }
    if (*optlen < 0) {
        ret = -EINVAL;
        goto out;
    }
    size_t len = *optlen;
    if (!is_user_memory_writable(optval, len)) {
        ret = -EFAULT;
        goto out;
    }

    struct libos_sock_handle* sock = &handle->info.sock;

    lock(&sock->lock);
    switch (level) {
        case SOL_SOCKET:
            ret = get_socket_option(handle, optname, optval, &len);
            if (ret != -ENOPROTOOPT) {
                break;
            }
            /* Maybe the callback can handle this option. */
            /* Fallthrough. */
        default:
            if (!sock->ops->getsockopt) {
                ret = -EOPNOTSUPP;
            } else {
                ret = sock->ops->getsockopt(handle, level, optname, optval, &len);
            }
            break;
    }
    unlock(&sock->lock);

    if (ret == 0) {
        if (!is_user_memory_writable(optlen, sizeof(*optlen))) {
            ret = -EFAULT;
            goto out;
        }
        *optlen = len;
    }

out:
    put_handle(handle);
    return ret;
}
