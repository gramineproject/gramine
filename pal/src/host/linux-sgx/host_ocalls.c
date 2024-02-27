/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include <stddef.h> /* must be included before linux/signal.h */

#include <asm/errno.h>
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <asm/poll.h>
#include <limits.h>
#include <linux/futex.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/signal.h>

#include "cpu.h"
#include "debug_map.h"
#include "host_ecalls.h"
#include "host_internal.h"
#include "host_process.h"
#include "linux_utils.h"
#include "pal_ocall_types.h"
#include "pal_rpc_queue.h"
#include "pal_tcb.h"
#include "pal_topology.h"
#include "sgx_arch.h"
#include "sigset.h"

#define DEFAULT_BACKLOG 2048

rpc_queue_t* g_rpc_queue = NULL; /* pointer to untrusted queue */

static long sgx_ocall_exit(void* args) {
    struct ocall_exit* ocall_exit_args = args;

    if (ocall_exit_args->exitcode != (int)((uint8_t)ocall_exit_args->exitcode)) {
        log_debug("Saturation error in exit code %d getting rounded down to %u",
                  ocall_exit_args->exitcode, (uint8_t)ocall_exit_args->exitcode);
        ocall_exit_args->exitcode = 255;
    }

    /* exit the whole process if exit_group() */
    if (ocall_exit_args->is_exitgroup) {
        update_and_print_stats(/*process_wide=*/true);
#ifdef DEBUG
        sgx_profile_finish();
#endif

#ifdef SGX_VTUNE_PROFILE
        if (g_vtune_profile_enabled) {
            extern void __itt_fini_ittlib(void);
            __itt_fini_ittlib();
        }
#endif
        DO_SYSCALL(exit_group, (int)ocall_exit_args->exitcode);
        die_or_inf_loop();
    }

    /* otherwise call SGX-related thread reset and exit this thread */
    block_async_signals(true);
    ecall_thread_reset();

    unmap_my_tcs();

    if (!current_enclave_thread_cnt()) {
        /* no enclave threads left, kill the whole process */
        update_and_print_stats(/*process_wide=*/true);
#ifdef DEBUG
        sgx_profile_finish();
#endif
#ifdef SGX_VTUNE_PROFILE
        if (g_vtune_profile_enabled) {
            extern void __itt_fini_ittlib(void);
            __itt_fini_ittlib();
        }
#endif
        DO_SYSCALL(exit_group, (int)ocall_exit_args->exitcode);
        die_or_inf_loop();
    }

    thread_exit((int)ocall_exit_args->exitcode);
    return 0;
}

static long sgx_ocall_mmap_untrusted(void* args) {
    struct ocall_mmap_untrusted* ocall_mmap_args = args;
    void* addr;

    addr = (void*)DO_SYSCALL(mmap, ocall_mmap_args->addr, ocall_mmap_args->size,
                             ocall_mmap_args->prot, ocall_mmap_args->flags, ocall_mmap_args->fd,
                             ocall_mmap_args->offset);
    if (IS_PTR_ERR(addr))
        return PTR_TO_ERR(addr);

    ocall_mmap_args->addr = addr;
    return 0;
}

static long sgx_ocall_munmap_untrusted(void* args) {
    struct ocall_munmap_untrusted* ocall_munmap_args = args;
    DO_SYSCALL(munmap, ocall_munmap_args->addr, ocall_munmap_args->size);
    return 0;
}

static long sgx_ocall_cpuid(void* args) {
    struct ocall_cpuid* ocall_cpuid_args = args;
    __asm__ volatile("cpuid"
                     : "=a"(ocall_cpuid_args->values[0]),
                       "=b"(ocall_cpuid_args->values[1]),
                       "=c"(ocall_cpuid_args->values[2]),
                       "=d"(ocall_cpuid_args->values[3])
                     : "a"(ocall_cpuid_args->leaf), "c"(ocall_cpuid_args->subleaf)
                     : "memory");
    return 0;
}

static long sgx_ocall_open(void* args) {
    struct ocall_open* ocall_open_args = args;
    return DO_SYSCALL_INTERRUPTIBLE(open, ocall_open_args->pathname, ocall_open_args->flags,
                                    ocall_open_args->mode);
}

static long sgx_ocall_close(void* args) {
    struct ocall_close* ocall_close_args = args;
    /* Callers cannot retry close on `-EINTR`, so we do not call `DO_SYSCALL_INTERRUPTIBLE`. */
    return DO_SYSCALL(close, ocall_close_args->fd);
}

static long sgx_ocall_read(void* args) {
    struct ocall_read* ocall_read_args = args;
    return DO_SYSCALL_INTERRUPTIBLE(read, ocall_read_args->fd, ocall_read_args->buf,
                                    ocall_read_args->count);
}

static long sgx_ocall_write(void* args) {
    struct ocall_write* ocall_write_args = args;
    return DO_SYSCALL_INTERRUPTIBLE(write, ocall_write_args->fd, ocall_write_args->buf,
                                    ocall_write_args->count);
}

static long sgx_ocall_pread(void* args) {
    struct ocall_pread* ocall_pread_args = args;
    return DO_SYSCALL_INTERRUPTIBLE(pread64, ocall_pread_args->fd, ocall_pread_args->buf,
                                    ocall_pread_args->count, ocall_pread_args->offset);
}

static long sgx_ocall_pwrite(void* args) {
    struct ocall_pwrite* ocall_pwrite_args = args;
    return DO_SYSCALL_INTERRUPTIBLE(pwrite64, ocall_pwrite_args->fd, ocall_pwrite_args->buf,
                                    ocall_pwrite_args->count, ocall_pwrite_args->offset);
}

static long sgx_ocall_fstat(void* args) {
    struct ocall_fstat* ocall_fstat_args = args;
    return DO_SYSCALL_INTERRUPTIBLE(fstat, ocall_fstat_args->fd, &ocall_fstat_args->stat);
}

static long sgx_ocall_fionread(void* args) {
    struct ocall_fionread* ocall_fionread_args = args;
    int val;
    long ret = DO_SYSCALL_INTERRUPTIBLE(ioctl, ocall_fionread_args->fd, FIONREAD, &val);
    return ret < 0 ? ret : val;
}

static long sgx_ocall_fsetnonblock(void* args) {
    struct ocall_fsetnonblock* ocall_fsetnonblock_args = args;
    long ret;
    int flags;

    ret = DO_SYSCALL(fcntl, ocall_fsetnonblock_args->fd, F_GETFL);
    if (ret < 0)
        return ret;

    flags = ret;
    if (ocall_fsetnonblock_args->nonblocking) {
        if (!(flags & O_NONBLOCK))
            ret = DO_SYSCALL(fcntl, ocall_fsetnonblock_args->fd, F_SETFL, flags | O_NONBLOCK);
    } else {
        if (flags & O_NONBLOCK)
            ret = DO_SYSCALL(fcntl, ocall_fsetnonblock_args->fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    return ret;
}

static long sgx_ocall_fchmod(void* args) {
    struct ocall_fchmod* ocall_fchmod_args = args;
    return DO_SYSCALL(fchmod, ocall_fchmod_args->fd, ocall_fchmod_args->mode);
}

static long sgx_ocall_fsync(void* args) {
    struct ocall_fsync* ocall_fsync_args = args;
    return DO_SYSCALL_INTERRUPTIBLE(fsync, ocall_fsync_args->fd);
}

static long sgx_ocall_ftruncate(void* args) {
    struct ocall_ftruncate* ocall_ftruncate_args = args;
    return DO_SYSCALL(ftruncate, ocall_ftruncate_args->fd, ocall_ftruncate_args->length);
}

static long sgx_ocall_mkdir(void* args) {
    struct ocall_mkdir* ocall_mkdir_args = args;
    return DO_SYSCALL(mkdir, ocall_mkdir_args->pathname, ocall_mkdir_args->mode);
}

static long sgx_ocall_getdents(void* args) {
    struct ocall_getdents* ocall_getdents_args = args;
    unsigned int count;
    count = ocall_getdents_args->size <= UINT_MAX ? ocall_getdents_args->size : UINT_MAX;
    return DO_SYSCALL_INTERRUPTIBLE(getdents64, ocall_getdents_args->fd, ocall_getdents_args->dirp,
                                    count);
}

static long sgx_ocall_resume_thread(void* args) {
    int tid = get_tid_from_tcs(args);
    if (tid < 0)
        return tid;

    return DO_SYSCALL(tgkill, g_host_pid, tid, SIGCONT);
}

static long sgx_ocall_sched_setaffinity(void* args) {
    struct ocall_sched_setaffinity* ocall_sched_args = args;
    int tid = get_tid_from_tcs(ocall_sched_args->tcs);
    if (tid < 0)
        return tid;

    return DO_SYSCALL(sched_setaffinity, tid, ocall_sched_args->cpumask_size,
                      ocall_sched_args->cpu_mask);
}

static long sgx_ocall_sched_getaffinity(void* args) {
    struct ocall_sched_getaffinity* ocall_sched_args = args;
    int tid = get_tid_from_tcs(ocall_sched_args->tcs);
    if (tid < 0)
        return tid;

    return DO_SYSCALL(sched_getaffinity, tid, ocall_sched_args->cpumask_size,
                      ocall_sched_args->cpu_mask);
}

static long sgx_ocall_clone_thread(void* args) {
    return clone_thread(args);
}

static long sgx_ocall_create_process(void* args) {
    struct ocall_create_process* ocall_cp_args = args;

    return sgx_create_process(ocall_cp_args->nargs, ocall_cp_args->args,
                              g_pal_enclave.raw_manifest_data, ocall_cp_args->reserved_mem_ranges,
                              ocall_cp_args->reserved_mem_ranges_size, &ocall_cp_args->stream_fd);
}

static long sgx_ocall_futex(void* args) {
    struct ocall_futex* ocall_futex_args = args;
    long ret;

    struct timespec timeout = { 0 };
    bool have_timeout = ocall_futex_args->timeout_us != (uint64_t)-1;
    if (have_timeout) {
        time_get_now_plus_ns(&timeout, ocall_futex_args->timeout_us * TIME_NS_IN_US);
    }

    /* `FUTEX_WAIT` treats timeout parameter as a relative value. We want to have an absolute one
     * (since we need to get start time anyway, to calculate remaining time later on), hence we use
     * `FUTEX_WAIT_BITSET` with `FUTEX_BITSET_MATCH_ANY`. */
    uint32_t val3 = 0;
    int priv_flag = ocall_futex_args->op & FUTEX_PRIVATE_FLAG;
    int op = ocall_futex_args->op & ~FUTEX_PRIVATE_FLAG;
    if (op == FUTEX_WAKE) {
        op = FUTEX_WAKE_BITSET;
        val3 = FUTEX_BITSET_MATCH_ANY;
    } else if (op == FUTEX_WAIT) {
        op = FUTEX_WAIT_BITSET;
        val3 = FUTEX_BITSET_MATCH_ANY;
    } else {
        /* Other operations are not supported atm. */
        return -EINVAL;
    }

    ret = DO_SYSCALL_INTERRUPTIBLE(futex, ocall_futex_args->futex, op | priv_flag,
                                   ocall_futex_args->val,
                                   have_timeout ? &timeout : NULL, NULL, val3);

    if (have_timeout) {
        int64_t diff = time_ns_diff_from_now(&timeout);
        if (diff < 0) {
            /* We might have slept a bit too long. */
            diff = 0;
        }
        ocall_futex_args->timeout_us = (uint64_t)diff / TIME_NS_IN_US;
    }
    return ret;
}

static long sgx_ocall_socket(void* args) {
    struct ocall_socket* ocall_socket_args = args;
    return DO_SYSCALL(socket, ocall_socket_args->family, ocall_socket_args->type,
                      ocall_socket_args->protocol);
}

static long sgx_ocall_bind(void* args) {
    struct ocall_bind* ocall_bind_args = args;
    int ret = DO_SYSCALL(bind, ocall_bind_args->fd, ocall_bind_args->addr,
                         (int)ocall_bind_args->addrlen);
    if (ret < 0) {
        return ret;
    }

    struct sockaddr_storage addr = { 0 };
    int addrlen = sizeof(addr);
    ret = DO_SYSCALL(getsockname, ocall_bind_args->fd, &addr, &addrlen);
    if (ret < 0) {
        return ret;
    }

    switch (addr.ss_family) {
        case AF_INET:
            memcpy(&ocall_bind_args->new_port,
                   (char*)&addr + offsetof(struct sockaddr_in, sin_port),
                   sizeof(ocall_bind_args->new_port));
            break;
        case AF_INET6:
            memcpy(&ocall_bind_args->new_port,
                   (char*)&addr + offsetof(struct sockaddr_in6, sin6_port),
                   sizeof(ocall_bind_args->new_port));
            break;
        default:
            log_error("unknown address family: %d", addr.ss_family);
            DO_SYSCALL(exit_group, 1);
            die_or_inf_loop();
    }

    return 0;
}

static long sgx_ocall_listen_simple(void* args) {
    struct ocall_listen_simple* ocall_listen_args = args;
    return DO_SYSCALL(listen, ocall_listen_args->fd, ocall_listen_args->backlog);
}

static long sgx_ocall_listen(void* args) {
    struct ocall_listen* ocall_listen_args = args;
    long ret;
    int fd;

    if (ocall_listen_args->addrlen > INT_MAX) {
        ret = -EINVAL;
        goto err;
    }

    ret = DO_SYSCALL(socket, ocall_listen_args->domain, ocall_listen_args->type,
                     ocall_listen_args->protocol);
    if (ret < 0)
        goto err;

    fd = ret;

    /* must set the socket to be reuseable */
    int reuseaddr = 1;
    ret = DO_SYSCALL(setsockopt, fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    if (ret < 0)
        goto err_fd;

    if (ocall_listen_args->domain == AF_INET6) {
        /* IPV6_V6ONLY socket option can only be set before first bind */
        ret = DO_SYSCALL(setsockopt, fd, IPPROTO_IPV6, IPV6_V6ONLY, &ocall_listen_args->ipv6_v6only,
                         sizeof(ocall_listen_args->ipv6_v6only));
        if (ret < 0)
            goto err_fd;
    }

    ret = DO_SYSCALL_INTERRUPTIBLE(bind, fd, ocall_listen_args->addr,
                                   (int)ocall_listen_args->addrlen);
    if (ret < 0)
        goto err_fd;

    if (ocall_listen_args->addr) {
        int addrlen = ocall_listen_args->addrlen;
        ret = DO_SYSCALL(getsockname, fd, ocall_listen_args->addr, &addrlen);
        if (ret < 0)
            goto err_fd;
        ocall_listen_args->addrlen = addrlen;
    }

    if (ocall_listen_args->type & SOCK_STREAM) {
        ret = DO_SYSCALL_INTERRUPTIBLE(listen, fd, DEFAULT_BACKLOG);
        if (ret < 0)
            goto err_fd;
    }

    return fd;

err_fd:
    DO_SYSCALL(close, fd);
err:
    return ret;
}

static long sgx_ocall_accept(void* args) {
    struct ocall_accept* ocall_accept_args = args;
    long ret;

    if (ocall_accept_args->addrlen > INT_MAX || ocall_accept_args->local_addrlen > INT_MAX) {
        return -EINVAL;
    }
    int addrlen = ocall_accept_args->addrlen;
    int options = ocall_accept_args->options;
    assert(WITHIN_MASK(options, SOCK_CLOEXEC | SOCK_NONBLOCK));

    ret = DO_SYSCALL_INTERRUPTIBLE(accept4, ocall_accept_args->sockfd, ocall_accept_args->addr,
                                   &addrlen, options);
    if (ret < 0)
        return ret;

    int fd = ret;
    ocall_accept_args->addrlen = addrlen;

    if (ocall_accept_args->local_addrlen > 0) {
        int addrlen = ocall_accept_args->local_addrlen;
        ret = DO_SYSCALL(getsockname, fd, ocall_accept_args->local_addr, &addrlen);
        if (ret < 0) {
            goto err;
        }
        ocall_accept_args->local_addrlen = addrlen;
    }
    return fd;

err:
    DO_SYSCALL(close, fd);
    return ret;
}

static long sgx_ocall_connect(void* args) {
    struct ocall_connect* ocall_connect_args = args;
    long ret;
    int fd;

    if (ocall_connect_args->addrlen > INT_MAX || ocall_connect_args->bind_addrlen > INT_MAX) {
        ret = -EINVAL;
        goto err;
    }

    ret = DO_SYSCALL(socket, ocall_connect_args->domain, ocall_connect_args->type,
                     ocall_connect_args->protocol);
    if (ret < 0)
        goto err;

    fd = ret;

    if (ocall_connect_args->bind_addr && ocall_connect_args->bind_addr->sa_family) {
        if (ocall_connect_args->domain == AF_INET6) {
            /* IPV6_V6ONLY socket option can only be set before first bind */
            ret = DO_SYSCALL(setsockopt, fd, IPPROTO_IPV6, IPV6_V6ONLY,
                             &ocall_connect_args->ipv6_v6only,
                             sizeof(ocall_connect_args->ipv6_v6only));
            if (ret < 0)
                goto err_fd;
        }

        ret = DO_SYSCALL_INTERRUPTIBLE(bind, fd, ocall_connect_args->bind_addr,
                                       ocall_connect_args->bind_addrlen);
        if (ret < 0)
            goto err_fd;
    }

    if (ocall_connect_args->addr) {
        ret = DO_SYSCALL_INTERRUPTIBLE(connect, fd, ocall_connect_args->addr,
                                       ocall_connect_args->addrlen);

        if (ret == -EINPROGRESS) {
            do {
                struct pollfd pfd = {
                    .fd      = fd,
                    .events  = POLLOUT,
                    .revents = 0,
                };
                ret = DO_SYSCALL_INTERRUPTIBLE(ppoll, &pfd, 1, NULL, NULL);
            } while (ret == -EWOULDBLOCK);
        }

        if (ret < 0)
            goto err_fd;
    }

    if (ocall_connect_args->bind_addr && !ocall_connect_args->bind_addr->sa_family) {
        int addrlen = ocall_connect_args->bind_addrlen;
        ret = DO_SYSCALL(getsockname, fd, ocall_connect_args->bind_addr, &addrlen);
        if (ret < 0)
            goto err_fd;
        ocall_connect_args->bind_addrlen = addrlen;
    }

    return fd;

err_fd:
    DO_SYSCALL(close, fd);
err:
    return ret;
}

static long sgx_ocall_connect_simple(void* args) {
    struct ocall_connect_simple* ocall_connect_args = args;
    int ret = DO_SYSCALL_INTERRUPTIBLE(connect, ocall_connect_args->fd, ocall_connect_args->addr,
                                       (int)ocall_connect_args->addrlen);
    if (ret < 0 && ret != -EINPROGRESS) {
        return ret;
    }

    /* Connect succeeded or in progress (EINPROGRESS); in both cases retrieve local name -- host
     * Linux binds the socket to address even in case of EINPROGRESS. */
    int addrlen = sizeof(*ocall_connect_args->addr);
    int getsockname_ret = DO_SYSCALL(getsockname, ocall_connect_args->fd, ocall_connect_args->addr,
                                     &addrlen);
    if (getsockname_ret < 0) {
        /* This should never happen, but we have to handle it somehow. */
        return getsockname_ret;
    }
    ocall_connect_args->addrlen = addrlen;

    assert(ret == 0 || ret == -EINPROGRESS);
    return ret;
}

static long sgx_ocall_recv(void* args) {
    struct ocall_recv* ocall_recv_args = args;
    long ret;

    if (ocall_recv_args->addr && ocall_recv_args->addrlen > INT_MAX) {
        return -EINVAL;
    }
    int addrlen = ocall_recv_args->addr ? ocall_recv_args->addrlen : 0;

    struct msghdr hdr;
    struct iovec iov[1];

    iov[0].iov_base    = ocall_recv_args->buf;
    iov[0].iov_len     = ocall_recv_args->count;
    hdr.msg_name       = ocall_recv_args->addr;
    hdr.msg_namelen    = addrlen;
    hdr.msg_iov        = iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = ocall_recv_args->control;
    hdr.msg_controllen = ocall_recv_args->controllen;
    hdr.msg_flags      = 0;

    ret = DO_SYSCALL_INTERRUPTIBLE(recvmsg, ocall_recv_args->sockfd, &hdr, ocall_recv_args->flags);

    if (ret >= 0 && hdr.msg_name) {
        /* note that ocall_recv_args->addr is filled by recvmsg() itself */
        ocall_recv_args->addrlen = hdr.msg_namelen;
    }

    if (ret >= 0 && hdr.msg_control) {
        /* note that ocall_recv_args->control is filled by recvmsg() itself */
        ocall_recv_args->controllen = hdr.msg_controllen;
    }

    return ret;
}

static long sgx_ocall_send(void* args) {
    struct ocall_send* ocall_send_args = args;

    if (ocall_send_args->addr && ocall_send_args->addrlen > INT_MAX) {
        return -EINVAL;
    }
    int addrlen = ocall_send_args->addr ? ocall_send_args->addrlen : 0;

    struct msghdr hdr;
    struct iovec iov[1];

    iov[0].iov_base    = (void*)ocall_send_args->buf;
    iov[0].iov_len     = ocall_send_args->count;
    hdr.msg_name       = (void*)ocall_send_args->addr;
    hdr.msg_namelen    = addrlen;
    hdr.msg_iov        = iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = ocall_send_args->control;
    hdr.msg_controllen = ocall_send_args->controllen;
    hdr.msg_flags      = 0;

    return DO_SYSCALL_INTERRUPTIBLE(sendmsg, ocall_send_args->sockfd, &hdr,
                                    MSG_NOSIGNAL | ocall_send_args->flags);
}

static long sgx_ocall_setsockopt(void* args) {
    struct ocall_setsockopt* ocall_setsockopt_args = args;
    if (ocall_setsockopt_args->optlen > INT_MAX) {
        return -EINVAL;
    }
    return DO_SYSCALL(setsockopt, ocall_setsockopt_args->sockfd, ocall_setsockopt_args->level,
                      ocall_setsockopt_args->optname, ocall_setsockopt_args->optval,
                      (int)ocall_setsockopt_args->optlen);
}

static long sgx_ocall_shutdown(void* args) {
    struct ocall_shutdown* ocall_shutdown_args = args;
    DO_SYSCALL_INTERRUPTIBLE(shutdown, ocall_shutdown_args->sockfd, ocall_shutdown_args->how);
    return 0;
}

static long sgx_ocall_gettime(void* args) {
    struct ocall_gettime* ocall_gettime_args = args;
    struct timeval tv;
    DO_SYSCALL(gettimeofday, &tv, NULL);
    ocall_gettime_args->microsec = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
    return 0;
}

static long sgx_ocall_sched_yield(void* args) {
    __UNUSED(args);
    DO_SYSCALL_INTERRUPTIBLE(sched_yield);
    return 0;
}

static long sgx_ocall_poll(void* args) {
    struct ocall_poll* ocall_poll_args = args;
    long ret;

    struct timespec* timeout = NULL;
    struct timespec end_time = { 0 };
    bool have_timeout = ocall_poll_args->timeout_us != (uint64_t)-1;
    if (have_timeout) {
        uint64_t timeout_ns = ocall_poll_args->timeout_us * TIME_NS_IN_US;
        timeout = __alloca(sizeof(*timeout));
        timeout->tv_sec = timeout_ns / TIME_NS_IN_S;
        timeout->tv_nsec = timeout_ns % TIME_NS_IN_S;
        time_get_now_plus_ns(&end_time, timeout_ns);
    }

    ret = DO_SYSCALL_INTERRUPTIBLE(ppoll, ocall_poll_args->fds, ocall_poll_args->nfds, timeout, NULL);

    if (have_timeout) {
        int64_t diff = time_ns_diff_from_now(&end_time);
        if (diff < 0) {
            /* We might have slept a bit too long. */
            diff = 0;
        }
        ocall_poll_args->timeout_us = (uint64_t)diff / TIME_NS_IN_US;
    }

    return ret;
}

static long sgx_ocall_rename(void* args) {
    struct ocall_rename* ocall_rename_args = args;
    return DO_SYSCALL(rename, ocall_rename_args->oldpath, ocall_rename_args->newpath);
}

static long sgx_ocall_delete(void* args) {
    struct ocall_delete* ocall_delete_args = args;
    long ret;

    ret = DO_SYSCALL(unlink, ocall_delete_args->pathname);

    if (ret == -EISDIR)
        ret = DO_SYSCALL(rmdir, ocall_delete_args->pathname);

    return ret;
}

static long sgx_ocall_eventfd(void* args) {
    struct ocall_eventfd* ocall_eventfd_args = args;
    return DO_SYSCALL(eventfd2, 0, ocall_eventfd_args->flags);
}

static long sgx_ocall_debug_map_add(void* args) {
    struct ocall_debug_map_add* ocall_debug_args = args;

#ifdef DEBUG
    int ret = debug_map_add(ocall_debug_args->name, ocall_debug_args->addr);
    if (ret < 0) {
        log_error("debug_map_add(%s, %p) failed: %s", ocall_debug_args->name,
                  ocall_debug_args->addr, unix_strerror(ret));
    }

    sgx_profile_report_elf(ocall_debug_args->name, ocall_debug_args->addr);
#else
    __UNUSED(ocall_debug_args);
#endif
    return 0;
}

static long sgx_ocall_debug_map_remove(void* args) {
    struct ocall_debug_map_remove* ocall_debug_args = args;

#ifdef DEBUG
    int ret = debug_map_remove(ocall_debug_args->addr);
    if (ret < 0) {
        log_error("debug_map_remove(%p) failed: %s", ocall_debug_args->addr,
                  unix_strerror(ret));
    }
#else
    __UNUSED(ocall_debug_args);
#endif
    return 0;
}

static long sgx_ocall_debug_describe_location(void* args) {
    struct ocall_debug_describe_location* ocall_debug_args = args;

#ifdef DEBUG
    return debug_describe_location(ocall_debug_args->addr, ocall_debug_args->buf,
                                   ocall_debug_args->buf_size);
#else
    __UNUSED(ocall_debug_args);
    return -ENOSYS;
#endif
}

static long sgx_ocall_ioctl(void* args) {
    struct ocall_ioctl* ocall_ioctl_args = args;
    return DO_SYSCALL(ioctl, ocall_ioctl_args->fd, ocall_ioctl_args->cmd, ocall_ioctl_args->arg);
}

static long sgx_ocall_get_quote(void* args) {
    struct ocall_get_quote* ocall_quote_args = args;
    return retrieve_quote(ocall_quote_args->is_epid ? &ocall_quote_args->spid : NULL,
                          ocall_quote_args->linkable, &ocall_quote_args->report,
                          &ocall_quote_args->nonce, &ocall_quote_args->quote,
                          &ocall_quote_args->quote_len);
}

static long sgx_ocall_edmm_modify_pages_type(void* _args) {
    struct ocall_edmm_modify_pages_type* args = _args;
    return edmm_modify_pages_type(args->addr, args->count, args->type);
}

static long sgx_ocall_edmm_remove_pages(void* _args) {
    struct ocall_edmm_remove_pages* args = _args;
    return edmm_remove_pages(args->addr, args->count);
}

static long sgx_ocall_edmm_restrict_pages_perm(void* _args) {
    struct ocall_edmm_restrict_pages_perm* args = _args;
    return edmm_restrict_pages_perm(args->addr, args->count, args->prot);
}

sgx_ocall_fn_t ocall_table[OCALL_NR] = {
    [OCALL_EXIT]                     = sgx_ocall_exit,
    [OCALL_MMAP_UNTRUSTED]           = sgx_ocall_mmap_untrusted,
    [OCALL_MUNMAP_UNTRUSTED]         = sgx_ocall_munmap_untrusted,
    [OCALL_CPUID]                    = sgx_ocall_cpuid,
    [OCALL_OPEN]                     = sgx_ocall_open,
    [OCALL_CLOSE]                    = sgx_ocall_close,
    [OCALL_READ]                     = sgx_ocall_read,
    [OCALL_WRITE]                    = sgx_ocall_write,
    [OCALL_PREAD]                    = sgx_ocall_pread,
    [OCALL_PWRITE]                   = sgx_ocall_pwrite,
    [OCALL_FSTAT]                    = sgx_ocall_fstat,
    [OCALL_FIONREAD]                 = sgx_ocall_fionread,
    [OCALL_FSETNONBLOCK]             = sgx_ocall_fsetnonblock,
    [OCALL_FCHMOD]                   = sgx_ocall_fchmod,
    [OCALL_FSYNC]                    = sgx_ocall_fsync,
    [OCALL_FTRUNCATE]                = sgx_ocall_ftruncate,
    [OCALL_MKDIR]                    = sgx_ocall_mkdir,
    [OCALL_GETDENTS]                 = sgx_ocall_getdents,
    [OCALL_RESUME_THREAD]            = sgx_ocall_resume_thread,
    [OCALL_SCHED_SETAFFINITY]        = sgx_ocall_sched_setaffinity,
    [OCALL_SCHED_GETAFFINITY]        = sgx_ocall_sched_getaffinity,
    [OCALL_CLONE_THREAD]             = sgx_ocall_clone_thread,
    [OCALL_CREATE_PROCESS]           = sgx_ocall_create_process,
    [OCALL_FUTEX]                    = sgx_ocall_futex,
    [OCALL_SOCKET]                   = sgx_ocall_socket,
    [OCALL_BIND]                     = sgx_ocall_bind,
    [OCALL_LISTEN_SIMPLE]            = sgx_ocall_listen_simple,
    [OCALL_LISTEN]                   = sgx_ocall_listen,
    [OCALL_ACCEPT]                   = sgx_ocall_accept,
    [OCALL_CONNECT]                  = sgx_ocall_connect,
    [OCALL_CONNECT_SIMPLE]           = sgx_ocall_connect_simple,
    [OCALL_RECV]                     = sgx_ocall_recv,
    [OCALL_SEND]                     = sgx_ocall_send,
    [OCALL_SETSOCKOPT]               = sgx_ocall_setsockopt,
    [OCALL_SHUTDOWN]                 = sgx_ocall_shutdown,
    [OCALL_GETTIME]                  = sgx_ocall_gettime,
    [OCALL_SCHED_YIELD]              = sgx_ocall_sched_yield,
    [OCALL_POLL]                     = sgx_ocall_poll,
    [OCALL_RENAME]                   = sgx_ocall_rename,
    [OCALL_DELETE]                   = sgx_ocall_delete,
    [OCALL_DEBUG_MAP_ADD]            = sgx_ocall_debug_map_add,
    [OCALL_DEBUG_MAP_REMOVE]         = sgx_ocall_debug_map_remove,
    [OCALL_DEBUG_DESCRIBE_LOCATION]  = sgx_ocall_debug_describe_location,
    [OCALL_EVENTFD]                  = sgx_ocall_eventfd,
    [OCALL_IOCTL]                    = sgx_ocall_ioctl,
    [OCALL_GET_QUOTE]                = sgx_ocall_get_quote,
    [OCALL_EDMM_MODIFY_PAGES_TYPE]   = sgx_ocall_edmm_modify_pages_type,
    [OCALL_EDMM_REMOVE_PAGES]        = sgx_ocall_edmm_remove_pages,
    [OCALL_EDMM_RESTRICT_PAGES_PERM] = sgx_ocall_edmm_restrict_pages_perm,
};

static int rpc_thread_loop(void* arg) {
    __UNUSED(arg);
    long mytid = DO_SYSCALL(gettid);

    /* block all signals except SIGUSR2 for RPC thread */
    __sigset_t mask;
    __sigfillset(&mask);
    __sigdelset(&mask, SIGUSR2);
    DO_SYSCALL(rt_sigprocmask, SIG_SETMASK, &mask, NULL, sizeof(mask));

    spinlock_lock(&g_rpc_queue->lock);
    g_rpc_queue->rpc_threads[g_rpc_queue->rpc_threads_cnt] = mytid;
    g_rpc_queue->rpc_threads_cnt++;
    spinlock_unlock(&g_rpc_queue->lock);

    static const uint64_t SPIN_ATTEMPTS_MAX = 10000;     /* rather arbitrary */
    static const uint64_t SLEEP_TIME_MAX    = 100000000; /* nanoseconds (0.1 seconds) */
    static const uint64_t SLEEP_TIME_STEP   = 1000000;   /* 100 steps before capped */

    /* no races possible since vars are thread-local and RPC threads don't receive signals */
    uint64_t spin_attempts = 0;
    uint64_t sleep_time    = 0;

    while (1) {
        rpc_request_t* req = rpc_dequeue(g_rpc_queue);
        if (!req) {
            if (spin_attempts == SPIN_ATTEMPTS_MAX) {
                if (sleep_time < SLEEP_TIME_MAX)
                    sleep_time += SLEEP_TIME_STEP;

                struct timespec tv = {.tv_sec = 0, .tv_nsec = sleep_time};
                (void)DO_SYSCALL(nanosleep, &tv, /*rem=*/NULL);
            } else {
                spin_attempts++;
                CPU_RELAX();
            }
            continue;
        }

        /* new request came, reset spin/sleep heuristics */
        spin_attempts = 0;
        sleep_time    = 0;

        /* call actual function and notify awaiting enclave thread when done */
        sgx_ocall_fn_t f = ocall_table[req->ocall_index];
        req->result = f(req->buffer);

        /* this code is based on Mutex 2 from Futexes are Tricky */
        int old_lock_state = __atomic_fetch_sub(&req->lock.lock, 1, __ATOMIC_ACQ_REL);
        if (old_lock_state == SPINLOCK_LOCKED_WITH_WAITERS) {
            /* must unlock and wake waiters */
            spinlock_unlock(&req->lock);
            int ret = DO_SYSCALL(futex, &req->lock.lock, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
            if (ret == -1)
                log_error("RPC thread failed to wake up enclave thread");
        }
    }

    /* NOTREACHED */
    return 0;
}

int start_rpc(size_t threads_cnt) {
    g_rpc_queue = (rpc_queue_t*)DO_SYSCALL(mmap, NULL,
                                           ALIGN_UP(sizeof(rpc_queue_t), PRESET_PAGESIZE),
                                           PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
                                           -1, 0);
    if (IS_PTR_ERR(g_rpc_queue))
        return -ENOMEM;

    /* initialize g_rpc_queue just for sanity, it will be overwritten by in-enclave code */
    rpc_queue_init(g_rpc_queue);

    for (size_t i = 0; i < threads_cnt; i++) {
        void* stack = (void*)DO_SYSCALL(mmap, NULL, RPC_STACK_SIZE, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (IS_PTR_ERR(stack))
            return -ENOMEM;

        void* child_stack_top = stack + RPC_STACK_SIZE;
        child_stack_top = ALIGN_DOWN_PTR(child_stack_top, 16);

        int dummy_parent_tid_field = 0;
        int ret = clone(rpc_thread_loop, child_stack_top,
                        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM |
                        CLONE_THREAD | CLONE_SIGHAND | CLONE_PTRACE | CLONE_PARENT_SETTID,
                        /*arg=*/NULL, &dummy_parent_tid_field, /*tls=*/NULL, /*child_tid=*/NULL,
                        thread_exit);

        if (ret < 0) {
            DO_SYSCALL(munmap, stack, RPC_STACK_SIZE);
            return -ENOMEM;
        }
    }

    /* wait until all RPC threads are initialized in rpc_thread_loop */
    while (1) {
        spinlock_lock(&g_rpc_queue->lock);
        size_t n = g_rpc_queue->rpc_threads_cnt;
        spinlock_unlock(&g_rpc_queue->lock);
        if (n == g_pal_enclave.rpc_thread_num)
            break;
        DO_SYSCALL(sched_yield);
    }

    return 0;
}
