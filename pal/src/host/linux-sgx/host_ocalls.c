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

extern bool g_vtune_profile_enabled;

rpc_queue_t* g_rpc_queue = NULL; /* pointer to untrusted queue */

static long sgx_ocall_exit(void* pms) {
    ocall_exit_t* ms = (ocall_exit_t*)pms;

    if (ms->exitcode != (int)((uint8_t)ms->exitcode)) {
        log_debug("Saturation error in exit code %d, getting rounded down to %u",
                  ms->exitcode, (uint8_t)ms->exitcode);
        ms->exitcode = 255;
    }

    /* exit the whole process if exit_group() */
    if (ms->is_exitgroup) {
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
        DO_SYSCALL(exit_group, (int)ms->exitcode);
        die_or_inf_loop();
    }

    /* otherwise call SGX-related thread reset and exit this thread */
    block_async_signals(true);
    ecall_thread_reset();

    unmap_tcs();

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
        DO_SYSCALL(exit_group, (int)ms->exitcode);
        die_or_inf_loop();
    }

    thread_exit((int)ms->exitcode);
    return 0;
}

static long sgx_ocall_mmap_untrusted(void* pms) {
    ocall_mmap_untrusted_t* ms = (ocall_mmap_untrusted_t*)pms;
    void* addr;

    addr = (void*)DO_SYSCALL(mmap, ms->addr, ms->size, ms->prot, ms->flags, ms->fd, ms->offset);
    if (IS_PTR_ERR(addr))
        return PTR_TO_ERR(addr);

    ms->addr = addr;
    return 0;
}

static long sgx_ocall_munmap_untrusted(void* pms) {
    ocall_munmap_untrusted_t* ms = (ocall_munmap_untrusted_t*)pms;
    DO_SYSCALL(munmap, ms->addr, ms->size);
    return 0;
}

static long sgx_ocall_cpuid(void* pms) {
    ocall_cpuid_t* ms = (ocall_cpuid_t*)pms;
    __asm__ volatile("cpuid"
                     : "=a"(ms->values[0]),
                       "=b"(ms->values[1]),
                       "=c"(ms->values[2]),
                       "=d"(ms->values[3])
                     : "a"(ms->leaf), "c"(ms->subleaf)
                     : "memory");
    return 0;
}

static long sgx_ocall_open(void* pms) {
    ocall_open_t* ms = (ocall_open_t*)pms;
    long ret;
    // FIXME: No idea why someone hardcoded O_CLOEXEC here. We should drop it and carefully
    // investigate if this cause any descriptor leaks.
    ret = DO_SYSCALL_INTERRUPTIBLE(open, ms->pathname, ms->flags | O_CLOEXEC, ms->mode);
    return ret;
}

static long sgx_ocall_close(void* pms) {
    ocall_close_t* ms = (ocall_close_t*)pms;
    /* Callers cannot retry close on `-EINTR`, so we do not call `DO_SYSCALL_INTERRUPTIBLE`. */
    return DO_SYSCALL(close, ms->fd);
}

static long sgx_ocall_read(void* pms) {
    ocall_read_t* ms = (ocall_read_t*)pms;
    long ret;
    ret = DO_SYSCALL_INTERRUPTIBLE(read, ms->fd, ms->buf, ms->count);
    return ret;
}

static long sgx_ocall_write(void* pms) {
    ocall_write_t* ms = (ocall_write_t*)pms;
    long ret;
    ret = DO_SYSCALL_INTERRUPTIBLE(write, ms->fd, ms->buf, ms->count);
    return ret;
}

static long sgx_ocall_pread(void* pms) {
    ocall_pread_t* ms = (ocall_pread_t*)pms;
    long ret;
    ret = DO_SYSCALL_INTERRUPTIBLE(pread64, ms->fd, ms->buf, ms->count, ms->offset);
    return ret;
}

static long sgx_ocall_pwrite(void* pms) {
    ocall_pwrite_t* ms = (ocall_pwrite_t*)pms;
    long ret;
    ret = DO_SYSCALL_INTERRUPTIBLE(pwrite64, ms->fd, ms->buf, ms->count, ms->offset);
    return ret;
}

static long sgx_ocall_fstat(void* pms) {
    ocall_fstat_t* ms = (ocall_fstat_t*)pms;
    long ret;
    ret = DO_SYSCALL_INTERRUPTIBLE(fstat, ms->fd, &ms->stat);
    return ret;
}

static long sgx_ocall_fionread(void* pms) {
    ocall_fionread_t* ms = (ocall_fionread_t*)pms;
    long ret;
    int val;
    ret = DO_SYSCALL_INTERRUPTIBLE(ioctl, ms->fd, FIONREAD, &val);
    return ret < 0 ? ret : val;
}

static long sgx_ocall_fsetnonblock(void* pms) {
    ocall_fsetnonblock_t* ms = (ocall_fsetnonblock_t*)pms;
    long ret;
    int flags;

    ret = DO_SYSCALL(fcntl, ms->fd, F_GETFL);
    if (ret < 0)
        return ret;

    flags = ret;
    if (ms->nonblocking) {
        if (!(flags & O_NONBLOCK))
            ret = DO_SYSCALL(fcntl, ms->fd, F_SETFL, flags | O_NONBLOCK);
    } else {
        if (flags & O_NONBLOCK)
            ret = DO_SYSCALL(fcntl, ms->fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    return ret;
}

static long sgx_ocall_fchmod(void* pms) {
    ocall_fchmod_t* ms = (ocall_fchmod_t*)pms;
    long ret;
    ret = DO_SYSCALL(fchmod, ms->fd, ms->mode);
    return ret;
}

static long sgx_ocall_fsync(void* pms) {
    ocall_fsync_t* ms = (ocall_fsync_t*)pms;
    return DO_SYSCALL_INTERRUPTIBLE(fsync, ms->fd);
}

static long sgx_ocall_ftruncate(void* pms) {
    ocall_ftruncate_t* ms = (ocall_ftruncate_t*)pms;
    long ret;
    ret = DO_SYSCALL(ftruncate, ms->fd, ms->length);
    return ret;
}

static long sgx_ocall_mkdir(void* pms) {
    ocall_mkdir_t* ms = (ocall_mkdir_t*)pms;
    long ret;
    ret = DO_SYSCALL(mkdir, ms->pathname, ms->mode);
    return ret;
}

static long sgx_ocall_getdents(void* pms) {
    ocall_getdents_t* ms = (ocall_getdents_t*)pms;
    long ret;
    unsigned int count = ms->size <= UINT_MAX ? ms->size : UINT_MAX;
    ret = DO_SYSCALL_INTERRUPTIBLE(getdents64, ms->fd, ms->dirp, count);
    return ret;
}

static long sgx_ocall_resume_thread(void* pms) {
    int tid = get_tid_from_tcs(pms);
    if (tid < 0)
        return tid;

    long ret = DO_SYSCALL(tgkill, g_host_pid, tid, SIGCONT);
    return ret;
}

static long sgx_ocall_sched_setaffinity(void* pms) {
    ocall_sched_setaffinity_t* ms = (ocall_sched_setaffinity_t*)pms;
    int tid = get_tid_from_tcs(ms->tcs);
    if (tid < 0)
        return tid;

    long ret = DO_SYSCALL(sched_setaffinity, tid, ms->cpumask_size, ms->cpu_mask);
    return ret;
}

static long sgx_ocall_sched_getaffinity(void* pms) {
    ocall_sched_getaffinity_t* ms = (ocall_sched_getaffinity_t*)pms;
    int tid = get_tid_from_tcs(ms->tcs);
    if (tid < 0)
        return tid;

    long ret = DO_SYSCALL(sched_getaffinity, tid, ms->cpumask_size, ms->cpu_mask);
    return ret;
}

static long sgx_ocall_clone_thread(void* pms) {
    __UNUSED(pms);
    return clone_thread();
}

static long sgx_ocall_create_process(void* pms) {
    ocall_create_process_t* ms = (ocall_create_process_t*)pms;

    return sgx_create_process(ms->nargs, ms->args, g_pal_enclave.raw_manifest_data, &ms->stream_fd);
}

static long sgx_ocall_futex(void* pms) {
    ocall_futex_t* ms = (ocall_futex_t*)pms;
    long ret;

    struct timespec timeout = { 0 };
    bool have_timeout = ms->timeout_us != (uint64_t)-1;
    if (have_timeout) {
        time_get_now_plus_ns(&timeout, ms->timeout_us * TIME_NS_IN_US);
    }

    /* `FUTEX_WAIT` treats timeout parameter as a relative value. We want to have an absolute one
     * (since we need to get start time anyway, to calculate remaining time later on), hence we use
     * `FUTEX_WAIT_BITSET` with `FUTEX_BITSET_MATCH_ANY`. */
    uint32_t val3 = 0;
    int priv_flag = ms->op & FUTEX_PRIVATE_FLAG;
    int op = ms->op & ~FUTEX_PRIVATE_FLAG;
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

    ret = DO_SYSCALL_INTERRUPTIBLE(futex, ms->futex, op | priv_flag, ms->val,
                                   have_timeout ? &timeout : NULL, NULL, val3);

    if (have_timeout) {
        int64_t diff = time_ns_diff_from_now(&timeout);
        if (diff < 0) {
            /* We might have slept a bit too long. */
            diff = 0;
        }
        ms->timeout_us = (uint64_t)diff / TIME_NS_IN_US;
    }
    return ret;
}

static long sgx_ocall_socket(void* pms) {
    ocall_socket_t* ms = pms;
    return DO_SYSCALL(socket, ms->family, ms->type | SOCK_CLOEXEC, ms->protocol);
}

static long sgx_ocall_bind(void* pms) {
    ocall_bind_t* ms = pms;
    int ret = DO_SYSCALL(bind, ms->fd, ms->addr, (int)ms->addrlen);
    if (ret < 0) {
        return ret;
    }

    struct sockaddr_storage addr = { 0 };
    int addrlen = sizeof(addr);
    ret = DO_SYSCALL(getsockname, ms->fd, &addr, &addrlen);
    if (ret < 0) {
        return ret;
    }

    switch (addr.ss_family) {
        case AF_INET:
            memcpy(&ms->new_port, (char*)&addr + offsetof(struct sockaddr_in, sin_port),
                   sizeof(ms->new_port));
            break;
        case AF_INET6:
            memcpy(&ms->new_port, (char*)&addr + offsetof(struct sockaddr_in6, sin6_port),
                   sizeof(ms->new_port));
            break;
        default:
            log_error("%s: unknown address family: %d", __func__, addr.ss_family);
            DO_SYSCALL(exit_group, 1);
            die_or_inf_loop();
    }

    return 0;
}

static long sgx_ocall_listen_simple(void* pms) {
    ocall_listen_simple_t* ms = pms;
    return DO_SYSCALL(listen, ms->fd, ms->backlog);
}

static long sgx_ocall_listen(void* pms) {
    ocall_listen_t* ms = (ocall_listen_t*)pms;
    long ret;
    int fd;

    if (ms->addrlen > INT_MAX) {
        ret = -EINVAL;
        goto err;
    }

    ret = DO_SYSCALL(socket, ms->domain, ms->type | SOCK_CLOEXEC, ms->protocol);
    if (ret < 0)
        goto err;

    fd = ret;

    /* must set the socket to be reuseable */
    int reuseaddr = 1;
    ret = DO_SYSCALL(setsockopt, fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    if (ret < 0)
        goto err_fd;

    if (ms->domain == AF_INET6) {
        /* IPV6_V6ONLY socket option can only be set before first bind */
        ret = DO_SYSCALL(setsockopt, fd, IPPROTO_IPV6, IPV6_V6ONLY, &ms->ipv6_v6only,
                         sizeof(ms->ipv6_v6only));
        if (ret < 0)
            goto err_fd;
    }

    ret = DO_SYSCALL_INTERRUPTIBLE(bind, fd, ms->addr, (int)ms->addrlen);
    if (ret < 0)
        goto err_fd;

    if (ms->addr) {
        int addrlen = ms->addrlen;
        ret = DO_SYSCALL(getsockname, fd, ms->addr, &addrlen);
        if (ret < 0)
            goto err_fd;
        ms->addrlen = addrlen;
    }

    if (ms->type & SOCK_STREAM) {
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

static long sgx_ocall_accept(void* pms) {
    ocall_accept_t* ms = (ocall_accept_t*)pms;
    long ret;

    if (ms->addrlen > INT_MAX || ms->local_addrlen > INT_MAX) {
        return -EINVAL;
    }
    int addrlen = ms->addrlen;
    int options = ms->options | SOCK_CLOEXEC;
    assert(WITHIN_MASK(options, SOCK_CLOEXEC | SOCK_NONBLOCK));

    ret = DO_SYSCALL_INTERRUPTIBLE(accept4, ms->sockfd, ms->addr, &addrlen, options);
    if (ret < 0)
        return ret;

    int fd = ret;
    ms->addrlen = addrlen;

    if (ms->local_addrlen > 0) {
        int addrlen = ms->local_addrlen;
        ret = DO_SYSCALL(getsockname, fd, ms->local_addr, &addrlen);
        if (ret < 0) {
            goto err;
        }
        ms->local_addrlen = addrlen;
    }
    return fd;

err:
    DO_SYSCALL(close, fd);
    return ret;
}

static long sgx_ocall_connect(void* pms) {
    ocall_connect_t* ms = (ocall_connect_t*)pms;
    long ret;
    int fd;

    if (ms->addrlen > INT_MAX || ms->bind_addrlen > INT_MAX) {
        ret = -EINVAL;
        goto err;
    }

    ret = DO_SYSCALL(socket, ms->domain, ms->type | SOCK_CLOEXEC, ms->protocol);
    if (ret < 0)
        goto err;

    fd = ret;

    if (ms->bind_addr && ms->bind_addr->sa_family) {
        if (ms->domain == AF_INET6) {
            /* IPV6_V6ONLY socket option can only be set before first bind */
            ret = DO_SYSCALL(setsockopt, fd, IPPROTO_IPV6, IPV6_V6ONLY, &ms->ipv6_v6only,
                             sizeof(ms->ipv6_v6only));
            if (ret < 0)
                goto err_fd;
        }

        ret = DO_SYSCALL_INTERRUPTIBLE(bind, fd, ms->bind_addr, ms->bind_addrlen);
        if (ret < 0)
            goto err_fd;
    }

    if (ms->addr) {
        ret = DO_SYSCALL_INTERRUPTIBLE(connect, fd, ms->addr, ms->addrlen);

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

    if (ms->bind_addr && !ms->bind_addr->sa_family) {
        int addrlen = ms->bind_addrlen;
        ret = DO_SYSCALL(getsockname, fd, ms->bind_addr, &addrlen);
        if (ret < 0)
            goto err_fd;
        ms->bind_addrlen = addrlen;
    }

    return fd;

err_fd:
    DO_SYSCALL(close, fd);
err:
    return ret;
}

static long sgx_ocall_connect_simple(void* pms) {
    ocall_connect_simple_t* ms = pms;
    int ret = DO_SYSCALL_INTERRUPTIBLE(connect, ms->fd, ms->addr, (int)ms->addrlen);
    if (ret < 0) {
        /* XXX: Non blocking socket. Currently there is no way of notifying LibOS of successful or
         * failed connection, so we have to block and wait. */
        if (ret != -EINPROGRESS) {
            return ret;
        }
        struct pollfd pfd = {
            .fd = ms->fd,
            .events = POLLOUT,
        };
        ret = DO_SYSCALL(poll, &pfd, 1, /*timeout=*/-1);
        if (ret != 1 || pfd.revents == 0) {
            return ret < 0 ? ret : -EINVAL;
        }
        int val = 0;
        unsigned int len = sizeof(val);
        ret = DO_SYSCALL(getsockopt, ms->fd, SOL_SOCKET, SO_ERROR, &val, &len);
        if (ret < 0 || val < 0) {
            return ret < 0 ? ret : -EINVAL;
        }
        if (val) {
            return -val;
        }
        /* Connect succeeded. */
    }

    int addrlen = sizeof(*ms->addr);
    ret = DO_SYSCALL(getsockname, ms->fd, ms->addr, &addrlen);
    if (ret < 0) {
        return ret;
    }

    ms->addrlen = addrlen;
    return 0;
}

static long sgx_ocall_recv(void* pms) {
    ocall_recv_t* ms = (ocall_recv_t*)pms;
    long ret;

    if (ms->addr && ms->addrlen > INT_MAX) {
        return -EINVAL;
    }
    int addrlen = ms->addr ? ms->addrlen : 0;

    struct msghdr hdr;
    struct iovec iov[1];

    iov[0].iov_base    = ms->buf;
    iov[0].iov_len     = ms->count;
    hdr.msg_name       = ms->addr;
    hdr.msg_namelen    = addrlen;
    hdr.msg_iov        = iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = ms->control;
    hdr.msg_controllen = ms->controllen;
    hdr.msg_flags      = 0;

    ret = DO_SYSCALL_INTERRUPTIBLE(recvmsg, ms->sockfd, &hdr, ms->flags);

    if (ret >= 0 && hdr.msg_name) {
        /* note that ms->addr is filled by recvmsg() itself */
        ms->addrlen = hdr.msg_namelen;
    }

    if (ret >= 0 && hdr.msg_control) {
        /* note that ms->control is filled by recvmsg() itself */
        ms->controllen = hdr.msg_controllen;
    }

    return ret;
}

static long sgx_ocall_send(void* pms) {
    ocall_send_t* ms = (ocall_send_t*)pms;
    long ret;

    if (ms->addr && ms->addrlen > INT_MAX) {
        return -EINVAL;
    }
    int addrlen = ms->addr ? ms->addrlen : 0;

    struct msghdr hdr;
    struct iovec iov[1];

    iov[0].iov_base    = (void*)ms->buf;
    iov[0].iov_len     = ms->count;
    hdr.msg_name       = (void*)ms->addr;
    hdr.msg_namelen    = addrlen;
    hdr.msg_iov        = iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = ms->control;
    hdr.msg_controllen = ms->controllen;
    hdr.msg_flags      = 0;

    ret = DO_SYSCALL_INTERRUPTIBLE(sendmsg, ms->sockfd, &hdr, MSG_NOSIGNAL | ms->flags);
    return ret;
}

static long sgx_ocall_setsockopt(void* pms) {
    ocall_setsockopt_t* ms = (ocall_setsockopt_t*)pms;
    long ret;
    if (ms->optlen > INT_MAX) {
        return -EINVAL;
    }
    ret = DO_SYSCALL(setsockopt, ms->sockfd, ms->level, ms->optname, ms->optval, (int)ms->optlen);
    return ret;
}

static long sgx_ocall_shutdown(void* pms) {
    ocall_shutdown_t* ms = (ocall_shutdown_t*)pms;
    DO_SYSCALL_INTERRUPTIBLE(shutdown, ms->sockfd, ms->how);
    return 0;
}

static long sgx_ocall_gettime(void* pms) {
    ocall_gettime_t* ms = (ocall_gettime_t*)pms;
    struct timeval tv;
    DO_SYSCALL(gettimeofday, &tv, NULL);
    ms->microsec = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
    return 0;
}

static long sgx_ocall_sched_yield(void* pms) {
    __UNUSED(pms);
    DO_SYSCALL_INTERRUPTIBLE(sched_yield);
    return 0;
}

static long sgx_ocall_poll(void* pms) {
    ocall_poll_t* ms = (ocall_poll_t*)pms;
    long ret;

    struct timespec* timeout = NULL;
    struct timespec end_time = { 0 };
    bool have_timeout = ms->timeout_us != (uint64_t)-1;
    if (have_timeout) {
        uint64_t timeout_ns = ms->timeout_us * TIME_NS_IN_US;
        timeout = __alloca(sizeof(*timeout));
        timeout->tv_sec = timeout_ns / TIME_NS_IN_S;
        timeout->tv_nsec = timeout_ns % TIME_NS_IN_S;
        time_get_now_plus_ns(&end_time, timeout_ns);
    }

    ret = DO_SYSCALL_INTERRUPTIBLE(ppoll, ms->fds, ms->nfds, timeout, NULL);

    if (have_timeout) {
        int64_t diff = time_ns_diff_from_now(&end_time);
        if (diff < 0) {
            /* We might have slept a bit too long. */
            diff = 0;
        }
        ms->timeout_us = (uint64_t)diff / TIME_NS_IN_US;
    }

    return ret;
}

static long sgx_ocall_rename(void* pms) {
    ocall_rename_t* ms = (ocall_rename_t*)pms;
    long ret;
    ret = DO_SYSCALL(rename, ms->oldpath, ms->newpath);
    return ret;
}

static long sgx_ocall_delete(void* pms) {
    ocall_delete_t* ms = (ocall_delete_t*)pms;
    long ret;

    ret = DO_SYSCALL(unlink, ms->pathname);

    if (ret == -EISDIR)
        ret = DO_SYSCALL(rmdir, ms->pathname);

    return ret;
}

static long sgx_ocall_eventfd(void* pms) {
    ocall_eventfd_t* ms = (ocall_eventfd_t*)pms;
    long ret;

    ret = DO_SYSCALL(eventfd2, 0, ms->flags);

    return ret;
}

static long sgx_ocall_debug_map_add(void* pms) {
    ocall_debug_map_add_t* ms = (ocall_debug_map_add_t*)pms;

#ifdef DEBUG
    int ret = debug_map_add(ms->name, ms->addr);
    if (ret < 0)
        log_error("debug_map_add(%s, %p): %d", ms->name, ms->addr, ret);

    sgx_profile_report_elf(ms->name, ms->addr);
#else
    __UNUSED(ms);
#endif
    return 0;
}

static long sgx_ocall_debug_map_remove(void* pms) {
    ocall_debug_map_remove_t* ms = (ocall_debug_map_remove_t*)pms;

#ifdef DEBUG
    int ret = debug_map_remove(ms->addr);
    if (ret < 0)
        log_error("debug_map_remove(%p): %d", ms->addr, ret);
#else
    __UNUSED(ms);
#endif
    return 0;
}

static long sgx_ocall_debug_describe_location(void* pms) {
    ocall_debug_describe_location_t* ms = (ocall_debug_describe_location_t*)pms;

#ifdef DEBUG
    return debug_describe_location(ms->addr, ms->buf, ms->buf_size);
#else
    __UNUSED(ms);
    return -ENOSYS;
#endif
}

static long sgx_ocall_get_quote(void* pms) {
    ocall_get_quote_t* ms = (ocall_get_quote_t*)pms;
    return retrieve_quote(ms->is_epid ? &ms->spid : NULL, ms->linkable, &ms->report, &ms->nonce,
                          &ms->quote, &ms->quote_len);
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
    [OCALL_GET_QUOTE]                = sgx_ocall_get_quote,
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
