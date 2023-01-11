/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Implementation of system calls "poll", "ppoll", "select" and "pselect6".
 */

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_signal.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "libos_utils.h"
#include "pal.h"

typedef unsigned long __fd_mask;

#ifndef __NFDBITS
#define __NFDBITS (8 * (int)sizeof(__fd_mask))
#endif

#ifndef __FDS_BITS
#define __FDS_BITS(set) ((set)->fds_bits)
#endif

#define __FD_ZERO(set)                                           \
    do {                                                         \
        unsigned int i;                                          \
        fd_set* arr = (set);                                     \
        for (i = 0; i < sizeof(fd_set) / sizeof(__fd_mask); i++) \
            __FDS_BITS(arr)[i] = 0;                              \
    } while (0)

#define __FD_ELT(d)        ((d) / __NFDBITS)
#define __FD_MASK(d)       ((__fd_mask)1 << ((d) % __NFDBITS))
#define __FD_SET(d, set)   ((void)(__FDS_BITS(set)[__FD_ELT(d)] |= __FD_MASK(d)))
#define __FD_CLR(d, set)   ((void)(__FDS_BITS(set)[__FD_ELT(d)] &= ~__FD_MASK(d)))
#define __FD_ISSET(d, set) ((__FDS_BITS(set)[__FD_ELT(d)] & __FD_MASK(d)) != 0)

#define POLLIN_SET (POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR)
#define POLLOUT_SET (POLLWRBAND | POLLWRNORM | POLLOUT | POLLERR)
#define POLLEX_SET (POLLPRI)
/* To avoid expensive malloc/free (due to locking), use stack if the required space is small
 * enough. */
#define NFDS_LIMIT_TO_USE_STACK 16

static long do_poll(struct pollfd* fds, size_t fds_len, uint64_t* timeout_us) {
    struct libos_handle** libos_handles = NULL;
    PAL_HANDLE* pal_handles = NULL;
    /* Double the amount of PAL events - one part are input events, the other - output. */
    pal_wait_flags_t* pal_events = NULL;
    bool allocate_on_stack = fds_len <= NFDS_LIMIT_TO_USE_STACK;

    if (allocate_on_stack) {
        static_assert((sizeof(*libos_handles) + sizeof(*pal_handles) + sizeof(*pal_events) * 2) *
                      NFDS_LIMIT_TO_USE_STACK <= 384,
                      "Would use too much space on stack, reduce the limit");
        libos_handles = __builtin_alloca(fds_len * sizeof(*libos_handles));
        pal_handles = __builtin_alloca(fds_len * sizeof(*pal_handles));
        pal_events = __builtin_alloca(fds_len * sizeof(*pal_events) * 2);
    } else {
        libos_handles = malloc(fds_len * sizeof(*libos_handles));
        pal_handles = malloc(fds_len * sizeof(*pal_handles));
        pal_events = malloc(fds_len * sizeof(*pal_events) * 2);
        if (!libos_handles || !pal_handles || !pal_events) {
            free(libos_handles);
            free(pal_handles);
            free(pal_events);
            return -ENOMEM;
        }
    }
    memset(libos_handles, 0, fds_len * sizeof(*libos_handles));
    memset(pal_handles, 0, fds_len * sizeof(*pal_handles));
    memset(pal_events, 0, fds_len * sizeof(*pal_events) * 2);

    long ret;
    size_t ret_events_count = 0;
    struct libos_handle_map* map = get_cur_thread()->handle_map;

    lock(&map->lock);

    /*
     * After each iteration of this loop either:
     * - `fds[i].revents` is set to its final value (possibly 0)
     * - `libos_handles[i]` and `pal_events[i]` are set to non-NULL values
     */
    for (size_t i = 0; i < fds_len; i++) {
        if (fds[i].fd < 0) {
            /* Negative file descriptors are ignored. */
            fds[i].revents = 0;
            continue;
        }

        struct libos_handle* handle = __get_fd_handle(fds[i].fd, NULL, map);
        if (!handle) {
            fds[i].revents = POLLNVAL;
            ret_events_count++;
            continue;
        }

        int events = fds[i].events;
        if (!(handle->acc_mode & MAY_READ)) {
            events &= ~(POLLIN | POLLRDNORM);
        }
        if (!(handle->acc_mode & MAY_WRITE)) {
            events &= ~(POLLOUT | POLLWRNORM);
        }

        if (handle->fs && handle->fs->fs_ops && handle->fs->fs_ops->poll) {
            ret = handle->fs->fs_ops->poll(handle, events, &events);
            /*
             * FIXME: remove this hack.
             * Initial 0,1,2 fds in Gramine are represented by "/dev/tty" (whatever that means)
             * and have `generic_inode_poll` set as poll callback, which returns `-EAGAIN` on
             * non-regular-file handles. In such case we let PAL do the actual polling.
             */
            if (ret == -EAGAIN && handle->uri && !strcmp(handle->uri, "dev:tty")) {
                goto dev_tty_hack;
            }

            if (ret < 0) {
                unlock(&map->lock);
                goto out;
            }

            fds[i].revents = events;
            if (events) {
                ret_events_count++;
            }

            continue;

            dev_tty_hack:;
        }

        PAL_HANDLE pal_handle;
        if (handle->type == TYPE_SOCK) {
            pal_handle = __atomic_load_n(&handle->info.sock.pal_handle, __ATOMIC_ACQUIRE);
            if (!pal_handle) {
                /* UNIX sockets that are still not connected have no `pal_handle`. */
                fds[i].revents = POLLHUP;
                ret_events_count++;
                continue;
            }
        } else {
            pal_handle = handle->pal_handle;
            if (!pal_handle) {
                fds[i].revents = POLLNVAL;
                ret_events_count++;
                continue;
            }
        }

        if (events & (POLLIN | POLLRDNORM))
            pal_events[i] |= PAL_WAIT_READ;
        if (events & (POLLOUT | POLLWRNORM))
            pal_events[i] |= PAL_WAIT_WRITE;

        libos_handles[i] = handle;
        get_handle(handle);
        pal_handles[i] = pal_handle;
    }

    unlock(&map->lock);

    uint64_t tmp_timeout_us = 0;
    if (ret_events_count) {
        /* If we already have events to return, we should not sleep below. */
        timeout_us = &tmp_timeout_us;
    }

    pal_wait_flags_t* ret_events = pal_events + fds_len;
    ret = PalStreamsWaitEvents(fds_len, pal_handles, pal_events, ret_events, timeout_us);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        if (ret == -EAGAIN) {
            /* Timeout - return number of already seen events, which might be 0. */
            ret = ret_events_count;
        }
        goto out;
    }

    for (size_t i = 0; i < fds_len; i++) {
        if (!libos_handles[i]) {
            continue;
        }

        fds[i].revents = 0;
        if (ret_events[i] & PAL_WAIT_ERROR)
            fds[i].revents |= POLLERR | POLLHUP;
        if (ret_events[i] & PAL_WAIT_READ)
            fds[i].revents |= fds[i].events & (POLLIN | POLLRDNORM);
        if (ret_events[i] & PAL_WAIT_WRITE)
            fds[i].revents |= fds[i].events & (POLLOUT | POLLWRNORM);

        if (fds[i].revents)
            ret_events_count++;
    }

    ret = ret_events_count;

out:
    for (size_t i = 0; i < fds_len; i++) {
        if (libos_handles[i]) {
            put_handle(libos_handles[i]);
        }
    }
    if (!allocate_on_stack) {
        free(libos_handles);
        free(pal_handles);
        free(pal_events);
    }

    if (ret == -EINTR) {
        /* `poll`, `ppoll`, `select` and `pselect` are not restarted after being interrupted by
         * a signal handler. */
        ret = -ERESTARTNOHAND;
    }
    return ret;
}

long libos_syscall_poll(struct pollfd* fds, unsigned int nfds, int timeout_ms) {
    if (nfds > get_rlimit_cur(RLIMIT_NOFILE) || nfds > INT_MAX)
        return -EINVAL;

    if (!is_user_memory_writable(fds, nfds * sizeof(*fds)))
        return -EFAULT;

    uint64_t timeout_us = (unsigned int)timeout_ms * TIME_US_IN_MS;
    return do_poll(fds, nfds, timeout_ms < 0 ? NULL : &timeout_us);
}

long libos_syscall_ppoll(struct pollfd* fds, unsigned int nfds, struct timespec* tsp,
                         const __sigset_t* sigmask_ptr, size_t sigsetsize) {
    if (nfds > get_rlimit_cur(RLIMIT_NOFILE) || nfds > INT_MAX)
        return -EINVAL;

    if (!is_user_memory_writable(fds, nfds * sizeof(*fds))) {
        return -EFAULT;
    }

    long ret = set_user_sigmask(sigmask_ptr, sigsetsize);
    if (ret < 0) {
        return ret;
    }

    uint64_t timeout_us = 0;
    if (tsp) {
        if (!is_user_memory_readable(tsp, sizeof(*tsp))) {
            return -EFAULT;
        }
        if (tsp->tv_sec < 0 || tsp->tv_nsec < 0 || (unsigned long)tsp->tv_nsec >= TIME_NS_IN_S) {
            return -EINVAL;
        }
        timeout_us = tsp->tv_sec * TIME_US_IN_S + tsp->tv_nsec / TIME_NS_IN_US;
    }

    ret = do_poll(fds, nfds, tsp ? &timeout_us : NULL);

    /* If `tsp` is in read-only memory, skip the update. */
    if (tsp && is_user_memory_writable_no_skip(tsp, sizeof(*tsp))) {
        tsp->tv_sec = timeout_us / TIME_US_IN_S;
        tsp->tv_nsec = (timeout_us % TIME_US_IN_S) * TIME_NS_IN_US;
    }
    return ret;
}

static long do_select(int nfds, fd_set* read_set, fd_set* write_set, fd_set* except_set,
                      uint64_t* timeout_us) {
    size_t total_fds = 0;
    for (size_t i = 0; i < (size_t)nfds; i++) {
        if ((read_set && __FD_ISSET(i, read_set)) || (write_set && __FD_ISSET(i, write_set))
                || (except_set && __FD_ISSET(i, except_set))) {
            total_fds++;
        }
    }

    struct pollfd* poll_fds = NULL;
    bool allocate_on_stack = total_fds <= NFDS_LIMIT_TO_USE_STACK;

    if (allocate_on_stack) {
        static_assert(sizeof(*poll_fds) * NFDS_LIMIT_TO_USE_STACK <= 128,
                      "Would use too much space on stack, reduce the limit");
        poll_fds = __builtin_alloca(total_fds * sizeof(*poll_fds));
    } else {
        poll_fds = malloc(total_fds * sizeof(*poll_fds));
        if (!poll_fds)
            return -ENOMEM;
    }

    long ret;
    size_t poll_fds_idx = 0;
    for (size_t i = 0; i < (size_t)nfds; i++) {
        short events = 0;
        if (read_set && __FD_ISSET(i, read_set)) {
            events |= POLLIN_SET;
        }
        if (write_set && __FD_ISSET(i, write_set)) {
            events |= POLLOUT_SET;
        }
        if (except_set && __FD_ISSET(i, except_set)) {
            events |= POLLEX_SET;
        }

        if (!events)
            continue;

        if (poll_fds_idx == total_fds) {
            log_error("User app is buggy and changed `select` fds sets concurrently!");
            ret = -EAGAIN;
            goto out;
        }

        poll_fds[poll_fds_idx] = (struct pollfd){
            .fd = i,
            .events = events,
        };
        poll_fds_idx++;
    }

    if (poll_fds_idx != total_fds) {
        log_error("User app is buggy and changed `select` fds sets concurrently!");
        ret = -EAGAIN;
        goto out;
    }

    ret = do_poll(poll_fds, total_fds, timeout_us);
    if (ret < 0) {
        goto out;
    }

    /* `select` modifies read_set, write_set and except_set in-place. */
    for (size_t i = 0; i < total_fds; i++) {
        if (poll_fds[i].revents & POLLNVAL) {
            /* `select` returns error on invalid fds, but also fills sets. */
            ret = -EBADF;
            continue;
        }

        if (read_set && !(poll_fds[i].revents & POLLIN_SET)) {
            __FD_CLR(poll_fds[i].fd, read_set);
        }
        if (write_set && !(poll_fds[i].revents & POLLOUT_SET)) {
            __FD_CLR(poll_fds[i].fd, write_set);
        }
        if (except_set && !(poll_fds[i].revents & POLLEX_SET)) {
            __FD_CLR(poll_fds[i].fd, except_set);
        }
    }

out:
    if (!allocate_on_stack) {
        free(poll_fds);
    }
    return ret;
}

long libos_syscall_select(int nfds, fd_set* read_set, fd_set* write_set, fd_set* except_set,
                          struct __kernel_timeval* tv) {
    if (nfds < 0 || (uint64_t)nfds > get_rlimit_cur(RLIMIT_NOFILE) || nfds > INT_MAX)
        return -EINVAL;

    /* Each of `read_set`, `write_set` and `except_set` is an array of fd_set items; each fd_set
     * item has a single inline array `fd_set::fds_bits` of constant size (typically 128B, which
     * allows to accommodate 1024 bits, i.e. 1024 file descriptors). Therefore we calculate how many
     * fd_set items are required to accommodate `nfds` number of file descriptors, i.e., we
     * calculate the length of each of `read_set`, `write_set` and `except_set` arrays. */
    static_assert(sizeof(((fd_set*)0)->fds_bits) == sizeof(fd_set), "unexpected fd_set struct");
    size_t fd_set_arr_len = UDIV_ROUND_UP(nfds, BITS_IN_TYPE(((fd_set*)0)->fds_bits));
    if (read_set && !is_user_memory_writable(read_set, fd_set_arr_len * sizeof(*read_set))) {
            return -EFAULT;
    }
    if (write_set && !is_user_memory_writable(write_set, fd_set_arr_len * sizeof(*write_set))) {
            return -EFAULT;
    }
    if (except_set && !is_user_memory_writable(except_set, fd_set_arr_len * sizeof(*except_set))) {
            return -EFAULT;
    }

    uint64_t timeout_us = 0;
    if (tv) {
        if (!is_user_memory_readable(tv, sizeof(*tv))) {
            return -EFAULT;
        }
        if (tv->tv_sec < 0 || tv->tv_usec < 0 || (unsigned long)tv->tv_usec >= TIME_US_IN_S) {
            return -EINVAL;
        }
        timeout_us = tv->tv_sec * TIME_US_IN_S + tv->tv_usec;
    }

    long ret = do_select(nfds, read_set, write_set, except_set, tv ? &timeout_us : NULL);

    /* If `tv` is in read-only memory, skip the update. */
    if (tv && is_user_memory_writable_no_skip(tv, sizeof(*tv))) {
        tv->tv_sec = timeout_us / TIME_US_IN_S;
        tv->tv_usec = timeout_us % TIME_US_IN_S;
    }
    return ret;
}

struct sigset_argpack {
    __sigset_t* p;
    size_t size;
};

long libos_syscall_pselect6(int nfds, fd_set* read_set, fd_set* write_set, fd_set* except_set,
                            struct __kernel_timespec* tsp, void* _sigmask_argpack) {
    if (nfds < 0 || (uint64_t)nfds > get_rlimit_cur(RLIMIT_NOFILE) || nfds > INT_MAX)
        return -EINVAL;

    /* for explanation on calculations below, see libos_syscall_select() */
    static_assert(sizeof(((fd_set*)0)->fds_bits) == sizeof(fd_set), "unexpected fd_set struct");
    size_t fd_set_arr_len = UDIV_ROUND_UP(nfds, BITS_IN_TYPE(((fd_set*)0)->fds_bits));
    if (read_set && !is_user_memory_writable(read_set, fd_set_arr_len * sizeof(*read_set))) {
            return -EFAULT;
    }
    if (write_set && !is_user_memory_writable(write_set, fd_set_arr_len * sizeof(*write_set))) {
            return -EFAULT;
    }
    if (except_set && !is_user_memory_writable(except_set, fd_set_arr_len * sizeof(*except_set))) {
            return -EFAULT;
    }

    struct sigset_argpack* sigmask_argpack = _sigmask_argpack;
    if (sigmask_argpack) {
        if (!is_user_memory_readable(sigmask_argpack, sizeof(*sigmask_argpack))) {
            return -EFAULT;
        }
        int ret = set_user_sigmask(sigmask_argpack->p, sigmask_argpack->size);
        if (ret < 0) {
            return ret;
        }
    }

    uint64_t timeout_us = 0;
    if (tsp) {
        if (!is_user_memory_readable(tsp, sizeof(*tsp))) {
            return -EFAULT;
        }
        if (tsp->tv_sec < 0 || tsp->tv_nsec < 0 || (unsigned long)tsp->tv_nsec >= TIME_NS_IN_S) {
            return -EINVAL;
        }
        timeout_us = tsp->tv_sec * TIME_US_IN_S + tsp->tv_nsec / TIME_NS_IN_US;
    }

    long ret = do_select(nfds, read_set, write_set, except_set, tsp ? &timeout_us : NULL);

    /* If `tsp` is in read-only memory, skip the update. */
    if (tsp && is_user_memory_writable_no_skip(tsp, sizeof(*tsp))) {
        tsp->tv_sec = timeout_us / TIME_US_IN_S;
        tsp->tv_nsec = (timeout_us % TIME_US_IN_S) * TIME_NS_IN_US;
    }
    return ret;
}
