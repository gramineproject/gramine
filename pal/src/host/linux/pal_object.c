/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <linux/poll.h>

#include "linux_utils.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux_error.h"

/* To avoid expensive malloc/free (due to locking), use stack if the required space is small
 * enough. */
#define NFDS_LIMIT_TO_USE_STACK 16

int _PalStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, pal_wait_flags_t* events,
                          pal_wait_flags_t* ret_events, uint64_t* timeout_us) {
    int ret;
    uint64_t remaining_time_us = timeout_us ? *timeout_us : 0;

    struct pollfd* fds = NULL;
    bool allocate_on_stack = count <= NFDS_LIMIT_TO_USE_STACK;

    if (allocate_on_stack) {
        static_assert(sizeof(*fds) * NFDS_LIMIT_TO_USE_STACK <= 128,
                      "Would use too much space on stack, reduce the limit");
        fds = __builtin_alloca(count * sizeof(*fds));
    } else {
        fds = malloc(count * sizeof(*fds));
        if (!fds) {
            return -PAL_ERROR_NOMEM;
        }
    }
    memset(fds, 0, count * sizeof(*fds));

    for (size_t i = 0; i < count; i++) {
        PAL_HANDLE handle = handle_array[i];
        /* If `handle` does not have a host fd, just ignore it. */
        if (handle && (handle->flags & (PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE))
                && handle->generic.fd != PAL_IDX_POISON) {
            short fdevents = 0;
            if (events[i] & PAL_WAIT_READ) {
                fdevents |= POLLIN;
            }
            if (events[i] & PAL_WAIT_WRITE) {
                fdevents |= POLLOUT;
            }
            fds[i].fd = handle->generic.fd;
            fds[i].events = fdevents;
        } else {
            fds[i].fd = -1;
        }
    }

    struct timespec* timeout = NULL;
    struct timespec end_time = { 0 };
    if (timeout_us) {
        uint64_t timeout_ns = *timeout_us * TIME_NS_IN_US;
        timeout = __alloca(sizeof(*timeout));
        timeout->tv_sec = timeout_ns / TIME_NS_IN_S;
        timeout->tv_nsec = timeout_ns % TIME_NS_IN_S;
        time_get_now_plus_ns(&end_time, timeout_ns);
    }

    ret = DO_SYSCALL(ppoll, fds, count, timeout, NULL, 0);

    if (timeout_us) {
        int64_t diff = time_ns_diff_from_now(&end_time);
        if (diff < 0) {
            /* We might have slept a bit too long. */
            diff = 0;
        }
        remaining_time_us = (uint64_t)diff / TIME_NS_IN_US;
    }

    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        goto out;
    } else if (ret == 0) {
        /* timed out */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    for (size_t i = 0; i < count; i++) {
        ret_events[i] = 0;

        if (fds[i].fd == -1) {
            /* We skipped this fd. */
            continue;
        }

        if (fds[i].revents & POLLIN)
            ret_events[i] |= PAL_WAIT_READ;
        if (fds[i].revents & POLLOUT)
            ret_events[i] |= PAL_WAIT_WRITE;

        /* FIXME: something is wrong here, it reads and writes to flags without any locks... */
        PAL_HANDLE handle = handle_array[i];
        if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL))
            handle->flags |= PAL_HANDLE_FD_ERROR;
        if (handle->flags & PAL_HANDLE_FD_ERROR)
            ret_events[i] |= PAL_WAIT_ERROR;
    }

    ret = 0;

out:
    if (timeout_us) {
        *timeout_us = remaining_time_us;
    }
    if (!allocate_on_stack) {
        free(fds);
    }
    return ret;
}
