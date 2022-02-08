/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for waiting on PAL handles (polling).
 */

#include <asm/errno.h>
#include <linux/poll.h>
#include <linux/time.h>
#include <linux/wait.h>

#include "api.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"

int _DkStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, pal_wait_flags_t* events,
                         pal_wait_flags_t* ret_events, uint64_t* timeout_us) {
    int ret;
    uint64_t remaining_time_us = timeout_us ? *timeout_us : 0;

    if (count == 0)
        return 0;

    struct pollfd* fds = malloc(count * sizeof(*fds));
    if (!fds) {
        return -PAL_ERROR_NOMEM;
    }

    size_t* offsets = malloc(count * sizeof(*offsets));
    if (!offsets) {
        free(fds);
        return -PAL_ERROR_NOMEM;
    }

    /* collect all FDs of all PAL handles that may report read/write events */
    size_t nfds = 0;
    for (size_t i = 0; i < count; i++) {
        ret_events[i] = 0;

        PAL_HANDLE hdl = handle_array[i];
        if (!hdl)
            continue;

        /* collect internal-handle FD (only if it is readable/writable)
         * hdl might be a event/non-pollable object, simply ignore it */
        uint32_t flags = hdl->flags;
        if ((flags & (PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE))
                && hdl->generic.fd != PAL_IDX_POISON) {
            int fdevents = 0;

            // TODO: why does these check for flags?
            if ((flags & PAL_HANDLE_FD_READABLE) && (events[i] & PAL_WAIT_READ)) {
                fdevents |= POLLIN;
            }
            if ((flags & PAL_HANDLE_FD_WRITABLE) && (events[i] & PAL_WAIT_WRITE)) {
                fdevents |= POLLOUT;
            }

            if (fdevents) {
                fds[nfds].fd      = hdl->generic.fd;
                fds[nfds].events  = fdevents;
                fds[nfds].revents = 0;
                offsets[nfds] = i;
                nfds++;
            }
        }
    }

    if (!nfds) {
        /* did not find any waitable FDs (LibOS supplied closed FDs or empty events) */
        ret = -PAL_ERROR_INVAL;
        goto out;
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

    ret = DO_SYSCALL(ppoll, fds, nfds, timeout, NULL, 0);

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
    }

    if (!ret) {
        /* timed out */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    for (size_t i = 0; i < nfds; i++) {
        if (!fds[i].revents)
            continue;

        size_t j = offsets[i];

        /* update revents */
        if (fds[i].revents & POLLIN)
            ret_events[j] |= PAL_WAIT_READ;
        if (fds[i].revents & POLLOUT)
            ret_events[j] |= PAL_WAIT_WRITE;
        if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL))
            ret_events[j] |= PAL_WAIT_ERROR;

        /* update handle's internal fields (flags) */
        PAL_HANDLE hdl = handle_array[j];
        assert(hdl);
        if (hdl->flags & PAL_HANDLE_FD_ERROR)
            ret_events[j] |= PAL_WAIT_ERROR;
        if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL))
            hdl->flags |= PAL_HANDLE_FD_ERROR;
    }

    ret = 0;

out:
    if (timeout_us) {
        *timeout_us = remaining_time_us;
    }
    free(fds);
    free(offsets);
    return ret;
}
