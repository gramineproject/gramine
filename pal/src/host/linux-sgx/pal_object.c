/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <linux/poll.h>

#include "cpu.h"
#include "enclave_ocalls.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux_error.h"

/* To avoid expensive malloc/free (due to locking), use stack if the required space is small
 * enough. */
#define NFDS_LIMIT_TO_USE_STACK 16

int _PalStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, pal_wait_flags_t* events,
                          pal_wait_flags_t* ret_events, uint64_t* timeout_us) {
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

            if (handle->hdr.type == PAL_TYPE_PIPE) {
                while (!__atomic_load_n(&handle->pipe.handshake_done, __ATOMIC_ACQUIRE)) {
                    CPU_RELAX();
                }
            }
        } else {
            fds[i].fd = -1;
        }
    }

    int ret = ocall_poll(fds, count, timeout_us);

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

        PAL_HANDLE handle = handle_array[i];
        if (!handle || !(handle->flags & (PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE))
                || handle->generic.fd == PAL_IDX_POISON) {
            /* We skipped this fd. */
            continue;
        }

        if (fds[i].revents & POLLIN)
            ret_events[i] |= PAL_WAIT_READ;
        if (fds[i].revents & POLLOUT)
            ret_events[i] |= PAL_WAIT_WRITE;

        /* FIXME: something is wrong here, it reads and writes to flags without any locks... */
        if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL))
            handle->flags |= PAL_HANDLE_FD_ERROR;
        if (handle->flags & PAL_HANDLE_FD_ERROR)
            ret_events[i] |= PAL_WAIT_ERROR;
    }

    ret = 0;

out:
    if (!allocate_on_stack) {
        free(fds);
    }
    return ret;
}
