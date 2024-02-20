/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/*
 * This file contains code for implementation of "timerfd" filesystem. For more information, see
 * `libos/src/sys/libos_timerfd.c`.
 */

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "linux_abi/errors.h"
#include "pal.h"

static void timerfd_dummy_host_read(struct libos_handle* hdl) {
    int ret;
    uint64_t buf_dummy_host_val = 0;
    size_t dummy_host_val_count = sizeof(buf_dummy_host_val);
    do {
        ret = PalStreamRead(hdl->pal_handle, /*offset=*/0, &dummy_host_val_count,
                            &buf_dummy_host_val);
    } while (ret == -PAL_ERROR_INTERRUPTED);
    if (ret < 0 || dummy_host_val_count != sizeof(buf_dummy_host_val)) {
        /* must not happen in benign case, consider it an attack and panic */
        BUG();
    }
}

static void timerfd_dummy_host_wait_for_read(struct libos_handle* hdl) {
    pal_wait_flags_t wait_for_events = PAL_WAIT_READ;
    pal_wait_flags_t ret_events = 0;
    int ret = PalStreamsWaitEvents(1, &hdl->pal_handle, &wait_for_events, &ret_events, NULL);
    if (ret < 0 && ret != -PAL_ERROR_INTERRUPTED) {
        BUG();
    }
    (void)ret_events; /* we don't care what events the host returned, we can't trust them anyway */
}

static ssize_t timerfd_read(struct libos_handle* hdl, void* buf, size_t count, file_off_t* pos) {
    __UNUSED(pos);
    assert(hdl->type == TYPE_TIMERFD);

    if (count < sizeof(uint64_t))
        return -EINVAL;

    int ret;
    spinlock_lock(&hdl->info.timerfd.expiration_lock);

    while (!hdl->info.timerfd.num_expirations) {
        if (hdl->flags & O_NONBLOCK) {
            ret = -EAGAIN;
            goto out;
        }
        spinlock_unlock(&hdl->info.timerfd.expiration_lock);
        timerfd_dummy_host_wait_for_read(hdl);
        spinlock_lock(&hdl->info.timerfd.expiration_lock);
    }

    memcpy(buf, &hdl->info.timerfd.num_expirations, sizeof(uint64_t));
    hdl->info.timerfd.num_expirations = 0;

    /* perform a read (not supposed to block) to clear the event from polling threads and to send an
     * event to writing threads */
    if (hdl->info.timerfd.dummy_host_val) {
        timerfd_dummy_host_read(hdl);
        hdl->info.timerfd.dummy_host_val = 0;
    }

    ret = (ssize_t)count;
out:
    spinlock_unlock(&hdl->info.timerfd.expiration_lock);
    maybe_epoll_et_trigger(hdl, ret, /*in=*/true, /*unused was_partial=*/false);
    return ret;
}

static void timerfd_post_poll(struct libos_handle* hdl, pal_wait_flags_t* pal_ret_events) {
    assert(hdl->type == TYPE_TIMERFD);

    if (*pal_ret_events & (PAL_WAIT_ERROR | PAL_WAIT_HANG_UP | PAL_WAIT_WRITE)) {
        /* impossible: we control eventfd inside the LibOS, and we never raise such conditions */
        BUG();
    }

    spinlock_lock(&hdl->info.timerfd.expiration_lock);
    if (*pal_ret_events & PAL_WAIT_READ) {
        /* there is data to read: verify if timerfd has number of expirations greater than zero */
        if (!hdl->info.timerfd.num_expirations) {
            /* spurious or malicious notification -- for now we don't BUG but ignore it */
            *pal_ret_events &= ~PAL_WAIT_READ;
        }
    }
    spinlock_unlock(&hdl->info.timerfd.expiration_lock);
}

static int timerfd_close(struct libos_handle* hdl) {
    __UNUSED(hdl);

    /* see `libos_timerfd.c` for the handle-open counterpart */
    (void)__atomic_sub_fetch(&g_timerfd_cnt, 1, __ATOMIC_ACQ_REL);
    return 0;
}

struct libos_fs_ops timerfd_fs_ops = {
    .read      = &timerfd_read,
    .close     = &timerfd_close,
    .post_poll = &timerfd_post_poll,
};

struct libos_fs timerfd_builtin_fs = {
    .name   = "timerfd",
    .fs_ops = &timerfd_fs_ops,
};
