/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/*
 * This file contains code for implementation of 'timerfd' filesystem.
 */

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "linux_abi/errors.h"
#include "pal.h"

static void timerfd_dummy_host_read(struct libos_handle* hdl, uint64_t* out_host_val) {
    uint64_t buf_dummy_host_val = 0;
    size_t dummy_host_val_count = sizeof(buf_dummy_host_val);

    int ret = PalStreamRead(hdl->pal_handle, /*offset=*/0, &dummy_host_val_count,
                            &buf_dummy_host_val);
    if (ret < 0 || dummy_host_val_count != sizeof(buf_dummy_host_val)) {
        /* should not happen in benign case, but can happen under racing, e.g. threads may race on
         * the same eventfd event, one of them wins and updates `dummy_host_val` and the other one
         * looses and gets an unexpected `dummy_host_val` */
        log_warning("timerfd dummy host read failed or got unexpected value");
        return;
    }

    if (out_host_val)
        *out_host_val = buf_dummy_host_val;
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
        /* must block -- use the host's blocking read() on a dummy eventfd */
        if (hdl->info.timerfd.dummy_host_val) {
            /* value on host is non-zero, must perform a read to make it zero (and thus the next
             * read will become blocking) */
            uint64_t host_val = 0;
            timerfd_dummy_host_read(hdl, &host_val);
            if (host_val != hdl->info.timerfd.dummy_host_val)
                BUG();
            hdl->info.timerfd.dummy_host_val = 0;
        }

        spinlock_unlock(&hdl->info.timerfd.expiration_lock);
        /* blocking read to wait for some value (we don't care which value) */
        timerfd_dummy_host_read(hdl, /*out_host_val=*/NULL);
        spinlock_lock(&hdl->info.timerfd.expiration_lock);
        hdl->info.timerfd.dummy_host_val = 0;
    }

    memcpy(buf, &hdl->info.timerfd.num_expirations, sizeof(uint64_t));
    hdl->info.timerfd.num_expirations = 0;

    /* perform a read (not supposed to block) to clear the event from writing/polling threads */
    if (hdl->info.timerfd.dummy_host_val) {
        timerfd_dummy_host_read(hdl, /*out_host_val=*/NULL);
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

    if (*pal_ret_events & (PAL_WAIT_ERROR | PAL_WAIT_HANG_UP)) {
        /* impossible: we control eventfd inside the LibOS, and we never raise such conditions */
        BUG();
    }

    spinlock_lock(&hdl->info.timerfd.expiration_lock);
    if (*pal_ret_events & PAL_WAIT_READ) {
        /* there is data to read: verify if counter has value greater than zero */
        if (!hdl->info.timerfd.num_expirations) {
            /* spurious or malicious notification -- for now we don't BUG but ignore it */
            *pal_ret_events &= ~PAL_WAIT_READ;
        }
    }
    if (*pal_ret_events & PAL_WAIT_WRITE) {
        /* spurious or malicious notification */
        BUG();
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
