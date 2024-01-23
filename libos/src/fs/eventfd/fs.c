/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019 Intel Corporation */

/*
 * This file contains code for passthrough-to-host and emulate-in-libos implementations of 'eventfd'
 * filesystem. For more information on the modes, see `libos_eventfd.c`.
 */

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "linux_abi/errors.h"
#include "pal.h"

static void eventfd_dummy_host_read(struct libos_handle* hdl, uint64_t* out_host_val) {
    uint64_t buf_dummy_host_val = 0;
    size_t dummy_host_val_count = sizeof(buf_dummy_host_val);

    int ret = PalStreamRead(hdl->pal_handle, /*offset=*/0, &dummy_host_val_count,
                            &buf_dummy_host_val);
    if (ret < 0 || dummy_host_val_count != sizeof(buf_dummy_host_val)) {
        /* must not happen in benign case, consider it an attack and panic */
        BUG();
    }

    if (out_host_val)
        *out_host_val = buf_dummy_host_val;
}

static void eventfd_dummy_host_write(struct libos_handle* hdl, uint64_t host_val) {
    uint64_t buf_dummy_host_val = host_val;
    size_t dummy_host_val_count = sizeof(buf_dummy_host_val);

    int ret = PalStreamWrite(hdl->pal_handle, /*offset=*/0, &dummy_host_val_count,
                             &buf_dummy_host_val);
    if (ret < 0 || dummy_host_val_count != sizeof(buf_dummy_host_val)) {
        /* must not happen in benign case, consider it an attack and panic */
        BUG();
    }
}

static ssize_t eventfd_read(struct libos_handle* hdl, void* buf, size_t count, file_off_t* pos) {
    __UNUSED(pos);

    if (count < sizeof(uint64_t))
        return -EINVAL;

    if (g_eventfd_passthrough_mode) {
        /* passthrough-to-host mode */
        int ret = PalStreamRead(hdl->pal_handle, /*offset=*/0, &count, buf);
        ret = pal_to_unix_errno(ret);
        maybe_epoll_et_trigger(hdl, ret, /*in=*/true, /*unused was_partial=*/false);
        return ret < 0 ? ret : (ssize_t)count;
    }

    /* emulate-in-libos mode */
    int ret;
    spinlock_lock(&hdl->info.eventfd.lock);

    while (!hdl->info.eventfd.val) {
        if (hdl->flags & O_NONBLOCK) {
            ret = -EAGAIN;
            goto out;
        }
        /* must block -- use the host's blocking read() on a dummy eventfd */
        if (hdl->info.eventfd.dummy_host_val) {
            /* value on host is non-zero, must perform a read to make it zero (and thus the next
             * read will become blocking) */
            uint64_t host_val;
            eventfd_dummy_host_read(hdl, &host_val);
            if (host_val != hdl->info.eventfd.dummy_host_val)
                BUG();
            hdl->info.eventfd.dummy_host_val = 0;
        }

        spinlock_unlock(&hdl->info.eventfd.lock);
        /* blocking read to wait for some value (we don't care which value) */
        eventfd_dummy_host_read(hdl, /*out_host_val=*/NULL);
        spinlock_lock(&hdl->info.eventfd.lock);
        hdl->info.eventfd.dummy_host_val = 0;
    }

    if (!hdl->info.eventfd.is_semaphore) {
        memcpy(buf, &hdl->info.eventfd.val, sizeof(uint64_t));
        hdl->info.eventfd.val = 0;
    } else {
        uint64_t one_val = 1;
        memcpy(buf, &one_val, sizeof(uint64_t));
        hdl->info.eventfd.val--;
    }

    /* perform a read (not supposed to block) to clear the event from writing/polling threads */
    if (hdl->info.eventfd.dummy_host_val) {
        eventfd_dummy_host_read(hdl, /*out_host_val=*/NULL);
        hdl->info.eventfd.dummy_host_val = 0;
    }

    ret = (ssize_t)count;
out:
    spinlock_unlock(&hdl->info.eventfd.lock);
    maybe_epoll_et_trigger(hdl, ret, /*in=*/true, /*unused was_partial=*/false);
    return ret;
}

static ssize_t eventfd_write(struct libos_handle* hdl, const void* buf, size_t count,
                             file_off_t* pos) {
    __UNUSED(pos);

    if (count < sizeof(uint64_t))
        return -EINVAL;

    if (g_eventfd_passthrough_mode) {
        /* passthrough-to-host mode */
        int ret = PalStreamWrite(hdl->pal_handle, /*offset=*/0, &count, (void*)buf);
        ret = pal_to_unix_errno(ret);
        maybe_epoll_et_trigger(hdl, ret, /*in=*/false, /*unused was_partial=*/false);
        return ret < 0 ? ret : (ssize_t)count;
    }

    /* emulate-in-libos mode */
    uint64_t buf_val;
    memcpy(&buf_val, buf, sizeof(uint64_t));
    if (buf_val == UINT64_MAX)
        return -EINVAL;

    int ret;
    spinlock_lock(&hdl->info.eventfd.lock);

    uint64_t val;
    while (__builtin_add_overflow(hdl->info.eventfd.val, buf_val, &val) || val > UINT64_MAX - 1) {
        if (hdl->flags & O_NONBLOCK) {
            ret = -EAGAIN;
            goto out;
        }

        /* must block -- use the host's blocking write() on a dummy eventfd */
        if (!hdl->info.eventfd.dummy_host_val) {
            /* value on host is zero, a write will not be able to block, so perform a helper write
             * now (thus the next write will become blocking) */
            eventfd_dummy_host_write(hdl, /*host_val=*/1);
            hdl->info.eventfd.dummy_host_val = 1;
        }
        spinlock_unlock(&hdl->info.eventfd.lock);
        /* blocking write to wait for some other's read */
        eventfd_dummy_host_write(hdl, UINT64_MAX - 1);
        spinlock_lock(&hdl->info.eventfd.lock);
        /* we are back from blocking write, it means that some other thread unblocked this thread
         * via the read, which forced dummy_host_val to be reset */
        if (hdl->info.eventfd.dummy_host_val != 0)
            BUG();
    }

    hdl->info.eventfd.val = val;

    /* perform a write (not supposed to block) to send an event to reading/polling threads */
    assert(hdl->info.eventfd.dummy_host_val < UINT64_MAX - 1);
    hdl->info.eventfd.dummy_host_val++;
    eventfd_dummy_host_write(hdl, /*host_val=*/1);

    ret = (ssize_t)count;
out:
    spinlock_unlock(&hdl->info.eventfd.lock);
    maybe_epoll_et_trigger(hdl, ret, /*in=*/false, /*unused was_partial=*/false);
    return ret;
}

static int eventfd_close(struct libos_handle* hdl) {
    __UNUSED(hdl);

    /* see `libos_eventfd.c` for the handle-open counterpart */
    (void)__atomic_sub_fetch(&g_eventfd_cnt, 1, __ATOMIC_ACQ_REL);
    return 0;
}

struct libos_fs_ops eventfd_fs_ops = {
    .read  = &eventfd_read,
    .write = &eventfd_write,
    .close = &eventfd_close,
};

struct libos_fs eventfd_builtin_fs = {
    .name   = "eventfd",
    .fs_ops = &eventfd_fs_ops,
};
