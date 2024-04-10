/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

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

/* In emulate-in-libos mode, enforce a restriction: all eventfds created in the parent process are
 * marked as invalid in child processes, i.e. inter-process communication via eventfds is not
 * allowed. This restriction is because LibOS doesn't yet implement sync between eventfd objects. */
static int eventfd_checkin(struct libos_handle* hdl) {
    assert(hdl->type == TYPE_EVENTFD);
    if (!g_eventfd_passthrough_mode)
        hdl->info.eventfd.broken_in_child = true;
    return 0;
}

static void eventfd_dummy_host_read(struct libos_handle* hdl) {
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

static void eventfd_dummy_host_write(struct libos_handle* hdl) {
    int ret;
    uint64_t buf_dummy_host_val = 1;
    size_t dummy_host_val_count = sizeof(buf_dummy_host_val);
    do {
        ret = PalStreamWrite(hdl->pal_handle, /*offset=*/0, &dummy_host_val_count,
                             &buf_dummy_host_val);
    } while (ret == -PAL_ERROR_INTERRUPTED);
    if (ret < 0 || dummy_host_val_count != sizeof(buf_dummy_host_val)) {
        /* must not happen in benign case, consider it an attack and panic */
        BUG();
    }
}

static void eventfd_dummy_host_wait(struct libos_handle* hdl, bool wait_for_read) {
    pal_wait_flags_t wait_for_events = wait_for_read ? PAL_WAIT_READ : PAL_WAIT_WRITE;
    pal_wait_flags_t ret_events = 0;
    int ret = PalStreamsWaitEvents(1, &hdl->pal_handle, &wait_for_events, &ret_events, NULL);
    if (ret < 0 && ret != -PAL_ERROR_INTERRUPTED) {
        BUG();
    }
    (void)ret_events; /* we don't care what events the host returned, we can't trust them anyway */
}

static ssize_t eventfd_read(struct libos_handle* hdl, void* buf, size_t count, file_off_t* pos) {
    __UNUSED(pos);

    if (count < sizeof(uint64_t))
        return -EINVAL;

    if (g_eventfd_passthrough_mode) {
        /* passthrough-to-host mode */
        int ret = PalStreamRead(hdl->pal_handle, /*offset=*/0, &count, buf);
        if (!ret && count != sizeof(uint64_t)) {
            /* successful read must return 8 bytes, otherwise it's an attack or host malfunction */
            return -EPERM;
        }
        ret = pal_to_unix_errno(ret);
        /* eventfd objects never perform partial reads, see also check above */
        maybe_epoll_et_trigger(hdl, ret, /*in=*/true, /*unused was_partial=*/false);
        return ret < 0 ? ret : (ssize_t)count;
    }

    /* emulate-in-libos mode */
    if (hdl->info.eventfd.broken_in_child) {
        log_warning("Child process tried to access eventfd created by parent process. This is "
                    "disallowed in Gramine (but see `sys.insecure__allow_eventfd`).");
        return -EIO;
    }

    int ret;
    spinlock_lock(&hdl->info.eventfd.lock);

    while (!hdl->info.eventfd.val) {
        if (hdl->flags & O_NONBLOCK) {
            ret = -EAGAIN;
            goto out;
        }
        spinlock_unlock(&hdl->info.eventfd.lock);
        eventfd_dummy_host_wait(hdl, /*wait_for_read=*/true);
        spinlock_lock(&hdl->info.eventfd.lock);
    }

    if (!hdl->info.eventfd.is_semaphore) {
        memcpy(buf, &hdl->info.eventfd.val, sizeof(uint64_t));
        hdl->info.eventfd.val = 0;
    } else {
        uint64_t one_val = 1;
        memcpy(buf, &one_val, sizeof(uint64_t));
        hdl->info.eventfd.val--;
    }

    /* perform a read (not supposed to block) to clear the event from polling threads and to send an
     * event to writing threads */
    if (hdl->info.eventfd.dummy_host_val) {
        eventfd_dummy_host_read(hdl);
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
        if (!ret && count != sizeof(uint64_t)) {
            /* successful write must return 8 bytes, otherwise it's an attack or host malfunction */
            return -EPERM;
        }
        ret = pal_to_unix_errno(ret);
        /* eventfd objects never perform partial writes, see also check above */
        maybe_epoll_et_trigger(hdl, ret, /*in=*/false, /*unused was_partial=*/false);
        return ret < 0 ? ret : (ssize_t)count;
    }

    /* emulate-in-libos mode */
    if (hdl->info.eventfd.broken_in_child) {
        log_warning("Child process tried to access eventfd created by parent process. This is "
                    "disallowed in Gramine (but see `sys.insecure__allow_eventfd`).");
        return -EIO;
    }

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
        spinlock_unlock(&hdl->info.eventfd.lock);
        eventfd_dummy_host_wait(hdl, /*wait_for_read=*/false);
        spinlock_lock(&hdl->info.eventfd.lock);
    }

    hdl->info.eventfd.val = val;

    /* perform a write (not supposed to block) to send an event to reading/polling threads */
    if (hdl->info.eventfd.dummy_host_val >= UINT64_MAX - 1)
        BUG();
    hdl->info.eventfd.dummy_host_val++;
    eventfd_dummy_host_write(hdl);

    ret = (ssize_t)count;
out:
    spinlock_unlock(&hdl->info.eventfd.lock);
    maybe_epoll_et_trigger(hdl, ret, /*in=*/false, /*unused was_partial=*/false);
    return ret;
}

static void eventfd_post_poll(struct libos_handle* hdl, pal_wait_flags_t* pal_ret_events) {
    if (g_eventfd_passthrough_mode)
        return;

    if (hdl->info.eventfd.broken_in_child) {
        log_warning("Child process tried to access eventfd created by parent process. This is "
                    "disallowed in Gramine (but see `sys.insecure__allow_eventfd`).");
        *pal_ret_events = PAL_WAIT_ERROR;
        return;
    }

    if (*pal_ret_events & (PAL_WAIT_ERROR | PAL_WAIT_HANG_UP)) {
        /* impossible: we control eventfd inside the LibOS, and we never raise such conditions */
        BUG();
    }

    spinlock_lock(&hdl->info.eventfd.lock);
    if (*pal_ret_events & PAL_WAIT_READ) {
        /* there is data to read: verify if counter has value greater than zero */
        if (!hdl->info.eventfd.val) {
            /* spurious or malicious notification, can legitimately happen if another thread
             * consumed this event between this thread's poll wakeup and the post_poll callback;
             * we currently choose to return a spurious notification to the user */
            *pal_ret_events &= ~PAL_WAIT_READ;
        }
    }
    if (*pal_ret_events & PAL_WAIT_WRITE) {
        /* verify it's really possible to write a value of at least "1" without blocking */
        if (hdl->info.eventfd.val >= UINT64_MAX - 1) {
            /* spurious or malicious notification, see comment above */
            *pal_ret_events &= ~PAL_WAIT_WRITE;
        }
    }
    spinlock_unlock(&hdl->info.eventfd.lock);
}

struct libos_fs_ops eventfd_fs_ops = {
    .checkin   = &eventfd_checkin,
    .read      = &eventfd_read,
    .write     = &eventfd_write,
    .post_poll = &eventfd_post_poll,
};

struct libos_fs eventfd_builtin_fs = {
    .name   = "eventfd",
    .fs_ops = &eventfd_fs_ops,
};
