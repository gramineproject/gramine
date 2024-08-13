/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/* Implementation of "timerfd" system calls.
 *
 * The timerfd object is created inside the LibOS, and all operations are resolved entirely inside
 * the LibOS (note that the time source in Gramine SGX is still untrusted). Each timerfd object is
 * associated with a dummy eventfd created on the host. This is purely for triggering read
 * notifications (e.g., in epoll); timerfd data is verified inside the LibOS and is never exposed to
 * the host. Since the host is used purely for notifications, a malicious host can only induce
 * Denial of Service (DoS) attacks.
 *
 * The emulation is currently implemented at the level of a single process. All timerfds created in
 * the parent process are marked as invalid in child processes. In multi-process applications,
 * Gramine does not exit immediately after fork; it only exits if the application attempts to use
 * timerfds in the child. Therefore, inter-process timing signals via timerfds are not allowed.
 *
 * The host's eventfd object is "dummy" and used purely for notifications -- to unblock blocking
 * read/select/poll/epoll system calls. The read notify logic is already hardened, by
 * double-checking that the timerfd object indeed expired. However, there are three possible attacks
 * on polling mechanisms (select/poll/epoll):
 *
 * a. Malicious host may inject the notification too early: POLLIN when no timer expired yet. This
 *    may lead to a synchronization failure of the app. To prevent this, timerfd implements a
 *    callback `post_poll()` where it verifies that a timer was indeed expired (i.e., that the
 *    notification is not spurious).
 * b. Malicious host may inject the notification too late or not send a notification at all.
 *    This is a Denial of Service (DoS), which we don't care about.
 * c. Malicious host may inject POLLERR, POLLHUP, POLLRDHUP, POLLNVAL, POLLOUT. This is impossible
 *    as we control timerfd objects inside the LibOS, and we never raise such conditions. So the
 *    callback `post_poll()` panics if it detects such a return event.
 */

#include "libos_checkpoint.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_table.h"
#include "libos_utils.h"
#include "linux_abi/fs.h"
#include "linux_abi/time.h"
#include "linux_eventfd.h"
#include "pal.h"

/* This implementation is the same as `eventfd_dummy_host_write()` in "fs/eventfd/fs.c". */
static void timerfd_dummy_host_write(struct libos_handle* hdl) {
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

static int create_timerfd_pal_handle(PAL_HANDLE* out_pal_handle) {
    PAL_HANDLE hdl = NULL;

    int ret = PalStreamOpen(URI_PREFIX_EVENTFD, PAL_ACCESS_RDWR, /*share_flags=*/0,
                            PAL_CREATE_IGNORED, /*options=*/0, &hdl);
    if (ret < 0) {
        log_error("timerfd: dummy host eventfd creation failure");
        return pal_to_unix_errno(ret);
    }

    *out_pal_handle = hdl;
    return 0;
}

long libos_syscall_timerfd_create(int clockid, int flags) {
    int ret;

    if ((flags & ~TFD_CREATE_FLAGS) ||
        (clockid != CLOCK_MONOTONIC && clockid != CLOCK_REALTIME &&
         clockid != CLOCK_REALTIME_ALARM && clockid != CLOCK_BOOTTIME &&
         clockid != CLOCK_BOOTTIME_ALARM))
        return -EINVAL;

    if (clockid != CLOCK_REALTIME) {
        if (FIRST_TIME()) {
            log_warning("Unsupported clockid in 'timerfd_create()'; replaced by the system-wide "
                        "real-time clock.");
        }
    }

    struct libos_handle* hdl = get_new_handle();
    if (!hdl)
        return -ENOMEM;

    hdl->type = TYPE_TIMERFD;
    hdl->fs = &timerfd_builtin_fs;
    hdl->flags = O_RDONLY | (flags & TFD_NONBLOCK ? O_NONBLOCK : 0);
    hdl->acc_mode = MAY_READ;

    hdl->info.timerfd.broken_in_child = false;
    hdl->info.timerfd.num_expirations = 0;
    hdl->info.timerfd.dummy_host_val = 0;
    hdl->info.timerfd.timeout = 0;
    hdl->info.timerfd.reset = 0;

    ret = create_timerfd_pal_handle(&hdl->pal_handle);
    if (ret < 0)
        goto out;

    ret = set_new_fd_handle(hdl, flags & TFD_CLOEXEC ? FD_CLOEXEC : 0, NULL);
out:
    put_handle(hdl);
    return ret;
}

static void timerfd_update(struct libos_handle* hdl) {
    spinlock_lock(&hdl->info.timerfd.expiration_lock);

    /* When the expiration count overflows, the read will saturate at UINT64_MAX while the timer
     * will continue to fire. */
    if (hdl->info.timerfd.num_expirations < UINT64_MAX)
        hdl->info.timerfd.num_expirations++;

    hdl->info.timerfd.dummy_host_val++;

    /* perform a write (not supposed to block) to send an event to reading/polling threads */
    timerfd_dummy_host_write(hdl);

    spinlock_unlock(&hdl->info.timerfd.expiration_lock);
}

static void callback_itimer(IDTYPE caller, void* arg) {
    __UNUSED(caller);

    struct libos_handle* hdl = (struct libos_handle*)arg;

    spinlock_lock(&hdl->info.timerfd.timer_lock);
    hdl->info.timerfd.timeout += hdl->info.timerfd.reset;
    uint64_t next_reset = hdl->info.timerfd.reset;
    spinlock_unlock(&hdl->info.timerfd.timer_lock);

    if (next_reset) {
        int64_t ret = install_async_event(ASYNC_EVENT_TYPE_ALARM_TIMER, hdl->pal_handle,
                                          next_reset, /*absolute_time=*/false,
                                          &callback_itimer, (void*)hdl);
        if (ret < 0) {
            log_error(
                "failed to re-enqueue the next timer event initially set up by "
                "'timerfd_settime()': %s", unix_strerror(ret));
            die_or_inf_loop();
        }
    }

    timerfd_update(hdl);
}

long libos_syscall_timerfd_settime(int fd, int flags, const struct __kernel_itimerspec* value,
                                   struct __kernel_itimerspec* ovalue) {
    int ret;

    struct libos_handle* hdl = get_fd_handle(fd, /*fd_flags=*/NULL, /*map=*/NULL);
    if (!hdl)
        return -EBADF;

    if (hdl->type != TYPE_TIMERFD) {
        ret = -EINVAL;
        goto out;
    }

    if (hdl->info.timerfd.broken_in_child) {
        log_warning("Child process tried to access timerfd created by parent process. This is "
                    "disallowed in Gramine.");
        return -EIO;
    }

    if (!is_user_memory_readable(value, sizeof(*value))) {
        ret = -EFAULT;
        goto out;
    }
    if (ovalue && !is_user_memory_writable(ovalue, sizeof(*ovalue))) {
        ret = -EFAULT;
        goto out;
    }

    /* `TFD_TIMER_CANCEL_ON_SET` is silently ignored because there are no "discontinuous changes of
     * time" in Gramine (via e.g., `settimeofday()`). */

    if (flags & ~TFD_SETTIME_FLAGS) {
        ret = -EINVAL;
        goto out;
    }

    uint64_t setup_time = 0;
    ret = PalSystemTimeQuery(&setup_time);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    uint64_t new_timeout = timespec_to_us(&value->it_value);
    uint64_t new_reset = timespec_to_us(&value->it_interval);

    spinlock_lock(&hdl->info.timerfd.timer_lock);

    uint64_t current_timeout = hdl->info.timerfd.timeout > setup_time
                               ? hdl->info.timerfd.timeout - setup_time
                               : 0;
    uint64_t current_reset = hdl->info.timerfd.reset;

    bool absolute_time = flags & TFD_TIMER_ABSTIME;
    if (absolute_time) {
        hdl->info.timerfd.timeout = new_timeout;
    } else {
        hdl->info.timerfd.timeout = setup_time + new_timeout;
    }
    hdl->info.timerfd.reset = new_reset;

    spinlock_unlock(&hdl->info.timerfd.timer_lock);

    int64_t install_ret;
    if (new_timeout) {
        install_ret = install_async_event(ASYNC_EVENT_TYPE_ALARM_TIMER, hdl->pal_handle,
                                          new_timeout, absolute_time,
                                          &callback_itimer, (void*)hdl);
    } else {
        /* cancel the pending timerfd object */
        install_ret = install_async_event(ASYNC_EVENT_TYPE_ALARM_TIMER, hdl->pal_handle,
                                          /*time_us=*/0, /*absolute_time=*/false,
                                          /*callback=*/NULL, /*arg=*/NULL);
    }
    if (install_ret < 0) {
        ret = install_ret;
        goto out;
    }

    if (ovalue) {
        ovalue->it_interval.tv_sec  = current_reset / TIME_US_IN_S;
        ovalue->it_interval.tv_nsec = (current_reset % TIME_US_IN_S) * TIME_NS_IN_US;
        ovalue->it_value.tv_sec     = current_timeout / TIME_US_IN_S;
        ovalue->it_value.tv_nsec    = (current_timeout % TIME_US_IN_S) * TIME_NS_IN_US;
    }

    ret = 0;
out:
    put_handle(hdl);
    return ret;
}

long libos_syscall_timerfd_gettime(int fd, struct __kernel_itimerspec* value) {
    int ret;

    struct libos_handle* hdl = get_fd_handle(fd, /*fd_flags=*/NULL, /*map=*/NULL);
    if (!hdl)
        return -EBADF;

    if (hdl->type != TYPE_TIMERFD) {
        ret = -EINVAL;
        goto out;
    }

    if (hdl->info.timerfd.broken_in_child) {
        log_warning("Child process tried to access timerfd created by parent process. This is "
                    "disallowed in Gramine.");
        return -EIO;
    }

    if (!is_user_memory_writable(value, sizeof(*value))) {
        ret = -EFAULT;
        goto out;
    }

    uint64_t setup_time = 0;
    ret = PalSystemTimeQuery(&setup_time);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    spinlock_lock(&hdl->info.timerfd.timer_lock);
    uint64_t current_timeout = hdl->info.timerfd.timeout > setup_time
                               ? hdl->info.timerfd.timeout - setup_time
                               : 0;
    uint64_t current_reset = hdl->info.timerfd.reset;
    spinlock_unlock(&hdl->info.timerfd.timer_lock);

    value->it_interval.tv_sec  = current_reset / TIME_US_IN_S;
    value->it_interval.tv_nsec = (current_reset % TIME_US_IN_S) * TIME_NS_IN_US;
    value->it_value.tv_sec     = current_timeout / TIME_US_IN_S;
    value->it_value.tv_nsec    = (current_timeout % TIME_US_IN_S) * TIME_NS_IN_US;

    ret = 0;
out:
    put_handle(hdl);
    return ret;
}
