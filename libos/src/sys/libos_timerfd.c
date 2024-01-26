/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/* Implementation of "timerfd" system calls.
 *
 * The timerfd object is created inside Gramine, and all operations are resolved entirely inside
 * Gramine. Each timerfd object is associated with a dummy eventfd created on the host. This is
 * purely for triggering read/write notifications (e.g., in epoll); timerfd data is verified inside
 * Gramine and is never exposed to the host. Since the host is used purely for notifications, a
 * malicious host can only induce Denial of Service (DoS) attacks. The dummy eventfd object is
 * hardened following the similar approaches as Gramine's `eventfd`/`eventfd2` syscall
 * implementation, see "libos/src/sys/libos_eventfd.c" for details.
 *
 * The emulation is currently implemented at the level of a single process. The emulation may work
 * for multi-process applications, e.g., if the child process inherits the timerfd object but
 * doesn't use it. However, multi-process support is brittle and thus disabled by default (Gramine
 * will issue a warning). To enable it still, set the manifest option
 * `sys.experimental__allow_timerfd_fork`.
 */

#include "libos_checkpoint.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_table.h"
#include "libos_utils.h"
#include "linux_abi/fs.h"
#include "linux_abi/timerfd.h"
#include "linux_eventfd.h"
#include "pal.h"
#include "toml_utils.h"

bool g_timerfd_allow_fork __attribute_migratable = false;

/* atomic per-process number of currently existing timerfds, used in `libos_clone.c` */
uint32_t g_timerfd_cnt = 0;

int init_timerfd(void) {
    int ret;

    assert(g_manifest_root);
    ret = toml_bool_in(g_manifest_root, "sys.experimental__allow_timerfd_fork",
                       /*defaultval=*/false, &g_timerfd_allow_fork);
    if (ret < 0) {
        log_error("Cannot parse 'sys.experimental__allow_timerfd_fork' (the value must be `true` "
                  "or `false`)");
        return -EINVAL;
    }

    return 0;
}

static void timerfd_dummy_host_write(struct libos_handle* hdl, uint64_t host_val) {
    uint64_t buf_dummy_host_val = host_val;
    size_t dummy_host_val_count = sizeof(buf_dummy_host_val);

    int ret = PalStreamWrite(hdl->pal_handle, /*offset=*/0, &dummy_host_val_count,
                             &buf_dummy_host_val);
    if (ret < 0 || dummy_host_val_count != sizeof(buf_dummy_host_val)) {
        /* must not happen in benign case, consider it an attack and panic */
        BUG();
    }
}

static int create_timerfd_pal_handle(PAL_HANDLE* out_pal_handle) {
    int ret;

    PAL_HANDLE hdl = NULL;

    ret = PalStreamOpen(URI_PREFIX_EVENTFD, PAL_ACCESS_RDWR, /*share_flags=*/0,
                        PAL_CREATE_IGNORED, /*options=*/0, &hdl);
    if (ret < 0) {
        log_error("timerfd: dummy host eventfd creation failure");
        return pal_to_unix_errno(ret);
    }

    /* see `fs/timerfd/fs.c` for the handle-close counterpart */
    (void)__atomic_add_fetch(&g_timerfd_cnt, 1, __ATOMIC_ACQ_REL);

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
            log_warning("Unsupported clockid; replaced by the system-wide real-time clock.");
        }
    }

    struct libos_handle* hdl = get_new_handle();
    if (!hdl)
        return -ENOMEM;

    hdl->type = TYPE_TIMERFD;
    hdl->fs = &timerfd_builtin_fs;
    hdl->flags = O_RDONLY | (flags & TFD_NONBLOCK ? O_NONBLOCK : 0);
    hdl->acc_mode = MAY_READ;

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

    if (hdl->info.timerfd.num_expirations < UINT64_MAX) {
        hdl->info.timerfd.num_expirations++;
        hdl->info.timerfd.dummy_host_val++;

        /* perform a write (not supposed to block) to send an event to reading/polling threads */
        timerfd_dummy_host_write(hdl, /*host_val=*/1);
    }

    spinlock_unlock(&hdl->info.timerfd.expiration_lock);

    maybe_epoll_et_trigger(hdl, /*ret=*/0, /*in=*/false, /*unused was_partial=*/false);
}

static void callback_itimer(IDTYPE caller, void* arg) {
    // XXX: Can we simplify this code or streamline with the other callback?
    __UNUSED(caller);

    struct libos_handle* hdl = (struct libos_handle*)arg;

    spinlock_lock(&hdl->info.timerfd.timer_lock);
    hdl->info.timerfd.timeout += hdl->info.timerfd.reset;
    uint64_t next_reset = hdl->info.timerfd.reset;
    spinlock_unlock(&hdl->info.timerfd.timer_lock);

    if (next_reset)
        install_async_event(hdl->pal_handle, next_reset, /*absolute_time=*/false, &callback_itimer,
                            (void*)hdl);

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

    if (!is_user_memory_readable(value, sizeof(*value))) {
        ret = -EFAULT;
        goto out;
    }
    if (ovalue && !is_user_memory_writable(ovalue, sizeof(*ovalue))) {
        ret = -EFAULT;
        goto out;
    }

    if (flags & ~TFD_SETTIME_FLAGS) {
        ret = -EINVAL;
        goto out;
    }

    /* NOTE: cancelable timer (for the case where reads on timerfd would return `ECANCELED` when the
     * real-time clock undergoes a discontinuous change) is currently unsupported; needs to be
     * specified along with `TFD_TIMER_ABSTIME`. */
    if (flags & TFD_TIMER_CANCEL_ON_SET) {
        ret = -ENOSYS;
        goto out;
    }

    uint64_t setup_time = 0;
    ret = PalSystemTimeQuery(&setup_time);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    uint64_t next_value = timespec_to_us(&value->it_value);
    uint64_t next_reset = timespec_to_us(&value->it_interval);

    spinlock_lock(&hdl->info.timerfd.timer_lock);

    uint64_t current_timeout = hdl->info.timerfd.timeout > setup_time
                               ? hdl->info.timerfd.timeout - setup_time
                               : 0;
    uint64_t current_reset = hdl->info.timerfd.reset;

    bool absolute_time = flags & TFD_TIMER_ABSTIME;
    if (absolute_time) {
        hdl->info.timerfd.timeout = next_value;
    } else {
        hdl->info.timerfd.timeout = setup_time + next_value;
    }
    hdl->info.timerfd.reset = next_reset;

    spinlock_unlock(&hdl->info.timerfd.timer_lock);

    if (next_value) {
        int64_t install_ret = install_async_event(hdl->pal_handle, next_value, absolute_time,
                                                  &callback_itimer, (void*)hdl);
        if (install_ret < 0) {
            ret = install_ret;
            goto out;
        }
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
