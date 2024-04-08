/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

/*
 * Implementation of system calls "eventfd" and "eventfd2".
 *
 * There are two modes of eventfd:
 *
 * 1. Passthrough-to-host -- the eventfd object is created on the host, and all operations are
 *    delegated to the host. Since this implementation is insecure, it is disallowed by default. To
 *    use this implementation, it must be explicitly allowed via the `sys.insecure__allow_eventfd`
 *    manifest option.
 *
 * 2. Emulate-in-libos -- the eventfd object is created inside the LibOS, and all operations are
 *    resolved entirely inside the LibOS. A dummy eventfd object is created on the host, purely to
 *    trigger read/write notifications (e.g., in epoll); eventfd values are verified inside the
 *    LibOS and are never exposed to the host. Since the host is used purely for notifications (see
 *    notes below), this implementation is considered secure and enabled by default. It is
 *    automatically disabled if the manifest option `sys.insecure__allow_eventfd` is enabled.
 *
 *    - The emulation is currently implemented at the level of a single process. The emulation *may*
 *      work for multi-process applications, e.g., if the child process inherits the eventfd object
 *      but doesn't use it. However, all eventfds created in the parent process are marked as
 *      invalid in child processes, i.e. inter-process communication via eventfds is not allowed.
 *
 *    - The host's eventfd object is "dummy" and used purely for notifications -- to unblock
 *      blocking read/write/select/poll/epoll system calls. The read/write notify logic is already
 *      hardened, by double-checking that the object was indeed updated. However, there are three
 *      possible attacks on polling mechanisms (select/poll/epoll):
 *
 *      a. Malicious host may inject the notification too early: POLLIN when nothing was written
 *         yet or POLLOUT when nothing was read yet. This may lead to a synchronization failure
 *         of the app: e.g., Rust Tokio's Metal I/O (mio) lib would incorrectly wake up a thread.
 *         To prevent this, eventfd implements a callback `post_poll()` where it verifies that some
 *         data was indeed written/read (i.e., that the notification is not spurious).
 *      b. Malicious host may inject the notification too late or not send a notification at all.
 *         This is a Denial of Service (DoS), which we don't care about.
 *      c. Malicious host may inject POLLERR, POLLHUP, POLLRDHUP, POLLNVAL. This is impossible as we
 *         control eventfd objects inside the LibOS, and we never raise such conditions. So the
 *         callback `post_poll()` panics if it detects such a return event.
 */

#include "libos_checkpoint.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_table.h"
#include "libos_utils.h"
#include "linux_abi/fs.h"
#include "linux_eventfd.h"
#include "pal.h"
#include "toml_utils.h"

bool g_eventfd_passthrough_mode __attribute_migratable = false;

int init_eventfd_mode(void) {
    assert(g_manifest_root);
    int ret;

    ret = toml_bool_in(g_manifest_root, "sys.insecure__allow_eventfd", /*defaultval=*/false,
                       &g_eventfd_passthrough_mode);
    if (ret < 0) {
        log_error("Cannot parse 'sys.insecure__allow_eventfd' (the value must be `true` or "
                  "`false`)");
        return -EPERM;
    }

    return 0;
}

static int create_eventfd_pal_handle(uint64_t initial_count, int flags,
                                     PAL_HANDLE* out_pal_handle) {
    int ret;

    PAL_HANDLE hdl = NULL;

    int pal_flags = 0;
    pal_flags |= flags & EFD_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    pal_flags |= flags & EFD_SEMAPHORE ? PAL_OPTION_EFD_SEMAPHORE : 0;

    ret = PalStreamOpen(URI_PREFIX_EVENTFD, PAL_ACCESS_RDWR, /*share_flags=*/0,
                        PAL_CREATE_IGNORED, pal_flags, &hdl);
    if (ret < 0) {
        log_error("eventfd: creation failure");
        return pal_to_unix_errno(ret);
    }

    /* set the initial count */
    size_t write_size = sizeof(initial_count);
    ret = PalStreamWrite(hdl, /*offset=*/0, &write_size, &initial_count);
    if (ret < 0) {
        log_error("eventfd: failed to set initial count");
        return pal_to_unix_errno(ret);
    }
    if (write_size != sizeof(initial_count)) {
        log_error("eventfd: interrupted while setting initial count");
        return -EINTR;
    }

    *out_pal_handle = hdl;
    return 0;
}

long libos_syscall_eventfd2(unsigned int count, int flags) {
    int ret;

    struct libos_handle* hdl = get_new_handle();
    if (!hdl)
        return -ENOMEM;

    hdl->type = TYPE_EVENTFD;
    hdl->fs = &eventfd_builtin_fs;
    hdl->flags = O_RDWR | (flags & EFD_NONBLOCK ? O_NONBLOCK : 0);
    hdl->acc_mode = MAY_READ | MAY_WRITE;

    hdl->info.eventfd.is_semaphore = !!(flags & EFD_SEMAPHORE);
    hdl->info.eventfd.val = count;
    hdl->info.eventfd.dummy_host_val = 0;
    hdl->info.eventfd.broken_in_child = false;

    if (g_eventfd_passthrough_mode) {
        ret = create_eventfd_pal_handle(hdl->info.eventfd.val, flags, &hdl->pal_handle);
    } else {
        ret = create_eventfd_pal_handle(hdl->info.eventfd.dummy_host_val, /*flags=*/0,
                                        &hdl->pal_handle);
    }
    if (ret < 0)
        goto out;

    ret = set_new_fd_handle(hdl, flags & EFD_CLOEXEC ? FD_CLOEXEC : 0, NULL);
out:
    put_handle(hdl);
    return ret;
}

long libos_syscall_eventfd(unsigned int count) {
    return libos_syscall_eventfd2(count, 0);
}
