/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019 Intel Corporation */

/*
 * Implementation of system calls "eventfd" and "eventfd2". Since eventfd emulation currently relies
 * on the host, these system calls are disallowed by default due to security concerns. To use them,
 * they must be explicitly allowed through the "sys.insecure__allow_eventfd" manifest key.
 */

#include <asm/fcntl.h>

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_table.h"
#include "libos_utils.h"
#include "linux_eventfd.h"
#include "pal.h"
#include "toml_utils.h"

static int create_eventfd(PAL_HANDLE* efd, uint64_t initial_count, int flags) {
    int ret;

    assert(g_manifest_root);
    bool allow_eventfd;
    ret = toml_bool_in(g_manifest_root, "sys.insecure__allow_eventfd", /*defaultval=*/false,
                       &allow_eventfd);
    if (ret < 0) {
        log_error("Cannot parse \'sys.insecure__allow_eventfd\' (the value must be `true` or "
                  "`false`)");
        return -ENOSYS;
    }

    if (!allow_eventfd) {
        /* eventfd is not explicitly allowed in manifest */
        if (FIRST_TIME()) {
            log_warning("The app tried to use eventfd, but it's turned off "
                        "(sys.insecure__allow_eventfd = false)");
        }

        return -ENOSYS;
    }

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

    *efd = hdl;
    return 0;
}

long libos_syscall_eventfd2(unsigned int count, int flags) {
    int ret = 0;
    struct libos_handle* hdl = get_new_handle();

    if (!hdl) {
        ret = -ENOMEM;
        goto out;
    }

    hdl->type = TYPE_EVENTFD;
    hdl->fs = &eventfd_builtin_fs;
    hdl->flags = O_RDWR;
    hdl->acc_mode = MAY_READ | MAY_WRITE;

    if ((ret = create_eventfd(&hdl->pal_handle, count, flags)) < 0)
        goto out;

    hdl->info.eventfd.is_semaphore = !!(flags & EFD_SEMAPHORE);

    flags = flags & EFD_CLOEXEC ? FD_CLOEXEC : 0;

    /* get_new_handle() above increments hdl's refcount. Followed by another increment inside
     * set_new_fd_handle. So we need to put_handle() afterwards. */
    int vfd = set_new_fd_handle(hdl, flags, NULL);

    ret = vfd;

out:
    if (hdl)
        put_handle(hdl);

    return ret;
}

long libos_syscall_eventfd(unsigned int count) {
    return libos_syscall_eventfd2(count, 0);
}
