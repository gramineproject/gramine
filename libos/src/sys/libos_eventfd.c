/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019 Intel Corporation */

/*
 * Implementation of system calls "eventfd" and "eventfd2". Since eventfd emulation currently relies
 * on the host, these system calls are disallowed by default due to security concerns. To use them,
 * they must be explicitly allowed through the "sys.insecure__allow_eventfd" manifest key.
 */

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_table.h"
#include "libos_utils.h"
#include "linux_eventfd.h"
#include "linux_abi/fs.h"
#include "pal.h"
#include "toml_utils.h"

bool g_eventfd_passthrough_mode = false;

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

    if (!g_eventfd_passthrough_mode) {
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
    hdl->flags = O_RDWR;
    hdl->acc_mode = MAY_READ | MAY_WRITE;

    hdl->info.eventfd.is_semaphore = !!(flags & EFD_SEMAPHORE);

    ret = create_eventfd_pal_handle(count, flags, &hdl->pal_handle);
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
