/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "access" and "faccessat".
 */

#include <errno.h>
#include <linux/fcntl.h>

#include "linux_capabilities.h"
#include "libos_fs.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_table.h"

long libos_syscall_access(const char* file, mode_t mode) {
    return libos_syscall_faccessat(AT_FDCWD, file, mode);
}

long libos_syscall_faccessat(int dfd, const char* filename, mode_t mode) {
    if (!filename)
        return -EINVAL;

    if (!is_user_string_readable(filename))
        return -EFAULT;

    struct libos_dentry* dir = NULL;
    struct libos_dentry* dent = NULL;
    int ret = 0;

    if (*filename != '/' && (ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    lock(&g_dcache_lock);

    ret = path_lookupat(dir, filename, LOOKUP_FOLLOW, &dent);
    if (ret < 0)
        goto out;

    ret = check_permissions(dent, mode);

out:
    unlock(&g_dcache_lock);

    if (dir)
        put_dentry(dir);
    if (dent) {
        put_dentry(dent);
    }
    return ret;
}

long libos_syscall_capget(struct gramine_user_cap_header* hdrp_unaligned,
                          struct gramine_user_cap_data* datap_unaligned) {
    struct gramine_user_cap_header hdrp;
    struct gramine_user_cap_data datap[2];
    int ret;
    if (!is_user_memory_readable(hdrp_unaligned, sizeof(*hdrp_unaligned)))
        return -EFAULT;
    memcpy(&hdrp, hdrp_unaligned, sizeof(*hdrp_unaligned));

    struct libos_thread* cur_thread = get_cur_thread();
    lock(&cur_thread->lock);
    if (hdrp.pid != 0 && hdrp.pid != (int)cur_thread->tid) {
        ret = datap_unaligned == NULL ? 0 : -ESRCH;
        goto out_locked;
    }
    unlock(&cur_thread->lock);
    size_t size = 0;
    switch(hdrp.version) {
        case GRAMINE_LINUX_CAPABILITY_VERSION_1:
            size = 1;
            break;
        case GRAMINE_LINUX_CAPABILITY_VERSION_2:
        case GRAMINE_LINUX_CAPABILITY_VERSION_3:
            size = 2;
            break;
        default:
            hdrp.version = GRAMINE_LINUX_CAPABILITY_VERSION_3;
            if (!is_user_memory_writable(hdrp_unaligned, sizeof(hdrp))) {
                ret = -EFAULT;
            } else {
                memcpy(hdrp_unaligned, &hdrp, sizeof(*hdrp_unaligned));
                ret = datap_unaligned == NULL ? 0 : -EINVAL;
            }
            goto out;
    }
    if (datap_unaligned == NULL) {
        ret = 0;
        goto out;
    }
    /* For now we can get and set capabilities for current thread.
     * TODO: Add support to get and set capabalities for other threads */
    lock(&cur_thread->lock);
    if (!is_user_memory_writable(datap_unaligned, size * sizeof(datap[0]))) {
        ret = -EFAULT;
    } else {
        memcpy(datap_unaligned, cur_thread->capabilities, size * sizeof(datap[0]));
        ret = 0;
    }
out_locked:
    unlock(&cur_thread->lock);
out:
    return ret;
}

long libos_syscall_capset(struct gramine_user_cap_header* hdrp_unaligned,
                          struct gramine_user_cap_data* datap_unaligned) {
    struct libos_thread* cur_thread = get_cur_thread();
    if (!cur_thread->is_capability_enabled) {
        log_debug("Setting of capabilities is disabled. Please set sys.enable_capabilities to true "
                  "to enable setting of capabilities");
        return -ENOSYS;
    }
    struct gramine_user_cap_header hdrp;
    struct gramine_user_cap_data datap[2];
    int ret;
    if (!is_user_memory_readable(hdrp_unaligned, sizeof(*hdrp_unaligned)))
        return -EFAULT;
    memcpy(&hdrp, hdrp_unaligned, sizeof(*hdrp_unaligned));

    /* For now we can get and set capabilities for current thread.
     * TODO: Add support to get and set capabalities for other threads */
    lock(&cur_thread->lock);
    if (hdrp.pid != 0 && hdrp.pid != (int)cur_thread->tid) {
        unlock(&cur_thread->lock);
        return -ESRCH;
    }
    size_t size = 0;
    switch(hdrp.version) {
        case GRAMINE_LINUX_CAPABILITY_VERSION_1:
            size = 1;
            break;
        case GRAMINE_LINUX_CAPABILITY_VERSION_2:
        case GRAMINE_LINUX_CAPABILITY_VERSION_3:
            size = 2;
            break;
        default:
            hdrp.version = GRAMINE_LINUX_CAPABILITY_VERSION_3;
            if (!is_user_memory_writable(hdrp_unaligned,
                sizeof(*hdrp_unaligned))) {
                unlock(&cur_thread->lock);
                return -EFAULT;
            }
            memcpy(hdrp_unaligned, &hdrp, sizeof(hdrp));
            unlock(&cur_thread->lock);
            return -EINVAL;
    }
    if (!is_user_memory_readable(datap_unaligned, size * sizeof(datap[0]))) {
        unlock(&cur_thread->lock);
        return -EFAULT;
    }
    memcpy(datap, datap_unaligned, size * sizeof(datap[0]));

    ret = cur_thread->euid == 0 ? 0 : -EPERM;
    if (ret < 0) {
        unlock(&cur_thread->lock);
        return ret;
    }

    for(size_t i = 0; i < size; i++) {
        cur_thread->capabilities[i].effective = datap[i].effective;
        cur_thread->capabilities[i].permitted = datap[i].permitted;
        cur_thread->capabilities[i].inheritable = datap[i].inheritable;
    }
    unlock(&cur_thread->lock);
    return 0;
}
