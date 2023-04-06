/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "access" and "faccessat".
 */

#include <errno.h>
#include <linux/fcntl.h>
#include <linux/capability.h>

#include "libos_fs.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_table.h"
#include "linux_capabilities.h"

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

long libos_syscall_capget(cap_user_header_t _hdrp, const cap_user_data_t _datap) {

    struct gramine_user_cap_header hdrp;
    struct gramine_user_cap_data datap[2];
    int ret;
    if (!_hdrp || !is_user_memory_readable(_hdrp, sizeof(*_hdrp)))
        return -EFAULT;
    memcpy(&hdrp, _hdrp, sizeof(*_hdrp));
    struct libos_thread* cur_thread = get_cur_thread();
    lock(&cur_thread->lock);
    if (hdrp.pid != 0 && hdrp.pid != (int)cur_thread->tid) {
        ret = _datap == NULL ? 0 : -ESRCH;
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
            if (!_hdrp || !is_user_memory_writable(_hdrp, sizeof(hdrp)))
                ret = -EFAULT;
            else {
                memcpy(_hdrp, &hdrp, sizeof(*_hdrp));
                ret = _datap == NULL ? 0 : -EINVAL;
            }
            goto out;
    }
    if (_datap == NULL) {
        ret = 0;
        goto out;
    }
    /* For now we can get and set capabilties for current thread.
     * TODO: Add support to get and set capabalities for other threads */
    lock(&cur_thread->lock);
    if( cur_thread->is_cap_set) {
        if (!_datap || !is_user_memory_writable(_datap, size * sizeof(datap[0])))
            ret = -EFAULT;
        else {
            memcpy(_datap, cur_thread->capabilities, size * sizeof(datap[0]));
            ret = 0;
        }
        goto out_locked;
    } else {
        unlock(&cur_thread->lock);
        uint32_t version = hdrp.version;
        ret = Palcapget(version, datap);
        if (ret < 0) {
            goto out;
        }
        lock(&cur_thread->lock);
        for(size_t i = 0; i < size; i++) {
            cur_thread->capabilities[i].effective = datap[i].effective;
            cur_thread->capabilities[i].permitted = datap[i].permitted;
            cur_thread->capabilities[i].inheritable = datap[i].inheritable;
        }
        cur_thread->is_cap_set = true;
        unlock(&cur_thread->lock);
        if (!_datap || !is_user_memory_writable(_datap, size * sizeof(datap[0])))
            ret = -EFAULT;
        else {
            memcpy(_datap, cur_thread->capabilities, size * sizeof(datap[0]));
            ret = 0;
        }
        goto out;
    }
    goto out;

out_locked:
    unlock(&cur_thread->lock);
out:
    return ret;
}

long libos_syscall_capset(cap_user_header_t _hdrp, const cap_user_data_t _datap) {
    struct gramine_user_cap_header hdrp;
    struct gramine_user_cap_data datap[2];
    int ret;
    if (!_hdrp || !is_user_memory_readable(_hdrp, sizeof(*_hdrp)))
        return -EFAULT;
    memcpy(&hdrp, _hdrp, sizeof(*_hdrp));
    /* For now we can get and set capabilties for current thread.
     * TODO: Add support to get and set capabalities for other threads */
    struct libos_thread* cur_thread = get_cur_thread();
    lock(&cur_thread->lock);
    if (hdrp.pid != 0 && hdrp.pid != (int)cur_thread->tid) {
        unlock(&cur_thread->lock);
        return -ESRCH;
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
            if (!_hdrp || !is_user_memory_writable(_hdrp, sizeof(*_hdrp)))
                return -EFAULT;
            memcpy(_hdrp, &hdrp, sizeof(hdrp));
            return -EINVAL;
    }
    if (!_datap || !is_user_memory_readable(_datap, size * sizeof(datap[0])))
        return -EFAULT;
    memcpy(datap, _datap, size * sizeof(datap[0]));

    uint32_t version = hdrp.version;
    ret = Palcapset(version, datap);
    if (ret < 0) {
        return ret;
    }
    lock(&cur_thread->lock);
    cur_thread->is_cap_set = true;
    for(size_t i = 0; i < size; i++) {
        cur_thread->capabilities[i].effective = datap[i].effective;
        cur_thread->capabilities[i].permitted = datap[i].permitted;
        cur_thread->capabilities[i].inheritable = datap[i].inheritable;
    }
    unlock(&cur_thread->lock);
    return 0;
}
