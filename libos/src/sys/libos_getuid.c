/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "api.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "libos_types.h"

long libos_syscall_getuid(void) {
    struct libos_thread* current = get_cur_thread();
    lock(&current->lock);
    uid_t uid = current->uid;
    unlock(&current->lock);
    return uid;
}

long libos_syscall_getgid(void) {
    struct libos_thread* current = get_cur_thread();
    lock(&current->lock);
    gid_t gid = current->gid;
    unlock(&current->lock);
    return gid;
}

long libos_syscall_geteuid(void) {
    struct libos_thread* current = get_cur_thread();
    lock(&current->lock);
    uid_t euid = current->euid;
    unlock(&current->lock);
    return euid;
}

long libos_syscall_getegid(void) {
    struct libos_thread* current = get_cur_thread();
    lock(&current->lock);
    gid_t egid = current->egid;
    unlock(&current->lock);
    return egid;
}

long libos_syscall_setuid(uid_t uid) {
    int ret;
    struct libos_thread* current = get_cur_thread();

    lock(&current->lock);
    if (current->uid == 0) {
        /* if the user is root, the real UID and saved set-user-ID are also set */
        current->uid  = uid;
        current->suid = uid;
    } else if (uid != current->uid && uid != current->suid) {
        ret = -EPERM;
        goto out;
    }
    current->euid = uid;
    ret = 0;
out:
    unlock(&current->lock);
    return ret;
}

long libos_syscall_setgid(gid_t gid) {
    int ret;
    struct libos_thread* current = get_cur_thread();

    lock(&current->lock);
    if (current->uid == 0) {
        /* if the user is root, the real GID and saved set-group-ID are also set */
        current->gid  = gid;
        current->sgid = gid;
    } else if (gid != current->gid && gid != current->sgid) {
        ret = -EPERM;
        goto out;
    }
    current->egid = gid;
    ret = 0;
out:
    unlock(&current->lock);
    return ret;
}

#define NGROUPS_MAX 65536 /* # of supplemental group IDs; has to be same as host OS */

long libos_syscall_setgroups(int gidsetsize, gid_t* grouplist) {
    if (gidsetsize < 0 || (unsigned int)gidsetsize > NGROUPS_MAX)
        return -EINVAL;

    struct libos_thread* current = get_cur_thread();
    if (gidsetsize == 0) {
        free(current->groups_info.groups);
        current->groups_info.groups = NULL;
        current->groups_info.count = 0;
        return 0;
    }

    if (!is_user_memory_readable(grouplist, gidsetsize * sizeof(gid_t)))
        return -EFAULT;

    size_t groups_len = (size_t)gidsetsize;
    gid_t* groups = (gid_t*)malloc(groups_len * sizeof(*groups));
    if (!groups) {
        return -ENOMEM;
    }
    for (size_t i = 0; i < groups_len; i++) {
        groups[i] = grouplist[i];
    }

    void* old_groups = NULL;
    current->groups_info.count = groups_len;
    old_groups = current->groups_info.groups;
    current->groups_info.groups = groups;

    free(old_groups);

    return 0;
}

long libos_syscall_getgroups(int gidsetsize, gid_t* grouplist) {
    if (gidsetsize < 0)
        return -EINVAL;

    if (!is_user_memory_writable(grouplist, gidsetsize * sizeof(gid_t)))
        return -EFAULT;

    struct libos_thread* current = get_cur_thread();
    size_t ret_size = current->groups_info.count;

    if (gidsetsize) {
        if (ret_size > (size_t)gidsetsize) {
            return -EINVAL;
        }

        for (size_t i = 0; i < ret_size; i++) {
            grouplist[i] = current->groups_info.groups[i];
        }
    }

    return (int)ret_size;
}
