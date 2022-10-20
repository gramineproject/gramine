/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Li Xun <xun.li@intel.com>
 */

/*
 * This file contains code for implementation of 'shm' filesystem.
 * If mounted in manifest, files of this type are shared with the host OS when mapped.
 */

#include "libos_flags_conv.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_lock.h"
#include "linux_abi/errors.h"
#include "perm.h"
#include "stat.h"

#define HOST_PERM(perm) ((perm) | PERM_r________)

static int shm_mount(struct libos_mount_params* params, void** mount_data) {
    __UNUSED(mount_data);

    if (!params->uri) {
        log_error("Missing shared memory URI");
        return -EINVAL;
    }
    if (!strstartswith(params->uri, URI_PREFIX_DEV)) {
        log_error("'%s' is invalid shared memory URI (expected prefix %s)", params->uri,
                  URI_PREFIX_DEV);
        return -EINVAL;
    }

    return 0;
}

static int shm_mmap(struct libos_handle* hdl, void* addr, size_t size, int prot, int flags,
                    uint64_t offset) {
    assert(hdl->type == TYPE_SHM);
    assert(addr);

    pal_prot_flags_t pal_prot = LINUX_PROT_TO_PAL(prot, flags);

    if (flags & MAP_ANONYMOUS)
        return -EINVAL;

    int ret = PalStreamMap(hdl->pal_handle, addr, pal_prot, offset, size);
    if (ret < 0)
        return pal_to_unix_errno(ret);

    return 0;
}

/* Open a PAL handle, and associate it with a LibOS handle. */
static int shm_do_open(struct libos_handle* hdl, struct libos_dentry* dent, mode_t type,
                       int flags, mode_t perm) {
    assert(locked(&g_dcache_lock));

    char* uri;
    int ret = chroot_dentry_uri(dent, type, &uri);
    if (ret < 0)
        return ret;

    PAL_HANDLE palhdl;
    enum pal_access access = LINUX_OPEN_FLAGS_TO_PAL_ACCESS(flags);
    enum pal_create_mode create = LINUX_OPEN_FLAGS_TO_PAL_CREATE(flags);
    pal_stream_options_t options = LINUX_OPEN_FLAGS_TO_PAL_OPTIONS(flags);
    mode_t host_perm = HOST_PERM(perm);
    ret = PalStreamOpen(uri, access, host_perm, create, options, &palhdl);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    hdl->uri = uri;
    uri = NULL;

    hdl->type = TYPE_SHM;
    hdl->pal_handle = palhdl;
    ret = 0;

out:
    free(uri);
    return ret;
}

static int shm_setup_dentry(struct libos_dentry* dent, mode_t type, mode_t perm,
                            file_off_t size) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    struct libos_inode* inode = get_new_inode(dent->mount, type, perm);
    if (!inode)
        return -ENOMEM;
    inode->size = size;
    dent->inode = inode;
    return 0;
}

static int shm_lookup(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));

    char* uri = NULL;
    /*
     * We don't know the file type yet, so we can't construct a PAL URI with the right prefix.
     * However, "file:" prefix is good enough here: `PalStreamAttributesQuery` will access the file
     * and report the right file type.
     */
    int ret = chroot_dentry_uri(dent, S_IFREG, &uri);
    if (ret < 0)
        goto out;

    PAL_STREAM_ATTR pal_attr;
    ret = PalStreamAttributesQuery(uri, &pal_attr);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    mode_t type;
    switch (pal_attr.handle_type) {
        case PAL_TYPE_FILE: /* Regular files in shm file system are device files. */
        case PAL_TYPE_DEV:
            type = S_IFCHR;
            break;
        case PAL_TYPE_DIR:
            /* Subdirectories (e.g. /dev/shm/subdir/) are not allowed in shm file system. */
            if (dent != dent->mount->root) {
                log_warning("trying to access '%s' which is a subdirectory of shared memory mount",
                            uri);
                ret = -EACCES;
                goto out;
            }
            type = S_IFDIR;
            break;
        default:
            log_error("unexpected handle type returned by PAL: %d", pal_attr.handle_type);
            BUG();
    }

    file_off_t size = (type == S_IFCHR ? pal_attr.pending_size : 0);

    ret = shm_setup_dentry(dent, type, pal_attr.share_flags, size);
out:
    free(uri);
    return ret;
}

static int shm_open(struct libos_handle* hdl, struct libos_dentry* dent, int flags) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    return shm_do_open(hdl, dent, dent->inode->type, flags, /*perm=*/0);
}

static int shm_creat(struct libos_handle* hdl, struct libos_dentry* dent, int flags, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    mode_t type = S_IFCHR;
    int ret = shm_do_open(hdl, dent, type, flags | O_CREAT | O_EXCL, perm);
    if (ret < 0)
        return ret;

    return shm_setup_dentry(dent, type, perm, /*size=*/0);
}

struct libos_fs_ops shm_fs_ops = {
    .mount      = shm_mount,
    /* .read and .write are intentionally not supported according to POSIX shared memory API. */
    .mmap       = shm_mmap,
    .hstat      = generic_inode_hstat,
    .truncate   = generic_truncate,
};

struct libos_d_ops shm_d_ops = {
    .open    = shm_open,
    .lookup  = shm_lookup,
    .creat   = shm_creat,
    .stat    = generic_inode_stat,
    .unlink  = chroot_unlink,
};

struct libos_fs shm_builtin_fs = {
    .name   = "untrusted_shm",
    .fs_ops = &shm_fs_ops,
    .d_ops  = &shm_d_ops,
};
