/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Li Xun <xun.li@intel.com>
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file contains code for implementation of 'tmpfs' filesystem. The tmpfs files are *not*
 * cloned during fork/clone (except for files currently open) and cannot be synchronized between
 * processes.
 *
 * The tmpfs files are directly represented by their dentries and inodes (i.e. a file exists
 * whenever corresponding dentry exists, and is associated with inode). The file data is stored in
 * the `data` field of the inode (as a pointer to `struct libos_mem_file`).
 */

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_lock.h"
#include "libos_vma.h"
#include "linux_abi/errors.h"
#include "perm.h"
#include "stat.h"

#define USEC_IN_SEC 1000000

static int tmpfs_setup_dentry(struct libos_dentry* dent, mode_t type, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    struct libos_inode* inode = get_new_inode(dent->mount, type, perm);
    if (!inode)
        return -ENOMEM;

    struct libos_mem_file* mem = malloc(sizeof(*mem));
    if (!mem) {
        put_inode(inode);
        return -ENOMEM;
    }
    mem_file_init(mem, /*data=*/NULL, /*size=*/0);
    inode->data = mem;

    uint64_t time_us;
    if (PalSystemTimeQuery(&time_us) < 0) {
        put_inode(inode);
        return -EPERM;
    }

    inode->ctime = time_us / USEC_IN_SEC;
    inode->mtime = inode->ctime;
    inode->atime = inode->ctime;

    dent->inode = inode;
    return 0;
}

static void tmpfs_idrop(struct libos_inode* inode) {
    assert(locked(&inode->lock));

    if (inode->data) {
        mem_file_destroy(inode->data);
        free(inode->data);
    }
}

struct tmpfs_checkpoint {
    size_t size;
    char data[];
};

static int tmpfs_icheckpoint(struct libos_inode* inode, void** out_data, size_t* out_size) {
    assert(locked(&inode->lock));

    struct libos_mem_file* mem = inode->data;
    assert(mem->size >= 0);

    struct tmpfs_checkpoint* cp;
    size_t cp_size = sizeof(*cp) + mem->size;
    cp = malloc(cp_size);
    if (!cp)
        return -ENOMEM;
    cp->size = mem->size;
    memcpy(cp->data, mem->buf, mem->size);

    *out_data = cp;
    *out_size = cp_size;
    return 0;
}

static int tmpfs_irestore(struct libos_inode* inode, void* data) {
    struct tmpfs_checkpoint* cp = data;

    struct libos_mem_file* mem = malloc(sizeof(*mem));
    if (!mem)
        return -ENOMEM;
    mem->buf = malloc(cp->size);
    if (!mem->buf) {
        free(mem);
        return -ENOMEM;
    }
    memcpy(mem->buf, cp->data, cp->size);
    mem->size = cp->size;
    mem->buf_size = cp->size;

    inode->data = mem;
    return 0;
}

static int tmpfs_mount(struct libos_mount_params* params, void** mount_data) {
    __UNUSED(params);
    __UNUSED(mount_data);
    return 0;
}

static int tmpfs_flush(struct libos_handle* hdl) {
    return msync_handle(hdl);
}

static int tmpfs_lookup(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    if (!dent->parent) {
        /* This is the root dentry, initialize it. */
        return tmpfs_setup_dentry(dent, S_IFDIR, PERM_rwx______);
    }
    /* Looking up for other dentries should fail: if a dentry has not been already created by
     * `creat` or `mkdir`, the corresponding file does not exist. */
    return -ENOENT;
}

static void tmpfs_do_open(struct libos_handle* hdl, struct libos_dentry* dent, int flags) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);
    __UNUSED(dent);
    __UNUSED(flags);

    hdl->type = TYPE_TMPFS;
    hdl->pos = 0;
}

static int tmpfs_open(struct libos_handle* hdl, struct libos_dentry* dent, int flags) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    tmpfs_do_open(hdl, dent, flags);
    return 0;
}

static int tmpfs_creat(struct libos_handle* hdl, struct libos_dentry* dent, int flags,
                       mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    int ret = tmpfs_setup_dentry(dent, S_IFREG, perm);
    if (ret < 0)
        return ret;

    tmpfs_do_open(hdl, dent, flags);
    return 0;
}

static int tmpfs_mkdir(struct libos_dentry* dent, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    return tmpfs_setup_dentry(dent, S_IFDIR, perm);
}

static int tmpfs_unlink(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    if (dent->inode->type == S_IFDIR) {
        struct libos_dentry* child;
        bool found = false;
        LISTP_FOR_EACH_ENTRY(child, &dent->children, siblings) {
            if (child->inode) {
                found = true;
                break;
            }
        }
        if (found)
            return -ENOTEMPTY;
    }
    return 0;
}

static int tmpfs_rename(struct libos_dentry* old, struct libos_dentry* new) {
    assert(locked(&g_dcache_lock));
    assert(old->inode);
    __UNUSED(new);

    uint64_t time_us;
    if (PalSystemTimeQuery(&time_us) < 0)
        return -EPERM;

    /* TODO: this should be done in the syscall handler, not here */

    lock(&old->inode->lock);
    old->inode->ctime = time_us / USEC_IN_SEC;
    unlock(&old->inode->lock);

    return 0;
}

static int tmpfs_chmod(struct libos_dentry* dent, mode_t perm) {
    __UNUSED(dent);
    __UNUSED(perm);
    return 0;
}

static int tmpfs_fchmod(struct libos_handle* hdl, mode_t perm) {
    __UNUSED(hdl);
    __UNUSED(perm);
    return 0;
}

static ssize_t tmpfs_read(struct libos_handle* hdl, void* buf, size_t size, file_off_t* pos) {
    ssize_t ret;

    assert(hdl->type == TYPE_TMPFS);

    struct libos_inode* inode = hdl->inode;

    lock(&inode->lock);

    struct libos_mem_file* mem = inode->data;

    ret = mem_file_read(mem, *pos, buf, size);
    if (ret < 0)
        goto out;

    *pos += ret;

    /* technically, we should update access time here, but we skip this because it could hurt
     * performance on Linux-SGX host */

    /* keep `ret` */

out:
    unlock(&inode->lock);
    return ret;
}

static ssize_t tmpfs_write(struct libos_handle* hdl, const void* buf, size_t size,
                           file_off_t* pos) {
    ssize_t ret;

    assert(hdl->type == TYPE_TMPFS);

    uint64_t time_us;
    if (PalSystemTimeQuery(&time_us) < 0)
        return -EPERM;

    struct libos_inode* inode = hdl->inode;

    lock(&inode->lock);
    struct libos_mem_file* mem = inode->data;

    ret = mem_file_write(mem, *pos, buf, size);
    if (ret < 0) {
        unlock(&inode->lock);
        return ret;
    }

    inode->size = mem->size;

    *pos += ret;
    inode->mtime = time_us / USEC_IN_SEC;
    /* keep `ret` */

    unlock(&inode->lock);

    /* If there are any MAP_SHARED mappings for the file, this will read data from `hdl`. */
    if (__atomic_load_n(&hdl->inode->num_mmapped, __ATOMIC_ACQUIRE) != 0) {
        int reload_ret = reload_mmaped_from_file_handle(hdl);
        if (reload_ret < 0) {
            log_error("reload mmapped regions of file failed: %s", unix_strerror(reload_ret));
            BUG();
        }
    }

    return ret;
}

static int tmpfs_truncate(struct libos_handle* hdl, file_off_t size) {
    int ret;

    uint64_t time_us;
    if (PalSystemTimeQuery(&time_us) < 0)
        return -EPERM;

    lock(&hdl->inode->lock);
    struct libos_mem_file* mem = hdl->inode->data;

    ret = mem_file_truncate(mem, size);
    if (ret < 0)
        goto out;

    hdl->inode->mtime = time_us / USEC_IN_SEC;
    hdl->inode->size = size;
    ret = 0;

out:
    unlock(&hdl->inode->lock);
    return ret;
}

struct libos_fs_ops tmp_fs_ops = {
    .mount    = &tmpfs_mount,
    .flush    = &tmpfs_flush,
    .read     = &tmpfs_read,
    .write    = &tmpfs_write,
    .seek     = &generic_inode_seek,
    .hstat    = &generic_inode_hstat,
    .truncate = &tmpfs_truncate,
    .poll     = &generic_inode_poll,
    .mmap     = &generic_emulated_mmap,
    .msync    = &generic_emulated_msync,
    .fchmod   = &tmpfs_fchmod,
};

struct libos_d_ops tmp_d_ops = {
    .open        = &tmpfs_open,
    .lookup      = &tmpfs_lookup,
    .creat       = &tmpfs_creat,
    .mkdir       = &tmpfs_mkdir,
    .stat        = &generic_inode_stat,
    .readdir     = &generic_readdir,
    .unlink      = &tmpfs_unlink,
    .rename      = &tmpfs_rename,
    .chmod       = &tmpfs_chmod,
    .idrop       = &tmpfs_idrop,
    .icheckpoint = &tmpfs_icheckpoint,
    .irestore    = &tmpfs_irestore,
};

struct libos_fs tmp_builtin_fs = {
    .name   = "tmpfs",
    .fs_ops = &tmp_fs_ops,
    .d_ops  = &tmp_d_ops,
};
