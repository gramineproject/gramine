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

static int tmpfs_create_hardlink_file(struct libos_dentry* link_dent, const char* targetpath) {
    assert(locked(&g_dcache_lock));

    if (link_dent->inode != NULL)
        return -EEXIST;

    struct libos_dentry* target_dent = NULL;
    int ret = path_lookupat(NULL, targetpath, LOOKUP_NO_FOLLOW, &target_dent);
    if (ret < 0)
        return ret;
    assert(target_dent != NULL);
    assert(target_dent->inode != NULL);
    if (S_ISDIR(target_dent->inode->type))
        return -EPERM; /* no hardlinks to dirs */
    if (target_dent->mount != link_dent->mount)
        return -EXDEV; /* must be on the same mounted filesystem */

    struct libos_inode *inode = target_dent->inode;
    lock(&inode->lock);

    link_dent->inode = target_dent->inode;
    get_inode(link_dent->inode);

    unlock(&inode->lock);

    return 0;
}

static int tmpfs_create_symlink_file(struct libos_dentry* link_dent, const char* targetpath) {
    assert(locked(&g_dcache_lock));

    if (link_dent->inode != NULL)
        return -EEXIST;

    uint64_t time_us;
    if (PalSystemTimeQuery(&time_us) < 0)
        return -EPERM;

    mode_t perm = 0744;
    if ((link_dent->parent != NULL) && (link_dent->parent->inode != NULL))
        perm = link_dent->parent->inode->perm;
    int ret = tmpfs_setup_dentry(link_dent, S_IFLNK, perm);
    if (ret < 0)
        return ret;
    assert(link_dent->inode != NULL);

    struct libos_inode* inode = link_dent->inode;
    file_off_t pos = 0ULL;
    size_t target_sz = strlen(targetpath);

    lock(&inode->lock);
    bool do_unlock = true;

    struct libos_mem_file* mem = inode->data;
    assert(mem != NULL);
    ssize_t out_count = mem_file_write(mem, pos, targetpath, target_sz);
    if (out_count < 0) {
        ret = out_count;
        goto out;
    }
    assert(target_sz == (size_t)out_count);

    inode->size = mem->size;
    inode->mtime = time_us / USEC_IN_SEC;

out:
    if (do_unlock)
        unlock(&inode->lock);

    return ret;
}

static int tmpfs_follow_symlink(struct libos_dentry* link_dent, char** out_target) {
    assert(locked(&g_dcache_lock));

    if (link_dent->inode == NULL)
        return -ENOENT;
    struct libos_inode* inode = link_dent->inode;

    if (inode->size > PATH_MAX)
        return -EPERM;

    char* targetpath = malloc(inode->size + 1);
    if (targetpath == NULL)
        return -ENOMEM;

    struct libos_mem_file* mem = inode->data;
    assert(inode->size == mem->size);
    size_t sz = inode->size;
    file_off_t pos = 0ULL;
    int ret = mem_file_read(mem, pos, targetpath, sz);
    if (ret < 0) {
        free(targetpath);
        return ret;
    }
    *(targetpath + sz) = '\x00';

    *out_target = targetpath;
    return ret;
}

static int tmpfs_set_link(struct libos_dentry* link_dent, const char* targetpath,
                          bool is_soft_link) {
    assert(locked(&g_dcache_lock));

    int ret;
    if (is_soft_link)
        ret = tmpfs_create_symlink_file(link_dent, targetpath);
    else
        ret = tmpfs_create_hardlink_file(link_dent, targetpath);
    if (ret < 0)
        goto out;
    ret = 0;

out:
    return ret;
}

static int tmpfs_follow_link(struct libos_dentry* link_dent, char** out_target) {
    assert(locked(&g_dcache_lock));

    return tmpfs_follow_symlink(link_dent, out_target);
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
    .set_link    = &tmpfs_set_link,
    .follow_link = &tmpfs_follow_link,
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
