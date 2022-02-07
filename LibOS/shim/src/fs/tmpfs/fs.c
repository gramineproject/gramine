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
 * the `data` field of the inode (as a pointer to `struct shim_mem_file`).
 */

#include <asm/mman.h>
#include <asm/unistd.h>
#include <errno.h>

#include "perm.h"
#include "shim_flags_conv.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_utils.h"
#include "stat.h"

#define USEC_IN_SEC 1000000

static int tmpfs_setup_dentry(struct shim_dentry* dent, mode_t type, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    dent->type = type;
    dent->perm = perm;

    struct shim_inode* inode = get_new_inode(dent->mount, type, perm);
    if (!inode)
        return -ENOMEM;

    struct shim_mem_file* mem = malloc(sizeof(*mem));
    if (!mem) {
        put_inode(inode);
        return -ENOMEM;
    }
    mem_file_init(mem, /*data=*/NULL, /*size=*/0);
    inode->data = mem;

    uint64_t time_us;
    if (DkSystemTimeQuery(&time_us) < 0) {
        put_inode(inode);
        return -EPERM;
    }

    inode->ctime = time_us / USEC_IN_SEC;
    inode->mtime = inode->ctime;
    inode->atime = inode->ctime;

    dent->inode = inode;
    return 0;
}

static void tmpfs_idrop(struct shim_inode* inode) {
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

static int tmpfs_icheckpoint(struct shim_inode* inode, void** out_data, size_t* out_size) {
    assert(locked(&inode->lock));

    struct shim_mem_file* mem = inode->data;
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

static int tmpfs_irestore(struct shim_inode* inode, void* data) {
    struct tmpfs_checkpoint* cp = data;

    struct shim_mem_file* mem = malloc(sizeof(*mem));
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

static int tmpfs_mount(const char* uri, void** mount_data) {
    __UNUSED(uri);
    __UNUSED(mount_data);
    return 0;
}

static int tmpfs_flush(struct shim_handle* hdl) {
    __UNUSED(hdl);
    return 0;
}

static int tmpfs_lookup(struct shim_dentry* dent) {
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

static void tmpfs_do_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);
    __UNUSED(flags);

    hdl->type = TYPE_TMPFS;
    hdl->pos = 0;
    hdl->inode = dent->inode;
    get_inode(dent->inode);
}

static int tmpfs_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    tmpfs_do_open(hdl, dent, flags);
    return 0;
}

static int tmpfs_creat(struct shim_handle* hdl, struct shim_dentry* dent, int flags, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    mode_t type = S_IFREG;
    int ret = tmpfs_setup_dentry(dent, type, perm);
    if (ret < 0)
        return ret;

    tmpfs_do_open(hdl, dent, flags);
    return 0;
}

static int tmpfs_mkdir(struct shim_dentry* dent, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    mode_t type = S_IFREG;
    return tmpfs_setup_dentry(dent, type, perm);
}

static int tmpfs_unlink(struct shim_dentry* dent) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    if (dent->type == S_IFDIR) {
        struct shim_dentry* child;
        bool found = false;
        LISTP_FOR_EACH_ENTRY(child, &dent->children, siblings) {
            if ((child->state & DENTRY_VALID) && !(child->state & DENTRY_NEGATIVE)) {
                found = true;
                break;
            }
        }
        if (found)
            return -ENOTEMPTY;
    }

    struct shim_inode* inode = dent->inode;
    dent->inode = NULL;
    put_inode(inode);
    return 0;
}

static int tmpfs_rename(struct shim_dentry* old, struct shim_dentry* new) {
    assert(locked(&g_dcache_lock));
    assert(old->inode);

    uint64_t time_us;
    if (DkSystemTimeQuery(&time_us) < 0)
        return -EPERM;

    /* TODO: this should be done in the syscall handler, not here */

    struct shim_inode* new_inode = new->inode;
    if (new_inode) {
        new->inode = NULL;
        put_inode(new_inode);
    }

    struct shim_inode* old_inode = old->inode;

    lock(&old_inode->lock);

    /* No need to adjust refcount of `old->inode`: we add a reference from `new` and remove the one
     * from `old`. */
    new->inode = old_inode;
    new->type = old->type;
    new->perm = old->perm;

    old->inode = NULL;

    old_inode->ctime = time_us / USEC_IN_SEC;

    unlock(&old_inode->lock);

    return 0;
}

static int tmpfs_chmod(struct shim_dentry* dent, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    lock(&dent->inode->lock);

    /* `dent->perm` already updated by caller */
    dent->inode->perm = perm;

    unlock(&dent->inode->lock);
    return 0;
}

static ssize_t tmpfs_read(struct shim_handle* hdl, void* buf, size_t size) {
    ssize_t ret;

    assert(hdl->type == TYPE_TMPFS);

    struct shim_inode* inode = hdl->inode;

    lock(&inode->lock);
    lock(&hdl->lock);

    struct shim_mem_file* mem = inode->data;

    ret = mem_file_read(mem, hdl->pos, buf, size);
    if (ret < 0)
        goto out;

    hdl->pos += ret;

    /* technically, we should update access time here, but we skip this because it could hurt
     * performance on Linux-SGX host */

    /* keep `ret` */

out:
    unlock(&hdl->lock);
    unlock(&inode->lock);
    return ret;
}

static ssize_t tmpfs_write(struct shim_handle* hdl, const void* buf, size_t size) {
    ssize_t ret;

    assert(hdl->type == TYPE_TMPFS);

    uint64_t time_us;
    if (DkSystemTimeQuery(&time_us) < 0)
        return -EPERM;

    struct shim_inode* inode = hdl->inode;

    lock(&inode->lock);
    lock(&hdl->lock);
    struct shim_mem_file* mem = inode->data;

    ret = mem_file_write(mem, hdl->pos, buf, size);
    if (ret < 0)
        goto out;

    inode->size = mem->size;

    hdl->pos += ret;
    inode->mtime = time_us / USEC_IN_SEC;
    /* keep `ret` */

out:
    unlock(&hdl->lock);
    unlock(&inode->lock);
    return ret;
}

static int tmpfs_truncate(struct shim_handle* hdl, file_off_t size) {
    int ret;

    uint64_t time_us;
    if (DkSystemTimeQuery(&time_us) < 0)
        return -EPERM;

    lock(&hdl->inode->lock);
    struct shim_mem_file* mem = hdl->inode->data;

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

/* TODO: tmpfs_mmap() function is not implemented because shim_do_mmap() and shim_do_munmap()
   are currently not flexible enough for correct tmpfs implementation. In particular, shim_do_mmap()
   pre-allocates memory region at a specific address (making it impossible to have two mmaps on the
   same tmpfs file), and shim_do_munmap() doesn't have a callback into tmpfs at all. */
static int tmpfs_mmap(struct shim_handle* hdl, void** addr, size_t size, int prot, int flags,
                      uint64_t offset) {
    __UNUSED(hdl);
    __UNUSED(addr);
    __UNUSED(size);
    __UNUSED(prot);
    __UNUSED(flags);
    __UNUSED(offset);

    log_error("tmpfs_mmap(): mmap() function for tmpfs mount type is not implemented.");
    return -ENOSYS;
}

struct shim_fs_ops tmp_fs_ops = {
    .mount    = &tmpfs_mount,
    .flush    = &tmpfs_flush,
    .read     = &tmpfs_read,
    .write    = &tmpfs_write,
    .mmap     = &tmpfs_mmap,
    .seek     = &generic_inode_seek,
    .hstat    = &generic_inode_hstat,
    .truncate = &tmpfs_truncate,
    .poll     = &generic_inode_poll,
};

struct shim_d_ops tmp_d_ops = {
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

struct shim_fs tmp_builtin_fs = {
    .name   = "tmpfs",
    .fs_ops = &tmp_fs_ops,
    .d_ops  = &tmp_d_ops,
};
