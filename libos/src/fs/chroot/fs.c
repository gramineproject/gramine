/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file contains code for implementation of 'chroot' filesystem.
 *
 * TODO: reintroduce the file position sync (using libos_fs_sync.h) after the migration to inodes is
 * finished.
 */

#include "libos_flags_conv.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_utils.h"
#include "libos_vma.h"
#include "linux_abi/errors.h"
#include "linux_abi/fs.h"
#include "linux_abi/memory.h"
#include "pal.h"
#include "perm.h"
#include "stat.h"

/*
 * Always add a read permission to files created on host, because PAL requires opening the file even
 * for operations such as `unlink` or `chmod`.
 *
 * The updated file permissions will not be visible to the process creating the file or updating its
 * permissions, e.g. if a process creates a write-only file, Gramine's `stat` will still report it
 * as write-only. However, other Gramine processes accessing that file afterwards will see the
 * updated permissions.
 */
#define HOST_PERM(perm) ((perm) | PERM_r________)

static int chroot_mount(struct libos_mount_params* params, void** mount_data) {
    __UNUSED(mount_data);
    if (!params->uri || (!strstartswith(params->uri, URI_PREFIX_FILE) &&
                         !strstartswith(params->uri, URI_PREFIX_DEV)))
        return -EINVAL;
    return 0;
}

static const char* strip_prefix(const char* uri) {
    const char* s = strchr(uri, ':');
    assert(s);
    return s + 1;
}

int chroot_dentry_uri(struct libos_dentry* dent, mode_t type, char** out_uri) {
    assert(dent->mount);
    assert(dent->mount->uri);

    int ret;

    const char* root = strip_prefix(dent->mount->uri);

    const char* prefix;
    size_t prefix_len;
    switch (type) {
        case S_IFREG:
            prefix = URI_PREFIX_FILE;
            prefix_len = static_strlen(URI_PREFIX_FILE);
            break;
        case S_IFDIR:
            prefix = URI_PREFIX_DIR;
            prefix_len = static_strlen(URI_PREFIX_DIR);
            break;
        case S_IFCHR:
            prefix = URI_PREFIX_DEV;
            prefix_len = static_strlen(URI_PREFIX_DEV);
            break;
        default:
            BUG();
    }

    char* rel_path;
    size_t rel_path_size;
    ret = dentry_rel_path(dent, &rel_path, &rel_path_size);
    if (ret < 0)
        return ret;

    /* Treat empty path as "." */
    if (*root == '\0')
        root = ".";

    size_t root_len = strlen(root);

    /* Allocate buffer for "<prefix:><root>/<rel_path>" (if `rel_path` is empty, we don't need the
     * space for `/`, but overallocating 1 byte doesn't hurt us, and keeps the code simple) */
    char* uri = malloc(prefix_len + root_len + 1 + rel_path_size);
    if (!uri) {
        ret = -ENOMEM;
        goto out;
    }
    memcpy(uri, prefix, prefix_len);
    memcpy(uri + prefix_len, root, root_len);
    if (rel_path_size == 1) {
        /* this is the mount root, the URI is "<prefix:><root>"*/
        uri[prefix_len + root_len] = '\0';
    } else {
        /* this is not the mount root, the URI is "<prefix:><root>/<rel_path>" */
        uri[prefix_len + root_len] = '/';
        memcpy(uri + prefix_len + root_len + 1, rel_path, rel_path_size);
    }
    *out_uri = uri;
    ret = 0;

out:
    free(rel_path);
    return ret;
}

static int chroot_setup_dentry(struct libos_dentry* dent, mode_t type, mode_t perm,
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

static int chroot_lookup(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));

    int ret;

    /*
     * We don't know the file type yet, so we can't construct a PAL URI with the right prefix. In
     * most cases, a "file:" prefix is good enough: `PalStreamAttributesQuery` will access the file
     * and report the right file type.
     */
    char* uri = NULL;
    ret = chroot_dentry_uri(dent, S_IFREG, &uri);
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
        case PAL_TYPE_FILE:
            type = S_IFREG;
            break;
        case PAL_TYPE_DIR:
            type = S_IFDIR;
            break;
        case PAL_TYPE_DEV:
            type = S_IFCHR;
            break;
        case PAL_TYPE_PIPE:
            log_warning("trying to access '%s' which is a host-level FIFO (named pipe); "
                        "Gramine supports only named pipes created by Gramine processes",
                        uri);
            ret = -EACCES;
            goto out;
        default:
            log_error("unexpected handle type returned by PAL: %d", pal_attr.handle_type);
            BUG();
    }

    mode_t perm = pal_attr.share_flags;

    file_off_t size = (type == S_IFREG ? pal_attr.pending_size : 0);

    ret = chroot_setup_dentry(dent, type, perm, size);
out:
    free(uri);
    return ret;
}

/* Open a temporary read-only PAL handle for a file (used by `unlink` etc.) */
static int chroot_temp_open(struct libos_dentry* dent, mode_t type, PAL_HANDLE* out_palhdl) {
    char* uri;
    int ret = chroot_dentry_uri(dent, type, &uri);
    if (ret < 0)
        return ret;

    ret = PalStreamOpen(uri, PAL_ACCESS_RDONLY, /*share_flags=*/0, PAL_CREATE_NEVER,
                        /*options=*/0, out_palhdl);
    free(uri);
    return pal_to_unix_errno(ret);
}

/* Open a PAL handle, and associate it with a LibOS handle (if provided). */
static int chroot_do_open(struct libos_handle* hdl, struct libos_dentry* dent, mode_t type,
                          int flags, mode_t perm) {
    assert(locked(&g_dcache_lock));

    int ret;

    char* uri;
    ret = chroot_dentry_uri(dent, type, &uri);
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

    if (hdl) {
        hdl->uri = uri;
        uri = NULL;

        hdl->type = TYPE_CHROOT;
        hdl->pos = 0;
        hdl->pal_handle = palhdl;
    } else {
        PalObjectDestroy(palhdl);
    }
    ret = 0;

out:
    free(uri);
    return ret;
}

static int chroot_open(struct libos_handle* hdl, struct libos_dentry* dent, int flags) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    return chroot_do_open(hdl, dent, dent->inode->type, flags, /*perm=*/0);
}

static int chroot_creat(struct libos_handle* hdl, struct libos_dentry* dent, int flags, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    int ret;

    mode_t type = S_IFREG;

    ret = chroot_do_open(hdl, dent, type, flags | O_CREAT | O_EXCL, perm);
    if (ret < 0)
        return ret;

    return chroot_setup_dentry(dent, type, perm, /*size=*/0);
}

static int chroot_mkdir(struct libos_dentry* dent, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    int ret;

    mode_t type = S_IFDIR;

    ret = chroot_do_open(/*hdl=*/NULL, dent, type, O_CREAT | O_EXCL, perm);
    if (ret < 0)
        return ret;

    return chroot_setup_dentry(dent, type, perm, /*size=*/0);
}

static int chroot_flush(struct libos_handle* hdl) {
    assert(hdl->type == TYPE_CHROOT);

    int ret = PalStreamFlush(hdl->pal_handle);
    return pal_to_unix_errno(ret);
}

static ssize_t chroot_read(struct libos_handle* hdl, void* buf, size_t count, file_off_t* pos) {
    assert(hdl->type == TYPE_CHROOT);

    size_t actual_count = count;
    int ret = PalStreamRead(hdl->pal_handle, *pos, &actual_count, buf);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(actual_count <= count);
    if (hdl->inode->type == S_IFREG) {
        *pos += actual_count;
    }
    return actual_count;
}

static ssize_t chroot_write(struct libos_handle* hdl, const void* buf, size_t count,
                            file_off_t* pos) {
    assert(hdl->type == TYPE_CHROOT);

    size_t actual_count = count;
    int ret = PalStreamWrite(hdl->pal_handle, *pos, &actual_count, (void*)buf);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    assert(actual_count <= count);
    if (hdl->inode->type == S_IFREG) {
        *pos += actual_count;
        /* Update file size if we just wrote past the end of file */
        lock(&hdl->inode->lock);
        if (hdl->inode->size < *pos)
            hdl->inode->size = *pos;
        unlock(&hdl->inode->lock);
    }

    /* If there are any MAP_SHARED mappings for the file, this will read data from `hdl`. */
    if (__atomic_load_n(&hdl->inode->num_mmapped, __ATOMIC_ACQUIRE) != 0) {
        ret = reload_mmaped_from_file_handle(hdl);
        if (ret < 0) {
            log_error("reload mmapped regions of file failed: %s", unix_strerror(ret));
            BUG();
        }
    }

    return (ssize_t)actual_count;
}

static int chroot_mmap(struct libos_handle* hdl, void* addr, size_t size, int prot, int flags,
                       uint64_t offset) {
    assert(hdl->type == TYPE_CHROOT);
    assert(addr);

    pal_prot_flags_t pal_prot = LINUX_PROT_TO_PAL(prot, flags);

    if (flags & MAP_ANONYMOUS)
        return -EINVAL;

    int ret = PalStreamMap(hdl->pal_handle, addr, pal_prot, offset, size);
    if (ret < 0)
        return pal_to_unix_errno(ret);

    return 0;
}

int chroot_readdir(struct libos_dentry* dent, readdir_callback_t callback, void* arg) {
    int ret;
    PAL_HANDLE palhdl;
    char* buf = NULL;
    size_t buf_size = READDIR_BUF_SIZE;

    ret = chroot_temp_open(dent, S_IFDIR, &palhdl);
    if (ret < 0)
        return ret;

    buf = malloc(buf_size);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    while (true) {
        size_t read_size = buf_size;
        ret = PalStreamRead(palhdl, /*offset=*/0, &read_size, buf);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }
        if (read_size == 0) {
            /* End of directory listing */
            break;
        }

        /* Last entry must be null-terminated */
        assert(buf[read_size - 1] == '\0');

        /* Read all entries (separated by null bytes) and invoke `callback` on each */
        size_t start = 0;
        while (start < read_size - 1) {
            size_t end = start + strlen(&buf[start]);

            if (end == start) {
                log_error("chroot_readdir: empty name returned from PAL");
                BUG();
            }

            /* By the PAL convention, if a name ends with '/', it is a directory. However, we ignore
             * that distinction here and pass the name without '/' to the callback. */
            if (buf[end - 1] == '/')
                buf[end - 1] = '\0';

            if ((ret = callback(&buf[start], arg)) < 0)
                goto out;

            start = end + 1;
        }
    }
    ret = 0;

out:
    free(buf);
    PalObjectDestroy(palhdl);
    return ret;
}

int chroot_unlink(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    int ret;

    PAL_HANDLE palhdl;
    ret = chroot_temp_open(dent, dent->inode->type, &palhdl);
    if (ret < 0)
        return ret;

    ret = PalStreamDelete(palhdl, PAL_DELETE_ALL);
    PalObjectDestroy(palhdl);
    if (ret < 0)
        return pal_to_unix_errno(ret);

    return 0;
}

static int chroot_rename(struct libos_dentry* old, struct libos_dentry* new) {
    assert(locked(&g_dcache_lock));
    assert(old->inode);

    int ret;
    char* new_uri = NULL;

    ret = chroot_dentry_uri(new, old->inode->type, &new_uri);
    if (ret < 0)
        goto out;

    PAL_HANDLE palhdl;
    ret = chroot_temp_open(old, old->inode->type, &palhdl);
    if (ret < 0)
        goto out;

    ret = PalStreamChangeName(palhdl, new_uri);
    PalObjectDestroy(palhdl);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }
    ret = 0;

out:
    free(new_uri);
    return ret;
}

static int chroot_chmod(struct libos_dentry* dent, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    int ret;

    PAL_HANDLE palhdl;
    ret = chroot_temp_open(dent, dent->inode->type, &palhdl);
    if (ret < 0)
        return ret;

    mode_t host_perm = HOST_PERM(perm);
    PAL_STREAM_ATTR attr = {.share_flags = host_perm};
    ret = PalStreamAttributesSetByHandle(palhdl, &attr);
    PalObjectDestroy(palhdl);
    if (ret < 0)
        return pal_to_unix_errno(ret);

    return 0;
}

static int chroot_fchmod(struct libos_handle* hdl, mode_t perm) {
    int ret;

    mode_t host_perm = HOST_PERM(perm);
    PAL_STREAM_ATTR attr = {.share_flags = host_perm};
    ret = PalStreamAttributesSetByHandle(hdl->pal_handle, &attr);
    if (ret < 0)
        return pal_to_unix_errno(ret);

    return 0;
}

struct libos_fs_ops chroot_fs_ops = {
    .mount      = &chroot_mount,
    .flush      = &chroot_flush,
    .read       = &chroot_read,
    .write      = &chroot_write,
    .mmap       = &chroot_mmap,
    /* TODO: this function emulates lseek() completely inside the LibOS, but some device files may
     * report size == 0 during fstat() and may provide device-specific lseek() logic; this emulation
     * breaks for such device-specific cases */
    .seek       = &generic_inode_seek,
    .hstat      = &generic_inode_hstat,
    .truncate   = &generic_truncate,
    .poll       = &generic_inode_poll,
    .fchmod     = &chroot_fchmod,
};

struct libos_d_ops chroot_d_ops = {
    .open    = &chroot_open,
    .lookup  = &chroot_lookup,
    .creat   = &chroot_creat,
    .mkdir   = &chroot_mkdir,
    .stat    = &generic_inode_stat,
    .readdir = &chroot_readdir,
    .unlink  = &chroot_unlink,
    .rename  = &chroot_rename,
    .chmod   = &chroot_chmod,
};

struct libos_fs chroot_builtin_fs = {
    .name   = "chroot",
    .fs_ops = &chroot_fs_ops,
    .d_ops  = &chroot_d_ops,
};
