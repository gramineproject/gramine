/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file contains code for implementation of 'chroot' filesystem.
 *
 * This filesystem works on `file:` files and `dev:` devices (pseudo-files) on the host. Files can
 * be trusted (measured, integrity-protected via hash) or allowed (passthrough, not protected).
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
#include "path_utils.h"
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

enum file_protection_kind {
    /*
     * Not in sgx.allowed_files nor in sgx.trusted_files. Files of this type can still be accessed
     * if sgx.file_check_policy == "allow_all_but_log".
     */
    FILE_PROTECTION_KIND_NONE = 0,

    /*
     * File path (or its prefix directory path) is in sgx.allowed_files. Files of this type can be
     * opened/created but have no protections.
     */
    FILE_PROTECTION_KIND_ALLOWED,

    /*
     * File path is in sgx.trusted_files. Files of this type can be opened read-only and have
     * integrity checks (based on SHA256 hashes).
     */
    FILE_PROTECTION_KIND_TRUSTED,
};

/* this data is set up only once (at inode creation or restore), so doesn't require locking */
struct chroot_inode_data {
    enum file_protection_kind prot_kind;

    /* used only if `prot_kind == FILE_PROTECTION_KIND_TRUSTED`: array of hashes over file chunks */
    struct trusted_chunk_hash* chunk_hashes;
};

static bool is_allowed_from_inode_data(struct libos_inode* inode) {
    assert(inode->data);
    return ((struct chroot_inode_data*)inode->data)->prot_kind == FILE_PROTECTION_KIND_ALLOWED;
}

static bool is_trusted_from_inode_data(struct libos_inode* inode) {
    assert(inode->data);
    return ((struct chroot_inode_data*)inode->data)->prot_kind == FILE_PROTECTION_KIND_TRUSTED;
}

static const char* strip_prefix(const char* uri) {
    const char* s = strchr(uri, ':');
    assert(s);
    return s + 1;
}

static int setup_inode_data_created_file(const char* uri, struct libos_inode* inode) {
    assert(inode->type == S_IFREG);

    struct chroot_inode_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    /* can be only allowed file or unknown file (allowed via file check policy),
     * guaranteed to not be a trusted file */
    data->prot_kind = get_allowed_file(strip_prefix(uri))
                      ? FILE_PROTECTION_KIND_ALLOWED
                      : FILE_PROTECTION_KIND_NONE;

    inode->data = data;
    return 0;
}

static int setup_inode_data_created_dir(struct libos_inode* inode) {
    assert(inode->type == S_IFDIR);

    struct chroot_inode_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    data->prot_kind = FILE_PROTECTION_KIND_ALLOWED; /* dirs are always allowed */
    inode->data = data;
    return 0;
}

static bool normalize_and_compare_path(const char* path, const char* compare_with) {
    size_t norm_path_size = strlen(path) + 1; /* overapproximate */
    char* norm_path = malloc(norm_path_size);
    if (!norm_path)
        return false;

    bool normalized = get_norm_path(path, norm_path, &norm_path_size);
    if (!normalized) {
        free(norm_path);
        return false;
    }

    bool result = strcmp(norm_path, compare_with) == 0;
    free(norm_path);
    return result;
}

static int setup_inode_data(mode_t type, const char* uri, size_t file_size,
                            struct libos_inode* inode) {
    struct chroot_inode_data* data = calloc(1, sizeof(*data));
    if (!data)
        return -ENOMEM;

    if (g_pal_public_state->extra_runtime_domain_names_conf &&
            normalize_and_compare_path(strip_prefix(uri), "/etc/resolv.conf")) {
        /*
         * Manifest option `sys.enable_extra_runtime_domain_names_conf` is set to true, implying
         * that LibOS will generate /etc/resolv.conf by itself, but LibOS still calls this function
         * as part of mount_fs("emulated-etc-resolv-conf"), see src/fs/etc/fs.c.
         *
         * This file may be listed as allowed or trusted file (e.g., because the user specified a
         * blanket `/etc/` dir in the manifest to cover all allowed/trusted files in a directory).
         * However, this particular file must be skipped from checks below, as it will be anyhow
         * generated by LibOS from scratch.
         */
        data->prot_kind = FILE_PROTECTION_KIND_NONE;
        inode->data = data;
        return 0;
    }

    if (type == S_IFDIR || get_allowed_file(strip_prefix(uri))) {
        data->prot_kind = FILE_PROTECTION_KIND_ALLOWED;
        inode->data = data;
        return 0;
    }

    struct trusted_file* tf = get_trusted_file(strip_prefix(uri));
    if (tf) {
        struct trusted_chunk_hash* out_chunk_hashes;
        int ret = load_trusted_file(tf, file_size, &out_chunk_hashes);
        if (ret < 0) {
            free(data);
            return ret;
        }
        data->prot_kind = FILE_PROTECTION_KIND_TRUSTED;
        data->chunk_hashes = out_chunk_hashes;
        inode->data = data;
        return 0;
    }

    /* not an allowed or trusted file, may be still allowed via file check policy */
    data->prot_kind = FILE_PROTECTION_KIND_NONE;
    inode->data = data;
    return 0;
}

static void chroot_idrop(struct libos_inode* inode) {
    assert(locked(&inode->lock));
    if (inode->data) {
        struct chroot_inode_data* data = inode->data;
        free(data->chunk_hashes);
        free(data);
    }
}

struct chroot_checkpoint {
    size_t size;
    char data[];
};

static int chroot_icheckpoint(struct libos_inode* inode, void** out_data, size_t* out_size) {
    assert(locked(&inode->lock));
    assert(inode->data);

    struct chroot_inode_data* idata = inode->data;

    size_t chunk_hashes_size = 0;
    if (idata->prot_kind == FILE_PROTECTION_KIND_TRUSTED)
        chunk_hashes_size = get_chunk_hashes_size(inode->size);

    struct chroot_checkpoint* cp;
    size_t cp_size = sizeof(*cp) + sizeof(*idata) + chunk_hashes_size;
    cp = malloc(cp_size);
    if (!cp)
        return -ENOMEM;

    cp->size = sizeof(*idata) + chunk_hashes_size;
    memcpy(cp->data, idata, sizeof(*idata));
    if (chunk_hashes_size)
        memcpy(cp->data + sizeof(*idata), idata->chunk_hashes, chunk_hashes_size);

    *out_data = cp;
    *out_size = cp_size;
    return 0;
}

static int chroot_irestore(struct libos_inode* inode, void* data) {
    struct chroot_checkpoint* cp = data;

    struct chroot_inode_data* idata = malloc(sizeof(*idata));
    if (!idata)
        return -ENOMEM;

    memcpy(idata, cp->data, sizeof(*idata));
    if (idata->prot_kind == FILE_PROTECTION_KIND_TRUSTED) {
        size_t chunk_hashes_size = cp->size - sizeof(*idata);
        idata->chunk_hashes = malloc(chunk_hashes_size);
        if (!idata->chunk_hashes) {
            free(idata);
            return -ENOMEM;
        }
        memcpy(idata->chunk_hashes, cp->data + sizeof(*idata), chunk_hashes_size);
    } else {
        idata->chunk_hashes = NULL;
    }

    inode->data = idata;
    return 0;
}

static int chroot_mount(struct libos_mount_params* params, void** mount_data) {
    __UNUSED(mount_data);
    if (!params->uri || (!strstartswith(params->uri, URI_PREFIX_FILE) &&
                         !strstartswith(params->uri, URI_PREFIX_DEV)))
        return -EINVAL;
    return 0;
}

static int chroot_dentry_uri(struct libos_dentry* dent, mode_t type, char** out_uri) {
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

static int chroot_lookup(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));

    int ret;
    struct libos_inode* inode = NULL;
    char* uri = NULL;

    /*
     * We don't know the file type yet, so we can't construct a PAL URI with the right prefix. In
     * most cases, a "file:" prefix is good enough: `PalStreamAttributesQuery` will access the file
     * and report the right file type.
     */
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
    size_t file_size = type == S_IFREG ? pal_attr.pending_size : 0;

    inode = get_new_inode(dent->mount, type, perm);
    if (!inode) {
        ret = -ENOMEM;
        goto out;
    }

    ret = setup_inode_data(type, uri, file_size, inode);
    if (ret < 0)
        goto out;

    inode->size = file_size;
    dent->inode = inode;
    ret = 0;
out:
    if (ret < 0)
        free(inode);
    free(uri);
    return ret;
}

static bool is_open_allowed(struct libos_dentry* dent, enum pal_access access) {
    if (dent->inode->type == S_IFDIR) {
        /* directories have no protections, always allowed to be opened */
        return true;
    }
    assert(dent->inode->type == S_IFREG || dent->inode->type == S_IFCHR);

    if (is_allowed_from_inode_data(dent->inode))
        return true;

    if (is_trusted_from_inode_data(dent->inode)) {
        if (access == PAL_ACCESS_RDWR || access == PAL_ACCESS_WRONLY) {
            log_error("Disallowing write/append to a trusted file '%s'", dent->name);
            return false;
        }
        return true;
    }

    if (g_file_check_policy != FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG) {
        log_warning("Disallowing access to file '%s'; file is not allowed.", dent->name);
        return false;
    }

    log_warning("Allowing access to unknown file '%s' due to file_check_policy.", dent->name);
    return true;
}

/* Open a temporary read-only PAL handle for a file (used by `unlink` etc.) */
static int chroot_temp_open(struct libos_dentry* dent, PAL_HANDLE* out_palhdl) {
    char* uri;
    int ret = dentry_uri(dent, dent->inode->type, &uri);
    if (ret < 0)
        return ret;

    if (!is_open_allowed(dent, PAL_ACCESS_RDONLY)) {
        ret = -EACCES;
        goto out;
    }

    ret = PalStreamOpen(uri, PAL_ACCESS_RDONLY, /*share_flags=*/0, PAL_CREATE_NEVER,
                        /*options=*/0, out_palhdl);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    ret = 0;
out:
    free(uri);
    return ret;
}

/* Open a PAL handle, and associate it with a LibOS handle (if provided). */
static int chroot_do_open(struct libos_handle* hdl, struct libos_dentry* dent, mode_t type,
                          int flags, mode_t perm) {
    assert(locked(&g_dcache_lock));

    int ret;

    char* uri;
    ret = dentry_uri(dent, type, &uri);
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
        hdl->seekable = true;
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

    if (!is_open_allowed(dent, LINUX_OPEN_FLAGS_TO_PAL_ACCESS(flags)))
        return -EACCES;

    return chroot_do_open(hdl, dent, dent->inode->type, flags, /*perm=*/0);
}

static bool is_create_allowed(const char* uri) {
    assert(strstartswith(uri, URI_PREFIX_FILE));
    const char* path = strip_prefix(uri);

    if (get_allowed_file(path))
        return true;

    if (get_trusted_file(path)) {
        log_error("Disallowing creating a trusted file '%s'", path);
        return false;
    }

    if (g_file_check_policy != FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG) {
        log_warning("Disallowing creating file '%s'; file is not trusted or allowed.", path);
        return false;
    }

    log_warning("Allowing creating unknown file '%s' due to file_check_policy.", path);
    return true;
}

static int chroot_creat(struct libos_handle* hdl, struct libos_dentry* dent, int flags,
                        mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    int ret;
    struct libos_inode* inode = NULL;
    char* uri = NULL;

    ret = chroot_dentry_uri(dent, S_IFREG, &uri);
    if (ret < 0)
        goto out;

    if (!is_create_allowed(uri)) {
        ret = -EACCES;
        goto out;
    }

    ret = chroot_do_open(hdl, dent, S_IFREG, flags | O_CREAT | O_EXCL, perm);
    if (ret < 0)
        goto out;

    ret = register_allowed_file(strip_prefix(uri));
    if (ret < 0)
        goto out;

    inode = get_new_inode(dent->mount, S_IFREG, perm);
    if (!inode) {
        ret = -ENOMEM;
        goto out;
    }

    ret = setup_inode_data_created_file(uri, inode);
    if (ret < 0)
        goto out;

    dent->inode = inode;
    ret = 0;
out:
    if (ret < 0)
        free(inode);
    free(uri);
    return ret;
}

static int chroot_mkdir(struct libos_dentry* dent, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    int ret;
    struct libos_inode* inode = NULL;

    ret = chroot_do_open(/*hdl=*/NULL, dent, S_IFDIR, O_CREAT | O_EXCL, perm);
    if (ret < 0)
        goto out;

    inode = get_new_inode(dent->mount, S_IFDIR, perm);
    if (!inode) {
        ret = -ENOMEM;
        goto out;
    }

    ret = setup_inode_data_created_dir(inode);
    if (ret < 0)
        goto out;

    dent->inode = inode;
    ret = 0;
out:
    if (ret < 0)
        free(inode);
    return ret;
}

static int chroot_flush(struct libos_handle* hdl) {
    assert(hdl->type == TYPE_CHROOT);

    int ret = PalStreamFlush(hdl->pal_handle);
    return pal_to_unix_errno(ret);
}

static ssize_t chroot_read(struct libos_handle* hdl, void* buf, size_t count, file_off_t* pos) {
    assert(hdl->type == TYPE_CHROOT);

    int ret;
    uint64_t offset = *pos;
    uint64_t end = count + offset;

    if (is_trusted_from_inode_data(hdl->inode)) {
        struct chroot_inode_data* data = hdl->inode->data;
        ret = read_and_verify_trusted_file(hdl->pal_handle, offset, count, buf,
                                           hdl->inode->size, data->chunk_hashes);
        if (ret < 0)
            return ret;
        count = MIN(end, (uint64_t)hdl->inode->size) - offset;
    } else {
        ret = PalStreamRead(hdl->pal_handle, offset, &count, buf);
        if (ret < 0)
            return pal_to_unix_errno(ret);
    }

    if (hdl->inode->type == S_IFREG) {
        *pos += count;
    }
    return count;
}

static ssize_t chroot_write(struct libos_handle* hdl, const void* buf, size_t count,
                            file_off_t* pos) {
    assert(hdl->type == TYPE_CHROOT);

    if (is_trusted_from_inode_data(hdl->inode)) {
        log_warning("Writing to a trusted file is disallowed!");
        return -EACCES;
    }

    file_off_t actual_pos = *pos;
    lock(&hdl->inode->lock);
    if (hdl->inode->type == S_IFREG && (hdl->flags & O_APPEND))
        actual_pos = hdl->inode->size;
    unlock(&hdl->inode->lock);

    int ret = PalStreamWrite(hdl->pal_handle, actual_pos, &count, (void*)buf);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    size_t new_size = 0;
    if (hdl->inode->type == S_IFREG) {
        *pos = actual_pos + count;
        /* Update file size if we just wrote past the end of file */
        lock(&hdl->inode->lock);
        if (hdl->inode->size < *pos)
            hdl->inode->size = *pos;
        new_size = hdl->inode->size;
        unlock(&hdl->inode->lock);
    }

    refresh_mappings_on_file(hdl, new_size, /*reload_file_contents=*/true);
    return (ssize_t)count;
}

int chroot_readdir(struct libos_dentry* dent, readdir_callback_t callback, void* arg) {
    int ret;
    PAL_HANDLE palhdl;
    char* buf = NULL;
    size_t buf_size = READDIR_BUF_SIZE;

    assert(dent->inode->type == S_IFDIR);
    ret = chroot_temp_open(dent, &palhdl);
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

static int chroot_unlink(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);

    int ret;

    PAL_HANDLE palhdl;
    ret = chroot_temp_open(dent, &palhdl);
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

    ret = dentry_uri(new, old->inode->type, &new_uri);
    if (ret < 0)
        goto out;

    PAL_HANDLE palhdl;
    ret = chroot_temp_open(old, &palhdl);
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
    ret = chroot_temp_open(dent, &palhdl);
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
    .mmap       = &generic_emulated_mmap,
    .msync      = &generic_emulated_msync,
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
    .open        = &chroot_open,
    .lookup      = &chroot_lookup,
    .creat       = &chroot_creat,
    .mkdir       = &chroot_mkdir,
    .stat        = &generic_inode_stat,
    .readdir     = &chroot_readdir,
    .unlink      = &chroot_unlink,
    .rename      = &chroot_rename,
    .chmod       = &chroot_chmod,
    .idrop       = &chroot_idrop,
    .icheckpoint = &chroot_icheckpoint,
    .irestore    = &chroot_irestore,
};

struct libos_fs chroot_builtin_fs = {
    .name   = "chroot",
    .fs_ops = &chroot_fs_ops,
    .d_ops  = &chroot_d_ops,
};
