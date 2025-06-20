/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for creating filesystems in library OS.
 */

#include "api.h"
#include "libos_checkpoint.h"
#include "libos_fs.h"
#include "libos_fs_encrypted.h"
#include "libos_fs_pseudo.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_utils.h"
#include "list.h"
#include "pal.h"
#include "path_utils.h"
#include "toml.h"
#include "toml_utils.h"

static struct libos_fs* g_builtin_fs[] = {
    &chroot_builtin_fs,
    &chroot_encrypted_builtin_fs,
    &tmp_builtin_fs,
    &pipe_builtin_fs,
    &fifo_builtin_fs,
    &socket_builtin_fs,
    &epoll_builtin_fs,
    &eventfd_builtin_fs,
    &pseudo_builtin_fs,
    &synthetic_builtin_fs,
    &path_builtin_fs,
    &shm_builtin_fs,
};

static struct libos_lock g_mount_mgr_lock;

#define SYSTEM_LOCK()   lock(&g_mount_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&g_mount_mgr_lock)
#define SYSTEM_LOCKED() locked(&g_mount_mgr_lock)

#define MOUNT_MGR_ALLOC 64

#define OBJ_TYPE struct libos_mount
#include "memmgr.h"

static MEM_MGR g_mount_mgr = NULL;
DEFINE_LISTP(libos_mount);
/* Links to mount->list */
static LISTP_TYPE(libos_mount) g_mount_list;
static struct libos_lock g_mount_list_lock;

int init_fs(void) {
    int ret;
    if (!create_lock(&g_mount_mgr_lock) || !create_lock(&g_mount_list_lock)) {
        ret = -ENOMEM;
        goto err;
    }

    g_mount_mgr = create_mem_mgr(init_align_up(MOUNT_MGR_ALLOC));
    if (!g_mount_mgr) {
        ret = -ENOMEM;
        goto err;
    }

    INIT_LISTP(&g_mount_list);

    if ((ret = init_encrypted_files()) < 0)
        goto err;

    if ((ret = init_procfs()) < 0)
        goto err;
    if ((ret = init_devfs()) < 0)
        goto err;
    if ((ret = init_sysfs()) < 0)
        goto err;

    if ((ret = init_etcfs()) < 0)
        goto err;

    return 0;

err:
    if (g_mount_mgr) {
        destroy_mem_mgr(g_mount_mgr);
    }
    if (lock_created(&g_mount_mgr_lock))
        destroy_lock(&g_mount_mgr_lock);
    if (lock_created(&g_mount_list_lock))
        destroy_lock(&g_mount_list_lock);
    return ret;
}

int init_trusted_allowed_files(void) {
    int ret;

    if ((ret = init_file_check_policy()) < 0)
        return ret;
    if ((ret = init_allowed_files()) < 0)
        return ret;
    if ((ret = init_trusted_files()) < 0)
        return ret;

    return 0;
}

static struct libos_mount* alloc_mount(void) {
    return get_mem_obj_from_mgr_enlarge(g_mount_mgr, size_align_up(MOUNT_MGR_ALLOC));
}

static void free_mount(struct libos_mount* mount) {
    free_mem_obj_to_mgr(g_mount_mgr, mount);
}

static bool mount_migrated = false;

static int mount_root(void) {
    int ret;
    char* fs_root_type     = NULL;
    char* fs_root_uri      = NULL;
    char* fs_root_key_name = NULL;
    bool fs_root_enable_recovery;

    assert(g_manifest_root);

    ret = toml_string_in(g_manifest_root, "fs.root.type", &fs_root_type);
    if (ret < 0) {
        log_error("Cannot parse 'fs.root.type'");
        ret = -EINVAL;
        goto out;
    }

    ret = toml_string_in(g_manifest_root, "fs.root.uri", &fs_root_uri);
    if (ret < 0) {
        log_error("Cannot parse 'fs.root.uri'");
        ret = -EINVAL;
        goto out;
    }

    ret = toml_string_in(g_manifest_root, "fs.root.key_name", &fs_root_key_name);
    if (ret < 0) {
        log_error("Cannot parse 'fs.root.key_name'");
        ret = -EINVAL;
        goto out;
    }

    ret = toml_bool_in(g_manifest_root, "fs.root.enable_recovery", /*defaultval=*/false,
                       &fs_root_enable_recovery);
    if (ret < 0) {
        log_error("Cannot parse 'fs.root.enable_recovery'");
        ret = -EINVAL;
        goto out;
    }

    struct libos_mount_params params = {
        .path = "/",
        .key_name = fs_root_key_name,
        .enable_recovery = fs_root_enable_recovery,
    };

    if (!fs_root_type && !fs_root_uri) {
        params.type = "chroot";
        params.uri = URI_PREFIX_FILE ".";
    } else if (!fs_root_type || !strcmp(fs_root_type, "chroot")) {
        if (!fs_root_uri) {
            log_error("No value provided for 'fs.root.uri'");
            ret = -EINVAL;
            goto out;
        }
        params.type = "chroot";
        params.uri = fs_root_uri;
    } else {
        params.type = fs_root_type;
        params.uri = fs_root_uri;
    }
    ret = mount_fs(&params);

out:
    free(fs_root_type);
    free(fs_root_uri);
    return ret;
}

static int mount_sys(void) {
    int ret;

    ret = mount_fs(&(struct libos_mount_params){
        .type = "pseudo",
        .path = "/proc",
        .uri = "proc",
    });
    if (ret < 0)
        return ret;

    ret = mount_fs(&(struct libos_mount_params){
        .type = "pseudo",
        .path = "/dev",
        .uri = "dev",
    });
    if (ret < 0)
        return ret;

    ret = mount_fs(&(struct libos_mount_params){
        .type = "pseudo",
        .path = "/sys",
        .uri = "sys",
    });
    if (ret < 0)
        return ret;

    return 0;
}

static int mount_one_nonroot(toml_table_t* mount, const char* prefix) {
    assert(mount);

    int ret;

    char* mount_type     = NULL;
    char* mount_path     = NULL;
    char* mount_uri      = NULL;
    char* mount_key_name = NULL;
    bool mount_enable_recovery;

    ret = toml_string_in(mount, "type", &mount_type);
    if (ret < 0) {
        log_error("Cannot parse '%s.type'", prefix);
        ret = -EINVAL;
        goto out;
    }

    ret = toml_string_in(mount, "path", &mount_path);
    if (ret < 0) {
        log_error("Cannot parse '%s.path'", prefix);
        ret = -EINVAL;
        goto out;
    }

    ret = toml_string_in(mount, "uri", &mount_uri);
    if (ret < 0) {
        log_error("Cannot parse '%s.uri'", prefix);
        ret = -EINVAL;
        goto out;
    }

    ret = toml_string_in(mount, "key_name", &mount_key_name);
    if (ret < 0) {
        log_error("Cannot parse '%s.key_name'", prefix);
        ret = -EINVAL;
        goto out;
    }

    ret = toml_bool_in(mount, "enable_recovery", /*defaultval=*/false, &mount_enable_recovery);
    if (ret < 0) {
        log_error("Cannot parse '%s.enable_recovery'", prefix);
        ret = -EINVAL;
        goto out;
    }

    if (!mount_path) {
        log_error("No value provided for '%s.path'", prefix);
        ret = -EINVAL;
        goto out;
    }

    if (!strcmp(mount_path, "/")) {
        log_error("'%s.path' cannot be \"/\". The root mount (\"/\") can be customized "
                  "via the 'fs.root' manifest entry.", prefix);
        ret = -EINVAL;
        goto out;
    }

    if (mount_path[0] != '/') {
        log_error("Relative mount path: '%s.path' (\"%s\") is disallowed! "
                  "Consider converting it to absolute by adding \"/\" at the beginning.",
                  prefix, mount_path);
        ret = -EINVAL;
        goto out;
    }

    if (!mount_type || !strcmp(mount_type, "chroot")) {
        if (!mount_uri) {
            log_error("No value provided for '%s.uri'", prefix);
            ret = -EINVAL;
            goto out;
        }

        if (!strcmp(mount_uri, "file:/proc") ||
                !strcmp(mount_uri, "file:/sys") ||
                !strcmp(mount_uri, "file:/dev") ||
                !strncmp(mount_uri, "file:/proc/", strlen("file:/proc/")) ||
                !strncmp(mount_uri, "file:/sys/", strlen("file:/sys/")) ||
                !strncmp(mount_uri, "file:/dev/", strlen("file:/dev/"))) {
            log_error("Mounting %s may expose unsanitized, unsafe files to unsuspecting "
                      "application. Gramine will continue application execution, but this "
                      "configuration is not recommended for use in production!", mount_uri);
        }
    }

    struct libos_mount_params params = {
        .type = mount_type ?: "chroot",
        .path = mount_path,
        .uri = mount_uri,
        .key_name = mount_key_name,
        .enable_recovery = mount_enable_recovery,
    };
    ret = mount_fs(&params);

out:
    free(mount_type);
    free(mount_path);
    free(mount_uri);
    free(mount_key_name);
    return ret;
}

static int mount_nonroot_from_toml_array(void) {
    int ret;

    assert(g_manifest_root);
    toml_table_t* manifest_fs = toml_table_in(g_manifest_root, "fs");
    if (!manifest_fs)
        return 0;

    toml_array_t* manifest_fs_mounts = toml_array_in(manifest_fs, "mounts");
    if (!manifest_fs_mounts)
        return 0;

    ssize_t mounts_cnt = toml_array_nelem(manifest_fs_mounts);
    if (mounts_cnt < 0)
        return -EINVAL;

    for (size_t i = 0; i < (size_t)mounts_cnt; i++) {
        toml_table_t* mount = toml_table_at(manifest_fs_mounts, i);
        if (!mount) {
            log_error("Invalid mount in manifest at index %zd (not a TOML table)", i);
            return -EINVAL;
        }

        char prefix[static_strlen("fs.mounts[]") + 21];
        snprintf(prefix, sizeof(prefix), "fs.mounts[%zu]", i);

        ret = mount_one_nonroot(mount, prefix);
        if (ret < 0)
            return ret;
    }
    return 0;
}

int init_mount_root(void) {
    if (mount_migrated)
        return 0;

    int ret;

    ret = mount_root();
    if (ret < 0)
        return ret;

    struct libos_dentry* dent = NULL;
    lock(&g_dcache_lock);
    ret = path_lookupat(/*start=*/NULL, "/", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dent);
    unlock(&g_dcache_lock);
    if (ret < 0) {
        log_error("Could not set up dentry for \"/\", something is seriously broken.");
        return ret;
    }

    lock(&g_process.fs_lock);
    put_dentry(g_process.root);
    /* Pass ownership of `dent`. */
    g_process.root = dent;
    unlock(&g_process.fs_lock);

    ret = mount_sys();
    if (ret < 0)
        return ret;

    return 0;
}

int init_mount(void) {
    if (mount_migrated)
        return 0;

    int ret;

    ret = mount_nonroot_from_toml_array();
    if (ret < 0)
        return ret;

    assert(g_manifest_root);

    char* fs_start_dir = NULL;
    ret = toml_string_in(g_manifest_root, "fs.start_dir", &fs_start_dir);
    if (ret < 0) {
        log_error("Can't parse 'fs.start_dir'");
        return ret;
    }

    if (fs_start_dir) {
        struct libos_dentry* dent = NULL;

        lock(&g_dcache_lock);
        ret = path_lookupat(/*start=*/NULL, fs_start_dir, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dent);
        unlock(&g_dcache_lock);

        free(fs_start_dir);
        if (ret < 0) {
            log_error("Invalid 'fs.start_dir' in manifest.");
            return ret;
        }
        lock(&g_process.fs_lock);
        put_dentry(g_process.cwd);
        g_process.cwd = dent;
        unlock(&g_process.fs_lock);
    }
    /* Otherwise `cwd` is already initialized. */

    /* The mount_etcfs takes precedence over user's fs.mounts, and because of that,
     * it has to be called at the end. */
    return mount_etcfs();
}

struct libos_fs* find_fs(const char* name) {
    for (size_t i = 0; i < ARRAY_SIZE(g_builtin_fs); i++) {
        struct libos_fs* fs = g_builtin_fs[i];
        if (!strncmp(fs->name, name, sizeof(fs->name)))
            return fs;
    }

    return NULL;
}

static int mount_fs_at_dentry(struct libos_mount_params* params, struct libos_dentry* mount_point) {
    assert(locked(&g_dcache_lock));
    assert(!mount_point->attached_mount);

    int ret;
    struct libos_fs* fs = find_fs(params->type);
    if (!fs || !fs->fs_ops || !fs->fs_ops->mount)
        return -ENODEV;

    if (!fs->d_ops || !fs->d_ops->lookup)
        return -ENODEV;

    void* mount_data = NULL;

    /* Call filesystem-specific mount operation */
    if ((ret = fs->fs_ops->mount(params, &mount_data)) < 0)
        return ret;

    /* Allocate and set up `libos_mount` object */

    struct libos_mount* mount = alloc_mount();
    if (!mount) {
        ret = -ENOMEM;
        goto err;
    }
    memset(mount, 0, sizeof(*mount));

    mount->path = strdup(params->path);
    if (!mount->path) {
        ret = -ENOMEM;
        goto err;
    }
    if (params->uri) {
        mount->uri = strdup(params->uri);
        if (!mount->uri) {
            ret = -ENOMEM;
            goto err;
        }
    } else {
        mount->uri = NULL;
    }
    mount->fs = fs;
    mount->data = mount_data;

    mount->enable_recovery = params->enable_recovery;

    /* Attach mount to mountpoint, and the other way around */

    mount->mount_point = mount_point;
    get_dentry(mount_point);
    mount_point->attached_mount = mount;
    get_mount(mount);

    /* Initialize root dentry of the new filesystem */

    mount->root = get_new_dentry(mount, /*parent=*/NULL, mount_point->name, mount_point->name_len);
    if (!mount->root) {
        ret = -ENOMEM;
        goto err;
    }

    /*
     * Trigger filesystem lookup for the root dentry, so that it's already positive. If there is a
     * problem looking up the root, we want the mount operation to fail.
     *
     * We skip the lookup for the `encrypted` filesystem, because the key for encrypted files might
     * not be set yet.
     */
    if (strcmp(params->type, "encrypted") != 0) {
        struct libos_dentry* root;
        if ((ret = path_lookupat(g_dentry_root, params->path, LOOKUP_NO_FOLLOW, &root))) {
            log_warning("Failed to look up mount root %s: %s", params->path, unix_strerror(ret));
            goto err;
        }
        assert(root == mount->root);
        put_dentry(root);
    }

    /* Add `mount` to the global list */

    lock(&g_mount_list_lock);
    LISTP_ADD_TAIL(mount, &g_mount_list, list);
    get_mount(mount);
    unlock(&g_mount_list_lock);

    return 0;

err:
    if (mount_point->attached_mount)
        mount_point->attached_mount = NULL;

    if (mount) {
        if (mount->mount_point)
            put_dentry(mount_point);

        if (mount->root)
            put_dentry(mount->root);

        free_mount(mount);
    }

    if (fs->fs_ops->unmount) {
        int ret_unmount = fs->fs_ops->unmount(mount_data);
        if (ret_unmount < 0) {
            log_warning("Unmounting %s failed: %d", params->path, ret_unmount);
        }
    }

    return ret;
}

int mount_fs(struct libos_mount_params* params) {
    int ret;
    struct libos_dentry* mount_point = NULL;

    log_debug("mounting \"%s\" (%s) under %s", params->uri, params->type, params->path);

    lock(&g_dcache_lock);

    if (!g_dentry_root->attached_mount && !strcmp(params->path, "/")) {
        /* `g_dentry_root` does not belong to any mounted filesystem, so lookup will fail. Use it
         * directly. */
        mount_point = g_dentry_root;
        get_dentry(g_dentry_root);
    } else {
        int lookup_flags = LOOKUP_NO_FOLLOW | LOOKUP_MAKE_SYNTHETIC;
        ret = path_lookupat(g_dentry_root, params->path, lookup_flags, &mount_point);
        if (ret < 0) {
            log_error("Looking up mountpoint %s failed: %s", params->path, unix_strerror(ret));
            goto out;
        }
    }

    if ((ret = mount_fs_at_dentry(params, mount_point)) < 0) {
        log_error("Mounting \"%s\" (%s) under %s failed: %s", params->uri, params->type,
                  params->path, unix_strerror(ret));
        goto out;
    }

    ret = 0;
out:
    if (mount_point)
        put_dentry(mount_point);
    unlock(&g_dcache_lock);

    return ret;
}

/*
 * XXX: These two functions are useless - `mount` is not freed even if refcount reaches 0.
 * Unfortunately Gramine is not keeping track of this refcount correctly, so we cannot free
 * the object. Fixing this would require revising whole filesystem implementation - but this code
 * is, uhm, not the best achievement of humankind and probably requires a complete rewrite.
 */
void get_mount(struct libos_mount* mount) {
    __UNUSED(mount);
    // refcount_inc(&mount->ref_count);
}

void put_mount(struct libos_mount* mount) {
    __UNUSED(mount);
    // refcount_dec(&mount->ref_count);
}

int walk_mounts(int (*walk)(struct libos_mount* mount, void* arg), void* arg) {
    struct libos_mount* mount;
    struct libos_mount* n;
    int ret = 0;
    int nsrched = 0;

    lock(&g_mount_list_lock);

    LISTP_FOR_EACH_ENTRY_SAFE(mount, n, &g_mount_list, list) {
        if ((ret = (*walk)(mount, arg)) < 0)
            break;

        if (ret > 0)
            nsrched++;
    }

    unlock(&g_mount_list_lock);
    return ret < 0 ? ret : (nsrched ? 0 : -ESRCH);
}

struct libos_mount* find_mount_from_uri(const char* uri) {
    struct libos_mount* mount;
    struct libos_mount* found = NULL;
    size_t longest_path = 0;

    lock(&g_mount_list_lock);
    LISTP_FOR_EACH_ENTRY(mount, &g_mount_list, list) {
        if (!mount->uri)
            continue;

        if (strcmp(mount->uri, uri) == 0) {
            size_t path_len = strlen(mount->path);
            if (path_len > longest_path) {
                longest_path = path_len;
                found = mount;
            }
        }
    }

    if (found)
        get_mount(found);

    unlock(&g_mount_list_lock);
    return found;
}

/*
 * Note that checkpointing the `libos_fs` structure copies it, instead of using a pointer to
 * corresponding global object on the remote side. This does not waste too much memory (because each
 * global object is only copied once), but it means that `libos_fs` objects cannot be compared by
 * pointer.
 */
BEGIN_CP_FUNC(fs) {
    __UNUSED(size);
    assert(size == sizeof(struct libos_fs));

    struct libos_fs* fs = (struct libos_fs*)obj;
    struct libos_fs* new_fs = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct libos_fs));
        ADD_TO_CP_MAP(obj, off);

        new_fs = (struct libos_fs*)(base + off);

        memcpy(new_fs->name, fs->name, sizeof(new_fs->name));
        new_fs->fs_ops = NULL;
        new_fs->d_ops = NULL;

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_fs = (struct libos_fs*)(base + off);
    }

    if (objp)
        *objp = (void*)new_fs;
}
END_CP_FUNC(fs)

BEGIN_RS_FUNC(fs) {
    __UNUSED(offset);
    __UNUSED(rebase);
    struct libos_fs* fs = (void*)(base + GET_CP_FUNC_ENTRY());

    struct libos_fs* builtin_fs = find_fs(fs->name);
    if (!builtin_fs)
        return -EINVAL;

    fs->fs_ops = builtin_fs->fs_ops;
    fs->d_ops = builtin_fs->d_ops;
}
END_RS_FUNC(fs)

BEGIN_CP_FUNC(mount) {
    __UNUSED(size);
    assert(size == sizeof(struct libos_mount));

    struct libos_mount* mount     = (struct libos_mount*)obj;
    struct libos_mount* new_mount = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct libos_mount));
        ADD_TO_CP_MAP(obj, off);

        mount->cpdata = NULL;
        if (mount->fs->fs_ops && mount->fs->fs_ops->checkpoint) {
            void* cpdata = NULL;
            int bytes = mount->fs->fs_ops->checkpoint(&cpdata, mount->data);
            if (bytes > 0) {
                mount->cpdata = cpdata;
                mount->cpsize = bytes;
            }
        }

        new_mount  = (struct libos_mount*)(base + off);
        *new_mount = *mount;

        DO_CP(fs, mount->fs, &new_mount->fs);

        if (mount->cpdata) {
            size_t cp_off = ADD_CP_OFFSET(mount->cpsize);
            memcpy((char*)base + cp_off, mount->cpdata, mount->cpsize);
            new_mount->cpdata = (char*)base + cp_off;
        }

        new_mount->data            = NULL;
        new_mount->mount_point     = NULL;
        new_mount->root            = NULL;
        new_mount->enable_recovery = mount->enable_recovery;
        INIT_LIST_HEAD(new_mount, list);
        refcount_set(&new_mount->ref_count, 0);

        DO_CP_MEMBER(str, mount, new_mount, path);

        if (mount->uri)
            DO_CP_MEMBER(str, mount, new_mount, uri);

        if (mount->mount_point)
            DO_CP_MEMBER(dentry, mount, new_mount, mount_point);

        if (mount->root)
            DO_CP_MEMBER(dentry, mount, new_mount, root);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_mount = (struct libos_mount*)(base + off);
    }

    if (objp)
        *objp = (void*)new_mount;
}
END_CP_FUNC(mount)

BEGIN_RS_FUNC(mount) {
    __UNUSED(offset);
    struct libos_mount* mount = (void*)(base + GET_CP_FUNC_ENTRY());

    CP_REBASE(mount->cpdata);
    CP_REBASE(mount->list);
    CP_REBASE(mount->mount_point);
    CP_REBASE(mount->root);
    CP_REBASE(mount->path);
    CP_REBASE(mount->uri);

    if (mount->mount_point) {
        get_dentry(mount->mount_point);
    }

    if (mount->root) {
        get_dentry(mount->root);
    }

    CP_REBASE(mount->fs);
    if (mount->fs->fs_ops && mount->fs->fs_ops->migrate && mount->cpdata) {
        void* mount_data = NULL;
        if (mount->fs->fs_ops->migrate(mount->cpdata, &mount_data) == 0)
            mount->data = mount_data;
        mount->cpdata = NULL;
    }

    LISTP_ADD_TAIL(mount, &g_mount_list, list);

    if (mount->path) {
        DEBUG_RS("type=%s,uri=%s,path=%s", mount->type, mount->uri, mount->path);
    } else {
        DEBUG_RS("type=%s,uri=%s", mount->type, mount->uri);
    }
}
END_RS_FUNC(mount)

BEGIN_CP_FUNC(all_mounts) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    struct libos_mount* mount;
    lock(&g_mount_list_lock);
    LISTP_FOR_EACH_ENTRY(mount, &g_mount_list, list) {
        DO_CP(mount, mount, NULL);
    }
    unlock(&g_mount_list_lock);

    /* add an empty entry to mark as migrated */
    ADD_CP_FUNC_ENTRY(0UL);
}
END_CP_FUNC(all_mounts)

BEGIN_RS_FUNC(all_mounts) {
    __UNUSED(entry);
    __UNUSED(base);
    __UNUSED(offset);
    __UNUSED(rebase);
    /* to prevent file system from being mount again */
    mount_migrated = true;
}
END_RS_FUNC(all_mounts)
