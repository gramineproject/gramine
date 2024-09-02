/* Copyright (C) 2024 Intel Corporation
 *                    Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>
 */

/*
 * This file contains code for allowed files in 'chroot' filesystem.
 *
 * Allowed files (AF) have no protections applied. It is the responsibility of the application to
 * apply suitable protections for each AF.
 *
 * Allowed files are useful for debugging, or when files are guaranteed to have no effect on
 * security of the execution (e.g. non-confidential logs), or when the application itself protects
 * these files.
 */

#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "libos_fs.h"
#include "list.h"
#include "path_utils.h"
#include "toml.h"

DEFINE_LIST(allowed_file);
struct allowed_file {
    LIST_TYPE(allowed_file) list;
    size_t path_len;
    char path[]; /* must be NULL-terminated */
};

DEFINE_LISTP(allowed_file);
static LISTP_TYPE(allowed_file) g_allowed_files_list = LISTP_INIT;
static spinlock_t g_allowed_files_lock = INIT_SPINLOCK_UNLOCKED;

/* assumes that both af->path and full_path are already normalized */
static bool is_af_path_equal_or_subpath(const struct allowed_file* af, const char* full_path,
                                        size_t full_path_len) {
    if (af->path_len > full_path_len || memcmp(af->path, full_path, af->path_len)) {
        /* af path is not a prefix of `path` */
        return false;
    }
    if (af->path_len == full_path_len) {
        /* Both are equal */
        return true;
    }
    if (af->path[af->path_len - 1] == '/') {
        /* af path is a subpath of `path` (with slash), e.g. "foo/" and "foo/bar" */
        return true;
    }
    if (full_path[af->path_len] == '/') {
        /* af path is a subpath of `path` (without slash), e.g. "foo" and "foo/bar" */
        return true;
    }
    return false;
}

struct allowed_file* get_allowed_file(const char* path) {
    size_t norm_path_size = strlen(path) + 1; /* overapproximate */
    char* norm_path = malloc(norm_path_size);
    if (!norm_path)
        return NULL;

    bool normalized = get_norm_path(path, norm_path, &norm_path_size);
    if (!normalized) {
        free(norm_path);
        return NULL;
    }

    struct allowed_file* found_af = NULL;

    spinlock_lock(&g_allowed_files_lock);
    struct allowed_file* af;
    LISTP_FOR_EACH_ENTRY(af, &g_allowed_files_list, list) {
        /* must be a sub-directory or file */
        if (is_af_path_equal_or_subpath(af, norm_path, strlen(norm_path))) {
            found_af = af;
            break;
        }
    }
    spinlock_unlock(&g_allowed_files_lock);
    free(norm_path);
    return found_af;
}

int register_allowed_file(const char* path) {
    size_t path_len = strlen(path);
    if (path_len > URI_MAX) {
        log_error("Size of file exceeds maximum %dB: %s", URI_MAX, path);
        return -EINVAL;
    }

    struct allowed_file* new = malloc(sizeof(*new) + path_len + 1);
    if (!new)
        return -ENOMEM;

    INIT_LIST_HEAD(new, list);
    new->path_len = path_len;
    memcpy(new->path, path, path_len + 1);

    spinlock_lock(&g_allowed_files_lock);
    struct allowed_file* af;
    LISTP_FOR_EACH_ENTRY(af, &g_allowed_files_list, list) {
        /* below check is required because same file could have been added by another thread */
        if (af->path_len == path_len && !memcmp(af->path, path, path_len)) {
            spinlock_unlock(&g_allowed_files_lock);
            free(new);
            return 0;
        }
    }
    LISTP_ADD_TAIL(new, &g_allowed_files_list, list);
    spinlock_unlock(&g_allowed_files_lock);
    return 0;
}

static int init_one_allowed_file(toml_raw_t toml_allowed_uri_raw, size_t idx) {
    int ret;

    /* FIXME: toml_allowed_uri_str is a temporary string, allocating it is redundant; however
     *        tomlc99 lib has only toml_rtos() function that returns a newly allocated string rather
     *        than a slice into the parsed TOML structure */
    char* toml_allowed_uri_str = NULL;

    /* FIXME: instead of re-allocating in register_allowed_file(), could pass ownership to it */
    char* norm_allowed_path = NULL;

    ret = toml_rtos(toml_allowed_uri_raw, &toml_allowed_uri_str);
    if (ret < 0) {
        log_error("Invalid allowed file in manifest at index %ld (not a string)", idx);
        ret = -EINVAL;
        goto out;
    }

    if (!strstartswith(toml_allowed_uri_str, URI_PREFIX_FILE)
            && !strstartswith(toml_allowed_uri_str, URI_PREFIX_DEV)) {
        log_error("Invalid URI [%s]: Allowed files must start with 'file:' or 'dev:'",
                  toml_allowed_uri_str);
        ret = -EINVAL;
        goto out;
    }

    size_t norm_allowed_path_size = strlen(toml_allowed_uri_str) + 1; /* overapproximate */
    norm_allowed_path = malloc(norm_allowed_path_size);
    if (!norm_allowed_path) {
        ret = -ENOMEM;
        goto out;
    }

    size_t uri_prefix_len = strstartswith(toml_allowed_uri_str, URI_PREFIX_FILE)
                                ? URI_PREFIX_FILE_LEN : URI_PREFIX_DEV_LEN;

    bool normalized = get_norm_path(toml_allowed_uri_str + uri_prefix_len,
                                    norm_allowed_path, &norm_allowed_path_size);
    if (!normalized) {
        log_error("Allowed file path (%s) normalization failed", toml_allowed_uri_str);
        ret = -EINVAL;
        goto out;
    }

    ret = register_allowed_file(norm_allowed_path);
    if (ret < 0) {
        log_error("Allowed file registration (%s) failed", toml_allowed_uri_str);
        goto out;
    }

    ret = 0;
out:
    free(norm_allowed_path);
    free(toml_allowed_uri_str);
    return ret;
}

int init_allowed_files(void) {
    int ret;

    assert(g_manifest_root);
    toml_table_t* manifest_sgx = toml_table_in(g_manifest_root, "sgx");
    if (!manifest_sgx)
        return 0;

    toml_array_t* toml_allowed_files = toml_array_in(manifest_sgx, "allowed_files");
    if (!toml_allowed_files)
        return 0;

    ssize_t toml_allowed_files_cnt = toml_array_nelem(toml_allowed_files);
    assert(toml_allowed_files_cnt >= 0);

    for (ssize_t i = 0; i < toml_allowed_files_cnt; i++) {
        toml_raw_t toml_allowed_uri_raw = toml_raw_at(toml_allowed_files, i);
        if (!toml_allowed_uri_raw) {
            log_error("Invalid allowed file in manifest at index %ld", i);
            return -EINVAL;
        }

        ret = init_one_allowed_file(toml_allowed_uri_raw, i);
        if (ret < 0)
            return ret;
    }

    return 0;
}
