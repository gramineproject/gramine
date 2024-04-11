/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include "assert.h"
#include "crypto.h"
#include "hex.h"
#include "libos_checkpoint.h"
#include "libos_fs_encrypted.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_utils.h"
#include "path_utils.h"
#include "protected_files.h"
#include "toml_utils.h"

static LISTP_TYPE(libos_encrypted_files_key) g_keys = LISTP_INIT;

/* Protects the `g_keys` list, but also individual keys, since they can be updated */
static struct libos_lock g_keys_lock;

static LISTP_TYPE(libos_encrypted_volume) g_volumes = LISTP_INIT;

/* Protects the `g_volumes` list. */
static struct libos_lock g_volumes_lock;

static pf_status_t cb_read(pf_handle_t handle, void* buffer, uint64_t offset, size_t size) {
    PAL_HANDLE pal_handle = (PAL_HANDLE)handle;

    size_t buffer_offset = 0;
    size_t remaining = size;

    while (remaining > 0) {
        size_t count = remaining;
        int ret = PalStreamRead(pal_handle, offset + buffer_offset, &count, buffer + buffer_offset);
        if (ret == PAL_ERROR_INTERRUPTED)
            continue;

        if (ret < 0) {
            log_warning("PalStreamRead failed: %s", pal_strerror(ret));
            return PF_STATUS_CALLBACK_FAILED;
        }

        if (count == 0) {
            log_warning("EOF");
            return PF_STATUS_CALLBACK_FAILED;
        }

        assert(count <= remaining);
        remaining -= count;
        buffer_offset += count;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_write(pf_handle_t handle, const void* buffer, uint64_t offset, size_t size) {
    PAL_HANDLE pal_handle = (PAL_HANDLE)handle;

    size_t buffer_offset = 0;
    size_t remaining = size;

    while (remaining > 0) {
        size_t count = remaining;
        int ret = PalStreamWrite(pal_handle, offset + buffer_offset, &count,
                                 (void*)(buffer + buffer_offset));
        if (ret == PAL_ERROR_INTERRUPTED)
            continue;

        if (ret < 0) {
            log_warning("PalStreamWrite failed: %s", pal_strerror(ret));
            return PF_STATUS_CALLBACK_FAILED;
        }

        if (count == 0) {
            log_warning("EOF");
            return PF_STATUS_CALLBACK_FAILED;
        }

        assert(count <= remaining);
        remaining -= count;
        buffer_offset += count;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_truncate(pf_handle_t handle, uint64_t size) {
    PAL_HANDLE pal_handle = (PAL_HANDLE)handle;

    int ret = PalStreamSetLength(pal_handle, size);
    if (ret < 0) {
        log_warning("PalStreamSetLength failed: %s", pal_strerror(ret));
        return PF_STATUS_CALLBACK_FAILED;
    }

    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_fsync(pf_handle_t handle) {
    PAL_HANDLE pal_handle = (PAL_HANDLE)handle;

    int ret = PalStreamFlush(pal_handle);
    if (ret < 0) {
        log_warning("PalStreamFlush failed: %s", pal_strerror(ret));
        return PF_STATUS_CALLBACK_FAILED;
    }

    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_aes_cmac(const pf_key_t* key, const void* input, size_t input_size,
                               pf_mac_t* mac) {
    int ret = lib_AESCMAC((const uint8_t*)key, sizeof(*key), input, input_size, (uint8_t*)mac,
                          sizeof(*mac));
    if (ret != 0) {
        log_warning("lib_AESCMAC failed: %d", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_aes_gcm_encrypt(const pf_key_t* key, const pf_iv_t* iv, const void* aad,
                                      size_t aad_size, const void* input, size_t input_size,
                                      void* output, pf_mac_t* mac) {
    int ret = lib_AESGCMEncrypt((const uint8_t*)key, sizeof(*key), (const uint8_t*)iv, input,
                                input_size, aad, aad_size, output, (uint8_t*)mac, sizeof(*mac));
    if (ret != 0) {
        log_warning("lib_AESGCMEncrypt failed: %d", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_aes_gcm_decrypt(const pf_key_t* key, const pf_iv_t* iv, const void* aad,
                                      size_t aad_size, const void* input, size_t input_size,
                                      void* output, const pf_mac_t* mac) {
    int ret = lib_AESGCMDecrypt((const uint8_t*)key, sizeof(*key), (const uint8_t*)iv, input,
                                input_size, aad, aad_size, output, (const uint8_t*)mac,
                                sizeof(*mac));
    if (ret != 0) {
        log_warning("lib_AESGCMDecrypt failed: %d", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_random(uint8_t* buffer, size_t size) {
    int ret = PalRandomBitsRead(buffer, size);
    if (ret < 0) {
        log_warning("PalRandomBitsRead failed: %s", pal_strerror(ret));
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

#ifdef DEBUG
static void cb_debug(const char* msg) {
    log_debug("%s", msg);
}
#endif

static int uri_to_normalized_path(const char* uri, char** out_norm_path) {
    assert(strstartswith(uri, URI_PREFIX_FILE));
    const char* path = uri + static_strlen(URI_PREFIX_FILE);

    size_t norm_path_size = strlen(path) + 1;
    char* norm_path       = malloc(norm_path_size);
    if (!norm_path) {
        return -ENOMEM;
    }

    if (!get_norm_path(path, norm_path, &norm_path_size)) {
        free(norm_path);
        return -EINVAL;
    }

    *out_norm_path = norm_path;
    return 0;
}

/*
 * The `pal_handle` parameter is used if this is a checkpointed file, and we have received the PAL
 * handle from the parent process. Note that in this case, it would not be safe to attempt opening
 * the file again in the child process, as it might actually be deleted on host.
 */
static int encrypted_file_internal_open(struct libos_encrypted_file* enc, PAL_HANDLE pal_handle,
                                        bool create, pal_share_flags_t share_flags) {
    assert(!enc->pf);

    int ret;
    char* norm_path = NULL;

    if (!pal_handle) {
        enum pal_create_mode create_mode = create ? PAL_CREATE_ALWAYS : PAL_CREATE_NEVER;
        ret = PalStreamOpen(enc->uri, PAL_ACCESS_RDWR, share_flags, create_mode,
                            PAL_OPTION_PASSTHROUGH, &pal_handle);
        if (ret < 0) {
            log_warning("PalStreamOpen failed: %s", pal_strerror(ret));
            return pal_to_unix_errno(ret);
        }
    }

    PAL_STREAM_ATTR pal_attr;
    ret = PalStreamAttributesQueryByHandle(pal_handle, &pal_attr);
    if (ret < 0) {
        log_warning("PalStreamAttributesQueryByHandle failed: %s", pal_strerror(ret));
        ret = pal_to_unix_errno(ret);
        goto out;
    }
    size_t size = pal_attr.pending_size;

    ret = uri_to_normalized_path(enc->uri, &norm_path);
    if (ret < 0)
        goto out;

    pf_context_t* pf;
    lock(&g_keys_lock);
    if (!enc->volume->key->is_set) {
        log_warning("key '%s' is not set", enc->volume->key->name);
        unlock(&g_keys_lock);
        ret = -EACCES;
        goto out;
    }
    pf_mac_t opening_root_gmac;
    pf_status_t pfs = pf_open(pal_handle, norm_path, size, PF_FILE_MODE_READ | PF_FILE_MODE_WRITE,
                              create, &enc->volume->key->pf_key, &opening_root_gmac, &pf);
    unlock(&g_keys_lock);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_open failed: %s", pf_strerror(pfs));
        ret = -EACCES;
        goto out;
    }
    /* rollback protection */
    struct libos_encrypted_volume_state_map* file_state = NULL;
    log_debug("file '%s' opened with MAC=" MAC_PRINTF_PATTERN, norm_path,
              MAC_PRINTF_ARGS(opening_root_gmac));  // TODO (MST): remove me eventually?
    lock(&(enc->volume->files_state_map_lock));
    /* - get current state */
    HASH_FIND_STR(enc->volume->files_state_map, norm_path, file_state);
    /* - check current state */
    if (create) {
        if (file_state && (file_state->state != PF_FILE_STATE_DELETED)) {
            log_error("file '%s' already exists or is in error state", norm_path);
            if (enc->volume->protection_mode != PF_ENCLAVE_LIFE_RB_PROTECTION_NONE) {
                pf_set_corrupted(pf);
                ret = -EEXIST;
                goto out_unlock_map;
            }
        }
    } else {
        if (file_state) {
            if ((file_state->state == PF_FILE_STATE_ERROR) ||
                (file_state->state == PF_FILE_STATE_DELETED)) {
                log_error("file '%s' was seen before but in %s state", norm_path,
                          file_state->state == PF_FILE_STATE_DELETED ? "deleted" : "error");
                if (enc->volume->protection_mode != PF_ENCLAVE_LIFE_RB_PROTECTION_NONE) {
                    pf_set_corrupted(pf);
                    ret = -EACCES;
                    goto out_unlock_map;
                }
            }
            if (memcmp(file_state->last_seen_root_gmac, opening_root_gmac, sizeof(pf_mac_t)) != 0) {
                log_error(
                    "file '%s' was seen before but in different inconsistent (rolled-back?) "
                    "state, expected MAC=" MAC_PRINTF_PATTERN
                    " but file had "
                    "MAC=" MAC_PRINTF_PATTERN,
                    norm_path, MAC_PRINTF_ARGS(file_state->last_seen_root_gmac),
                    MAC_PRINTF_ARGS(opening_root_gmac));
                if (enc->volume->protection_mode != PF_ENCLAVE_LIFE_RB_PROTECTION_NONE) {
                    pf_set_corrupted(pf);
                    ret = -EACCES;
                    goto out_unlock_map;
                }
            }
        } else {
            if (enc->volume->protection_mode == PF_ENCLAVE_LIFE_RB_PROTECTION_STRICT) {
                log_error(
                    "file '%s' was not seen before which is not allowed with strict rollback "
                    "protection mode",
                    norm_path);
                pf_set_corrupted(pf);
                ret = -EACCES;
                goto out_unlock_map;
            }
        }
    }
    /* - uodate map with new state */
    if (file_state == NULL) {
        file_state = malloc(sizeof(struct libos_encrypted_volume_state_map));
        if (file_state == NULL) {
            ret = -ENOMEM;
            goto out_unlock_map;
        }
        file_state->norm_path = norm_path;
        norm_path             = NULL; /* to prevent freeing it */
        HASH_ADD_KEYPTR(hh, enc->volume->files_state_map, file_state->norm_path,
                        strlen(file_state->norm_path), file_state);
    }
    /*   we do below unconditionally as we might recreate a deleted file or overwrite an existing
     *   one */
    memcpy(file_state->last_seen_root_gmac, opening_root_gmac, sizeof(pf_mac_t));
    file_state->state = PF_FILE_STATE_ACTIVE;

    enc->pf = pf;
    enc->pal_handle = pal_handle;
    ret = 0;

out_unlock_map:
    unlock(&(enc->volume->files_state_map_lock));
out:
    free(norm_path);
    if (ret < 0)
        PalObjectDestroy(pal_handle);
    return ret;
}

/* Used only in debug code, no need to be side-channel-resistant. */
int parse_pf_key(const char* key_str, pf_key_t* pf_key) {
    size_t len = strlen(key_str);
    if (len != sizeof(*pf_key) * 2) {
        log_warning("wrong key length (%zu instead of %zu)", len, (size_t)(sizeof(*pf_key) * 2));
        return -EINVAL;
    }

    pf_key_t tmp_pf_key;
    char* bytes = hex2bytes(key_str, len, tmp_pf_key, sizeof(tmp_pf_key));
    if (!bytes) {
        log_warning("unexpected character encountered");
        return -EINVAL;
    }
    memcpy(pf_key, &tmp_pf_key, sizeof(tmp_pf_key));
    return 0;
}

static void encrypted_file_internal_close(struct libos_encrypted_file* enc, bool fs_reachable) {
    assert(enc->pf);
    pf_mac_t closing_root_gmac;
    pf_status_t pfs = pf_close(enc->pf, &closing_root_gmac);
    char* norm_path = NULL;
    int ret         = uri_to_normalized_path(enc->uri, &norm_path);
    if (ret < 0) {
        log_error("Could not normalize uri %s while closing file (ret=%d)", enc->uri, ret);
    } else {
        log_debug("%sreachable file '%s' closed with MAC=" MAC_PRINTF_PATTERN,
                  (fs_reachable ? "" : "un"), norm_path,
                  MAC_PRINTF_ARGS(closing_root_gmac));  // TODO (MST): remove me eventually?
        lock(&(enc->volume->files_state_map_lock));
        struct libos_encrypted_volume_state_map* file_state = NULL;

        HASH_FIND_STR(enc->volume->files_state_map, norm_path, file_state);
        assert(file_state != NULL);
        if (PF_FAILURE(pfs)) {
            log_warning("pf_close failed: %s", pf_strerror(pfs));
            file_state->state = PF_FILE_STATE_ERROR;
            pf_set_corrupted(enc->pf);
        } else {
            if (fs_reachable && (file_state->state == PF_FILE_STATE_ACTIVE)) {
                /* note: we only update if reachable in fileystem to prevent file-handles made
                 * unreachable via unlink or rename to modify state.  We also do not touch it if
                 * earlier we determined this file is in inconsistent error state. */
                memcpy(file_state->last_seen_root_gmac, closing_root_gmac, sizeof(pf_mac_t));
            }
        }
        unlock(&(enc->volume->files_state_map_lock));
        free(norm_path);
    }

    enc->pf = NULL;
    PalObjectDestroy(enc->pal_handle);
    enc->pal_handle = NULL;
    return;
}

static int parse_and_update_key(const char* key_name, const char* key_str) {
    pf_key_t pf_key;
    int ret = parse_pf_key(key_str, &pf_key);
    if (ret < 0) {
        log_error("Cannot parse hex key: '%s'", key_str);
        return ret;
    }

    struct libos_encrypted_files_key* key;
    ret = get_or_create_encrypted_files_key(key_name, &key);
    if (ret < 0)
        return ret;

    update_encrypted_files_key(key, &pf_key);
    return 0;
}

int init_encrypted_files(void) {
    pf_debug_f cb_debug_ptr = NULL;
#ifdef DEBUG
    cb_debug_ptr = &cb_debug;
#endif
    if (!create_lock(&g_keys_lock))
        return -ENOMEM;
    if (!create_lock(&g_volumes_lock))
        return -ENOMEM;

    pf_set_callbacks(&cb_read, &cb_write, &cb_fsync, &cb_truncate,
                     &cb_aes_cmac, &cb_aes_gcm_encrypt, &cb_aes_gcm_decrypt,
                     &cb_random, cb_debug_ptr);

    int ret;

    /* Parse `fs.insecure__keys.*` */

    toml_table_t* manifest_fs = toml_table_in(g_manifest_root, "fs");
    toml_table_t* manifest_fs_keys =
        manifest_fs ? toml_table_in(manifest_fs, "insecure__keys") : NULL;
    if (manifest_fs && manifest_fs_keys) {
        ssize_t keys_cnt = toml_table_nkval(manifest_fs_keys);
        if (keys_cnt < 0)
            return -EINVAL;

        for (ssize_t i = 0; i < keys_cnt; i++) {
            const char* key_name = toml_key_in(manifest_fs_keys, i);
            assert(key_name);

            char* key_str;
            ret = toml_string_in(manifest_fs_keys, key_name, &key_str);
            if (ret < 0) {
                log_error("Cannot parse 'fs.insecure__keys.%s'", key_name);
                return -EINVAL;
            }
            assert(key_str);

            ret = parse_and_update_key(key_name, key_str);
            free(key_str);
            if (ret < 0)
                return ret;
        }
    }

    return 0;
}

static struct libos_encrypted_files_key* get_key(const char* name) {
    assert(locked(&g_keys_lock));

    struct libos_encrypted_files_key* key;
    LISTP_FOR_EACH_ENTRY(key, &g_keys, list) {
        if (!strcmp(key->name, name)) {
            return key;
        }
    }

    return NULL;
}

static struct libos_encrypted_files_key* get_or_create_key(const char* name, bool* out_created) {
    assert(locked(&g_keys_lock));

    struct libos_encrypted_files_key* key = get_key(name);
    if (key) {
        *out_created = false;
        return key;
    }

    key = calloc(1, sizeof(*key));
    if (!key)
        return NULL;
    key->name = strdup(name);
    if (!key->name) {
        free(key);
        return NULL;
    }
    key->is_set = false;
    LISTP_ADD_TAIL(key, &g_keys, list);
    *out_created = true;
    return key;
}

struct libos_encrypted_files_key* get_encrypted_files_key(const char* name) {
    lock(&g_keys_lock);
    struct libos_encrypted_files_key* key = get_key(name);
    unlock(&g_keys_lock);
    return key;
}

int list_encrypted_files_keys(int (*callback)(struct libos_encrypted_files_key* key, void* arg),
                              void* arg) {
    lock(&g_keys_lock);

    int ret;

    struct libos_encrypted_files_key* key;
    LISTP_FOR_EACH_ENTRY(key, &g_keys, list) {
        ret = callback(key, arg);
        if (ret < 0)
            goto out;
    }
    ret = 0;
out:
    unlock(&g_keys_lock);
    return ret;
}

int get_or_create_encrypted_files_key(const char* name,
                                      struct libos_encrypted_files_key** out_key) {
    lock(&g_keys_lock);

    int ret;

    bool created;
    struct libos_encrypted_files_key* key = get_or_create_key(name, &created);
    if (!key) {
        ret = -ENOMEM;
        goto out;
    }

    if (created && name[0] == '_') {
        pf_key_t pf_key;
        size_t size = sizeof(pf_key);
        ret = PalGetSpecialKey(name, &pf_key, &size);

        if (ret == 0) {
            if (size != sizeof(pf_key)) {
                log_debug("PalGetSpecialKey(\"%s\") returned wrong size: %zu", name, size);
                ret = -EINVAL;
                goto out;
            }
            log_debug("Successfully retrieved special key \"%s\"", name);
            memcpy(&key->pf_key, &pf_key, sizeof(pf_key));
            key->is_set = true;
        } else if (ret == PAL_ERROR_NOTIMPLEMENTED) {
            log_debug("Special key \"%s\" is not supported by current PAL. Mounts using this key "
                      "will not work.", name);
            /* proceed without setting value */
        } else {
            log_debug("PalGetSpecialKey(\"%s\") failed: %s", name, pal_strerror(ret));
            ret = pal_to_unix_errno(ret);
            goto out;
        }
    }

    *out_key = key;
    ret = 0;
out:
    unlock(&g_keys_lock);
    return ret;
}

bool read_encrypted_files_key(struct libos_encrypted_files_key* key, pf_key_t* pf_key) {
    lock(&g_keys_lock);
    bool is_set = key->is_set;
    if (is_set) {
        memcpy(pf_key, &key->pf_key, sizeof(key->pf_key));
    }
    unlock(&g_keys_lock);
    return is_set;
}

void update_encrypted_files_key(struct libos_encrypted_files_key* key, const pf_key_t* pf_key) {
    lock(&g_keys_lock);
    memcpy(&key->pf_key, pf_key, sizeof(*pf_key));
    key->is_set = true;
    unlock(&g_keys_lock);
}

static struct libos_encrypted_volume* get_volume(const char* mount_point_path) {
    assert(locked(&g_volumes_lock));

    struct libos_encrypted_volume* volume;
    LISTP_FOR_EACH_ENTRY(volume, &g_volumes, list) {
        if (!strcmp(volume->mount_point_path, mount_point_path)) {
            return volume;
        }
    }

    return NULL;
}

int register_encrypted_volume(struct libos_encrypted_volume* volume) {
    assert(volume && volume->mount_point_path);

    lock(&g_volumes_lock);

    int ret = 0;

    struct libos_encrypted_volume* existing_volume = get_volume(volume->mount_point_path);
    if (existing_volume) {
        ret = -EEXIST;
        goto out;
    }
    LISTP_ADD_TAIL(volume, &g_volumes, list);
out:
    unlock(&g_volumes_lock);
    return ret;
}

struct libos_encrypted_volume* get_encrypted_volume(const char* mount_point_path) {
    lock(&g_volumes_lock);
    struct libos_encrypted_volume* volume = get_volume(mount_point_path);
    unlock(&g_volumes_lock);
    return volume;
}

int list_encrypted_volumes(int (*callback)(struct libos_encrypted_volume* volume, void* arg),
                           void* arg) {
    lock(&g_volumes_lock);

    int ret;

    struct libos_encrypted_volume* volume;
    LISTP_FOR_EACH_ENTRY(volume, &g_volumes, list) {
        ret = callback(volume, arg);
        if (ret < 0)
            goto out;
    }
    ret = 0;
out:
    unlock(&g_volumes_lock);
    return ret;
}

static int encrypted_file_alloc(const char* uri, struct libos_encrypted_volume* volume,
                                struct libos_encrypted_file** out_enc) {
    assert(strstartswith(uri, URI_PREFIX_FILE));

    if (!volume) {
        log_debug("trying to open a file (%s) before volume is set", uri);
        return -EACCES;
    }

    struct libos_encrypted_file* enc = malloc(sizeof(*enc));
    if (!enc)
        return -ENOMEM;

    int ret;
    enc->uri = NULL;

    enc->uri = strdup(uri);
    if (!enc->uri) {
        ret = -ENOMEM;
        goto err;
    }

    enc->volume     = volume;
    enc->use_count = 0;
    enc->pf = NULL;
    enc->pal_handle = NULL;
    *out_enc = enc;
    return 0;

err:
    if (enc) {
        if (enc->uri)
            free(enc->uri);
        free(enc);
    }
    return ret;
}

int encrypted_file_open(const char* uri, struct libos_encrypted_volume* volume,
                        struct libos_encrypted_file** out_enc) {
    struct libos_encrypted_file* enc;
    int ret = encrypted_file_alloc(uri, volume, &enc);
    if (ret < 0)
        return ret;

    ret = encrypted_file_internal_open(enc, /*pal_handle=*/NULL, /*create=*/false,
                                       /*share_flags=*/0);
    if (ret < 0) {
        encrypted_file_destroy(enc);
        return ret;
    }
    enc->use_count++;
    *out_enc = enc;
    return 0;
}

int encrypted_file_create(const char* uri, mode_t perm, struct libos_encrypted_volume* volume,
                          struct libos_encrypted_file** out_enc) {
    struct libos_encrypted_file* enc;
    int ret = encrypted_file_alloc(uri, volume, &enc);
    if (ret < 0)
        return ret;

    ret = encrypted_file_internal_open(enc, /*pal_handle=*/NULL, /*create=*/true, perm);
    if (ret < 0) {
        encrypted_file_destroy(enc);
        return ret;
    }
    enc->use_count++;
    *out_enc = enc;
    return 0;
}

void encrypted_file_destroy(struct libos_encrypted_file* enc) {
    assert(enc->use_count == 0);
    assert(!enc->pf);
    assert(!enc->pal_handle);
    free(enc->uri);
    free(enc);
}

int encrypted_file_get(struct libos_encrypted_file* enc) {
    if (enc->use_count > 0) {
        assert(enc->pf);
        enc->use_count++;
        return 0;
    }
    assert(!enc->pf);
    int ret = encrypted_file_internal_open(enc, /*pal_handle=*/NULL, /*create=*/false,
                                           /*share_flags=*/0);
    if (ret < 0)
        return ret;
    enc->use_count++;
    return 0;
}

void encrypted_file_put(struct libos_encrypted_file* enc, bool fs_reachable) {
    assert(enc->use_count > 0);
    assert(enc->pf);
    enc->use_count--;
    if (enc->use_count == 0) {
        encrypted_file_internal_close(enc, fs_reachable);
    }
}

int encrypted_file_flush(struct libos_encrypted_file* enc) {
    assert(enc->pf);

    pf_status_t pfs = pf_flush(enc->pf);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_flush failed: %s", pf_strerror(pfs));
        return -EACCES;
    }
    return 0;
}

int encrypted_file_read(struct libos_encrypted_file* enc, void* buf, size_t buf_size,
                        file_off_t offset, size_t* out_count) {
    assert(enc->pf);

    if (offset < 0)
        return -EINVAL;
    if (OVERFLOWS(uint64_t, offset))
        return -EOVERFLOW;

    size_t count;
    pf_status_t pfs = pf_read(enc->pf, offset, buf_size, buf, &count);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_read failed: %s", pf_strerror(pfs));
        return -EACCES;
    }
    *out_count = count;
    return 0;
}

int encrypted_file_write(struct libos_encrypted_file* enc, const void* buf, size_t buf_size,
                         file_off_t offset, size_t* out_count) {
    assert(enc->pf);

    if (offset < 0)
        return -EINVAL;
    if (OVERFLOWS(uint64_t, offset))
        return -EOVERFLOW;

    pf_status_t pfs = pf_write(enc->pf, offset, buf_size, buf);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_write failed: %s", pf_strerror(pfs));
        return -EACCES;
    }
    /* We never write less than `buf_size` */
    *out_count = buf_size;
    return 0;
}

int encrypted_file_get_size(struct libos_encrypted_file* enc, file_off_t* out_size) {
    assert(enc->pf);

    uint64_t size;
    pf_status_t pfs = pf_get_size(enc->pf, &size);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_get_size failed: %s", pf_strerror(pfs));
        return -EACCES;
    }
    if (OVERFLOWS(file_off_t, size))
        return -EOVERFLOW;
    *out_size = size;
    return 0;
}

int encrypted_file_set_size(struct libos_encrypted_file* enc, file_off_t size) {
    assert(enc->pf);

    if (size < 0)
        return -EINVAL;
    if (OVERFLOWS(uint64_t, size))
        return -EOVERFLOW;

    pf_status_t pfs = pf_set_size(enc->pf, size);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_set_size failed: %s", pf_strerror(pfs));
        return -EACCES;
    }
    return 0;
}

int encrypted_file_rename(struct libos_encrypted_file* enc, const char* new_uri) {
    assert(enc->pf);

    char* new_uri_copy = strdup(new_uri);
    if (!new_uri_copy)
        return -ENOMEM;

    int ret;
    char* new_norm_path = NULL;
    char* old_norm_path = NULL;
    ret                 = uri_to_normalized_path(enc->uri, &old_norm_path);
    if (ret < 0)
        goto out;
    ret = uri_to_normalized_path(new_uri, &new_norm_path);
    if (ret < 0)
        goto out;

    pf_mac_t new_root_gmac;
    pf_status_t pfs = pf_rename(enc->pf, new_norm_path, &new_root_gmac);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_rename failed: %s", pf_strerror(pfs));
        ret = -EACCES;
        goto out;
    }

    ret = PalStreamChangeName(enc->pal_handle, new_uri);
    if (ret < 0) {
        log_warning("PalStreamChangeName failed: %s", pal_strerror(ret));

        /* We failed to rename the file. Try to restore the name in header. */
        pfs = pf_rename(enc->pf, old_norm_path, &new_root_gmac);
        if (PF_FAILURE(pfs)) {
            log_warning("pf_rename (during cleanup) failed, the file might be unusable: %s",
                        pf_strerror(pfs));
        }
        old_norm_path = NULL;  // don't free it later ...
        ret = pal_to_unix_errno(ret);
        goto out;
    }
    /* update file state map */
    log_debug("file '%s' renamed to '%s' with MAC=" MAC_PRINTF_PATTERN, old_norm_path,
              new_norm_path,
              MAC_PRINTF_ARGS(new_root_gmac));  // TODO (MST): remove me eventually?
    lock(&(enc->volume->files_state_map_lock));
    struct libos_encrypted_volume_state_map* old_file_state = NULL;
    HASH_FIND_STR(enc->volume->files_state_map, old_norm_path, old_file_state);
    assert(old_file_state != NULL);
    struct libos_encrypted_volume_state_map* new_file_state = NULL;
    HASH_FIND_STR(enc->volume->files_state_map, new_norm_path, new_file_state);
    if (new_file_state == NULL) {
        new_file_state = malloc(sizeof(struct libos_encrypted_volume_state_map));
        if (new_file_state == NULL) {
            ret = -ENOMEM;
            goto out;
        }
        new_file_state->norm_path = new_norm_path;
        HASH_ADD_KEYPTR(hh, enc->volume->files_state_map, new_file_state->norm_path,
                        strlen(new_file_state->norm_path), new_file_state);
    } else {
        free(new_norm_path); /* should be same as old one used during HASH_ADD */
        new_norm_path = new_file_state->norm_path;
    }
    new_file_state->state = old_file_state->state;
    memcpy(new_file_state->last_seen_root_gmac, new_root_gmac, sizeof(pf_mac_t));
    old_file_state->state = PF_FILE_STATE_DELETED; /* note: this might remove error state from that
                                                      file but that is fine as it is deleted now. */
    memset(old_file_state->last_seen_root_gmac, 0, sizeof(pf_mac_t));
    unlock(&(enc->volume->files_state_map_lock));

    free(enc->uri);
    enc->uri       = new_uri_copy;
    new_uri_copy   = NULL;
    new_norm_path  = NULL;

    ret = 0;

out:
    if (ret) {
        // store in file state map fact that we could not rename file properly
        if (!locked(&(enc->volume->files_state_map_lock)))  // for OOM case from above!
            lock(&(enc->volume->files_state_map_lock));
        if (old_file_state == NULL)  // we might already have it!
            HASH_FIND_STR(enc->volume->files_state_map, old_norm_path, old_file_state);
        assert(old_file_state != NULL);
        old_file_state->state = PF_FILE_STATE_ERROR;
        pf_set_corrupted(enc->pf);
        unlock(&(enc->volume->files_state_map_lock));
    }
    free(old_norm_path);
    free(new_norm_path);
    free(new_uri_copy);
    return ret;
}

int encrypted_file_unlink(struct libos_encrypted_file* enc) {
    char* norm_path = NULL;
    int ret         = uri_to_normalized_path(enc->uri, &norm_path);
    if (ret < 0)
        return ret;

    lock(&(enc->volume->files_state_map_lock));
    struct libos_encrypted_volume_state_map* file_state = NULL;
    HASH_FIND_STR(enc->volume->files_state_map, norm_path, file_state);
    assert(file_state != NULL);
    pf_mac_t root_gmac_before_unlink;
    memcpy(root_gmac_before_unlink, file_state->last_seen_root_gmac, sizeof(pf_mac_t));
    file_state->state = PF_FILE_STATE_DELETED;
    memset(file_state->last_seen_root_gmac, 0, sizeof(pf_mac_t));
    unlock(&(enc->volume->files_state_map_lock));
    log_debug("file '%s' unlinked, previously with MAC=" MAC_PRINTF_PATTERN, norm_path,
              MAC_PRINTF_ARGS(root_gmac_before_unlink));  // TODO (MST): remove me eventually?
    return 0;
}

/* Checkpoint the `g_keys` list. */
BEGIN_CP_FUNC(all_encrypted_files_keys) {
    __UNUSED(size);
    __UNUSED(obj);
    __UNUSED(objp);

    lock(&g_keys_lock);
    struct libos_encrypted_files_key* key;
    LISTP_FOR_EACH_ENTRY(key, &g_keys, list) {
        DO_CP(encrypted_files_key, key, /*objp=*/NULL);
    }
    unlock(&g_keys_lock);
}
END_CP_FUNC_NO_RS(all_encrypted_files_keys)

BEGIN_CP_FUNC(encrypted_files_key) {
    __UNUSED(size);

    assert(locked(&g_keys_lock));

    struct libos_encrypted_files_key* key     = obj;
    struct libos_encrypted_files_key* new_key = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct libos_encrypted_files_key));
        ADD_TO_CP_MAP(obj, off);
        new_key = (struct libos_encrypted_files_key*)(base + off);

        DO_CP_MEMBER(str, key, new_key, name);
        new_key->is_set = key->is_set;
        memcpy(&new_key->pf_key, &key->pf_key, sizeof(key->pf_key));
        INIT_LIST_HEAD(new_key, list);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_key = (struct libos_encrypted_files_key*)(base + off);
    }

    if (objp)
        *objp = (void*)new_key;
}
END_CP_FUNC(encrypted_files_key)

BEGIN_RS_FUNC(encrypted_files_key) {
    __UNUSED(offset);
    struct libos_encrypted_files_key* migrated_key = (void*)(base + GET_CP_FUNC_ENTRY());

    CP_REBASE(migrated_key->name);

    /*
     * NOTE: We do not add `migrated_key` directly to the list, because a key with this name might
     * already have been created (e.g. during `init_encrypted_files`). Instead, we retrieve (or
     * create) a key in the usual way, and update its value.
     */
    struct libos_encrypted_files_key* key;
    int ret = get_or_create_encrypted_files_key(migrated_key->name, &key);
    if (ret < 0)
        return ret;

    lock(&g_keys_lock);
    key->is_set = migrated_key->is_set;
    memcpy(&key->pf_key, &migrated_key->pf_key, sizeof(migrated_key->pf_key));
    unlock(&g_keys_lock);
}
END_RS_FUNC(encrypted_files_key)

/* Checkpoint the `g_volumes` list.  Note we only call this to checkpoint all volumes.  The list
 * itself is not checkpointed (and hence also no corresponding restore function).  The list is
 * reconstructed in the restore function of the volumes itself. */
BEGIN_CP_FUNC(all_encrypted_volumes) {
    __UNUSED(size);
    __UNUSED(obj);
    __UNUSED(objp);

    lock(&g_volumes_lock);
    struct libos_encrypted_volume* volume;
    LISTP_FOR_EACH_ENTRY(volume, &g_volumes, list) {
        DO_CP(encrypted_volume, volume, /*objp=*/NULL);
    }
    unlock(&g_volumes_lock);
}
END_CP_FUNC_NO_RS(all_encrypted_volumes)

BEGIN_CP_FUNC(encrypted_volume) {
    __UNUSED(size);

    struct libos_encrypted_volume* volume     = obj;
    struct libos_encrypted_volume* new_volume = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) { /* We haven't already checkpointed this volume */
        off = ADD_CP_OFFSET(sizeof(struct libos_encrypted_volume));
        ADD_TO_CP_MAP(obj, off);
        new_volume = (struct libos_encrypted_volume*)(base + off);

        log_debug("CP(encrypted_volume): mount_point_path=%s protection_mode=%d file_state_mape=%p",
                  volume->mount_point_path, volume->protection_mode,
                  volume->files_state_map);  // TODO (MST): remove me eventually?
        DO_CP_MEMBER(str, volume, new_volume, mount_point_path);
        new_volume->protection_mode = volume->protection_mode;
        lock(&volume->files_state_map_lock);
        /* Note: for now we do not serialize hashmap so just make sure it is treated as empty list.
         * Serialization would cover some corner cases, e.g., `send_handle_enc` test case might work
         * in strict and not only in non-strict mode. However, checkpoint/restore with current
         * framework does not provide a low-hanging fruit. For other reasons (persistant rollback
         * protection) we will need file-based (de)serialization and so could use that here.
         * However, to really solve multi-processor case, we have to adopt the same strategy as for
         * file locks, i.e., a leader-based centralized map and IPC to access/modify. Hence, no
         * point in doing some complicated interim throw-away variant. */
        new_volume->files_state_map = NULL;
        unlock(&volume->files_state_map_lock);
        /* files_state_map_lock has no check point, it will be recreated in restore */
        lock(&g_keys_lock);
        DO_CP_MEMBER(encrypted_files_key, volume, new_volume, key);
        unlock(&g_keys_lock);
        INIT_LIST_HEAD(new_volume, list);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_volume = (struct libos_encrypted_volume*)(base + off);
    }
    if (objp)
        *objp = (void*)new_volume;
}
END_CP_FUNC(encrypted_volume)

BEGIN_RS_FUNC(encrypted_volume) {
    __UNUSED(offset);
    struct libos_encrypted_volume* migrated_volume = (void*)(base + GET_CP_FUNC_ENTRY());

    CP_REBASE(migrated_volume->mount_point_path);

    /* protection_mode needs no restore action. */
    /* files_state_map for now is not serialized but just an empty list, so no restore action
     * needed. See above in checkpoint for more information. */
    if (!create_lock(&migrated_volume->files_state_map_lock)) {
        return -ENOMEM;
    }
    CP_REBASE(migrated_volume->key);
    log_debug("RS(encrypted_volume): mount_point_path=%s protection_mode=%d file_state_mape=%p",
              migrated_volume->mount_point_path, migrated_volume->protection_mode,
              migrated_volume->files_state_map);  // TODO (MST): remove me eventually?

    int ret = register_encrypted_volume(migrated_volume);
    if (ret < 0)
        return ret;
}
END_RS_FUNC(encrypted_volume)

BEGIN_CP_FUNC(encrypted_file) {
    __UNUSED(size);

    struct libos_encrypted_file* enc = obj;
    struct libos_encrypted_file* new_enc = NULL;

    if (enc->pf) {
        int ret = encrypted_file_flush(enc);
        if (ret < 0)
            return ret;
    }

    size_t off = ADD_CP_OFFSET(sizeof(struct libos_encrypted_file));
    new_enc = (struct libos_encrypted_file*)(base + off);

    new_enc->use_count = enc->use_count;
    DO_CP_MEMBER(str, enc, new_enc, uri);

    DO_CP_MEMBER(encrypted_volume, enc, new_enc, volume);

    /* `enc->pf` will be recreated during restore */
    new_enc->pf = NULL;

    if (enc->pal_handle) {
        struct libos_palhdl_entry* entry;
        DO_CP(palhdl_ptr, &enc->pal_handle, &entry);
        entry->phandle = &new_enc->pal_handle;
    }
    ADD_CP_FUNC_ENTRY(off);

    if (objp)
        *objp = new_enc;
}
END_CP_FUNC(encrypted_file)

BEGIN_RS_FUNC(encrypted_file) {
    struct libos_encrypted_file* enc = (void*)(base + GET_CP_FUNC_ENTRY());
    __UNUSED(offset);

    CP_REBASE(enc->uri);

    CP_REBASE(enc->volume);

    /* If the file was used, recreate `enc->pf` based on the PAL handle */
    assert(!enc->pf);
    if (enc->use_count > 0) {
        assert(enc->pal_handle);
        int ret = encrypted_file_internal_open(enc, enc->pal_handle, /*create=*/false,
                                               /*share_flags=*/0);
        if (ret < 0)
            return ret;
    } else {
        assert(!enc->pal_handle);
    }
}
END_RS_FUNC(encrypted_file)
