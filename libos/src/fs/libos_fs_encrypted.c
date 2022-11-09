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

static pf_status_t cb_read(pf_handle_t handle, void* buffer, uint64_t offset, size_t size) {
    PAL_HANDLE pal_handle = (PAL_HANDLE)handle;

    size_t buffer_offset = 0;
    size_t remaining = size;

    while (remaining > 0) {
        size_t count = remaining;
        int ret = PalStreamRead(pal_handle, offset + buffer_offset, &count, buffer + buffer_offset);
        if (ret == -PAL_ERROR_INTERRUPTED)
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
        if (ret == -PAL_ERROR_INTERRUPTED)
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

/*
 * The `pal_handle` parameter is used if this is a checkpointed file, and we have received the PAL
 * handle from the parent process. Note that in this case, it would not be safe to attempt opening
 * the file again in the child process, as it might actually be deleted on host.
 */
static int encrypted_file_internal_open(struct libos_encrypted_file* enc, PAL_HANDLE pal_handle,
                                        bool create, pal_share_flags_t share_flags) {
    assert(!enc->pf);

    int ret;
    char* normpath = NULL;

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

    assert(strstartswith(enc->uri, URI_PREFIX_FILE));
    const char* path = enc->uri + static_strlen(URI_PREFIX_FILE);

    size_t normpath_size = strlen(path) + 1;
    normpath = malloc(normpath_size);
    if (!normpath) {
        ret = -ENOMEM;
        goto out;
    }

    if (!get_norm_path(path, normpath, &normpath_size)) {
        ret = -EINVAL;
        goto out;
    }

    pf_context_t* pf;
    lock(&g_keys_lock);
    if (!enc->key->is_set) {
        log_warning("key '%s' is not set", enc->key->name);
        unlock(&g_keys_lock);
        ret = -EACCES;
        goto out;
    }
    pf_status_t pfs = pf_open(pal_handle, normpath, size, PF_FILE_MODE_READ | PF_FILE_MODE_WRITE,
                              create, &enc->key->pf_key, &pf);
    unlock(&g_keys_lock);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_open failed: %s", pf_strerror(pfs));
        ret = -EACCES;
        goto out;
    }

    enc->pf = pf;
    enc->pal_handle = pal_handle;
    ret = 0;
out:
    free(normpath);
    if (ret < 0)
        PalObjectClose(pal_handle);
    return ret;
}

/* Used only in debug code / by deprecated options, no need to be side-channel-resistant. */
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

int dump_pf_key(const pf_key_t* pf_key, char* buf, size_t buf_size) {
    if (buf_size < sizeof(*pf_key) * 2 + 1)
        return -EINVAL;

    bytes2hex(pf_key, sizeof(*pf_key), buf, buf_size);
    return 0;
}

static void encrypted_file_internal_close(struct libos_encrypted_file* enc) {
    assert(enc->pf);

    pf_status_t pfs = pf_close(enc->pf);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_close failed: %s", pf_strerror(pfs));
    }

    enc->pf = NULL;
    PalObjectClose(enc->pal_handle);
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

    pf_set_callbacks(&cb_read, &cb_write, &cb_truncate,
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

    /*
     * If we're under SGX PAL, parse `sgx.insecure__protected_files_key` (and interpret it as the
     * "default" key).
     *
     * TODO: this is deprecated in v1.2, remove two versions later.
     */
    if (!strcmp(g_pal_public_state->host_type, "Linux-SGX")) {
        char* key_str;
        ret = toml_string_in(g_manifest_root, "sgx.insecure__protected_files_key", &key_str);
        if (ret < 0) {
            log_error("Cannot parse 'sgx.insecure__protected_files_key'");
            return -EINVAL;
        }

        if (key_str) {
            log_error("Detected deprecated syntax: 'sgx.insecure__protected_files_key'. "
                      "Consider converting it to 'fs.insecure__keys.default'.");

            ret = parse_and_update_key("default", key_str);
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
        } else if (ret == -PAL_ERROR_NOTIMPLEMENTED) {
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

static int encrypted_file_alloc(const char* uri, struct libos_encrypted_files_key* key,
                                struct libos_encrypted_file** out_enc) {
    assert(strstartswith(uri, URI_PREFIX_FILE));

    if (!key) {
        log_debug("trying to open a file (%s) before key is set", uri);
        return -EACCES;
    }

    struct libos_encrypted_file* enc = malloc(sizeof(*enc));
    if (!enc)
        return -ENOMEM;

    enc->uri = strdup(uri);
    if (!enc->uri) {
        free(enc);
        return -ENOMEM;
    }
    enc->key = key;
    enc->use_count = 0;
    enc->pf = NULL;
    enc->pal_handle = NULL;
    *out_enc = enc;
    return 0;
}

int encrypted_file_open(const char* uri, struct libos_encrypted_files_key* key,
                        struct libos_encrypted_file** out_enc) {
    struct libos_encrypted_file* enc;
    int ret = encrypted_file_alloc(uri, key, &enc);
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

int encrypted_file_create(const char* uri, mode_t perm, struct libos_encrypted_files_key* key,
                          struct libos_encrypted_file** out_enc) {
    struct libos_encrypted_file* enc;
    int ret = encrypted_file_alloc(uri, key, &enc);
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

void encrypted_file_put(struct libos_encrypted_file* enc) {
    assert(enc->use_count > 0);
    assert(enc->pf);
    enc->use_count--;
    if (enc->use_count == 0) {
        encrypted_file_internal_close(enc);
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

    int ret;
    char* new_normpath = NULL;

    char* new_uri_copy = strdup(new_uri);
    if (!new_uri_copy)
        return -ENOMEM;

    assert(strstartswith(enc->uri, URI_PREFIX_FILE));
    const char* old_path = enc->uri + static_strlen(URI_PREFIX_FILE);

    assert(strstartswith(new_uri, URI_PREFIX_FILE));
    const char* new_path = new_uri + static_strlen(URI_PREFIX_FILE);

    size_t new_normpath_size = strlen(new_path) + 1;
    new_normpath = malloc(new_normpath_size);
    if (!new_normpath) {
        ret = -ENOMEM;
        goto out;
    }

    if (!get_norm_path(new_path, new_normpath, &new_normpath_size)) {
        ret = -EINVAL;
        goto out;
    }

    pf_status_t pfs = pf_rename(enc->pf, new_normpath);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_rename failed: %s", pf_strerror(pfs));
        ret = -EACCES;
        goto out;
    }

    ret = PalStreamChangeName(enc->pal_handle, new_uri);
    if (ret < 0) {
        log_warning("PalStreamChangeName failed: %s", pal_strerror(ret));

        /* We failed to rename the file. Try to restore the name in header. */
        pfs = pf_rename(enc->pf, old_path);
        if (PF_FAILURE(pfs)) {
            log_warning("pf_rename (during cleanup) failed, the file might be unusable: %s",
                        pf_strerror(pfs));
        }

        ret = pal_to_unix_errno(ret);
        goto out;
    }

    free(enc->uri);
    enc->uri = new_uri_copy;
    new_uri_copy = NULL;
    ret = 0;

out:
    free(new_normpath);
    free(new_uri_copy);
    return ret;
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

    lock(&g_keys_lock);
    DO_CP_MEMBER(encrypted_files_key, enc, new_enc, key);
    unlock(&g_keys_lock);

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
    CP_REBASE(enc->key);

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
