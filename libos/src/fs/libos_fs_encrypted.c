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
    PAL_HANDLE recovery_file_pal_handle = NULL;
    size_t recovery_file_size = 0;
    bool try_recover = !create && !pal_handle;

    if (!pal_handle) {
        enum pal_create_mode create_mode = create ? PAL_CREATE_ALWAYS : PAL_CREATE_NEVER;
        ret = PalStreamOpen(enc->uri, PAL_ACCESS_RDWR, share_flags, create_mode,
                            /*options=*/0, &pal_handle);
        if (ret < 0) {
            log_warning("PalStreamOpen failed: %s", pal_strerror(ret));
            return pal_to_unix_errno(ret);
        }

        if (enc->enable_recovery) {
            char* recovery_file_uri = alloc_concat(enc->uri, -1, RECOVERY_FILE_URI_SUFFIX, -1);
            if (!recovery_file_uri) {
                ret = -ENOMEM;
                goto out;
            }

            ret = PalStreamOpen(recovery_file_uri, PAL_ACCESS_RDWR, RECOVERY_FILE_PERM_RW,
                                PAL_CREATE_TRY, /*options=*/0, &recovery_file_pal_handle);
            free(recovery_file_uri);
            if (ret < 0) {
                log_warning("PalStreamOpen failed: %s", pal_strerror(ret));
                ret = pal_to_unix_errno(ret);
                goto out;
            }

            PAL_STREAM_ATTR pal_attr;
            ret = PalStreamAttributesQueryByHandle(recovery_file_pal_handle, &pal_attr);
            if (ret < 0) {
                log_warning("PalStreamAttributesQueryByHandle failed: %s", pal_strerror(ret));
                ret = pal_to_unix_errno(ret);
                goto out;
            }
            recovery_file_size = pal_attr.pending_size;
        }
    }
    assert(enc->enable_recovery == (recovery_file_pal_handle != NULL));

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
                              create, &enc->key->pf_key, recovery_file_pal_handle,
                              recovery_file_size, try_recover, &pf);
    unlock(&g_keys_lock);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_open failed: %s", pf_strerror(pfs));
        ret = -EACCES;
        goto out;
    }

    enc->pf = pf;
    enc->pal_handle = pal_handle;
    enc->recovery_file_pal_handle = recovery_file_pal_handle;
    ret = 0;
out:
    if (normpath)
        free(normpath);
    if (ret < 0) {
        PalObjectDestroy(pal_handle);
        if (recovery_file_pal_handle)
            PalObjectDestroy(recovery_file_pal_handle);
    }
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


static void encrypted_file_internal_close(struct libos_encrypted_file* enc) {
    assert(enc->pf);

    pf_status_t pfs = pf_close(enc->pf);
    if (PF_FAILURE(pfs)) {
        log_warning("pf_close failed: %s", pf_strerror(pfs));
        /* `pf_close` may fail due to a recoverable flush error; keep the recovery file for
         * potential recovery. */
        goto out;
    }

    if (enc->recovery_file_pal_handle)
        (void)PalStreamDelete(enc->recovery_file_pal_handle, PAL_DELETE_ALL);

out:
    enc->pf = NULL;
    PalObjectDestroy(enc->pal_handle);
    enc->pal_handle = NULL;
    if (enc->recovery_file_pal_handle)
        PalObjectDestroy(enc->recovery_file_pal_handle);
    enc->recovery_file_pal_handle = NULL;
}

static int encrypted_file_copy_contents(struct libos_encrypted_file* dest,
                                        struct libos_encrypted_file* src) {
    assert(dest->pf);
    assert(src->pf);
    int ret;
    char * buf = NULL;
    file_off_t buf_size = 0;
    ret = encrypted_file_get_size(src, &buf_size);
    if (ret < 0) {
        log_error("copy content: encrypted_file_get_size failed for %s: %d", src->uri, ret);
        goto out;
    }

    buf = malloc(buf_size);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }
    file_off_t remaining_read = buf_size;
    while (remaining_read > 0) {
        size_t read_size;
        ret = encrypted_file_read(src, buf + (buf_size - remaining_read), remaining_read,
                                  buf_size - remaining_read, &read_size);
        if (ret < 0) {
            log_error("copy content: encrypted_file_read failed for %s: %d", src->uri, ret);
            goto out;
        }
        remaining_read -= read_size;
    }

    // write the data to the new file
    size_t remaining_write = buf_size;
    while (remaining_write > 0) {
        size_t write_size;
        ret = encrypted_file_write(dest, buf + (buf_size - remaining_write), remaining_write,
                                   buf_size - remaining_write, &write_size);
        if (ret < 0) {
            log_error("copy content: encrypted_file_write failed for %s: %d", dest->uri, ret);
            goto out;
        }
        remaining_write -= write_size;
    }
out:
    if (buf)
        free(buf);
    return ret;
}


static int create_encrypted_files_key(const char* name,
                                      struct libos_encrypted_files_key** out_key) {
    if (name[0] != '_') {
        return -EINVAL;
    }

    int ret;

    struct libos_encrypted_files_key* key =  NULL;
    key = calloc(1, sizeof(*key));
    if (!key){
        ret = -ENOMEM;
        goto out;
    }
    key->name = strdup(name);
    if (!key->name) {
        ret = -ENOMEM;
        goto out;
    }

    pf_key_t pf_key;
    size_t size = sizeof(pf_key);
    ret = PalGetSpecialKey(name, &pf_key, &size);

    if (ret == 0) {
        if (size != sizeof(pf_key)) {
            ret = -EINVAL;
            goto out;
        }
        memcpy(&key->pf_key, &pf_key, sizeof(pf_key));
        key->is_set = true;
    } else if (ret == PAL_ERROR_NOTIMPLEMENTED) {
        log_warning(
            "Special key \"%s\" is not supported by current PAL. Mounts using this key "
            "will not work.",
            name);
        /* proceed without setting value */
    } else {
        log_error("PalGetSpecialKey(\"%s\") failed: %s", name, pal_strerror(ret));
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    *out_key = key;
    ret = 0;
out:
    if (ret < 0) {
        if (key) {
            if (key->name)
                free(key->name);
            free(key);
        }
    }
    return ret;
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

static int migrate_file(const char* uri, struct libos_encrypted_files_key* old_key,
                        struct libos_encrypted_files_key* new_key) {
    struct libos_encrypted_file* new_encrypted_file = NULL;
    struct libos_encrypted_file* old_encrypted_file = NULL;
    char* old_file_uri = NULL;
    int ret = encrypted_file_open(uri, old_key, /*enable_recovery=*/false, &old_encrypted_file);
    if (ret < 0) {
        log_error("migrate: encrypted_file_open failed for %s: %d", uri, ret);
        return ret;
    }

    old_file_uri = alloc_concat(uri, -1, OLD_TCB_FILE_URI_SUFFIX, -1);
    // save the old file
    ret = encrypted_file_rename(old_encrypted_file, old_file_uri);
    free(old_file_uri);
    if (ret < 0) {
        log_error("migrate: encrypted_file_rename failed for %s: %d", uri, ret);
        goto out;
    }
    PAL_STREAM_ATTR pal_attr;
    ret = PalStreamAttributesQueryByHandle(old_encrypted_file->pal_handle, &pal_attr);
    if (ret < 0) {
        log_warning("PalStreamAttributesQueryByHandle failed: %s", pal_strerror(ret));
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    ret = encrypted_file_create(uri, pal_attr.share_flags, new_key, /*enable_recovery=*/false,
                                &new_encrypted_file);
    if (ret < 0) {
        log_error("migrate: encrypted_file_create failed for %s: %d", uri, ret);
        goto out;
    }

    ret = encrypted_file_copy_contents(new_encrypted_file, old_encrypted_file);
    if (ret < 0) {
        log_error("migrate: encrypted_file_copy_contents failed for %s: %d", uri, ret);
        goto out;
    }

out:
    if (old_encrypted_file) {
        encrypted_file_put(old_encrypted_file);
        encrypted_file_destroy(old_encrypted_file);
    }
    if (new_encrypted_file) {
        encrypted_file_put(new_encrypted_file);
        encrypted_file_destroy(new_encrypted_file);
    }
    return ret;
}

static int migrate_dir(const char* uri, struct libos_encrypted_files_key* old_key,
                       struct libos_encrypted_files_key* new_key) {
    char* sub_entry_uri = NULL;
    char* buf = NULL;
    size_t buf_size = READDIR_BUF_SIZE;
    PAL_HANDLE palhdl;
    int ret = PalStreamOpen(uri, PAL_ACCESS_RDONLY, /*share_flags=*/0, PAL_CREATE_NEVER,
                            /*options=*/0, &palhdl);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
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

        /* Read all entries (separated by null bytes) and invoke `migrate` on each */
        size_t start = 0;
        while (start < read_size - 1) {
            size_t end = start + strlen(&buf[start]);

            if (end == start) {
                log_error("migrate: empty name returned from PAL");
                BUG();
            }

            if (!strcmp(&buf[start], TCB_INFO_FILE_NAME)) {
                start = end + 1;
                continue;
            }

            /* By the PAL convention, if a name ends with '/', it is a directory. */
            if (buf[end - 1] == '/') {
                if (uri[strlen(uri) - 1] == '/')
                    sub_entry_uri = alloc_concat(uri, -1, &buf[start], -1);
                else
                    sub_entry_uri = alloc_concat3(uri, -1, "/", 1, &buf[start], -1);
                if (!sub_entry_uri) {
                    ret = -ENOMEM;
                    goto out;
                }
                log_debug("migrating directory %s", sub_entry_uri);

                if ((ret = migrate_dir(sub_entry_uri, old_key, new_key)) < 0)
                    goto out;
            } else {
                if (uri[strlen(uri) - 1] == '/')
                    sub_entry_uri = alloc_concat3(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN,
                                                  uri + URI_PREFIX_DIR_LEN, -1, &buf[start], -1);
                else {
                    size_t sub_entry_uri_len = URI_PREFIX_FILE_LEN + strlen(uri) -
                                               URI_PREFIX_DIR_LEN + 1 + strlen(&buf[start]) + 1;
                    sub_entry_uri = malloc(sub_entry_uri_len);
                    if (!sub_entry_uri) {
                        ret = -ENOMEM;
                        goto out;
                    }
                    snprintf(sub_entry_uri, sub_entry_uri_len, "%s%s/%s", URI_PREFIX_FILE,
                             uri + URI_PREFIX_DIR_LEN, &buf[start]);
                }
                if (!sub_entry_uri) {
                    ret = -ENOMEM;
                    goto out;
                }
                log_debug("migrating file %s", sub_entry_uri);
                if ((ret = migrate_file(sub_entry_uri, old_key, new_key)) < 0)
                    goto out;
            }
            free(sub_entry_uri);
            sub_entry_uri = NULL;
            start = end + 1;
        }
    }
    ret = 0;

out:
    if (sub_entry_uri)
        free(sub_entry_uri);
    if (buf)
        free(buf);
    PalObjectDestroy(palhdl);
    return ret;
}

static int do_migrate(const char* uri, cpu_svn_t* old_cpu_svn, const char* key_name) {
    struct libos_encrypted_files_key* old_key = NULL;
    struct libos_encrypted_files_key* new_key = NULL;
    char* dir_entry_uri = NULL;

    int ret = create_encrypted_files_key_for_svn(key_name, old_cpu_svn, &old_key);
    if (ret < 0)
        return ret;

    ret = create_encrypted_files_key(key_name, &new_key);
    if (ret < 0) {
        goto out;
    }

    PAL_STREAM_ATTR pal_attr;
    ret = PalStreamAttributesQuery(uri, &pal_attr);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }
    assert(strstartswith(uri, URI_PREFIX_FILE));

    switch (pal_attr.handle_type) {
        case PAL_TYPE_FILE:
            ret = migrate_file(uri, old_key, new_key);
            break;
        case PAL_TYPE_DIR:
            dir_entry_uri =
                alloc_concat(URI_PREFIX_DIR, URI_PREFIX_DIR_LEN, uri + URI_PREFIX_FILE_LEN, -1);
            if (!dir_entry_uri) {
                ret = -ENOMEM;
                goto out;
            }
            ret = migrate_dir(dir_entry_uri, old_key, new_key);
            break;
        default:
            log_warning("trying to access '%s' which is not an encrypted file or directory", uri);
            ret = -EACCES;
            goto out;
    }
    ret = 0;
out:
    if (dir_entry_uri)
        free(dir_entry_uri);
    if (old_key) {
        if (old_key->name)
            free(old_key->name);
        free(old_key);
    }
    if (new_key) {
        if (new_key->name)
            free(new_key->name);
        free(new_key);
    }
    return ret;
}

int init_encrypted_files(void) {
    pf_debug_f cb_debug_ptr = NULL;
#ifdef DEBUG
    cb_debug_ptr = &cb_debug;
#endif
    if (!create_lock(&g_keys_lock))
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

int handle_tcb_migration(const char* uri, const char* key_name) {
    PAL_HANDLE tcb_info_file_pal_handle = NULL;
    int ret;

    cpu_svn_t current_cpu_svn;
    size_t cpu_svn_size = sizeof(current_cpu_svn);
    ret = PalGetCPUSVN(&current_cpu_svn, &cpu_svn_size);
    if (ret < 0) {
        log_warning("PalGetCPUSVN failed: %s", pal_strerror(ret));
        return pal_to_unix_errno(ret);
    }
    char cpu_svn_str[CPU_SVN_SIZE * 2 + 1] = {0};
    bytes2hex(current_cpu_svn, cpu_svn_size, cpu_svn_str, sizeof(cpu_svn_str));

    log_debug("current CPU SVN %s", cpu_svn_str);

    char *tcb_info_uri = NULL;
    size_t uri_len = strlen(uri);
    if (uri[uri_len - 1] == '/') {
        tcb_info_uri = alloc_concat(uri, -1, TCB_INFO_FILE_NAME, -1);
    } else {
        tcb_info_uri = alloc_concat3(uri, -1, "/\0", -1, TCB_INFO_FILE_NAME, -1);
    }

    log_debug("Opening TCB info file URI: %s", tcb_info_uri);
    ret = PalStreamOpen(tcb_info_uri, PAL_ACCESS_RDWR, TCB_INFO_PERM_RW, PAL_CREATE_TRY,
                        /*options=*/0, &tcb_info_file_pal_handle);
    free(tcb_info_uri);
    if (ret < 0) {
        log_warning("tcb_info PalStreamOpen failed: %s", pal_strerror(ret));
        ret = pal_to_unix_errno(ret);
        return ret;
    }
    PAL_STREAM_ATTR pal_attr;
    ret = PalStreamAttributesQueryByHandle(tcb_info_file_pal_handle, &pal_attr);
    if (ret < 0) {
        log_warning("tcb_info PalStreamAttributesQueryByHandle failed: %s", pal_strerror(ret));
        ret = pal_to_unix_errno(ret);
        goto out;
    }
    if (pal_attr.pending_size == 0) {
        log_debug("tcb_info file is empty - writing current CPU SVN");
        ret = write_exact(tcb_info_file_pal_handle, current_cpu_svn, CPU_SVN_SIZE);
        if (ret < 0) {
            log_warning("writing to tcb_info file failed");
            goto out;
        }
    } else {
        cpu_svn_t saved_cpu_svn = {0};
        ret = read_exact(tcb_info_file_pal_handle, saved_cpu_svn, sizeof(saved_cpu_svn));
        if (ret < 0) {
            log_warning("reading from tcb_info file failed");
            goto out;
        }
        if (memcmp(&current_cpu_svn, &saved_cpu_svn, sizeof(saved_cpu_svn)) != 0) {
            log_warning("CPU SVN has changed - doing TCB migration for %s", uri);
            ret = do_migrate(uri, &saved_cpu_svn, key_name);
        } else {
            log_debug("CPU SVN has not changed - no TCB migration needed for %s", uri);
        }
    }
out:
    if (tcb_info_file_pal_handle)
        PalObjectDestroy(tcb_info_file_pal_handle);
    return ret;
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

int set_cpu_svn(const cpu_svn_t* cpu_svn) {
    int ret;
    pf_key_t pf_key;
    size_t size = sizeof(pf_key);
    char name[] = PAL_KEY_NAME_SGX_MRENCLAVE;
    ret = PalGetSpecialKeyForSVN(cpu_svn, sizeof(*cpu_svn), name, &pf_key, &size);
    if (ret == 0) {
        if (size != sizeof(pf_key)) {
            return -EINVAL;
        }
    } else if (ret == PAL_ERROR_NOTIMPLEMENTED) {
        log_warning(
            "Special key \"%s\" is not supported by current PAL. Mounts using this key "
            "will not work.",
            name);
        return -ENOSYS;
    } else {
        log_error("PalGetSpecialKeyForSVN(\"%s\") failed: %s", name, pal_strerror(ret));
        return pal_to_unix_errno(ret);
    }
    
    struct libos_encrypted_files_key* key = get_encrypted_files_key(PAL_KEY_NAME_SGX_MRENCLAVE);
    if (!key) {
        log_warning("Key with current SVN not found");
        return -ENOENT;
    }
    if (!key->is_set) {
        log_warning("Key with current SVN not set");
        return -ENOENT;
    }

    update_encrypted_files_key(key, &pf_key);
    ret = PalSetCPUSVN(cpu_svn, sizeof(*cpu_svn));
    if (ret < 0) {
        log_warning("PalSetCPUSVN failed: %s", pal_strerror(ret));
        return pal_to_unix_errno(ret);
    }
    return 0;
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
            log_debug(
                "Special key \"%s\" is not supported by current PAL. Mounts using this key "
                "will not work.",
                name);
            /* proceed without setting value */
        } else {
            log_error("PalGetSpecialKey(\"%s\") failed: %s", name, pal_strerror(ret));
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

int create_encrypted_files_key_for_svn(const char* name, cpu_svn_t* cpu_svn,
                                       struct libos_encrypted_files_key** out_key) {
    if (name[0] != '_') {
        return -EINVAL;
    }

    int ret;

    struct libos_encrypted_files_key* key =  NULL;
    key = calloc(1, sizeof(*key));
    if (!key){
        ret = -ENOMEM;
        goto out;
    }
    key->name = strdup(name);
    if (!key->name) {
        ret = -ENOMEM;
        goto out;
    }

    pf_key_t pf_key;
    size_t size = sizeof(pf_key);
    ret = PalGetSpecialKeyForSVN(cpu_svn, sizeof(*cpu_svn), name, &pf_key, &size);

    if (ret == 0) {
        if (size != sizeof(pf_key)) {
            log_debug("PalGetSpecialKeyForSVN(\"%s\") returned wrong size: %zu", name, size);
            ret = -EINVAL;
            goto out;
        }
        log_debug("Successfully retrieved special key for svn \"%s\"", name);
        memcpy(&key->pf_key, &pf_key, sizeof(pf_key));
        key->is_set = true;
    } else if (ret == PAL_ERROR_NOTIMPLEMENTED) {
        log_debug(
            "Special key \"%s\" is not supported by current PAL. Mounts using this key "
            "will not work.",
            name);
        /* proceed without setting value */
    } else {
        log_error("PalGetSpecialKeyForSVN(\"%s\") failed: %s", name, pal_strerror(ret));
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    *out_key = key;
    ret = 0;
out:
    if (ret < 0) {
        if (key) {
            if (key->name)
                free(key->name);
            free(key);
        }
    }
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
                                bool enable_recovery, struct libos_encrypted_file** out_enc) {
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

    enc->enable_recovery = enable_recovery;
    enc->recovery_file_pal_handle = NULL;

    *out_enc = enc;
    return 0;
}

int encrypted_file_open(const char* uri, struct libos_encrypted_files_key* key,
                        bool enable_recovery, struct libos_encrypted_file** out_enc) {
    struct libos_encrypted_file* enc;
    int ret = encrypted_file_alloc(uri, key, enable_recovery, &enc);
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
                          bool enable_recovery, struct libos_encrypted_file** out_enc) {
    struct libos_encrypted_file* enc;
    int ret = encrypted_file_alloc(uri, key, enable_recovery, &enc);
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
    assert(!enc->recovery_file_pal_handle);
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
    new_enc->enable_recovery = enc->enable_recovery;

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

    if (enc->recovery_file_pal_handle) {
        struct libos_palhdl_entry* entry;
        DO_CP(palhdl_ptr, &enc->recovery_file_pal_handle, &entry);
        entry->phandle = &new_enc->recovery_file_pal_handle;
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
