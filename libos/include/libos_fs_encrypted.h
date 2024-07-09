/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This module implements encrypted files. It is a wrapper around the platform-independent
 * `protected_files` module, and PAL handles.
 *
 * NOTE: There is currently no notion of file permissions, all files are open in read-write mode.
 */

#pragma once

#include <stddef.h>

#include "libos_checkpoint.h"  // for include of uthash.h _and_ consistent uthash_fatal macros
#include "libos_types.h"
#include "list.h"
#include "pal.h"
#include "protected_files.h"

/*
 * Represents a named key for opening files. The key might not be set yet: value of a key can be
 * specified in the manifest, or set using `update_encrypted_files_key`. Before the key is set,
 * operations that use it will fail.
 */
DEFINE_LIST(libos_encrypted_files_key);
DEFINE_LISTP(libos_encrypted_files_key);
struct libos_encrypted_files_key {
    char* name;
    bool is_set;
    pf_key_t pf_key;

    LIST_TYPE(libos_encrypted_files_key) list;
};

typedef enum {
    PF_FILE_STATE_ERROR   = 0,  // file is in non-determined state due to some errors
    PF_FILE_STATE_ACTIVE  = 1,  // file was provisously seen with known (good committed) state
    PF_FILE_STATE_DELETED = 2,  // file was previously seen but then either unlinked or renamed
} libos_encrypted_file_state_t;

/*
 * Map mapping file URIs to state providing information on files, in particular whether we have seen
 * them before and what the last seen root-hash is.  This is necessary to provide rollback
 */
struct libos_encrypted_volume_state_map {
    char* norm_path;  // assumptions: all paths canonicalized, symlinks are resolved & no hard links
    libos_encrypted_file_state_t state;
    pf_mac_t last_seen_root_mac;
    UT_hash_handle hh;
};

typedef enum {
    PF_ENCLAVE_LIFE_RB_PROTECTION_NONE       = 0,
    PF_ENCLAVE_LIFE_RB_PROTECTION_NON_STRICT = 1,
    PF_ENCLAVE_LIFE_RB_PROTECTION_STRICT     = 2,
} libos_encrypted_files_mode_t;

DEFINE_LIST(libos_encrypted_volume);
DEFINE_LISTP(libos_encrypted_volume);
struct libos_encrypted_volume {
    char* mount_point_path;
    libos_encrypted_files_mode_t protection_mode;

    struct libos_encrypted_volume_state_map* files_state_map;
    struct libos_lock files_state_map_lock;

    struct libos_encrypted_files_key* key;

    LIST_TYPE(libos_encrypted_volume) list;
};

/*
 * Represents a specific encrypted file. The file is open as long as `use_count` is greater than 0.
 * Note that the file can be open and closed multiple times before it's destroyed.
 *
 * Operations on a single `libos_encrypted_file` are NOT thread-safe, it is intended to be protected
 * by a lock.
 */
struct libos_encrypted_file {
    size_t use_count;
    char* uri;
    struct libos_encrypted_volume* volume;

    /* `pf` and `pal_handle` are non-null as long as `use_count` is greater than 0 */
    pf_context_t* pf;
    PAL_HANDLE pal_handle;
};

/*
 * \brief Initialize the encrypted files module.
 *
 * Performs necessary setup, including loading keys specified in manifest.
 */
int init_encrypted_files(void);

/*
 * \brief Retrieve a key.
 *
 * Returns a key with a given name, or NULL if it has not been created yet. Note that even if the
 * key exists, it might not be set yet (see `struct libos_encrypted_files_key`).
 *
 * This does not pass ownership of the key: the key objects are still managed by this module.
 */
struct libos_encrypted_files_key* get_encrypted_files_key(const char* name);

/*
 * \brief List existing keys.
 *
 * Calls `callback` on each currently existing key.
 */
int list_encrypted_files_keys(int (*callback)(struct libos_encrypted_files_key* key, void* arg),
                              void* arg);

/*
 * \brief Retrieve or create a key.
 *
 * Sets `*out_key` to a key with given name. If the key has not been created yet, creates a new one.
 *
 * Similar to `get_encrypted_files_key`, this does not pass ownership of `*out_key`.
 */
int get_or_create_encrypted_files_key(const char* name, struct libos_encrypted_files_key** out_key);

/*
 * \brief Read value of given key.
 *
 * \param      key     The key to read.
 * \param[out] pf_key  On success, will be set to the current value.
 *
 * \returns `true` if the key has a value, `false` otherwise
 *
 * If the key has already been set, writes its value to `*pf_key` and returns `true`. Otherwise,
 * returns `false`.
 */
bool read_encrypted_files_key(struct libos_encrypted_files_key* key, pf_key_t* pf_key);

/*
 * \brief Update value of given key.
 *
 * \param key     The key to update.
 * \param pf_key  New value for the key.
 */
void update_encrypted_files_key(struct libos_encrypted_files_key* key, const pf_key_t* pf_key);

/*
 * \brief Register a volume.
 *
 * Registers passed volume -- assumed to be initialized, in particular with valid mount_point_path
 * -- in global list of mounted volumes.  Returns an error if a volume with identical
 * mount_point_path already exists.
 */
int register_encrypted_volume(struct libos_encrypted_volume* volume);

/*
 * \brief Retrieve a volume.
 *
 * Returns a volume with a given mount_point_path, or NULL if it has not been created yet. Note that
 * even if the key exists, it might not be set yet (see `struct libos_encrypted_files_key`).
 *
 * This does not pass ownership of the key: the key objects are still managed by this module.
 */
struct libos_encrypted_volume* get_encrypted_volume(const char* mount_point_path);

/*
 * \brief List existing volumes.
 *
 * Calls `callback` on each currently existing volume.
 */
int list_encrypted_volumes(int (*callback)(struct libos_encrypted_volume* volume, void* arg),
                           void* arg);

/*
 * \brief Open an existing encrypted file.
 *
 * \param      uri      PAL URI to open, has to begin with "file:".
 * \param      volume   Volume assocated with file, has to be already set.
 * \param[out] out_enc  On success, set to a newly created `libos_encrypted_file` object.
 *
 * `uri` has to correspond to an existing file that can be decrypted with `key`.
 *
 * The newly created `libos_encrypted_file` object will have `use_count` set to 1.
 */
int encrypted_file_open(const char* uri, struct libos_encrypted_volume* volume,
                        struct libos_encrypted_file** out_enc);

/*
 * \brief Create a new encrypted file.
 *
 * \param      uri      PAL URI to open, has to begin with "file:".
 * \param      perm     Permissions for the new file.
 * \param      volume   Volume assocated with file, has to be already set.
 * \param[out] out_enc  On success, set to a newly created `libos_encrypted_file` object.
 *
 * `uri` must not correspond to an existing file.
 *
 * The newly created `libos_encrypted_file` object will have `use_count` set to 1.
 */
int encrypted_file_create(const char* uri, mode_t perm, struct libos_encrypted_volume* volume,
                          struct libos_encrypted_file** out_enc);

/*
 * \brief Deallocate an encrypted file.
 *
 * `enc` needs to have `use_count` set to 0.
 */
void encrypted_file_destroy(struct libos_encrypted_file* enc);

/*
 * \brief Increase the use count of an encrypted file.
 *
 * This increases `use_count`, and opens the file if `use_count` was 0.
 */
int encrypted_file_get(struct libos_encrypted_file* enc);

/*
 * \brief Decrease the use count of an encrypted file.
 *
 * This decreases `use_count`, and closes the file if it reaches 0.
 */
void encrypted_file_put(struct libos_encrypted_file* enc, bool fs_reachable);

/*
 * \brief Flush pending writes to an encrypted file.
 */
int encrypted_file_flush(struct libos_encrypted_file* enc);

int encrypted_file_read(struct libos_encrypted_file* enc, void* buf, size_t buf_size,
                        file_off_t offset, size_t* out_count);
int encrypted_file_write(struct libos_encrypted_file* enc, const void* buf, size_t buf_size,
                         file_off_t offset, size_t* out_count);
int encrypted_file_rename(struct libos_encrypted_file* enc, const char* new_uri);
int encrypted_file_unlink(struct libos_encrypted_file* enc);

int encrypted_file_get_size(struct libos_encrypted_file* enc, file_off_t* out_size);
int encrypted_file_set_size(struct libos_encrypted_file* enc, file_off_t size);

int parse_pf_key(const char* key_str, pf_key_t* pf_key);
