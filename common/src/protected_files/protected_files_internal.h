/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Rafal Wojdyla <omeg@invisiblethingslab.com>
 * Copyright (C) 2019 Intel Corporation
 */

#pragma once

#include <limits.h>

#include "lru_cache.h"
#include "protected_files.h"
#include "protected_files_format.h"

struct pf_context {
    pf_handle_t host_file_handle;  // opaque file handle (e.g. PAL handle) used by callbacks
    pf_file_mode_t mode;           // read-only, write-only or read-write
    bool need_writing;             // whether file was modified and thus needs writing to storage

    pf_status_t file_status;       // PF_STATUS_SUCCESS, PF_STATUS_CRYPTO_ERROR, etc.
    pf_status_t last_error;        // FIXME: unclear why this is needed

    pf_key_t user_kdk_key;         // KDK installed by user of PF (e.g. from Gramine manifest)

    metadata_node_t metadata_node; // plaintext and encrypted metadata from storage (bounce buffer)
    metadata_decrypted_t metadata_decrypted; // contains file path, size, etc.

    file_node_t root_mht_node;     // needed for files bigger than MD_USER_DATA_SIZE bytes

    lruc_context_t* cache;         // up to MAX_NODES_IN_CACHE nodes are cached for each file
#ifdef DEBUG
    char* debug_buffer;            // buffer for debug output
#endif
};
