/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Rafal Wojdyla <omeg@invisiblethingslab.com>
 * Copyright (C) 2019 Intel Corporation
 */

#pragma once

#include <limits.h>

#include "list.h"
#include "lru_cache.h"
#include "protected_files.h"
#include "protected_files_format.h"

struct pf_context {
    metadata_node_t file_metadata; // actual data from disk's meta data node
    pf_status_t last_error;
    metadata_encrypted_t encrypted_part_plain; // encrypted part of metadata node, decrypted
    file_node_t root_mht; // the root of the mht is always needed (for files bigger than 3KB)
    pf_handle_t file;
    void* addr;
    pf_file_mode_t mode;
    uint64_t real_file_size;
    bool need_writing;
    pf_status_t file_status;
    pf_key_t user_kdk_key;
    lruc_context_t* cache;
#ifdef DEBUG
    char* debug_buffer; // buffer for debug output
#endif
};
