/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Rafal Wojdyla <omeg@invisiblethingslab.com>
 * Copyright (C) 2019 Intel Corporation
 */

#include "protected_files.h"
#include "protected_files_format.h"
#include "protected_files_internal.h"

#include "api.h"

/* Host callbacks */
static pf_read_f     g_cb_read     = NULL;
static pf_write_f    g_cb_write    = NULL;
static pf_fsync_f    g_cb_fsync    = NULL;
static pf_truncate_f g_cb_truncate = NULL;
static pf_debug_f    g_cb_debug    = NULL;

static pf_aes_cmac_f        g_cb_aes_cmac        = NULL;
static pf_aes_gcm_encrypt_f g_cb_aes_gcm_encrypt = NULL;
static pf_aes_gcm_decrypt_f g_cb_aes_gcm_decrypt = NULL;
static pf_random_f          g_cb_random          = NULL;

#ifdef DEBUG
#define PF_DEBUG_PRINT_SIZE_MAX 4096

/* Debug print with function name prefix. Implicit param: pf (context pointer). */
#define DEBUG_PF(format, ...)                                                                \
    do {                                                                                     \
        if (g_cb_debug) {                                                                    \
            snprintf(pf->debug_buffer, PF_DEBUG_PRINT_SIZE_MAX, "%s: " format, __FUNCTION__, \
                     ##__VA_ARGS__);                                                         \
            g_cb_debug(pf->debug_buffer);                                                    \
        }                                                                                    \
    } while (0)

#else /* DEBUG */
#define DEBUG_PF(...)
#endif /* DEBUG */

static pf_iv_t g_empty_iv = {0};
static bool g_initialized = false;

static const char* g_pf_error_list[] = {
    [PF_STATUS_SUCCESS] = "Success",
    [-PF_STATUS_UNKNOWN_ERROR] = "Unknown error",
    [-PF_STATUS_UNINITIALIZED] = "Protected Files uninitialized",
    [-PF_STATUS_INVALID_PARAMETER] = "Invalid parameter",
    [-PF_STATUS_INVALID_MODE] = "Invalid mode",
    [-PF_STATUS_NO_MEMORY] = "Not enough memory",
    [-PF_STATUS_INVALID_VERSION] = "Invalid version",
    [-PF_STATUS_INVALID_HEADER] = "Invalid header",
    [-PF_STATUS_INVALID_PATH] = "Invalid path",
    [-PF_STATUS_MAC_MISMATCH] = "MAC mismatch",
    [-PF_STATUS_NOT_IMPLEMENTED] = "Functionality not implemented",
    [-PF_STATUS_CALLBACK_FAILED] = "Callback failed",
    [-PF_STATUS_PATH_TOO_LONG] = "Path is too long",
    [-PF_STATUS_RECOVERY_NEEDED] = "File recovery needed",
    [-PF_STATUS_FLUSH_ERROR] = "Flush error",
    [-PF_STATUS_CRYPTO_ERROR] = "Crypto error",
    [-PF_STATUS_CORRUPTED] = "File is corrupted",
    [-PF_STATUS_WRITE_TO_DISK_FAILED] = "Write to disk failed",
};

/* ipf prefix means "Intel protected files", these are functions from the SGX SDK implementation */
static file_node_t* ipf_append_mht_node(pf_context_t* pf, uint64_t logical_mht_node_number);
static file_node_t* ipf_append_data_node(pf_context_t* pf, uint64_t offset);
static file_node_t* ipf_read_mht_node(pf_context_t* pf, uint64_t logical_mht_node_number);
static file_node_t* ipf_read_data_node(pf_context_t* pf, uint64_t offset);

static void memcpy_or_zero_initialize(void* dest, const void* src, size_t size) {
    if (src)
        memcpy(dest, src, size);
    else
        memset(dest, 0, size);
}

const char* pf_strerror(int err) {
    unsigned err_idx = err >= 0 ? err : -err;
    if (err_idx >= ARRAY_SIZE(g_pf_error_list) || !g_pf_error_list[err_idx]) {
        return "Unknown error";
    }
    return g_pf_error_list[err_idx];
}

static void swap_nodes(file_node_t** data, size_t idx1, size_t idx2) {
    file_node_t* tmp = data[idx1];
    data[idx1] = data[idx2];
    data[idx2] = tmp;
}

// TODO: better sort?
static size_t partition(file_node_t** data, size_t low, size_t high) {
    assert(low <= high);
    file_node_t* pivot = data[(low + high) / 2];
    size_t i = low;
    size_t j = high;

    while (true) {
        while (data[i]->logical_node_number < pivot->logical_node_number)
            i++;
        while (data[j]->logical_node_number > pivot->logical_node_number)
            j--;
        if (i >= j)
            return j;
        swap_nodes(data, i, j);
        i++;
        j--;
    }
}

static void sort_nodes(file_node_t** data, size_t low, size_t high) {
    if (high - low == 1) {
        if (data[low]->logical_node_number > data[high]->logical_node_number)
            swap_nodes(data, low, high);
        return;
    }
    if (low < high) {
        size_t pi = partition(data, low, high);
        if (pi > 0)
            sort_nodes(data, low, pi);
        sort_nodes(data, pi + 1, high);
    }
}

static bool ipf_generate_random_key(pf_context_t* pf, pf_key_t* output) {
    pf_status_t status = g_cb_random((uint8_t*)output, sizeof(*output));
    if (PF_FAILURE(status)) {
        pf->last_error = status;
        return false;
    }

    return true;
}

// The key derivation function follow recommendations from NIST Special Publication 800-108:
// Recommendation for Key Derivation Using Pseudorandom Functions
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
//
// This function derives a metadata key in two modes:
//   - restore == false: derives a per-file random key from user_kdk_key using a random nonce, to
//                       encrypt the metadata node of the protected file; the nonce is stored in
//                       plaintext part of the metadata node so that the file can be loaded later
//                       and decrypted using the same key
//   - restore == true:  derives a key from user_kdk_key + nonce stored in plaintext part of the
//                       metadata node, to decrypt the encrypted part of the metadata node (and
//                       thus "restore" access to the whole protected file)
static bool ipf_generate_metadata_key(pf_context_t* pf, bool restore, pf_key_t* output) {
    kdf_input_t buf = {0};
    pf_status_t status;

    buf.counter = 1;
    if (!strcpy_static(buf.label, METADATA_KEY_NAME, MAX_LABEL_SIZE))
        return false;

    if (!restore) {
        status = g_cb_random((uint8_t*)&buf.nonce, sizeof(buf.nonce));
        if (PF_FAILURE(status)) {
            pf->last_error = status;
            return false;
        }
    } else {
        COPY_ARRAY(buf.nonce, pf->metadata_node.plaintext_part.metadata_key_nonce);
    }

    // length of output (128 bits)
    buf.output_len = 0x80;

    status = g_cb_aes_cmac(&pf->user_kdk_key, &buf, sizeof(buf), output);
    if (PF_FAILURE(status)) {
        pf->last_error = status;
        return false;
    }

    if (!restore) {
        COPY_ARRAY(pf->metadata_node.plaintext_part.metadata_key_nonce, buf.nonce);
    }

    erase_memory(&buf, sizeof(buf));
    return true;
}

static bool ipf_generate_random_metadata_key(pf_context_t* pf, pf_key_t* output) {
    return ipf_generate_metadata_key(pf, /*restore=*/false, output);
}

static bool ipf_recreate_metadata_key(pf_context_t* pf, pf_key_t* output) {
    return ipf_generate_metadata_key(pf, /*restore=*/true, output);
}

static void ipf_init_root_mht(file_node_t* mht) {
    memset(mht, 0, sizeof(*mht));

    mht->type                 = FILE_MHT_NODE_TYPE;
    mht->physical_node_number = 1;
    mht->logical_node_number  = 0;
    mht->need_writing         = false;
}

static bool ipf_update_all_data_and_mht_nodes(pf_context_t* pf) {
    bool ret = false;
    file_node_t** mht_array = NULL;
    pf_status_t status;

    // 1. encrypt the changed data nodes
    // 2. set the key + MAC in the parent MHT nodes
    // 3. set the need_writing flag for all the parent MHT nodes
    for (void* node = lruc_get_first(pf->cache); node != NULL; node = lruc_get_next(pf->cache)) {
        if (((file_node_t*)node)->type != FILE_DATA_NODE_TYPE)
            continue;

        file_node_t* data_node = (file_node_t*)node;
        if (!data_node->need_writing)
            continue;

        gcm_crypto_data_t* gcm_crypto_data = &data_node->parent->decrypted.mht
            .data_nodes_crypto[data_node->logical_node_number % ATTACHED_DATA_NODES_COUNT];

        if (!ipf_generate_random_key(pf, &gcm_crypto_data->key))
            goto out;

        // encrypt data node, this also saves MAC in the corresponding array item of MHT node
        status = g_cb_aes_gcm_encrypt(&gcm_crypto_data->key, &g_empty_iv, NULL, 0,  // aad
                                      data_node->decrypted.data.bytes, PF_NODE_SIZE,
                                      data_node->encrypted.bytes, &gcm_crypto_data->mac);
        if (PF_FAILURE(status)) {
            pf->last_error = status;
            goto out;
        }

#ifdef DEBUG
        file_node_t* file_mht_node = data_node->parent;
        while (file_mht_node->logical_node_number != 0) {
            assert(file_mht_node->need_writing == true);
            file_mht_node = file_mht_node->parent;
        }
#endif
    }

    // count dirty MHT nodes
    size_t dirty_count = 0;
    for (void* node = lruc_get_first(pf->cache); node != NULL; node = lruc_get_next(pf->cache)) {
        if (((file_node_t*)node)->type == FILE_MHT_NODE_TYPE) {
            if (((file_node_t*)node)->need_writing)
                dirty_count++;
        }
    }

    // add all the MHT nodes that needs writing to a list
    mht_array = malloc(dirty_count * sizeof(*mht_array));
    if (!mht_array) {
        pf->last_error = PF_STATUS_NO_MEMORY;
        goto out;
    }

    uint64_t dirty_idx = 0;
    for (void* node = lruc_get_first(pf->cache); node != NULL; node = lruc_get_next(pf->cache)) {
        if (((file_node_t*)node)->type == FILE_MHT_NODE_TYPE) {
            file_node_t* file_mht_node = (file_node_t*)node;

            if (file_mht_node->need_writing)
                mht_array[dirty_idx++] = file_mht_node;
        }
    }

    if (dirty_count > 0)
        sort_nodes(mht_array, 0, dirty_count - 1);

    // update the keys and MACs in the parents from last node to first (bottom layers first)
    for (dirty_idx = dirty_count; dirty_idx > 0; dirty_idx--) {
        file_node_t* file_mht_node = mht_array[dirty_idx - 1];

        gcm_crypto_data_t* gcm_crypto_data =
            &file_mht_node->parent->decrypted.mht
                 .mht_nodes_crypto[(file_mht_node->logical_node_number - 1) % CHILD_MHT_NODES_COUNT];

        if (!ipf_generate_random_key(pf, &gcm_crypto_data->key))
            goto out;

        status = g_cb_aes_gcm_encrypt(&gcm_crypto_data->key, &g_empty_iv, NULL, 0,
                                      &file_mht_node->decrypted.mht, PF_NODE_SIZE,
                                      &file_mht_node->encrypted.bytes, &gcm_crypto_data->mac);
        if (PF_FAILURE(status)) {
            pf->last_error = status;
            goto out;
        }
    }

    // update root MHT node's key and MAC in the metadata node's headers
    if (!ipf_generate_random_key(pf, &pf->metadata_decrypted.root_mht_node_key))
        goto out;

    status = g_cb_aes_gcm_encrypt(&pf->metadata_decrypted.root_mht_node_key, &g_empty_iv,
                                  NULL, 0,
                                  &pf->root_mht_node.decrypted.mht, PF_NODE_SIZE,
                                  &pf->root_mht_node.encrypted.bytes,
                                  &pf->metadata_decrypted.root_mht_node_mac);
    if (PF_FAILURE(status)) {
        pf->last_error = status;
        goto out;
    }

    ret = true;

out:
    free(mht_array);
    return ret;
}

static bool ipf_read_node(pf_context_t* pf, uint64_t physical_node_number, void* buffer) {
    uint64_t offset = physical_node_number * PF_NODE_SIZE;

    pf_status_t status = g_cb_read(pf->host_file_handle, buffer, offset, PF_NODE_SIZE);
    if (PF_FAILURE(status)) {
        pf->last_error = status;
        return false;
    }

    return true;
}

static bool ipf_write_node(pf_context_t* pf, uint64_t physical_node_number, void* buffer) {
    uint64_t offset = physical_node_number * PF_NODE_SIZE;

    pf_status_t status = g_cb_write(pf->host_file_handle, buffer, offset, PF_NODE_SIZE);
    if (PF_FAILURE(status)) {
        pf->last_error = status;
        return false;
    }

    return true;
}

// this is a very 'specific' function, tied to the architecture of the file layout,
// returning the node numbers according to the data offset in the file
static void get_node_numbers(uint64_t offset, uint64_t* logical_mht_node_number,
                             uint64_t* logical_data_node_number,
                             uint64_t* physical_mht_node_number,
                             uint64_t* physical_data_node_number) {
    // physical nodes (file layout):
    // node 0 - metadata node
    // node 1 - root MHT node
    // nodes 2-97 - data nodes (ATTACHED_DATA_NODES_COUNT == 96)
    // node 98 - MHT node
    // node 99-195 - data nodes
    // etc.
    uint64_t _physical_mht_node_number;
    uint64_t _physical_data_node_number;

    // "logical" nodes: sequential index of the corresponding MHT/data node in all MHT/data nodes
    uint64_t _logical_mht_node_number;
    uint64_t _logical_data_node_number;

    assert(offset >= MD_USER_DATA_SIZE);

    _logical_data_node_number = (offset - MD_USER_DATA_SIZE) / PF_NODE_SIZE;
    _logical_mht_node_number = _logical_data_node_number / ATTACHED_DATA_NODES_COUNT;
    _physical_data_node_number = _logical_data_node_number
                                 + 1 // metadata node
                                 + 1 // MHT root node
                                 + _logical_mht_node_number; // number of MHT nodes in the middle
                                 // (the mht_node_number of root MHT node is 0)
    _physical_mht_node_number = _physical_data_node_number
                                - _logical_data_node_number % ATTACHED_DATA_NODES_COUNT
                                // now we are at the first data node attached to this MHT node
                                - 1; // and now at the MHT node itself

    if (logical_mht_node_number != NULL)
        *logical_mht_node_number = _logical_mht_node_number;
    if (logical_data_node_number != NULL)
        *logical_data_node_number = _logical_data_node_number;
    if (physical_mht_node_number != NULL)
        *physical_mht_node_number = _physical_mht_node_number;
    if (physical_data_node_number != NULL)
        *physical_data_node_number = _physical_data_node_number;
}

static bool ipf_write_all_changes_to_disk(pf_context_t* pf) {
    if (pf->metadata_decrypted.file_size > MD_USER_DATA_SIZE && pf->root_mht_node.need_writing) {
        uint64_t physical_node_number;

        void* node;
        for (node = lruc_get_first(pf->cache); node != NULL; node = lruc_get_next(pf->cache)) {
            file_node_t* file_node = (file_node_t*)node;
            if (!file_node->need_writing)
                continue;

            uint8_t* data_to_write = (uint8_t*)&file_node->encrypted;
            physical_node_number = file_node->physical_node_number;

            if (!ipf_write_node(pf, physical_node_number, data_to_write))
                return false;

            file_node->need_writing = false;
        }

        if (!ipf_write_node(pf, /*physical_node_number=*/1, &pf->root_mht_node.encrypted))
            return false;

        pf->root_mht_node.need_writing = false;
    }

    if (!ipf_write_node(pf, /*physical_node_number=*/0, &pf->metadata_node))
        return false;

    return true;
}

static bool ipf_update_metadata_node(pf_context_t* pf) {
    pf_status_t status;
    pf_key_t key;

    // new key for metadata node encryption, saves the key nonce in metadata plaintext header
    if (!ipf_generate_random_metadata_key(pf, &key)) {
        // last error already set
        return false;
    }

    // encrypt metadata part-to-be-encrypted, also updating the MAC in metadata plaintext header
    status = g_cb_aes_gcm_encrypt(&key, &g_empty_iv, NULL, 0, &pf->metadata_decrypted,
                                  sizeof(metadata_decrypted_t), &pf->metadata_node.encrypted_part,
                                  &pf->metadata_node.plaintext_part.metadata_mac);
    if (PF_FAILURE(status)) {
        pf->last_error = status;
        return false;
    }

    return true;
}

static bool ipf_internal_flush(pf_context_t* pf) {
    if (!pf->need_writing) {
        DEBUG_PF("no need to write");
        return true;
    }

    if (pf->metadata_decrypted.file_size > MD_USER_DATA_SIZE && pf->root_mht_node.need_writing) {
        if (!ipf_update_all_data_and_mht_nodes(pf)) {
            // this is something that shouldn't happen, can't fix this...
            pf->file_status = PF_STATUS_CRYPTO_ERROR;
            DEBUG_PF("failed to update data and MHT nodes");
            return false;
        }
    }

    if (!ipf_update_metadata_node(pf)) {
        // this is something that shouldn't happen, can't fix this...
        pf->file_status = PF_STATUS_CRYPTO_ERROR;
        DEBUG_PF("failed to update metadata node");
        return false;
    }

    if (!ipf_write_all_changes_to_disk(pf)) {
        pf->file_status = PF_STATUS_WRITE_TO_DISK_FAILED;
        DEBUG_PF("failed to write changes to disk");
        return false;
    }

    pf->need_writing = false;
    return true;
}

static file_node_t* ipf_get_mht_node(pf_context_t* pf, uint64_t offset) {
    file_node_t* file_mht_node;
    uint64_t logical_mht_node_number;
    uint64_t physical_mht_node_number;

    if (offset < MD_USER_DATA_SIZE) {
        pf->last_error = PF_STATUS_UNKNOWN_ERROR;
        return NULL;
    }

    get_node_numbers(offset, &logical_mht_node_number, NULL, &physical_mht_node_number, NULL);

    if (logical_mht_node_number == 0)
        return &pf->root_mht_node;

    if ((offset - MD_USER_DATA_SIZE) % (ATTACHED_DATA_NODES_COUNT * PF_NODE_SIZE) == 0 &&
            offset == pf->metadata_decrypted.file_size) {
        file_mht_node = ipf_append_mht_node(pf, logical_mht_node_number);
    } else {
        file_mht_node = ipf_read_mht_node(pf, logical_mht_node_number);
    }

    return file_mht_node;
}

static file_node_t* ipf_append_mht_node(pf_context_t* pf, uint64_t logical_mht_node_number) {
    assert(logical_mht_node_number > 0);
    file_node_t* parent_file_mht_node =
        ipf_read_mht_node(pf, (logical_mht_node_number - 1) / CHILD_MHT_NODES_COUNT);

    if (parent_file_mht_node == NULL)
        return NULL;

    uint64_t physical_node_number = 1 + // metadata node
                                    // the '1' is for the MHT node preceding every 96 data nodes
                                    logical_mht_node_number * (1 + ATTACHED_DATA_NODES_COUNT);

    file_node_t* new_file_mht_node = calloc(1, sizeof(*new_file_mht_node));
    if (!new_file_mht_node) {
        pf->last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    new_file_mht_node->type = FILE_MHT_NODE_TYPE;
    new_file_mht_node->parent = parent_file_mht_node;
    new_file_mht_node->logical_node_number = logical_mht_node_number;
    new_file_mht_node->physical_node_number = physical_node_number;

    if (!lruc_add(pf->cache, new_file_mht_node->physical_node_number, new_file_mht_node)) {
        free(new_file_mht_node);
        pf->last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    return new_file_mht_node;
}

static file_node_t* ipf_get_data_node(pf_context_t* pf, uint64_t offset) {
    file_node_t* file_data_node = NULL;

    if (offset < MD_USER_DATA_SIZE) {
        pf->last_error = PF_STATUS_UNKNOWN_ERROR;
        return NULL;
    }

    if ((offset - MD_USER_DATA_SIZE) % PF_NODE_SIZE == 0
            && offset == pf->metadata_decrypted.file_size) {
        file_data_node = ipf_append_data_node(pf, offset);
    } else {
        file_data_node = ipf_read_data_node(pf, offset);
    }

    // bump all the parent MHT nodes to reside before the data node in the cache
    if (file_data_node != NULL) {
        file_node_t* file_mht_node = file_data_node->parent;
        while (file_mht_node->logical_node_number != 0) {
            // bump the MHT node to the head of the LRU
            lruc_get(pf->cache, file_mht_node->physical_node_number);
            file_mht_node = file_mht_node->parent;
        }
    }

    // even if we didn't get the required data_node, we might have read other nodes in the process
    while (lruc_size(pf->cache) > MAX_NODES_IN_CACHE) {
        void* node = lruc_get_last(pf->cache);
        assert(node);

        if (!((file_node_t*)node)->need_writing) {
            lruc_remove_last(pf->cache);

            // before deleting the memory, need to scrub the plain secrets
            file_node_t* file_node = (file_node_t*)node;
            erase_memory(&file_node->decrypted, sizeof(file_node->decrypted));
            free(file_node);
        } else {
            if (!ipf_internal_flush(pf)) {
                // error, can't flush cache, file status changed to error
                assert(pf->file_status != PF_STATUS_SUCCESS);
                if (pf->file_status == PF_STATUS_SUCCESS)
                    pf->file_status = PF_STATUS_FLUSH_ERROR; // for release set this anyway
                return NULL;                                 // even if we got the data_node!
            }
        }
    }

    return file_data_node;
}

static file_node_t* ipf_append_data_node(pf_context_t* pf, uint64_t offset) {
    file_node_t* file_mht_node = ipf_get_mht_node(pf, offset);
    if (file_mht_node == NULL)
        return NULL;

    file_node_t* new_file_data_node = calloc(1, sizeof(*new_file_data_node));
    if (!new_file_data_node) {
        pf->last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    uint64_t logical_node_number, physical_node_number;
    get_node_numbers(offset, NULL, &logical_node_number, NULL, &physical_node_number);

    new_file_data_node->type = FILE_DATA_NODE_TYPE;
    new_file_data_node->parent = file_mht_node;
    new_file_data_node->logical_node_number = logical_node_number;
    new_file_data_node->physical_node_number = physical_node_number;

    if (!lruc_add(pf->cache, new_file_data_node->physical_node_number, new_file_data_node)) {
        free(new_file_data_node);
        pf->last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    return new_file_data_node;
}

static file_node_t* ipf_read_data_node(pf_context_t* pf, uint64_t offset) {
    file_node_t* file_mht_node;
    pf_status_t status;

    uint64_t logical_data_node_number;
    uint64_t physical_node_number;
    get_node_numbers(offset, NULL, &logical_data_node_number, NULL, &physical_node_number);

    file_node_t* file_data_node = (file_node_t*)lruc_get(pf->cache, physical_node_number);
    if (file_data_node != NULL)
        return file_data_node;

    // need to read the data node from the disk
    file_mht_node = ipf_get_mht_node(pf, offset);
    if (file_mht_node == NULL)
        return NULL;

    file_data_node = calloc(1, sizeof(*file_data_node));
    if (!file_data_node) {
        pf->last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    file_data_node->type = FILE_DATA_NODE_TYPE;
    file_data_node->parent = file_mht_node;
    file_data_node->logical_node_number = logical_data_node_number;
    file_data_node->physical_node_number = physical_node_number;

    if (!ipf_read_node(pf, file_data_node->physical_node_number,
                       file_data_node->encrypted.bytes)) {
        free(file_data_node);
        return NULL;
    }

    gcm_crypto_data_t* gcm_crypto_data =
        &file_data_node->parent->decrypted.mht
             .data_nodes_crypto[file_data_node->logical_node_number % ATTACHED_DATA_NODES_COUNT];

    // decrypt data and check integrity against the MAC in corresponding array item in MHT node
    status = g_cb_aes_gcm_decrypt(&gcm_crypto_data->key, &g_empty_iv, NULL, 0,
                                  file_data_node->encrypted.bytes, PF_NODE_SIZE,
                                  file_data_node->decrypted.data.bytes, &gcm_crypto_data->mac);

    if (PF_FAILURE(status)) {
        free(file_data_node);
        pf->last_error = status;
        if (status == PF_STATUS_MAC_MISMATCH)
            pf->file_status = PF_STATUS_CORRUPTED;
        return NULL;
    }

    if (!lruc_add(pf->cache, file_data_node->physical_node_number, file_data_node)) {
        erase_memory(&file_data_node->decrypted, sizeof(file_data_node->decrypted));
        free(file_data_node);
        pf->last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    return file_data_node;
}

static file_node_t* ipf_read_mht_node(pf_context_t* pf, uint64_t logical_mht_node_number) {
    pf_status_t status;

    if (logical_mht_node_number == 0)
        return &pf->root_mht_node;

    uint64_t physical_node_number = 1 + // metadata node
                                    // the '1' is for the MHT node preceding every 96 data nodes
                                    logical_mht_node_number * (1 + ATTACHED_DATA_NODES_COUNT);

    file_node_t* file_mht_node = (file_node_t*)lruc_find(pf->cache, physical_node_number);
    if (file_mht_node != NULL)
        return file_mht_node;

    file_node_t* parent_file_mht_node =
        ipf_read_mht_node(pf, (logical_mht_node_number - 1) / CHILD_MHT_NODES_COUNT);

    if (parent_file_mht_node == NULL)
        return NULL;

    file_mht_node = calloc(1, sizeof(*file_mht_node));
    if (!file_mht_node) {
        pf->last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    file_mht_node->type                 = FILE_MHT_NODE_TYPE;
    file_mht_node->parent               = parent_file_mht_node;
    file_mht_node->logical_node_number  = logical_mht_node_number;
    file_mht_node->physical_node_number = physical_node_number;

    if (!ipf_read_node(pf, file_mht_node->physical_node_number, file_mht_node->encrypted.bytes)) {
        free(file_mht_node);
        return NULL;
    }

    gcm_crypto_data_t* gcm_crypto_data =
        &file_mht_node->parent->decrypted.mht
             .mht_nodes_crypto[(file_mht_node->logical_node_number - 1) % CHILD_MHT_NODES_COUNT];

    // decrypt data and check integrity against the MAC in corresponding array item in parent MHT
    // node
    status = g_cb_aes_gcm_decrypt(&gcm_crypto_data->key, &g_empty_iv, NULL, 0,
                                  file_mht_node->encrypted.bytes, PF_NODE_SIZE,
                                  &file_mht_node->decrypted.mht, &gcm_crypto_data->mac);
    if (PF_FAILURE(status)) {
        free(file_mht_node);
        pf->last_error = status;
        if (status == PF_STATUS_MAC_MISMATCH)
            pf->file_status = PF_STATUS_CORRUPTED;
        return NULL;
    }

    if (!lruc_add(pf->cache, file_mht_node->physical_node_number, file_mht_node)) {
        erase_memory(&file_mht_node->decrypted, sizeof(file_mht_node->decrypted));
        free(file_mht_node);
        pf->last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    return file_mht_node;
}

static bool ipf_init_new_file(pf_context_t* pf, const char* path) {
    pf->metadata_node.plaintext_part.file_id       = PF_FILE_ID;
    pf->metadata_node.plaintext_part.major_version = PF_MAJOR_VERSION;
    pf->metadata_node.plaintext_part.minor_version = PF_MINOR_VERSION;

    // path length is checked in ipf_open()
    memcpy(pf->metadata_decrypted.file_path, path, strlen(path) + 1);

    pf->need_writing = true;
    if (!ipf_internal_flush(pf))
        return false;

    return true;
}

static bool ipf_init_fields(pf_context_t* pf) {
#ifdef DEBUG
    pf->debug_buffer = malloc(PF_DEBUG_PRINT_SIZE_MAX);
    if (!pf->debug_buffer) {
        pf->last_error = PF_STATUS_NO_MEMORY;
        return false;
    }
#endif
    memset(&pf->metadata_node, 0, sizeof(pf->metadata_node));
    memset(&pf->metadata_decrypted, 0, sizeof(pf->metadata_decrypted));
    memset(&g_empty_iv, 0, sizeof(g_empty_iv));

    ipf_init_root_mht(&pf->root_mht_node);

    pf->host_file_handle = NULL;
    pf->need_writing     = false;
    pf->file_status      = PF_STATUS_UNINITIALIZED;
    pf->last_error       = PF_STATUS_SUCCESS;

    pf->cache = lruc_create();
    return true;
}

static bool ipf_init_existing_file(pf_context_t* pf, const char* path) {
    pf_status_t status;

    // read metadata node
    if (!ipf_read_node(pf, /*physical_node_number=*/0, (uint8_t*)&pf->metadata_node)) {
        return false;
    }

    if (pf->metadata_node.plaintext_part.file_id != PF_FILE_ID) {
        // such a file exists, but it is not a protected file
        pf->last_error = PF_STATUS_INVALID_HEADER;
        return false;
    }

    if (pf->metadata_node.plaintext_part.major_version != PF_MAJOR_VERSION) {
        pf->last_error = PF_STATUS_INVALID_VERSION;
        return false;
    }

    pf_key_t key;
    if (!ipf_recreate_metadata_key(pf, &key))
        return false;

    // decrypt the encrypted part of the metadata node
    status = g_cb_aes_gcm_decrypt(&key, &g_empty_iv, NULL, 0,
                                  &pf->metadata_node.encrypted_part,
                                  sizeof(pf->metadata_node.encrypted_part),
                                  &pf->metadata_decrypted,
                                  &pf->metadata_node.plaintext_part.metadata_mac);
    if (PF_FAILURE(status)) {
        pf->last_error = status;
        DEBUG_PF("failed to decrypt metadata: %d", status);
        return false;
    }

    DEBUG_PF("data size %lu", pf->metadata_decrypted.file_size);

    if (path) {
        size_t path_len = strlen(pf->metadata_decrypted.file_path);
        if (path_len != strlen(path)
                || memcmp(path, pf->metadata_decrypted.file_path, path_len) != 0) {
            pf->last_error = PF_STATUS_INVALID_PATH;
            return false;
        }
    }

    if (pf->metadata_decrypted.file_size > MD_USER_DATA_SIZE) {
        // read the root MHT node
        if (!ipf_read_node(pf, /*physical_node_number=*/1, &pf->root_mht_node.encrypted.bytes))
            return false;

        // also verifies root MHT node's MAC against the MAC in metadata node's decrypted header
        status = g_cb_aes_gcm_decrypt(&pf->metadata_decrypted.root_mht_node_key, &g_empty_iv,
                                      NULL, 0, // aad
                                      &pf->root_mht_node.encrypted.bytes, PF_NODE_SIZE,
                                      &pf->root_mht_node.decrypted.mht,
                                      &pf->metadata_decrypted.root_mht_node_mac);
        if (PF_FAILURE(status)) {
            pf->last_error = status;
            return false;
        }
    }

    return true;
}

static void ipf_try_clear_error(pf_context_t* pf) {
    if (pf->file_status == PF_STATUS_UNINITIALIZED ||
        pf->file_status == PF_STATUS_CRYPTO_ERROR ||
        pf->file_status == PF_STATUS_CORRUPTED) {
        // can't fix these...
        DEBUG_PF("Unrecoverable file status: %d", pf->file_status);
        return;
    }

    if (pf->file_status == PF_STATUS_FLUSH_ERROR) {
        if (ipf_internal_flush(pf))
            pf->file_status = PF_STATUS_SUCCESS;
    }

    if (pf->file_status == PF_STATUS_WRITE_TO_DISK_FAILED) {
        if (ipf_write_all_changes_to_disk(pf)) {
            pf->need_writing = false;
            pf->file_status = PF_STATUS_SUCCESS;
        }
    }

    if (pf->file_status == PF_STATUS_SUCCESS) {
        pf->last_error = PF_STATUS_SUCCESS;
    }
}

static pf_context_t* ipf_open(const char* path, pf_file_mode_t mode, bool create, pf_handle_t file,
                              uint64_t real_size, const pf_key_t* kdk_key, pf_status_t* status) {
    *status = PF_STATUS_NO_MEMORY;
    pf_context_t* pf = calloc(1, sizeof(*pf));

    if (!pf)
        goto out;

    if (!ipf_init_fields(pf))
        goto out;

    DEBUG_PF("handle: %d, path: '%s', real size: %lu, mode: 0x%x", *(int*)file, path, real_size,
             mode);

    if (kdk_key == NULL) {
        DEBUG_PF("no key specified");
        pf->last_error = PF_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (path && strlen(path) > PATH_MAX_SIZE - 1) {
        pf->last_error = PF_STATUS_PATH_TOO_LONG;
        goto out;
    }

    COPY_ARRAY(pf->user_kdk_key, *kdk_key);

    if (!file) {
        DEBUG_PF("invalid handle");
        pf->last_error = PF_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (real_size % PF_NODE_SIZE != 0) {
        pf->last_error = PF_STATUS_INVALID_HEADER;
        goto out;
    }

    pf->host_file_handle = file;
    pf->mode = mode;

    if (!create) {
        if (!ipf_init_existing_file(pf, path))
            goto out;

    } else {
        if (!ipf_init_new_file(pf, path))
            goto out;
    }

    pf->last_error = pf->file_status = PF_STATUS_SUCCESS;
    DEBUG_PF("OK (data size %lu)", pf->metadata_decrypted.file_size);

out:
    if (pf)
        *status = pf->last_error;

    if (pf && PF_FAILURE(pf->last_error)) {
        DEBUG_PF("failed: %d", pf->last_error);
        free(pf);
        pf = NULL;
    }

    return pf;
}

static bool ipf_check_writable(pf_context_t* pf) {
    if (PF_FAILURE(pf->file_status)) {
        pf->last_error = pf->file_status;
        DEBUG_PF("bad file status %d", pf->last_error);
        return false;
    }

    if (!(pf->mode & PF_FILE_MODE_WRITE)) {
        pf->last_error = PF_STATUS_INVALID_MODE;
        DEBUG_PF("File is read-only");
        return false;
    }

    return true;
}

// writes zeros if `ptr` is NULL
static size_t ipf_write(pf_context_t* pf, const void* ptr, uint64_t offset, size_t size) {
    if (size == 0) {
        pf->last_error = PF_STATUS_INVALID_PARAMETER;
        return 0;
    }


    if (!ipf_check_writable(pf))
        return 0;

    size_t data_left_to_write = size;
    const unsigned char* data_to_write = (const unsigned char*)ptr;

    // the first MD_USER_DATA_SIZE bytes of user data are written in metadata node's encrypted part
    if (offset < MD_USER_DATA_SIZE) {
        size_t empty_place_left_in_md = MD_USER_DATA_SIZE - (size_t)offset;
        size_t size_to_write = MIN(data_left_to_write, empty_place_left_in_md);

        memcpy_or_zero_initialize(&pf->metadata_decrypted.file_data[offset], data_to_write,
                                  size_to_write);
        offset += size_to_write;
        if (data_to_write)
            data_to_write += size_to_write;
        data_left_to_write -= size_to_write;

        if (offset > pf->metadata_decrypted.file_size)
            pf->metadata_decrypted.file_size = offset; // file grew, update the new file size

        pf->need_writing = true;
    }

    while (data_left_to_write > 0) {
        file_node_t* file_data_node = NULL;
        // return the data node of the current offset, will read it from disk or create new one
        // if needed (and also the MHT node(s) if needed)
        file_data_node = ipf_get_data_node(pf, offset);
        if (file_data_node == NULL) {
            DEBUG_PF("failed to get data node");
            break;
        }

        uint64_t offset_in_node = (offset - MD_USER_DATA_SIZE) % PF_NODE_SIZE;
        size_t empty_place_left_in_node = PF_NODE_SIZE - offset_in_node;
        size_t size_to_write = MIN(data_left_to_write, empty_place_left_in_node);

        memcpy_or_zero_initialize(&file_data_node->decrypted.data.bytes[offset_in_node],
                                  data_to_write, size_to_write);
        offset += size_to_write;
        if (data_to_write)
            data_to_write += size_to_write;
        data_left_to_write -= size_to_write;

        if (offset > pf->metadata_decrypted.file_size) {
            pf->metadata_decrypted.file_size = offset; // file grew, update the new file size
        }

        if (!file_data_node->need_writing) {
            file_data_node->need_writing = true;
            file_node_t* file_mht_node = file_data_node->parent;
            while (file_mht_node->logical_node_number != 0) {
                // set all the MHT parent nodes as 'need writing'
                file_mht_node->need_writing = true;
                file_mht_node = file_mht_node->parent;
            }
            pf->root_mht_node.need_writing = true;
            pf->need_writing = true;
        }
    }

    return size - data_left_to_write;
}

static size_t ipf_read(pf_context_t* pf, void* ptr, uint64_t offset, size_t size) {
    if (ptr == NULL) {
        pf->last_error = PF_STATUS_INVALID_PARAMETER;
        return 0;
    }

    if (PF_FAILURE(pf->file_status)) {
        pf->last_error = pf->file_status;
        return 0;
    }

    if (!(pf->mode & PF_FILE_MODE_READ)) {
        pf->last_error = PF_STATUS_INVALID_MODE;
        return 0;
    }

    size_t data_left_to_read = size;

    if (((uint64_t)data_left_to_read) > (uint64_t)(pf->metadata_decrypted.file_size - offset)) {
        // the request is bigger than what's left in the file
        data_left_to_read = (size_t)(pf->metadata_decrypted.file_size - offset);
    }

    // used at the end to return how much we actually read
    size_t data_attempted_to_read = data_left_to_read;

    unsigned char* out_buffer = (unsigned char*)ptr;

    // the first MD_USER_DATA_SIZE bytes of user data are read from metadata node's encrypted part
    if (offset < MD_USER_DATA_SIZE) {
        size_t data_left_in_md = MD_USER_DATA_SIZE - (size_t)offset;
        size_t size_to_read = MIN(data_left_to_read, data_left_in_md);

        memcpy(out_buffer, &pf->metadata_decrypted.file_data[offset], size_to_read);
        offset += size_to_read;
        out_buffer += size_to_read;
        data_left_to_read -= size_to_read;
    }

    while (data_left_to_read > 0) {
        file_node_t* file_data_node = NULL;
        // return the data node of the current offset, will read it from disk if needed
        // (and also the MHT node(s) if needed)
        file_data_node = ipf_get_data_node(pf, offset);
        if (file_data_node == NULL)
            break;

        uint64_t offset_in_node = (offset - MD_USER_DATA_SIZE) % PF_NODE_SIZE;
        size_t data_left_in_node = PF_NODE_SIZE - offset_in_node;
        size_t size_to_read = MIN(data_left_to_read, data_left_in_node);

        memcpy(out_buffer, &file_data_node->decrypted.data.bytes[offset_in_node], size_to_read);
        offset += size_to_read;
        out_buffer += size_to_read;
        data_left_to_read -= size_to_read;
    }

    return data_attempted_to_read - data_left_to_read;
}

static void ipf_delete_cache(pf_context_t* pf) {
    void* node;
    while ((node = lruc_get_last(pf->cache)) != NULL) {
        file_node_t* file_node = (file_node_t*)node;
        erase_memory(&file_node->decrypted, sizeof(file_node->decrypted));
        free(file_node);
        lruc_remove_last(pf->cache);
    }
}

static bool ipf_close(pf_context_t* pf) {
    bool retval = true;

    if (pf->file_status != PF_STATUS_SUCCESS) {
        ipf_try_clear_error(pf); // last attempt to fix it
        retval = false;
    } else {
        if (!ipf_internal_flush(pf)) {
            DEBUG_PF("internal flush failed");
            retval = false;
        }
    }

    // omeg: fs close is done by Gramine handler
    pf->file_status = PF_STATUS_UNINITIALIZED;

    ipf_delete_cache(pf);

    erase_memory(&pf->metadata_decrypted, sizeof(pf->metadata_decrypted));

    lruc_destroy(pf->cache);

#ifdef DEBUG
    free(pf->debug_buffer);
#endif
    erase_memory(pf, sizeof(struct pf_context));

    return retval;
}

// public API

void pf_set_callbacks(pf_read_f read_f, pf_write_f write_f, pf_fsync_f fsync_f,
                      pf_truncate_f truncate_f, pf_aes_cmac_f aes_cmac_f,
                      pf_aes_gcm_encrypt_f aes_gcm_encrypt_f,
                      pf_aes_gcm_decrypt_f aes_gcm_decrypt_f, pf_random_f random_f,
                      pf_debug_f debug_f) {
    g_cb_read            = read_f;
    g_cb_write           = write_f;
    g_cb_fsync           = fsync_f;
    g_cb_truncate        = truncate_f;
    g_cb_aes_cmac        = aes_cmac_f;
    g_cb_aes_gcm_encrypt = aes_gcm_encrypt_f;
    g_cb_aes_gcm_decrypt = aes_gcm_decrypt_f;
    g_cb_random          = random_f;
    g_cb_debug           = debug_f;
    g_initialized = true;
}

pf_status_t pf_open(pf_handle_t handle, const char* path, uint64_t underlying_size,
                    pf_file_mode_t mode, bool create, const pf_key_t* key, pf_context_t** context) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    pf_status_t status;
    *context = ipf_open(path, mode, create, handle, underlying_size, key, &status);
    return status;
}

pf_status_t pf_close(pf_context_t* pf) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (ipf_close(pf)) {
        free(pf);
        return PF_STATUS_SUCCESS;
    }

    pf_status_t ret = pf->last_error;
    free(pf);
    return ret;
}

pf_status_t pf_get_size(pf_context_t* pf, uint64_t* size) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    *size = pf->metadata_decrypted.file_size;
    return PF_STATUS_SUCCESS;
}

pf_status_t pf_set_size(pf_context_t* pf, uint64_t size) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (!(pf->mode & PF_FILE_MODE_WRITE))
        return PF_STATUS_INVALID_MODE;

    if (size == pf->metadata_decrypted.file_size)
        return PF_STATUS_SUCCESS;

    if (size > pf->metadata_decrypted.file_size) {
        uint64_t offset = pf->metadata_decrypted.file_size;
        DEBUG_PF("extending the file from %lu to %lu", offset, size);
        if (ipf_write(pf, NULL, offset, size - offset) != size - offset)
            return pf->last_error;

        return PF_STATUS_SUCCESS;
    }

    // Truncation.

    // The structure of the protected file is such that we can simply truncate
    // the file after the last data node belonging to still-used data.
    // Some MHT entries will be left with dangling data describing the truncated
    // nodes, but this is not a problem since they will be unused, and will be
    // overwritten with new data when the relevant nodes get allocated again.

    // First, ensure any nodes that will be truncated are not in cache. We do it
    // by simply flushing and then emptying the entire cache.
    if (!ipf_internal_flush(pf))
        return pf->last_error;
    ipf_delete_cache(pf);

    // Calculate new file size.
    uint64_t new_file_size;
    if (size <= MD_USER_DATA_SIZE) {
        new_file_size = PF_NODE_SIZE;
    } else {
        uint64_t physical_node_number;
        get_node_numbers(size - 1, NULL, NULL, NULL, &physical_node_number);
        new_file_size = (physical_node_number + 1) * PF_NODE_SIZE;
    }
    pf_status_t status = g_cb_truncate(pf->host_file_handle, new_file_size);
    if (PF_FAILURE(status))
        return status;
    // If successfully truncated, update our bookkeeping.
    pf->metadata_decrypted.file_size = size;
    pf->need_writing = true;
    return PF_STATUS_SUCCESS;
}

pf_status_t pf_rename(pf_context_t* pf, const char* new_path) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (!(pf->mode & PF_FILE_MODE_WRITE))
        return PF_STATUS_INVALID_MODE;

    size_t new_path_size = strlen(new_path) + 1;
    if (new_path_size > PATH_MAX_SIZE)
        return PF_STATUS_PATH_TOO_LONG;

    memset(pf->metadata_decrypted.file_path, 0, sizeof(pf->metadata_decrypted.file_path));
    memcpy(pf->metadata_decrypted.file_path, new_path, new_path_size);
    pf->need_writing = true;
    if (!ipf_internal_flush(pf))
        return pf->last_error;

    return PF_STATUS_SUCCESS;
}

pf_status_t pf_read(pf_context_t* pf, uint64_t offset, size_t size, void* output,
                    size_t* bytes_read) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (!size) {
        *bytes_read = 0;
        return PF_STATUS_SUCCESS;
    }

    if (PF_FAILURE(pf->file_status)) {
        pf->last_error = pf->file_status;
        return pf->last_error;
    }

    if (offset >= pf->metadata_decrypted.file_size) {
        *bytes_read = 0;
        return PF_STATUS_SUCCESS;
    }

    size_t bytes = ipf_read(pf, output, offset, size);
    if (!bytes)
        return pf->last_error;

    *bytes_read = bytes;
    return PF_STATUS_SUCCESS;
}

pf_status_t pf_write(pf_context_t* pf, uint64_t offset, size_t size, const void* input) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (!ipf_check_writable(pf))
        return pf->last_error;

    if (offset > pf->metadata_decrypted.file_size) {
        pf_status_t ret = pf_set_size(pf, offset);
        if (!PF_SUCCESS(ret)) {
            pf->last_error = ret;
            return pf->last_error;
        }
    }

    if (ipf_write(pf, input, offset, size) != size)
        return pf->last_error;

    return PF_STATUS_SUCCESS;
}

pf_status_t pf_flush(pf_context_t* pf) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (!ipf_internal_flush(pf))
        return pf->last_error;

    /* Perform a synchronous fsync in this "wrapper" function instead of `ipf_internal_flush()`.
     * This is because we want to fsync only when explicitly asked for: `pf_flush()` is called when
     * the app issues an actual fsync()/fdatasync() syscalls. The internal `ipf_internal_flush()` is
     * more broadly used: it's called when file contents must be flushed to the host OS (e.g. during
     * the rename operation). */
    pf_status_t status = g_cb_fsync(pf->host_file_handle);
    if (PF_FAILURE(status)) {
        pf->last_error = status;
        return pf->last_error;
    }

    return PF_STATUS_SUCCESS;
}
