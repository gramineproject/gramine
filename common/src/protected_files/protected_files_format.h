/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Rafal Wojdyla <omeg@invisiblethingslab.com>
 * Copyright (C) 2020 Intel Corporation
 */

#pragma once

#pragma pack(push, 1)

#ifdef USE_STDLIB
#include <assert.h>
#else
#include "assert.h"
#endif

#include <limits.h>

#include "protected_files.h"

#define PF_FILE_ID       0x46505f5346415247 /* GRAFS_PF */
#define PF_MAJOR_VERSION 0x01
#define PF_MINOR_VERSION 0x00

#define METADATA_KEY_NAME "SGX-PROTECTED-FS-METADATA-KEY"
#define MAX_LABEL_SIZE    64
static_assert(sizeof(METADATA_KEY_NAME) <= MAX_LABEL_SIZE, "label too long");

#define PATH_MAX_SIZE (260 + 512)

#define MD_USER_DATA_SIZE (PF_NODE_SIZE * 3 / 4)
static_assert(MD_USER_DATA_SIZE == 3072, "bad struct size");

#define MAX_PAGES_IN_CACHE 48

enum {
    FILE_MHT_NODE_TYPE  = 1,
    FILE_DATA_NODE_TYPE = 2,
};

typedef struct _gcm_crypto_data {
    pf_key_t key;
    pf_mac_t gmac;
} gcm_crypto_data_t;

// for PF_NODE_SIZE == 4096, we have 96 attached data nodes and 32 MHT child nodes
// 3/4 of the node is dedicated to data nodes, 1/4 to MHT nodes
#define ATTACHED_DATA_NODES_COUNT ((PF_NODE_SIZE / sizeof(gcm_crypto_data_t)) * 3 / 4)
#define CHILD_MHT_NODES_COUNT     ((PF_NODE_SIZE / sizeof(gcm_crypto_data_t)) * 1 / 4)
static_assert(ATTACHED_DATA_NODES_COUNT == 96, "ATTACHED_DATA_NODES_COUNT");
static_assert(CHILD_MHT_NODES_COUNT == 32, "CHILD_MHT_NODES_COUNT");

typedef struct _metadata_plaintext_header {
    uint64_t   file_id;
    uint8_t    major_version;
    uint8_t    minor_version;
    pf_salt_t  metadata_key_salt;
    pf_mac_t   metadata_gmac; /* GCM mac */
} metadata_plaintext_header_t;

typedef struct _metadata_decrypted_header {
    char     file_path[PATH_MAX_SIZE];
    uint64_t file_size;
    pf_key_t root_mht_node_key;
    pf_mac_t root_mht_node_gmac;
    uint8_t  file_data[MD_USER_DATA_SIZE];
} metadata_decrypted_header_t;

typedef uint8_t metadata_encrypted_blob_t[sizeof(metadata_decrypted_header_t)];

typedef uint8_t metadata_padding_t[PF_NODE_SIZE -
                                   (sizeof(metadata_plaintext_header_t) +
                                    sizeof(metadata_encrypted_blob_t))];

typedef struct _metadata_node {
    metadata_plaintext_header_t plaintext_header;
    metadata_encrypted_blob_t   encrypted_blob;
    metadata_padding_t          padding;
} metadata_node_t;
static_assert(sizeof(metadata_node_t) == PF_NODE_SIZE, "sizeof(metadata_node_t)");

typedef struct _mht_node {
    gcm_crypto_data_t data_nodes_crypto[ATTACHED_DATA_NODES_COUNT];
    gcm_crypto_data_t mht_nodes_crypto[CHILD_MHT_NODES_COUNT];
} mht_node_t;
static_assert(sizeof(mht_node_t) == PF_NODE_SIZE, "sizeof(mht_node_t)");

typedef struct _data_node {
    uint8_t bytes[PF_NODE_SIZE];
} data_node_t;
static_assert(sizeof(data_node_t) == PF_NODE_SIZE, "sizeof(data_node_t)");

typedef struct _encrypted_node {
    uint8_t bytes[PF_NODE_SIZE];
} encrypted_node_t;
static_assert(sizeof(encrypted_node_t) == PF_NODE_SIZE, "sizeof(encrypted_node_t)");

static_assert(sizeof(mht_node_t) == sizeof(data_node_t), "sizes of MHT and data nodes differ");

// Data struct that wraps the 4KB encrypted-node buffer (bounce buffer) and the corresponding 4KB
// decrypted-data buffer (plain buffer), plus additional fields. This data struct is used for both
// Data and MHT nodes (but not for Metadata node).
typedef struct _file_node {
    uint8_t type;
    bool need_writing;
    struct _file_node* parent;

    uint64_t logical_node_number;
    uint64_t physical_node_number;

    encrypted_node_t encrypted; // encrypted data from storage (bounce buffer)
    union {                     // decrypted data in private memory (plain buffer)
        mht_node_t mht;
        data_node_t data;
    } decrypted;
} file_node_t;

typedef struct {
    uint32_t index;             // always "1"; FIXME: what's the point of this?
    char label[MAX_LABEL_SIZE]; // must be NULL terminated
    pf_salt_t key_salt;         // salt for key derivation from KDK, stored in metadata node
    uint32_t output_len;        // in bits; always 128; FIXME: what's the point of this?
} kdf_input_t;

#pragma pack(pop)
