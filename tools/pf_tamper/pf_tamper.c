/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Rafal Wojdyla <omeg@invisiblethingslab.com>
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define USE_STDLIB
#include "api.h"
#include "pf_util.h"
#include "protected_files.h"
#include "protected_files_format.h"
#include "util.h"

/* Tamper with a PF in various ways for testing purposes. The PF is assumed to be valid and have at
 * least enough data to contain two MHT nodes. */

/* Command line options */
struct option g_options[] = {
    { "input", required_argument, 0, 'i' },
    { "output", required_argument, 0, 'o' },
    { "wrap-key", required_argument, 0, 'w' },
    { "verbose", no_argument, 0, 'v' },
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
};

static void usage(const char* argv0) {
    INFO("\nUsage: %s [options]\n", argv0);
    INFO("\nAvailable options:\n");
    INFO("  --help, -h           Display this help\n");
    INFO("  --verbose, -v        Enable verbose output\n");
    INFO("  --wrap-key, -w PATH  Path to wrap key file\n");
    INFO("  --input, -i PATH     Source file to be tampered with (must be a valid PF)\n");
    INFO("  --output, -o PATH    Directory where modified files will be written to\n");
}

#define FATAL(fmt, ...) do { \
    ERROR(fmt, ##__VA_ARGS__); \
    exit(-1); \
} while (0)

size_t g_input_size = 0;
char* g_input_name = NULL;
void* g_input_data = MAP_FAILED;
char* g_output_dir = NULL;
char* g_output_path = NULL;
size_t g_output_path_size = 0;
pf_key_t g_wrap_key;
pf_key_t g_meta_key;

static pf_iv_t g_empty_iv = {0};

static void derive_main_key(const pf_key_t* kdk, const pf_nonce_t* nonce, pf_key_t* out_key) {
    kdf_input_t buf = {0};
    pf_status_t status;

    buf.counter = 1;
    strncpy(buf.label, METADATA_KEY_NAME, MAX_LABEL_SIZE);
    COPY_ARRAY(buf.nonce, *nonce);
    buf.output_len = 0x80;

    status = mbedtls_aes_cmac(kdk, &buf, sizeof(buf), out_key);
    if (PF_FAILURE(status))
        FATAL("key derivation failed\n");
}

static void make_output_path(const char* suffix) {
    snprintf(g_output_path, g_output_path_size, "%s/%s.%s", g_output_dir, g_input_name, suffix);
    INFO("[*] %s\n", g_output_path);
}

/* PF layout (node size is PF_NODE_SIZE):
 * - Node 0: metadata (metadata_node_t)
 *   - metadata_plaintext_t
 *   - metadata_decrypted_t (may include MD_USER_DATA_SIZE bytes of data)
 *   - metadata_padding_t
 * - Node 1: MHT (mht_node_t)
 * - Node 2-97: data (ATTACHED_DATA_NODES_COUNT == 96)
 * - Node 98: MHT
 * - Node 99-195: data
 * - ...
 */
static void truncate_file(const char* suffix, size_t output_size) {
    int ret;

    make_output_path(suffix);

    if (output_size < g_input_size) {
        ret = write_file(g_output_path, output_size, g_input_data);
    } else {
        ret = write_file(g_output_path, g_input_size, g_input_data);
        if (ret < 0)
            goto out;
        ret = truncate(g_output_path, output_size);
    }
out:
    if (ret < 0)
        FATAL("truncate_file failed: %d\n", ret);
}

#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define FIELD_TRUNCATED(t, f) (offsetof(t, f) + (FIELD_SIZEOF(t, f) / 2))
#define DATA_CRYPTO_SIZE (FIELD_SIZEOF(mht_node_t, data_nodes_crypto))

static void tamper_truncate(void) {
    size_t mdps = sizeof(metadata_plaintext_t);
    DBG("size(metadata_plaintext_t)             = 0x%04lx\n", sizeof(metadata_plaintext_t));
    DBG("metadata_plaintext_t.file_id           : 0x%04lx (0x%04lx)\n",
        offsetof(metadata_plaintext_t, file_id), FIELD_SIZEOF(metadata_plaintext_t, file_id));
    DBG("metadata_plaintext_t.major_version     : 0x%04lx (0x%04lx)\n",
        offsetof(metadata_plaintext_t, major_version),
        FIELD_SIZEOF(metadata_plaintext_t, major_version));
    DBG("metadata_plaintext_t.minor_version     : 0x%04lx (0x%04lx)\n",
        offsetof(metadata_plaintext_t, minor_version),
        FIELD_SIZEOF(metadata_plaintext_t, minor_version));
    DBG("metadata_plaintext_t.metadata_key_nonce: 0x%04lx (0x%04lx)\n",
        offsetof(metadata_plaintext_t, metadata_key_nonce),
        FIELD_SIZEOF(metadata_plaintext_t, metadata_key_nonce));
    DBG("metadata_plaintext_t.metadata_mac     : 0x%04lx (0x%04lx)\n",
        offsetof(metadata_plaintext_t, metadata_mac),
        FIELD_SIZEOF(metadata_plaintext_t, metadata_mac));

    DBG("size(metadata_decrypted_t)         = 0x%04lx\n", sizeof(metadata_decrypted_t));
    DBG("metadata_decrypted_t.file_path     : 0x%04lx (0x%04lx)\n",
        mdps + offsetof(metadata_decrypted_t, file_path),
        FIELD_SIZEOF(metadata_decrypted_t, file_path));
    DBG("metadata_decrypted_t.file_size     : 0x%04lx (0x%04lx)\n",
        mdps + offsetof(metadata_decrypted_t, file_size),
        FIELD_SIZEOF(metadata_decrypted_t, file_size));
    DBG("metadata_decrypted_t.root_mht_node_key : 0x%04lx (0x%04lx)\n",
        mdps + offsetof(metadata_decrypted_t, root_mht_node_key),
        FIELD_SIZEOF(metadata_decrypted_t, root_mht_node_key));
    DBG("metadata_decrypted_t.root_mht_node_mac : 0x%04lx (0x%04lx)\n",
        mdps + offsetof(metadata_decrypted_t, root_mht_node_mac),
        FIELD_SIZEOF(metadata_decrypted_t, root_mht_node_mac));
    DBG("metadata_decrypted_t.file_data     : 0x%04lx (0x%04lx)\n",
        mdps + offsetof(metadata_decrypted_t, file_data),
        FIELD_SIZEOF(metadata_decrypted_t, file_data));

    DBG("size(metadata_padding_t)           = 0x%04lx\n", sizeof(metadata_padding_t));
    DBG("metadata_padding_t                 : 0x%04lx (0x%04lx)\n",
        mdps + sizeof(metadata_decrypted_t), sizeof(metadata_padding_t));

    /* node 0: metadata + 3k of user data */
    /* plain metadata */
    truncate_file("trunc_meta_plain_0", 0);
    truncate_file("trunc_meta_plain_1", FIELD_TRUNCATED(metadata_plaintext_t, file_id));
    truncate_file("trunc_meta_plain_2", offsetof(metadata_plaintext_t, major_version));
    truncate_file("trunc_meta_plain_3", offsetof(metadata_plaintext_t, minor_version));
    truncate_file("trunc_meta_plain_4", offsetof(metadata_plaintext_t, metadata_key_nonce));
    truncate_file("trunc_meta_plain_5", FIELD_TRUNCATED(metadata_plaintext_t, metadata_key_nonce));
    truncate_file("trunc_meta_plain_6", offsetof(metadata_plaintext_t, metadata_mac));
    truncate_file("trunc_meta_plain_7", FIELD_TRUNCATED(metadata_plaintext_t, metadata_mac));

    /* encrypted metadata */
    truncate_file("trunc_meta_enc_0", mdps + offsetof(metadata_decrypted_t, file_path));
    truncate_file("trunc_meta_enc_1", mdps + FIELD_TRUNCATED(metadata_decrypted_t, file_path));
    truncate_file("trunc_meta_enc_2", mdps + offsetof(metadata_decrypted_t, file_size));
    truncate_file("trunc_meta_enc_3", mdps + FIELD_TRUNCATED(metadata_decrypted_t, file_size));
    truncate_file("trunc_meta_enc_4", mdps + offsetof(metadata_decrypted_t, root_mht_node_key));
    truncate_file("trunc_meta_enc_5", mdps + FIELD_TRUNCATED(metadata_decrypted_t,
                                                             root_mht_node_key));
    truncate_file("trunc_meta_enc_6", mdps + offsetof(metadata_decrypted_t, root_mht_node_mac));
    truncate_file("trunc_meta_enc_7", mdps + FIELD_TRUNCATED(metadata_decrypted_t,
                                                             root_mht_node_mac));
    truncate_file("trunc_meta_enc_8", mdps + offsetof(metadata_decrypted_t, file_data));
    truncate_file("trunc_meta_enc_9", mdps + FIELD_TRUNCATED(metadata_decrypted_t, file_data));

    /* padding */
    truncate_file("trunc_meta_pad_0", mdps + sizeof(metadata_decrypted_t));
    truncate_file("trunc_meta_pad_1", mdps + sizeof(metadata_decrypted_t)
                  + sizeof(metadata_padding_t) / 2);

    /* node 1: mht root */
    /* after node 0 */
    truncate_file("trunc_mht_0", PF_NODE_SIZE);
    /* middle of data_nodes_crypto[0].key */
    truncate_file("trunc_mht_1", PF_NODE_SIZE + PF_KEY_SIZE / 2);
    /* after data_nodes_crypto[0].key */
    truncate_file("trunc_mht_2", PF_NODE_SIZE + PF_KEY_SIZE);
    /* middle of data_nodes_crypto[0].mac */
    truncate_file("trunc_mht_3", PF_NODE_SIZE + PF_KEY_SIZE + PF_MAC_SIZE / 2);
    /* after data_nodes_crypto[0].mac */
    truncate_file("trunc_mht_4", PF_NODE_SIZE + PF_KEY_SIZE + PF_MAC_SIZE);
    /* after data_nodes_crypto */
    truncate_file("trunc_mht_5", PF_NODE_SIZE + DATA_CRYPTO_SIZE);
    /* middle of mht_nodes_crypto[0].key */
    truncate_file("trunc_mht_6", PF_NODE_SIZE + DATA_CRYPTO_SIZE + PF_KEY_SIZE / 2);
    /* after mht_nodes_crypto[0].key */
    truncate_file("trunc_mht_7", PF_NODE_SIZE + DATA_CRYPTO_SIZE + PF_KEY_SIZE);
    /* middle of mht_nodes_crypto[0].mac */
    truncate_file("trunc_mht_8", PF_NODE_SIZE + DATA_CRYPTO_SIZE + PF_KEY_SIZE + PF_MAC_SIZE / 2);
    /* after mht_nodes_crypto[0].mac */
    truncate_file("trunc_mht_9", PF_NODE_SIZE + DATA_CRYPTO_SIZE + PF_KEY_SIZE + PF_MAC_SIZE);

    /* node 2-3: data #0, #1 */
    /* after mht root */
    truncate_file("trunc_data_0", 2 * PF_NODE_SIZE);
    /* middle of data #0 */
    truncate_file("trunc_data_1", 2 * PF_NODE_SIZE + PF_NODE_SIZE / 2);
    /* after data #0 */
    truncate_file("trunc_data_2", 3 * PF_NODE_SIZE);
    /* middle of data #1 */
    truncate_file("trunc_data_3", 3 * PF_NODE_SIZE + PF_NODE_SIZE / 2);

    /* extend */
    /* Note: The code implementing Gramine's encrypted filesystem in `common/src/protected_files.c`
     * tolerates the actual file to be longer than what the `file_size` attribute in the decrypted
     * header says. The only required invariant enforced in the code is ensuring that the file size
     * is a multiple of PF_NODE_SIZE, so let us validate this below. */
    truncate_file("extend_0", g_input_size + 1);
}

/* returns mmap'd output contents */
static void* create_output(const char* path) {
    void* mem = MAP_FAILED;
    int fd = open(path, O_RDWR|O_CREAT, 0664);
    if (fd < 0)
        FATAL("Failed to open output file '%s': %s\n", path, strerror(errno));

    if (ftruncate(fd, g_input_size) < 0)
        FATAL("Failed to ftruncate output file '%s': %s\n", path, strerror(errno));

    mem = mmap(NULL, g_input_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED)
        FATAL("Failed to mmap output file '%s': %s\n", path, strerror(errno));

    memcpy(mem, g_input_data, g_input_size);

    close(fd);
    return mem;
}

static void pf_decrypt(const void* encrypted, size_t size, const pf_key_t* key, const pf_mac_t* mac,
                       void* decrypted, const char* msg) {
    pf_status_t status = mbedtls_aes_gcm_decrypt(key, &g_empty_iv, NULL, 0,
                                                 encrypted, size,
                                                 decrypted, mac);
    if (PF_FAILURE(status))
        FATAL("decrypting %s failed\n", msg);
}

static void pf_encrypt(const void* decrypted, size_t size, const pf_key_t* key, pf_mac_t* mac,
                       void* encrypted, const char* msg) {
    pf_status_t status = mbedtls_aes_gcm_encrypt(key, &g_empty_iv, NULL, 0,
                                                 decrypted, size,
                                                 encrypted, mac);
    if (PF_FAILURE(status))
        FATAL("encrypting %s failed\n", msg);
}

/* copy input PF and apply some modifications */
#define __BREAK_PF(suffix, ...) do { \
    make_output_path(suffix); \
    meta = create_output(g_output_path); \
    out = (uint8_t*)meta; \
    pf_decrypt(&meta->encrypted_part, sizeof(meta->encrypted_part), &g_meta_key, \
               &meta->plaintext_part.metadata_mac, meta_dec, "metadata"); \
    mht_enc = (mht_node_t*)(out + PF_NODE_SIZE); \
    pf_decrypt(mht_enc, sizeof(*mht_enc), &meta_dec->root_mht_node_key, \
               &meta_dec->root_mht_node_mac, mht_dec, "mht"); \
    __VA_ARGS__ \
    munmap(meta, g_input_size); \
} while (0)

/*
 * Three different macros to tamper with a file:
 * - BREAK_PLN: tamper with the plaintext part of the metadata.
 * - BREAK_DEC: tamper with the decrypted part of the metadata and re-encrypt it.
 *   (Not something an adversary can do to attack the system but still tests overall reliability.)
 * - BREAK_MHT: tamper with the MHT nodes.
 *
 * The tampering is done by creating a new file with the tampered part and the rest copied from the
 * original file.
 */

/* if update is true, also create a file with correct metadata MAC */
#define BREAK_PLN(suffix, update, ...)                                                   \
    do {                                                                                 \
        __BREAK_PF(suffix, __VA_ARGS__);                                                 \
        if (update) {                                                                    \
            __BREAK_PF(                                                                  \
                suffix "_fixed", __VA_ARGS__ {                                           \
                    pf_encrypt(meta_dec, sizeof(*meta_dec), &g_meta_key,                 \
                               &meta->plaintext_part.metadata_mac, meta->encrypted_part, \
                               "metadata");                                              \
                });                                                                      \
        }                                                                                \
    } while (0)

#define BREAK_DEC(suffix, ...)                                                                    \
    do {                                                                                          \
        __BREAK_PF(                                                                               \
            suffix, __VA_ARGS__ {                                                                 \
                pf_encrypt(meta_dec, sizeof(*meta_dec), &g_meta_key,                              \
                           &meta->plaintext_part.metadata_mac, meta->encrypted_part, "metadata"); \
            });                                                                                   \
    } while (0)

#define BREAK_MHT(suffix, ...)                                                      \
    do {                                                                            \
        __BREAK_PF(                                                                 \
            suffix, __VA_ARGS__ {                                                   \
                pf_encrypt(mht_dec, sizeof(*mht_dec), &meta_dec->root_mht_node_key, \
                           &meta_dec->root_mht_node_mac, mht_enc, "mht");           \
            });                                                                     \
    } while (0)

#define LAST_BYTE(array) (((uint8_t*)&array)[sizeof(array) - 1])

static void tamper_modify(void) {
    metadata_node_t* meta = NULL;
    uint8_t* out = NULL;
    metadata_decrypted_t* meta_dec = malloc(sizeof(*meta_dec));
    if (!meta_dec)
        FATAL("Out of memory\n");
    mht_node_t* mht_enc = NULL;
    mht_node_t* mht_dec = malloc(sizeof(*mht_dec));
    if (!mht_dec)
        FATAL("Out of memory\n");

    /* plain part of the metadata isn't covered by the MAC so no point updating it */
    BREAK_PLN("meta_plain_id_0", /*update=*/false,
              { meta->plaintext_part.file_id = 0; });
    BREAK_PLN("meta_plain_id_1", /*update=*/false,
              { meta->plaintext_part.file_id = UINT64_MAX; });
    BREAK_PLN("meta_plain_version_0", /*update=*/false,
              { meta->plaintext_part.major_version = 0; });
    BREAK_PLN("meta_plain_version_1", /*update=*/false,
              { meta->plaintext_part.major_version = 0xff; });
    /* Note: Gramine's encrypted filesystem only tests (equality) on major version but nothing about
     * minor_version, so no point in tampering with meta->plaintext_part.minor_version. */

    /* metadata_key_nonce is the keying material for encrypted metadata key derivation, so create
     * also PFs with updated MACs */
    BREAK_PLN("meta_plain_nonce_0", /*update=*/true,
              { meta->plaintext_part.metadata_key_nonce[0] ^= 1; });
    BREAK_PLN("meta_plain_nonce_1", /*update=*/true,
              { LAST_BYTE(meta->plaintext_part.metadata_key_nonce) ^= 0xfe; });
    BREAK_PLN("meta_plain_mac_0", /*update=*/false,  // update would overwrite the tampering
              { meta->plaintext_part.metadata_mac[0] ^= 0xfe; });
    BREAK_PLN("meta_plain_mac_1", /*update=*/false,  // update would overwrite the tampering
              { LAST_BYTE(meta->plaintext_part.metadata_mac) ^= 1; });
    BREAK_PLN("meta_plain_encrypted_0", /*update=*/false,  // update would overwrite the tampering
              { meta->encrypted_part[0] ^= 1; });
    BREAK_PLN("meta_plain_encrypted_1", /*update=*/false,  // update would overwrite the tampering
              { LAST_BYTE(meta->encrypted_part) ^= 1; });

    BREAK_DEC("meta_enc_filename_0", { meta_dec->file_path[0] = 0; });
    BREAK_DEC("meta_enc_filename_1", { meta_dec->file_path[0] ^= 1; });
    assert(strlen(meta_dec->file_path) > 0);
    BREAK_DEC("meta_enc_filename_2", {
        meta_dec->file_path[strlen(meta_dec->file_path) - 1] =
            '\0';  // shorten path by one character
    });
    /* Note: Gramine's encrypted filesystem does not generally test whether a file is longer than
     * what `meta_dec->file_size` indicates; in particular it does not test for the case where the
     * header says the file is empty but file would contain (ignored) data blocks. So test only size
     * modifications which interfere with the mht tree but not with `meta_dec->file_size = 0`. */
    BREAK_DEC("meta_enc_size_0",    { meta_dec->file_size = g_input_size - PF_NODE_SIZE; });
    BREAK_DEC("meta_enc_size_1",    { meta_dec->file_size = g_input_size - 1; });
    BREAK_DEC("meta_enc_size_2",    { meta_dec->file_size = g_input_size + PF_NODE_SIZE; });
    BREAK_DEC("meta_enc_size_3",    { meta_dec->file_size = UINT64_MAX; });
    BREAK_DEC("meta_enc_size_4",    { meta_dec->file_size = g_input_size + 1; });
    BREAK_DEC("meta_enc_mht_key_0", { meta_dec->root_mht_node_key[0] ^= 1; });
    BREAK_DEC("meta_enc_mht_key_1", { LAST_BYTE(meta_dec->root_mht_node_key) ^= 0xfe; });
    BREAK_DEC("meta_enc_mht_mac_0", { meta_dec->root_mht_node_mac[0] ^= 1; });
    BREAK_DEC("meta_enc_mht_mac_1", { LAST_BYTE(meta_dec->root_mht_node_mac) ^= 0xfe; });
    /* Note: no point in tampering with (decrypted) meta_dec->file_data as there is no way to
     * detect such tampering, the re-encryption would turn it in authentic (different) data. */

    /* Note: padding is ignored during processing, so no point in tampering meta->padding */

    BREAK_MHT("mht_0", { mht_dec->data_nodes_crypto[0].key[0] ^= 1; });
    BREAK_MHT("mht_1", { mht_dec->data_nodes_crypto[0].mac[0] ^= 1; });
    BREAK_MHT("mht_2", { mht_dec->mht_nodes_crypto[0].key[0] ^= 1; });
    BREAK_MHT("mht_3", { mht_dec->mht_nodes_crypto[0].mac[0] ^= 1; });
    BREAK_MHT("mht_4", { mht_dec->data_nodes_crypto[ATTACHED_DATA_NODES_COUNT - 1].key[0] ^= 1; });
    BREAK_MHT("mht_5", { mht_dec->data_nodes_crypto[ATTACHED_DATA_NODES_COUNT - 1].mac[0] ^= 1; });
    BREAK_MHT("mht_6", { mht_dec->mht_nodes_crypto[CHILD_MHT_NODES_COUNT - 1].key[0] ^= 1; });
    BREAK_MHT("mht_7", { mht_dec->mht_nodes_crypto[CHILD_MHT_NODES_COUNT - 1].mac[0] ^= 1; });
    BREAK_MHT("mht_8", {
        gcm_crypto_data_t crypto;
        memcpy(&crypto, &mht_dec->data_nodes_crypto[0], sizeof(crypto));
        memcpy(&mht_dec->data_nodes_crypto[0], &mht_dec->data_nodes_crypto[1], sizeof(crypto));
        memcpy(&mht_dec->data_nodes_crypto[1], &crypto, sizeof(crypto));
    });
    BREAK_MHT("mht_9", {
        gcm_crypto_data_t crypto;
        memcpy(&crypto, &mht_dec->mht_nodes_crypto[0], sizeof(crypto));
        memcpy(&mht_dec->mht_nodes_crypto[0], &mht_dec->mht_nodes_crypto[1], sizeof(crypto));
        memcpy(&mht_dec->mht_nodes_crypto[1], &crypto, sizeof(crypto));
    });

    /* data nodes start from node #2 */
    BREAK_PLN("data_0", /*update=*/false, { *(out + 2 * PF_NODE_SIZE) ^= 1; });
    BREAK_PLN("data_1", /*update=*/false, { *(out + 3 * PF_NODE_SIZE - 1) ^= 1; });
    BREAK_PLN("data_2", /*update=*/false, {
        /* swap data nodes */
        memcpy(out + 2 * PF_NODE_SIZE, g_input_data + 3 * PF_NODE_SIZE, PF_NODE_SIZE);
        memcpy(out + 3 * PF_NODE_SIZE, g_input_data + 2 * PF_NODE_SIZE, PF_NODE_SIZE);
    });

    free(mht_dec);
    free(meta_dec);
}

int main(int argc, char* argv[]) {
    int ret = -1;

    int option          = 0;
    char* input_path    = NULL;
    char* wrap_key_path = NULL;
    int input_fd        = -1;

    while (true) {
        option = getopt_long(argc, argv, "i:o:w:vh", g_options, NULL);
        if (option == -1)
            break;

        switch (option) {
            case 'i':
                input_path = optarg;
                break;
            case 'o':
                g_output_dir = optarg;
                break;
            case 'w':
                wrap_key_path = optarg;
                break;
            case 'v':
                set_verbose(true);
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                ERROR("Unknown option: %c\n", option);
                usage(argv[0]);
        }
    }

    if (!input_path) {
        ERROR("Input path not specified\n");
        usage(argv[0]);
        goto out;
    }

    if (!g_output_dir) {
        ERROR("Output path not specified\n");
        usage(argv[0]);
        goto out;
    }

    if (!wrap_key_path) {
        ERROR("Wrap key path not specified\n");
        usage(argv[0]);
        goto out;
    }

    input_fd = open(input_path, O_RDONLY);
    if (input_fd < 0) {
        ERROR("Failed to open input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    ssize_t input_size = get_file_size(input_fd);
    if (input_size < 0) {
        ERROR("Failed to stat input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }
    g_input_size = input_size;

    g_input_data = mmap(NULL, g_input_size, PROT_READ, MAP_PRIVATE, input_fd, 0);
    if (g_input_data == MAP_FAILED) {
        ERROR("Failed to mmap input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    load_wrap_key(wrap_key_path, &g_wrap_key);
    derive_main_key(&g_wrap_key, &((metadata_plaintext_t*)g_input_data)->metadata_key_nonce,
                    &g_meta_key);

    g_input_name = basename(input_path);
    g_output_path_size = strlen(g_input_name) + strlen(g_output_dir) + 256;
    g_output_path = malloc(g_output_path_size);
    if (!g_output_path) {
        ERROR("No memory\n");
        goto out;
    }

    tamper_truncate();
    tamper_modify();
    ret = 0;

out:
    /* skip cleanup as we are in main() */
    return ret;
}
