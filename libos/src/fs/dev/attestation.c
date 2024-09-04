/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of local- and remote-attestation logic implemented via
 * `/dev/attestation/{user_report_data, target_info, my_target_info, report, quote}` pseudo-files.
 *
 * The attestation logic uses PalAttestationReport() and PalAttestationQuote() and is generic enough
 * to support attestation flows similar to Intel SGX. Currently only SGX attestation is used.
 *
 * This pseudo-FS interface is not thread-safe. It is the responsibility of the application to
 * correctly synchronize concurrent accesses to the pseudo-files. We expect attestation flows to
 * be generally single-threaded and therefore do not introduce synchronization here.
 */

#include "api.h"
#include "libos_fs_encrypted.h"
#include "libos_fs_pseudo.h"
#include "pal.h"
#include "toml_utils.h"

/* user_report_data, target_info and quote are opaque blobs of predefined maximum sizes. Currently
 * these sizes are overapproximations of SGX requirements (report_data is 64B, target_info is
 * 512B, EPID quote is about 1KB, DCAP quote is about 4KB). */
#define USER_REPORT_DATA_MAX_SIZE 256
#define TARGET_INFO_MAX_SIZE      1024
#define QUOTE_MAX_SIZE            8192

static char g_user_report_data[USER_REPORT_DATA_MAX_SIZE] = {0};
static size_t g_user_report_data_size = 0;

static char g_target_info[TARGET_INFO_MAX_SIZE] = {0};
static size_t g_target_info_size = 0;

static size_t g_report_size = 0;

static int init_attestation_struct_sizes(void) {
    if (g_user_report_data_size && g_target_info_size && g_report_size) {
        /* already initialized, nothing to do here */
        return 0;
    }

    int ret = PalAttestationReport(/*user_report_data=*/NULL, &g_user_report_data_size,
                                   /*target_info=*/NULL, &g_target_info_size,
                                   /*report=*/NULL, &g_report_size);
    if (ret < 0)
        return -EACCES;

    assert(g_user_report_data_size && g_user_report_data_size <= sizeof(g_user_report_data));
    assert(g_target_info_size && g_target_info_size <= sizeof(g_target_info));
    assert(g_report_size);
    return 0;
}

/* Write at most `max_size` bytes of data to the buffer, padding the rest with zeroes. */
static void update_buffer(char* buffer, size_t max_size, const char* data, size_t size) {
   if (size < max_size) {
       memcpy(buffer, data, size);
       memset(buffer + size, 0, max_size - size);
   } else {
       memcpy(buffer, data, max_size);
   }
}

/*!
 * \brief Modify user-defined report data used in `report` and `quote` pseudo-files.
 *
 * This file `/dev/attestation/user_report_data` can be opened for read and write. Typically, it is
 * opened and written into before opening and reading from `/dev/attestation/report` or
 * `/dev/attestation/quote` files, so they can use the user-provided report data blob.
 *
 * In case of SGX, user report data can be an arbitrary string of size 64B.
 */
static int user_report_data_save(struct libos_dentry* dent, const char* data, size_t size) {
    __UNUSED(dent);

    int ret = init_attestation_struct_sizes();
    if (ret < 0)
        return ret;

    update_buffer(g_user_report_data, g_user_report_data_size, data, size);
    return 0;
}

/*!
 * \brief Modify target info used in `report` pseudo-file.
 *
 * This file `/dev/attestation/target_info` can be opened for read and write. Typically, it is
 * opened and written into before opening and reading from `/dev/attestation/report` file, so the
 * latter can use the provided target info.
 *
 * In case of SGX, target info is an opaque blob of size 512B.
 */
static int target_info_save(struct libos_dentry* dent, const char* data, size_t size) {
    __UNUSED(dent);

    int ret = init_attestation_struct_sizes();
    if (ret < 0)
        return ret;

    update_buffer(g_target_info, g_target_info_size, data, size);
    return 0;
}

/*!
 * \brief Obtain this enclave's target info via PalAttestationReport().
 *
 * This file `/dev/attestation/my_target_info` can be opened for read and will contain the
 * target info of this enclave. The resulting target info blob can be passed to another enclave
 * as part of the local attestation flow.
 *
 * In case of SGX, target info is an opaque blob of size 512B.
 */
static int my_target_info_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    int ret = init_attestation_struct_sizes();
    if (ret < 0)
        return ret;

    char* user_report_data = NULL;
    char* target_info = NULL;

    user_report_data = calloc(1, g_user_report_data_size);
    if (!user_report_data) {
        ret = -ENOMEM;
        goto out;
    }

    target_info = calloc(1, g_target_info_size);
    if (!target_info) {
        ret = -ENOMEM;
        goto out;
    }

    size_t user_report_data_size = g_user_report_data_size;
    size_t target_info_size = g_target_info_size;
    size_t report_size = g_report_size;

    /* below invocation returns this enclave's target info because we zeroed out (via calloc)
     * target_info: it's a hint to function to update target_info with this enclave's info */
    ret = PalAttestationReport(user_report_data, &user_report_data_size, target_info,
                               &target_info_size, /*report=*/NULL, &report_size);
    if (ret < 0) {
        ret = -EACCES;
        goto out;
    }

    /* sanity checks: returned struct sizes must be the same as previously obtained ones */
    assert(user_report_data_size == g_user_report_data_size);
    assert(target_info_size == g_target_info_size);
    assert(report_size == g_report_size);

    ret = 0;

out:
    if (ret == 0) {
        *out_data = target_info;
        *out_size = g_target_info_size;
    } else {
        free(target_info);
    }
    free(user_report_data);
    return ret;
}


/*!
 * \brief Obtain report via PalAttestationReport() with previously populated user_report_data
 *        and target_info.
 *
 * Before opening `/dev/attestation/report` for read, user_report_data must be written into
 * `/dev/attestation/user_report_data` and target info must be written into
 * `/dev/attestation/target_info`. Otherwise the obtained report will contain incorrect or
 * stale user_report_data and target_info.
 *
 * In case of SGX, report is a locally obtained EREPORT struct of size 432B.
 */
static int report_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    int ret = init_attestation_struct_sizes();
    if (ret < 0)
        return ret;

    char* report = calloc(1, g_report_size);
    if (!report)
        return -ENOMEM;

    ret = PalAttestationReport(&g_user_report_data, &g_user_report_data_size, &g_target_info,
                               &g_target_info_size, report, &g_report_size);
    if (ret < 0) {
        free(report);
        return -EACCES;
    }

    *out_data = report;
    *out_size = g_report_size;
    return 0;
}


/*!
 * \brief Obtain quote by communicating with the outside-of-enclave service.
 *
 * Before opening `/dev/attestation/quote` for read, user_report_data must be written into
 * `/dev/attestation/user_report_data`. Otherwise the obtained quote will contain incorrect or
 * stale user_report_data. The resulting quote can be passed to another enclave or service as
 * part of the remote attestation flow.
 *
 * Note that this file doesn't depend on contents of files `/dev/attestation/target_info` and
 * `/dev/attestation/my_target_info`. This is because the quote always embeds target info of
 * the current enclave.
 *
 * In case of SGX, the obtained quote is the SGX quote created by the Quoting Enclave.
 */
static int quote_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    int ret = init_attestation_struct_sizes();
    if (ret < 0)
        return ret;

    size_t quote_size = QUOTE_MAX_SIZE;
    char* quote = calloc(1, quote_size);
    if (!quote)
        return -ENOMEM;

    ret = PalAttestationQuote(&g_user_report_data, g_user_report_data_size, quote, &quote_size);
    if (ret < 0) {
        free(quote);
        return -EACCES;
    }

    *out_data = quote;
    *out_size = quote_size;
    return 0;
}

/*!
 * \brief Get remote attestation type used.
 *
 * In case of SGX, same as `sgx.remote_attestation` manifest option.
 */
static int attestation_type_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    assert(g_pal_public_state->attestation_type);
    char* str = strdup(g_pal_public_state->attestation_type);
    if (!str)
        return -ENOMEM;

    *out_data = str;
    *out_size = strlen(str);
    return 0;
}

static bool key_name_exists(struct libos_dentry* parent, const char* name) {
    __UNUSED(parent);

    struct libos_encrypted_files_key* key = get_encrypted_files_key(name);
    return key != NULL;
}

struct key_list_names_data {
    readdir_callback_t callback;
    void* arg;
};

static int key_list_names_callback(struct libos_encrypted_files_key* key, void* arg) {
    struct key_list_names_data* data = arg;
    return data->callback(key->name, data->arg);
}

static int key_list_names(struct libos_dentry* parent, readdir_callback_t callback, void* arg) {
    __UNUSED(parent);

    struct key_list_names_data data = {
        .callback = callback,
        .arg = arg,
    };
    return list_encrypted_files_keys(&key_list_names_callback, &data);
}

static int key_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    struct libos_encrypted_files_key* key = get_encrypted_files_key(dent->name);
    if (!key)
        return -ENOENT;

    pf_key_t pf_key;
    bool is_set = read_encrypted_files_key(key, &pf_key);

    if (is_set) {
        char* buf = malloc(sizeof(pf_key));
        if (!buf)
            return -ENOMEM;
        memcpy(buf, &pf_key, sizeof(pf_key));

        *out_data = buf;
        *out_size = sizeof(pf_key);
    } else {
        *out_data = NULL;
        *out_size = 0;
    }
    return 0;
}

static int key_save(struct libos_dentry* dent, const char* data, size_t size) {
    struct libos_encrypted_files_key* key = get_encrypted_files_key(dent->name);
    if (!key)
        return -ENOENT;

    pf_key_t pf_key;
    if (size != sizeof(pf_key)) {
        log_debug("/dev/attestation/keys: invalid length");
        return -EACCES;
    }

    memcpy(&pf_key, data, sizeof(pf_key));
    update_encrypted_files_key(key, &pf_key);
    return 0;
}

static int init_sgx_attestation(struct pseudo_node* attestation, struct pseudo_node* keys) {
    if (strcmp(g_pal_public_state->host_type, "Linux-SGX"))
        return 0;

    if (!g_pal_public_state->attestation_type) {
        log_error("Cannot determine remote attestation type during init of /dev/attestation/");
        return -EINVAL;
    }

    /* always add the following SGX-specific files, even if remote attestation type is "none" */
    pseudo_add_str(attestation, "attestation_type", attestation_type_load);
    pseudo_add_str(attestation, "my_target_info", &my_target_info_load);
    pseudo_add_str(attestation, "report", &report_load);

    struct pseudo_node* user_report_data = pseudo_add_str(attestation, "user_report_data", NULL);
    user_report_data->perm = PSEUDO_PERM_FILE_RW;
    user_report_data->str.save = &user_report_data_save;

    struct pseudo_node* target_info = pseudo_add_str(attestation, "target_info", NULL);
    target_info->perm = PSEUDO_PERM_FILE_RW;
    target_info->str.save = &target_info_save;

    /* dummy retrieval of SGX sealing keys, so that they appear under /dev/attestation/keys/ */
    const char* sealing_keys_names[] = { PAL_KEY_NAME_SGX_MRENCLAVE, PAL_KEY_NAME_SGX_MRSIGNER };
    for (size_t i = 0; i < ARRAY_SIZE(sealing_keys_names); i++) {
        struct libos_encrypted_files_key* key;
        int ret = get_or_create_encrypted_files_key(sealing_keys_names[i], &key);
        if (ret < 0) {
            log_error("Cannot initialize SGX sealing key `%s`", sealing_keys_names[i]);
            return ret;
        }
    }

    /* SGX sealing keys must be read-only, so we mount them over other /dev/attestation/keys/ */
    pseudo_add_str(keys, PAL_KEY_NAME_SGX_MRENCLAVE, &key_load);
    pseudo_add_str(keys, PAL_KEY_NAME_SGX_MRSIGNER, &key_load);

    if (!strcmp(g_pal_public_state->attestation_type, "none")) {
        log_debug("host is Linux-SGX and remote attestation type is 'none', skipping "
                  "/dev/attestation/quote file");
        return 0;
    }

    log_debug("host is Linux-SGX and remote attestation type is '%s', adding "
              "/dev/attestation/quote file", g_pal_public_state->attestation_type);
    pseudo_add_str(attestation, "quote", &quote_load);
    return 0;
}

int init_attestation(struct pseudo_node* dev) {
    struct pseudo_node* attestation = pseudo_add_dir(dev, "attestation");

    struct pseudo_node* keys = pseudo_add_dir(attestation, "keys");
    struct pseudo_node* key = pseudo_add_str(keys, /*name=*/NULL, &key_load);
    key->name_exists = &key_name_exists;
    key->list_names = &key_list_names;
    key->perm = PSEUDO_PERM_FILE_RW;
    key->str.save = &key_save;

    return init_sgx_attestation(attestation, keys);
}
