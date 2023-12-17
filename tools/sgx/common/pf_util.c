/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Rafal Wojdyla <omeg@invisiblethingslab.com>
 */

#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include "pf_util.h"

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mbedtls/cmac.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>

#define USE_STDLIB
#include "api.h"
#include "path_utils.h"
#include "perm.h"
#include "util.h"

/* High-level protected files helper functions. */

/* PF handle structure in Linux environment */
typedef struct _linux_pf_handle_t {
    int fd;
    void* addr;
    size_t size;
} linux_pf_handle_t;

/* PF callbacks usable in a standard Linux environment.*/
static pf_status_t linux_truncate(pf_handle_t handle, uint64_t size, void** ret_addr) {
    linux_pf_handle_t* hdl = (linux_pf_handle_t*)handle;

    DBG("linux_truncate: fd %d, size %zu\n", hdl->fd, hdl->size);
    int ret = ftruncate64(hdl->fd, size);
    if (ret < 0) {
        ERROR("ftruncate64 failed: %s\n", strerror(errno));
        return PF_STATUS_CALLBACK_FAILED;
    }

    DBG("linux_truncate: addr %p, old_size %zu, new_size %zu\n", hdl->addr, hdl->size, size);
    void* addr;
    if (!hdl->addr && hdl->size == 0)
        addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, hdl->fd, 0);
    else
        addr = mremap(hdl->addr, hdl->size, size, MREMAP_MAYMOVE);
    if (addr == MAP_FAILED) {
        ERROR("mmap/mremap failed: %s\n", strerror(errno));
        return PF_STATUS_CALLBACK_FAILED;
    }

    hdl->addr = addr;
    hdl->size = size;

    if (ret_addr)
        *ret_addr = addr;

    return PF_STATUS_SUCCESS;
}

/* Crypto callbacks for mbedTLS */

pf_status_t mbedtls_aes_cmac(const pf_key_t* key, const void* input, size_t input_size,
                             pf_mac_t* mac) {
    const mbedtls_cipher_info_t* cipher_info =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);

    int ret = mbedtls_cipher_cmac(cipher_info, (const unsigned char*)key, PF_KEY_SIZE * 8, input,
                                  input_size, (unsigned char*)mac);
    if (ret != 0) {
        ERROR("mbedtls_cipher_cmac failed: %d\n", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }

    return PF_STATUS_SUCCESS;
}

pf_status_t mbedtls_aes_gcm_encrypt(const pf_key_t* key, const pf_iv_t* iv, const void* aad,
                                    size_t aad_size, const void* input, size_t input_size,
                                    void* output, pf_mac_t* mac) {
    pf_status_t status = PF_STATUS_CALLBACK_FAILED;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key,
                                 PF_KEY_SIZE * 8);
    if (ret != 0) {
        ERROR("mbedtls_gcm_setkey failed: %d\n", ret);
        goto out;
    }

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_size, (const unsigned char*)iv,
                                    PF_IV_SIZE, aad, aad_size, input, output, PF_MAC_SIZE,
                                    (unsigned char*)mac);
    if (ret != 0) {
        ERROR("mbedtls_gcm_crypt_and_tag failed: %d\n", ret);
        goto out;
    }

    status = PF_STATUS_SUCCESS;
out:
    mbedtls_gcm_free(&gcm);
    return status;
}

pf_status_t mbedtls_aes_gcm_decrypt(const pf_key_t* key, const pf_iv_t* iv, const void* aad,
                                    size_t aad_size, const void* input, size_t input_size,
                                    void* output, const pf_mac_t* mac) {
    pf_status_t status = PF_STATUS_CALLBACK_FAILED;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key,
                                 PF_KEY_SIZE * 8);
    if (ret != 0) {
        ERROR("mbedtls_gcm_setkey failed: %d\n", ret);
        goto out;
    }

    ret = mbedtls_gcm_auth_decrypt(&gcm, input_size, (const unsigned char*)iv, PF_IV_SIZE, aad,
                                   aad_size, (const unsigned char*)mac, PF_MAC_SIZE, input, output);
    if (ret != 0) {
        ERROR("mbedtls_gcm_auth_decrypt failed: %d\n", ret);
        goto out;
    }

    status = PF_STATUS_SUCCESS;
out:
    mbedtls_gcm_free(&gcm);
    return status;
}

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_prng;

static pf_status_t mbedtls_random(uint8_t* buffer, size_t size) {
    if (mbedtls_ctr_drbg_random(&g_prng, buffer, size) != 0) {
        ERROR("Failed to get random bytes\n");
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

static int pf_set_linux_callbacks(pf_debug_f debug_f) {
    const char* prng_tag = "Gramine protected files library";

    /* Initialize mbedTLS CPRNG */
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_prng);
    int ret = mbedtls_ctr_drbg_seed(&g_prng, mbedtls_entropy_func, &g_entropy,
                                    (const unsigned char*)prng_tag, strlen(prng_tag));

    if (ret != 0) {
        ERROR("Failed to initialize mbedTLS RNG: %d\n", ret);
        return -1;
    }

    pf_set_callbacks(linux_truncate, mbedtls_aes_cmac, mbedtls_aes_gcm_encrypt,
                     mbedtls_aes_gcm_decrypt, mbedtls_random, debug_f);
    return 0;
}

/* Debug print callback for protected files */
static void cb_debug(const char* msg) {
    DBG("%s\n", msg);
}

/* Initialize protected files for native environment */
int pf_init(void) {
    return pf_set_linux_callbacks(cb_debug);
}

/* Generate random PF key and save it to file */
int pf_generate_wrap_key(const char* wrap_key_path) {
    pf_key_t wrap_key;

    int ret = mbedtls_ctr_drbg_random(&g_prng, (unsigned char*)&wrap_key, sizeof(wrap_key));
    if (ret != 0) {
        ERROR("Failed to read random bytes: %d\n", ret);
        return ret;
    }

    if (write_file(wrap_key_path, sizeof(wrap_key), wrap_key) != 0) {
        ERROR("Failed to save wrap key\n");
        return -1;
    }

    INFO("Wrap key saved to: %s\n", wrap_key_path);
    return 0;
}

int load_wrap_key(const char* wrap_key_path, pf_key_t* wrap_key) {
    int ret = -1;
    uint64_t size = 0;
    void* buf = read_file(wrap_key_path, &size, /*buffer=*/NULL);

    if (!buf) {
        ERROR("Failed to read wrap key\n");
        goto out;
    }

    if (size != PF_KEY_SIZE) {
        ERROR("Wrap key size %zu != %zu\n", size, sizeof(*wrap_key));
        goto out;
    }

    memcpy(wrap_key, buf, sizeof(*wrap_key));
    ret = 0;

out:
    free(buf);
    return ret;
}

/* Convert a single file to the protected format */
int pf_encrypt_file(const char* input_path, const char* output_path, const pf_key_t* wrap_key) {
    int ret = -1;
    int input = -1;
    int output = -1;
    pf_context_t* pf = NULL;
    char* norm_output_path = NULL;
    linux_pf_handle_t hdl = { .fd = output, .addr = NULL, .size = 0 };

    void* chunk = malloc(PF_NODE_SIZE);
    if (!chunk) {
        ERROR("Out of memory\n");
        goto out;
    }

    size_t output_path_size = strlen(output_path) + 1;
    norm_output_path = malloc(output_path_size);
    if (!norm_output_path) {
        ERROR("Out of memory\n");
        goto out;
    }

    bool norm_ret = get_norm_path(output_path, norm_output_path, &output_path_size);
    if (!norm_ret) {
        ERROR("Failed to normalize path '%s'\n", output_path);
        goto out;
    }

    input = open(input_path, O_RDONLY);
    if (input < 0) {
        ERROR("Failed to open input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    output = open(norm_output_path, O_RDWR | O_CREAT, PERM_rw_rw_r__);
    if (output < 0) {
        ERROR("Failed to create output file '%s': %s\n", norm_output_path, strerror(errno));
        goto out;
    }

    INFO("Encrypting: %s -> %s\n", input_path, norm_output_path);
    INFO("            (Gramine's encrypted files must contain this exact path: \"%s\")\n",
                      norm_output_path);

    hdl.fd = output;
    pf_handle_t handle = (pf_handle_t)&hdl;
    pf_status_t pfs = pf_open(handle, norm_output_path, /*size=*/0, NULL, PF_FILE_MODE_WRITE,
                              /*create=*/true, wrap_key, &pf);
    if (PF_FAILURE(pfs)) {
        ERROR("Failed to open output PF: %s\n", pf_strerror(pfs));
        goto out;
    }

    /* Process file contents */
    uint64_t input_size = get_file_size(input);
    if (input_size == (uint64_t)-1) {
        ERROR("Failed to get size of input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    uint64_t input_offset = 0;

    while (true) {
        ssize_t chunk_size = read(input, chunk, PF_NODE_SIZE);
        if (chunk_size == 0) // EOF
            break;

        if (chunk_size < 0) {
            if (errno == -EINTR)
                continue;

            ERROR("Failed to read file '%s': %s\n", input_path, strerror(errno));
            goto out;
        }

        pfs = pf_write(pf, input_offset, chunk_size, chunk);
        if (PF_FAILURE(pfs)) {
            ERROR("Failed to write to output PF: %s\n", pf_strerror(pfs));
            goto out;
        }

        input_offset += chunk_size;
    }

    ret = 0;

out:
    if (pf) {
        if (PF_FAILURE(pf_close(pf))) {
            ERROR("failed to close PF\n");
            ret = -1;
        }
    }

    if (hdl.addr && hdl.size > 0) {
        if (munmap(hdl.addr, hdl.size) < 0) {
            ERROR("failed to munmap: %s\n", strerror(errno));
            ret = -1;
        }
    }

    free(chunk);
    free(norm_output_path);
    if (input >= 0)
        close(input);
    if (output >= 0)
        close(output);
    return ret;
}

/* Convert a single file from the protected format */
int pf_decrypt_file(const char* input_path, const char* output_path, bool verify_path,
                    const pf_key_t* wrap_key) {
    int ret = -1;
    int input = -1;
    int output = -1;
    pf_context_t* pf = NULL;
    char* norm_input_path = NULL;
    linux_pf_handle_t hdl = { .fd = input, .addr = NULL, .size = 0 };

    void* chunk = malloc(PF_NODE_SIZE);
    if (!chunk) {
        ERROR("Out of memory\n");
        goto out;
    }

    input = open(input_path, O_RDONLY);
    if (input < 0) {
        ERROR("Failed to open input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    output = open(output_path, O_RDWR | O_CREAT, PERM_rw_rw_r__);
    if (output < 0) {
        ERROR("Failed to create output file '%s': %s\n", output_path, strerror(errno));
        goto out;
    }

    INFO("Decrypting: %s -> %s\n", input_path, output_path);

    /* Get underlying file size */
    uint64_t input_size = get_file_size(input);
    if (input_size == (uint64_t)-1) {
        ERROR("Failed to get size of input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    if (verify_path) {
        size_t input_path_size = strlen(input_path) + 1;
        norm_input_path = malloc(input_path_size);
        if (!norm_input_path) {
            ERROR("Out of memory\n");
            goto out;
        }

        bool norm_ret = get_norm_path(input_path, norm_input_path, &input_path_size);
        if (!norm_ret) {
            ERROR("Failed to normalize path '%s'\n", input_path);
            goto out;
        }
    }

    /* Get file mapped address */
    void* addr = mmap(NULL, input_size, PROT_READ, MAP_SHARED, input, 0);
    if (addr == MAP_FAILED) {
        ERROR("Failed to mmap input file '%s': %s\n", input_path, strerror(errno));
        goto out;
    }

    hdl.fd = input;
    hdl.addr = addr;
    hdl.size = input_size;
    pf_handle_t handle = (pf_handle_t)&hdl;
    pf_status_t pfs = pf_open(handle, norm_input_path, input_size, addr, PF_FILE_MODE_READ,
                              /*create=*/false, wrap_key, &pf);
    if (PF_FAILURE(pfs)) {
        ERROR("Opening protected input file failed: %s\n", pf_strerror(pfs));
        goto out;
    }

    /* Process file contents */
    uint64_t data_size;
    pfs = pf_get_size(pf, &data_size);
    if (PF_FAILURE(pfs)) {
        ERROR("pf_get_size failed: %s\n", pf_strerror(pfs));
        goto out;
    }

    if (ftruncate64(output, data_size) < 0) {
        ERROR("ftruncate64 output file '%s' failed: %s\n", output_path, strerror(errno));
        goto out;
    }

    uint64_t input_offset = 0;

    while (true) {
        assert(input_offset <= data_size);
        uint64_t chunk_size = MIN(data_size - input_offset, PF_NODE_SIZE);
        if (chunk_size == 0)
            break;

        size_t bytes_read = 0;
        pfs = pf_read(pf, input_offset, chunk_size, chunk, &bytes_read);
        if (bytes_read != chunk_size) {
            pfs = PF_STATUS_CORRUPTED;
        }
        if (PF_FAILURE(pfs)) {
            ERROR("Read from protected file failed (offset %" PRIu64 ", size %" PRIu64 "): %s\n",
                  input_offset, chunk_size, pf_strerror(pfs));
            goto out;
        }

        ssize_t written = write(output, chunk, chunk_size);

        if (written < 0) {
            if (errno == -EINTR)
                continue;

            ERROR("Failed to write file '%s': %s\n", output_path, strerror(errno));
            goto out;
        }

        input_offset += written;
    }

    ret = 0;

out:
    if (hdl.addr && hdl.size > 0) {
        if (munmap(hdl.addr, hdl.size) < 0) {
            ERROR("failed to munmap: %s\n", strerror(errno));
            ret = -1;
        }
    }

    free(norm_input_path);
    free(chunk);
    if (pf)
        pf_close(pf);
    if (input >= 0)
        close(input);
    if (output >= 0)
        close(output);
    return ret;
}

enum processing_mode_t {
    MODE_ENCRYPT = 1,
    MODE_DECRYPT = 2,
};

static int process_files(const char* input_dir, const char* output_dir, const char* wrap_key_path,
                         enum processing_mode_t mode, bool verify_path) {
    int ret = -1;
    pf_key_t wrap_key;
    struct stat st;
    char* input_path  = NULL;
    char* output_path = NULL;
    DIR* dfd = NULL;

    if (mode != MODE_ENCRYPT && mode != MODE_DECRYPT) {
        ERROR("Invalid mode: %d\n", mode);
        goto out;
    }

    if (mode == MODE_ENCRYPT && verify_path) {
        ERROR("Path verification can't be on in MODE_ENCRYPT\n");
        goto out;
    }

    ret = load_wrap_key(wrap_key_path, &wrap_key);
    if (ret != 0)
        goto out;

    if (stat(input_dir, &st) != 0) {
        ERROR("Failed to stat input path %s: %s\n", input_dir, strerror(errno));
        goto out;
    }

    /* single file? */
    if (S_ISREG(st.st_mode)) {
        if (mode == MODE_ENCRYPT)
            return pf_encrypt_file(input_dir, output_dir, &wrap_key);
        else
            return pf_decrypt_file(input_dir, output_dir, verify_path, &wrap_key);
    }

    ret = mkdir(output_dir, PERM_rwxrwxr_x);
    if (ret != 0 && errno != EEXIST) {
        ERROR("Failed to create directory %s: %s\n", output_dir, strerror(errno));
        goto out;
    }

    /* Process input directory */
    struct dirent* dir;
    dfd = opendir(input_dir);
    if (!dfd) {
        ERROR("Failed to open input directory: %s\n", strerror(errno));
        goto out;
    }

    size_t input_path_size, output_path_size;
    while ((dir = readdir(dfd)) != NULL) {
        if (!strcmp(dir->d_name, "."))
            continue;
        if (!strcmp(dir->d_name, ".."))
            continue;

        input_path_size = strlen(input_dir) + 1 + strlen(dir->d_name) + 1;
        output_path_size = strlen(output_dir) + 1 + strlen(dir->d_name) + 1;

        input_path = malloc(input_path_size);
        if (!input_path) {
            ERROR("No memory\n");
            goto out;
        }

        output_path = malloc(output_path_size);
        if (!output_path) {
            ERROR("No memory\n");
            goto out;
        }

        snprintf(input_path, input_path_size, "%s/%s", input_dir, dir->d_name);
        snprintf(output_path, output_path_size, "%s/%s", output_dir, dir->d_name);

        if (stat(input_path, &st) != 0) {
            ERROR("Failed to stat input file %s: %s\n", input_path, strerror(errno));
            goto out;
        }

        if (S_ISREG(st.st_mode)) {
            if (mode == MODE_ENCRYPT)
                ret = pf_encrypt_file(input_path, output_path, &wrap_key);
            else
                ret = pf_decrypt_file(input_path, output_path, verify_path, &wrap_key);

            if (ret != 0)
                goto out;
        } else if (S_ISDIR(st.st_mode)) {
            /* process directory recursively */
            ret = process_files(input_path, output_path, wrap_key_path, mode, verify_path);
            if (ret != 0)
                goto out;
        } else {
            INFO("Skipping non-regular file %s\n", input_path);
        }

        free(input_path);
        input_path = NULL;
        free(output_path);
        output_path = NULL;
    }
    ret = 0;

out:
    free(input_path);
    free(output_path);
    if (dfd)
        closedir(dfd);
    return ret;
}

/* Convert a file or directory (recursively) to the protected format */
int pf_encrypt_files(const char* input_dir, const char* output_dir, const char* wrap_key_path) {
    return process_files(input_dir, output_dir, wrap_key_path, MODE_ENCRYPT, false);
}

/* Convert a file or directory (recursively) from the protected format */
int pf_decrypt_files(const char* input_dir, const char* output_dir, bool verify_path,
                     const char* wrap_key_path) {
    return process_files(input_dir, output_dir, wrap_key_path, MODE_DECRYPT, verify_path);
}
