/* Copyright (C) 2024 Intel Corporation
 *                    Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>
 */

/*
 * This file contains code for trusted files in 'chroot' filesystem.
 *
 * Trusted files (TF) are integrity protected and transparently verified when accessed by Gramine
 * or by app running inside Gramine. For each file that requires authentication (specified in the
 * manifest as "sgx.trusted_files"), a SHA256 hash is generated and stored in the manifest, signed
 * and verified as part of the enclave's crypto measurement. When user opens such a file, Gramine
 * loads the whole file, calculates its SHA256 hash, and checks against the corresponding hash in
 * the manifest. If the hashes do not match, the file access will be rejected.
 *
 * During the generation of the SHA256 hash, a 128-bit hash (truncated SHA256) is also generated for
 * each chunk (of size TRUSTED_CHUNK_SIZE) in the file. The per-chunk hashes are used for partial
 * verification in future reads, to avoid re-verifying the whole file again or the need of caching
 * the whole file contents.
 */

#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "crypto.h"
#include "hex.h"
#include "libos_fs.h"
#include "list.h"
#include "path_utils.h"
#include "toml.h"

/* FIXME: current size is 16KB, but maybe there's a better size for perf/mem trade-off? */
#define TRUSTED_CHUNK_SIZE (PAGE_SIZE * 4UL)

/* FIXME: use hash table instead of list */
DEFINE_LIST(trusted_file);
struct trusted_file {
    LIST_TYPE(trusted_file) list;
    struct trusted_file_hash file_hash;      /* hash over file, retrieved from the manifest */
    size_t path_len;
    char path[]; /* must be NULL-terminated */
};

/* initialized once at startup and read-only afterwards, so doesn't require locking */
DEFINE_LISTP(trusted_file);
static LISTP_TYPE(trusted_file) g_trusted_file_list = LISTP_INIT;

static int read_file_exact(PAL_HANDLE handle, void* buffer, uint64_t offset, size_t size) {
    size_t buffer_offset = 0;
    size_t remaining = size;

    while (remaining > 0) {
        size_t count = remaining;
        int ret = PalStreamRead(handle, offset + buffer_offset, &count, buffer + buffer_offset);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                continue;
            }
            return pal_to_unix_errno(ret);
        } else if (count == 0) {
            return -ENODATA;
        }

        assert(count <= remaining);
        remaining -= count;
        buffer_offset += count;
    }
    return 0;
}

struct trusted_file* get_trusted_file(const char* path) {
    size_t norm_path_size = strlen(path) + 1; /* overapproximate */
    char* norm_path = malloc(norm_path_size);
    if (!norm_path)
        return NULL;

    bool normalized = get_norm_path(path, norm_path, &norm_path_size);
    if (!normalized) {
        free(norm_path);
        return NULL;
    }

    struct trusted_file* tf = NULL;
    struct trusted_file* tmp;
    LISTP_FOR_EACH_ENTRY(tmp, &g_trusted_file_list, list) {
        if (tmp->path_len == norm_path_size - 1 && !memcmp(tmp->path, norm_path, norm_path_size)) {
            tf = tmp;
            break;
        }
    }
    free(norm_path);
    return tf;
}

size_t get_chunk_hashes_size(size_t file_size) {
    return sizeof(struct trusted_chunk_hash) * UDIV_ROUND_UP(file_size, TRUSTED_CHUNK_SIZE);
}

/* calculate chunk hashes and compare with hash in manifest */
int load_trusted_file(struct trusted_file* tf, size_t file_size,
                      struct trusted_chunk_hash** out_chunk_hashes) {
    int ret;
    uint8_t* tmp_chunk = NULL;
    struct trusted_chunk_hash* chunk_hashes = NULL;
    PAL_HANDLE handle = NULL;

    char* uri = alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, tf->path, tf->path_len);
    if (!uri) {
        ret = -ENOMEM;
        goto out;
    }

    chunk_hashes = malloc(get_chunk_hashes_size(file_size));
    if (!chunk_hashes) {
        ret = -ENOMEM;
        goto out;
    }

    /* FIXME: use pre-allocated object in common case (e.g. for the first thread) */
    tmp_chunk = malloc(TRUSTED_CHUNK_SIZE);
    if (!tmp_chunk) {
        ret = -ENOMEM;
        goto out;
    }

    ret = PalStreamOpen(uri, PAL_ACCESS_RDONLY, /*share_flags=*/0, PAL_CREATE_NEVER,
                        /*options=*/0, &handle);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    LIB_SHA256_CONTEXT file_sha;
    ret = lib_SHA256Init(&file_sha);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    struct trusted_chunk_hash* chunk_hashes_item = chunk_hashes;
    for (uint64_t offset = 0; offset < file_size; offset += TRUSTED_CHUNK_SIZE) {
        /* For each file chunk of size TRUSTED_CHUNK_SIZE, generate 128-bit hash from SHA-256 hash
         * over contents of this file chunk (we simply truncate SHA-256 hash to first 128 bits; this
         * is fine for integrity purposes). Also, generate a SHA-256 hash for the whole file
         * contents to compare with the manifest "reference" hash value. */
        uint64_t chunk_size = MIN(file_size - offset, TRUSTED_CHUNK_SIZE);

        LIB_SHA256_CONTEXT chunk_sha;
        ret = lib_SHA256Init(&chunk_sha);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }
        ret = read_file_exact(handle, tmp_chunk, offset, chunk_size);
        if (ret < 0)
            goto out;
        ret = lib_SHA256Update(&file_sha, tmp_chunk, chunk_size);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }
        ret = lib_SHA256Update(&chunk_sha, tmp_chunk, chunk_size);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }

        struct trusted_chunk_hash chunk_hash[2];
        static_assert(sizeof(chunk_hash) * 8 == 256, "");
        ret = lib_SHA256Final(&chunk_sha, (uint8_t*)&chunk_hash[0]);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }

        /* note that we truncate SHA256 to 128 bits */
        memcpy(chunk_hashes_item, &chunk_hash[0], sizeof(*chunk_hashes_item));
        chunk_hashes_item++;
    }

    struct trusted_file_hash file_hash;
    ret = lib_SHA256Final(&file_sha, file_hash.bytes);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    /* check the generated hash-over-whole-file against the reference hash in the manifest */
    if (memcmp(&file_hash, &tf->file_hash, sizeof(file_hash))) {
        log_warning("Hash of trusted file '%s' does not match with the reference hash in manifest",
                    tf->path);
        ret = -EPERM;
        goto out;
    }

    *out_chunk_hashes = chunk_hashes;
    ret = 0;
out:
    if (ret < 0)
        free(chunk_hashes);
    if (handle)
        PalObjectDestroy(handle);
    free(tmp_chunk);
    free(uri);
    return ret;
}

int read_and_verify_trusted_file(PAL_HANDLE handle, uint64_t offset, size_t count, uint8_t* buf,
                                 size_t file_size, struct trusted_chunk_hash* chunk_hashes) {
    int ret;

    if (offset >= file_size)
        return 0;

    uint64_t end = MIN(offset + count, file_size);
    uint64_t aligned_offset = ALIGN_DOWN(offset, TRUSTED_CHUNK_SIZE);

    /* FIXME: use pre-allocated object in common case (e.g. for the first thread) */
    uint8_t* tmp_chunk = malloc(TRUSTED_CHUNK_SIZE);
    if (!tmp_chunk)
        return -ENOMEM;

    uint8_t* buf_pos = buf;
    uint64_t chunk_offset = aligned_offset;
    struct trusted_chunk_hash* chunk_hashes_item = chunk_hashes +
                                                       aligned_offset / TRUSTED_CHUNK_SIZE;
    for (; chunk_offset < end; chunk_offset += TRUSTED_CHUNK_SIZE) {
        size_t chunk_size  = MIN(file_size - chunk_offset, TRUSTED_CHUNK_SIZE);
        uint64_t chunk_end = chunk_offset + chunk_size;

        LIB_SHA256_CONTEXT chunk_sha;
        ret = lib_SHA256Init(&chunk_sha);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }

        if (chunk_offset >= offset && chunk_end <= end) {
            /* if current chunk-to-verify completely resides in the requested region-to-copy,
             * directly copy into buf (without a scratch buffer) and hash in-place */
            ret = read_file_exact(handle, buf_pos, chunk_offset, chunk_size);
            if (ret < 0)
                goto out;
            ret = lib_SHA256Update(&chunk_sha, buf_pos, chunk_size);
            if (ret < 0) {
                ret = pal_to_unix_errno(ret);
                goto out;
            }
            buf_pos += chunk_size;
        } else {
            /* if current chunk-to-verify only partially overlaps with the requested region-to-copy,
             * read the file contents into a scratch buffer, verify hash and then copy only the part
             * needed by the caller */
            ret = read_file_exact(handle, tmp_chunk, chunk_offset, chunk_size);
            if (ret < 0)
                goto out;
            ret = lib_SHA256Update(&chunk_sha, tmp_chunk, chunk_size);
            if (ret < 0) {
                ret = pal_to_unix_errno(ret);
                goto out;
            }

            /* determine which part of the chunk is needed by the caller */
            uint64_t copy_start = MAX(chunk_offset, offset);
            uint64_t copy_end   = MIN(chunk_offset + chunk_size, end);
            assert(copy_end > copy_start);

            memcpy(buf_pos, tmp_chunk + copy_start - chunk_offset, copy_end - copy_start);
            buf_pos += copy_end - copy_start;
        }

        struct trusted_chunk_hash chunk_hash[2]; /* each chunk_hash is 128 bits in size */
        static_assert(sizeof(chunk_hash) * 8 == 256, "");
        ret = lib_SHA256Final(&chunk_sha, (uint8_t*)&chunk_hash[0]);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }

        if (memcmp(chunk_hashes_item, &chunk_hash[0], sizeof(*chunk_hashes_item))) {
            ret = -EPERM;
            goto out;
        }

        chunk_hashes_item++;
    }

    ret = 0;
out:
    free(tmp_chunk);
    return ret;
}

static int register_trusted_file(const char* path, const char* hash_str) {
    if (strlen(hash_str) != sizeof(struct trusted_file_hash) * 2) {
        log_error("Hash (%s) of a trusted file %s is not a SHA256 hash", hash_str, path);
        return -EINVAL;
    }

    size_t path_len = strlen(path);
    if (path_len > URI_MAX) {
        log_error("Size of file exceeds maximum %dB: %s", URI_MAX, path);
        return -EINVAL;
    }

    struct trusted_file_hash file_hash;
    char* bytes = hex2bytes(hash_str, strlen(hash_str), file_hash.bytes, sizeof(file_hash.bytes));
    if (!bytes) {
        log_error("Could not parse hash of trusted file: %s", path);
        return -EINVAL;
    }

    struct trusted_file* new = malloc(sizeof(*new) + path_len + 1);
    if (!new)
        return -ENOMEM;

    INIT_LIST_HEAD(new, list);
    new->path_len = path_len;
    memcpy(new->path, path, path_len + 1);
    memcpy(&new->file_hash, &file_hash, sizeof(file_hash));

    LISTP_ADD_TAIL(new, &g_trusted_file_list, list);
    return 0;
}

static int init_one_trusted_file(toml_raw_t toml_trusted_uri_raw,
                                 toml_raw_t toml_trusted_sha256_raw, size_t idx) {
    int ret;

    /* FIXME: toml_trusted_uri_str and toml_trusted_sha256_str are temporary strings, allocating
     *        them is redundant; however tomlc99 lib has only toml_rtos() function that returns a
     *        newly allocated string rather than a slice into the parsed TOML structure */
    char* toml_trusted_uri_str = NULL;
    char* toml_trusted_sha256_str = NULL;

    /* FIXME: instead of re-allocating in register_trusted_file(), could pass ownership to it */
    char* norm_trusted_path = NULL;

    ret = toml_rtos(toml_trusted_uri_raw, &toml_trusted_uri_str);
    if (ret < 0 || !toml_trusted_uri_str) {
        log_error("Invalid trusted file in manifest at index %ld ('uri' is not a string)", idx);
        ret = -EINVAL;
        goto out;
    }

    ret = toml_rtos(toml_trusted_sha256_raw, &toml_trusted_sha256_str);
    if (ret < 0 || !toml_trusted_sha256_str) {
        log_error("Invalid trusted file in manifest at index %ld ('sha256' is not a string)", idx);
        ret = -EINVAL;
        goto out;
    }

    if (!strstartswith(toml_trusted_uri_str, URI_PREFIX_FILE)) {
        log_error("Invalid URI [%s]: Trusted files must start with '" URI_PREFIX_FILE "'",
                  toml_trusted_uri_str);
        ret = -EINVAL;
        goto out;
    }

    size_t norm_trusted_path_size = strlen(toml_trusted_uri_str) - URI_PREFIX_FILE_LEN + 1;
    norm_trusted_path = malloc(norm_trusted_path_size);
    if (!norm_trusted_path) {
        ret = -ENOMEM;
        goto out;
    }

    bool normalized = get_norm_path(toml_trusted_uri_str + URI_PREFIX_FILE_LEN,
                                    norm_trusted_path, &norm_trusted_path_size);
    if (!normalized) {
        log_error("Trusted file path (%s) normalization failed", toml_trusted_uri_str);
        ret = -EINVAL;
        goto out;
    }

    ret = register_trusted_file(norm_trusted_path, toml_trusted_sha256_str);
    if (ret < 0) {
        log_error("Trusted file registration (%s) failed", toml_trusted_uri_str);
        goto out;
    }

    ret = 0;
out:
    free(norm_trusted_path);
    free(toml_trusted_uri_str);
    free(toml_trusted_sha256_str);
    return ret;
}

int init_trusted_files(void) {
    int ret;

    assert(g_manifest_root);
    toml_table_t* manifest_sgx = toml_table_in(g_manifest_root, "sgx");
    if (!manifest_sgx)
        return 0;

    toml_array_t* toml_trusted_files = toml_array_in(manifest_sgx, "trusted_files");
    if (!toml_trusted_files)
        return 0;

    ssize_t toml_trusted_files_cnt = toml_array_nelem(toml_trusted_files);
    assert(toml_trusted_files_cnt >= 0);

    for (size_t i = 0; i < (size_t)toml_trusted_files_cnt; i++) {
        /* read `sgx.trusted_file = {uri = "file:foo", sha256 = "deadbeef"}` entry from manifest */
        toml_table_t* toml_trusted_file = toml_table_at(toml_trusted_files, i);
        if (!toml_trusted_file) {
            log_error("Invalid trusted file in manifest at index %ld (not a TOML table)", i);
            return -EINVAL;
        }

        toml_raw_t toml_trusted_uri_raw = toml_raw_in(toml_trusted_file, "uri");
        if (!toml_trusted_uri_raw) {
            log_error("Invalid trusted file in manifest at index %ld (no 'uri' key)", i);
            return -EINVAL;
        }

        toml_raw_t toml_trusted_sha256_raw = toml_raw_in(toml_trusted_file, "sha256");
        if (!toml_trusted_sha256_raw) {
            log_error("Invalid trusted file in manifest at index %ld (no 'sha256' key)", i);
            return -EINVAL;
        }

        ret = init_one_trusted_file(toml_trusted_uri_raw, toml_trusted_sha256_raw, i);
        if (ret < 0)
            return ret;
    }

    return 0;
}
