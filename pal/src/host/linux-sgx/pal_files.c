/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains operands to handle streams with URIs that start with "file:" or "dir:".
 */

#include <asm/fcntl.h>
#include <asm/stat.h>
#include <linux/types.h>

#include "api.h"
#include "asan.h"
#include "enclave_tf.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"
#include "pal_sgx.h"
#include "path_utils.h"
#include "stat.h"

/* this macro is used to emulate mmap() via pread() in chunks of 128MB (mmapped files may be many
 * GBs in size, and a pread OCALL could fail with -ENOMEM, so we cap to reasonably small size) */
#define MAX_READ_SIZE (PRESET_PAGESIZE * 1024 * 32)

static int file_open(PAL_HANDLE* handle, const char* type, const char* uri,
                     enum pal_access pal_access, pal_share_flags_t pal_share,
                     enum pal_create_mode pal_create, pal_stream_options_t pal_options) {
    assert(pal_create != PAL_CREATE_IGNORED);
    int ret;
    int fd = -1;
    bool encrypted = false;
    void* addr = NULL;
    PAL_HANDLE hdl = NULL;
    bool do_create = (pal_create == PAL_CREATE_ALWAYS) || (pal_create == PAL_CREATE_TRY);

    struct stat st;
    int flags = PAL_ACCESS_TO_LINUX_OPEN(pal_access) | PAL_CREATE_TO_LINUX_OPEN(pal_create)
                | PAL_OPTION_TO_LINUX_OPEN(pal_options) | O_CLOEXEC;

    if (strcmp(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    /* normalize uri into normpath */
    size_t normpath_size = strlen(uri) + 1;
    char* normpath = malloc(normpath_size);
    if (!normpath)
        return -PAL_ERROR_NOMEM;

    if (!get_norm_path(uri, normpath, &normpath_size)) {
        log_warning("Could not normalize path (%s)", uri);
        free(normpath);
        return -PAL_ERROR_DENIED;
    }

    /* create file PAL handle with path string placed at the end of this handle object */
    hdl = calloc(1, HANDLE_SIZE(file));
    if (!hdl) {
        free(normpath);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(hdl, PAL_TYPE_FILE);
    hdl->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;

    hdl->file.realpath = normpath;

    struct trusted_file* tf = NULL;

    if (!(pal_options & PAL_OPTION_PASSTHROUGH)) {
        tf = get_trusted_or_allowed_file(hdl->file.realpath);
        if (!tf) {
            if (get_file_check_policy() != FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG) {
                log_warning("Disallowing access to file '%s'; file is not trusted or allowed.",
                            hdl->file.realpath);
                ret = -PAL_ERROR_DENIED;
                goto fail;
            }
            log_warning("Allowing access to unknown file '%s' due to file_check_policy settings.",
                        hdl->file.realpath);
        }
    }

    if (!tf) {
        fd = ocall_open(uri, flags, pal_share);
        if (fd < 0) {
            ret = unix_to_pal_error(fd);
            goto fail;
        }

        ret = ocall_fstat(fd, &st);
        if (ret < 0) {
            ret = unix_to_pal_error(ret);
            goto fail;
        }

        /* map file into untrusted memroy when open encrypted files */
        if (pal_options & PAL_OPTION_ENCRYPTED_FILE) {
            encrypted = true;
            if (st.st_size > 0) {
                ret = ocall_mmap_untrusted(&addr, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
                if (ret < 0) {
                    ret = unix_to_pal_error(ret);
                    goto fail;
                }
            }
        }

        hdl->file.fd = fd;
        hdl->file.seekable = !S_ISFIFO(st.st_mode);
        hdl->file.total = st.st_size;
        hdl->file.encrypted = encrypted;
        hdl->file.addr = addr;

        *handle = hdl;
        return 0;
    }

    assert(tf); /* at this point, we want to open a trusted or allowed file */

    if (!tf->allowed && (do_create
                         || (pal_access == PAL_ACCESS_RDWR)
                         || (pal_access == PAL_ACCESS_WRONLY))) {
        log_error("Disallowing create/write/append to a trusted file '%s'", hdl->file.realpath);
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    fd = ocall_open(uri, flags, pal_share);
    if (fd < 0) {
        ret = unix_to_pal_error(fd);
        goto fail;
    }

    ret = ocall_fstat(fd, &st);
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        goto fail;
    }

    hdl->file.fd = fd;
    hdl->file.seekable = !S_ISFIFO(st.st_mode);
    hdl->file.total = st.st_size;

    sgx_chunk_hash_t* chunk_hashes;
    uint64_t total;
    void* umem;

    /* we lazily update the size of the trusted file */
    tf->size = st.st_size;
    ret = load_trusted_or_allowed_file(tf, hdl, do_create, &chunk_hashes, &total, &umem);
    if (ret < 0)
        goto fail;

    hdl->file.chunk_hashes = chunk_hashes;
    hdl->file.total = total;
    hdl->file.umem  = umem;

    *handle = hdl;
    return 0;

fail:
    if (fd >= 0)
        ocall_close(fd);

    free(hdl->file.realpath);

    free(hdl);
    return ret;
}

/* 'read' operation for file streams. */
static int64_t file_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    int64_t ret;
    sgx_chunk_hash_t* chunk_hashes = handle->file.chunk_hashes;

    if (!chunk_hashes) {
        if (handle->file.seekable) {
            ret = ocall_pread(handle->file.fd, buffer, count, offset);
        } else {
            ret = ocall_read(handle->file.fd, buffer, count);
        }

        if (ret < 0)
            return unix_to_pal_error(ret);

        return ret;
    }

    /* case of trusted file: already mmaped in umem, copy from there and verify hash */
    uint64_t total = handle->file.total;
    if (offset >= total)
        return 0;

    off_t end = MIN(offset + count, total);
    off_t aligned_offset = ALIGN_DOWN(offset, TRUSTED_CHUNK_SIZE);
    off_t aligned_end    = ALIGN_UP(end, TRUSTED_CHUNK_SIZE);

    ret = copy_and_verify_trusted_file(handle->file.realpath, buffer, handle->file.umem,
                                       aligned_offset, aligned_end, offset, end, chunk_hashes,
                                       total);
    if (ret < 0)
        return ret;

    return end - offset;
}

/* 'write' operation for file streams. */
static int64_t file_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    int64_t ret;
    sgx_chunk_hash_t* chunk_hashes = handle->file.chunk_hashes;

    if (!chunk_hashes) {
        if (handle->file.seekable) {
            ret = ocall_pwrite(handle->file.fd, buffer, count, offset);
        } else {
            ret = ocall_write(handle->file.fd, buffer, count);
        }

        if (ret < 0)
            return unix_to_pal_error(ret);

        return ret;
    }

    /* case of trusted file: disallow writing completely */
    log_warning("Writing to a trusted file (%s) is disallowed!", handle->file.realpath);
    return -PAL_ERROR_DENIED;
}

static void file_destroy(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_FILE);

    if (handle->file.addr && handle->file.total) {
        /* case of encrypted file: the whole file was mmapped in untrusted memory */
        ocall_munmap_untrusted(handle->file.addr, handle->file.total);
    }

    if (handle->file.chunk_hashes && handle->file.total) {
        /* case of trusted file: the whole file was mmapped in untrusted memory */
        ocall_munmap_untrusted(handle->file.umem, handle->file.total);
    }

    int ret = ocall_close(handle->file.fd);
    if (ret < 0) {
        log_error("closing file host fd %d failed: %s", handle->file.fd, unix_strerror(ret));
        /* We cannot do anything about it anyway... */
    }

    free(handle->file.realpath);
    free(handle);
}

/* 'delete' operation for file streams */
static int file_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    if (delete_mode != PAL_DELETE_ALL)
        return -PAL_ERROR_INVAL;

    int ret = ocall_delete(handle->file.realpath);
    return ret < 0 ? unix_to_pal_error(ret) : ret;
}

/* 'map' operation for file stream. */
static int file_map(PAL_HANDLE handle, void* addr, pal_prot_flags_t prot, uint64_t offset,
                    uint64_t size) {
    assert(IS_ALLOC_ALIGNED(offset) && IS_ALLOC_ALIGNED(size));
    int ret;

    uint64_t dummy;
    if (__builtin_add_overflow(offset, size, &dummy)) {
        return -PAL_ERROR_INVAL;
    }

    if (size > SIZE_MAX) {
        /* for compatibility with 32-bit systems */
        return -PAL_ERROR_INVAL;
    }

    if (!(prot & PAL_PROT_WRITECOPY) && (prot & PAL_PROT_WRITE)) {
        log_warning(
            "file_map does not currently support writable pass-through mappings on SGX. You "
            "may add the PAL_PROT_WRITECOPY (MAP_PRIVATE) flag to your file mapping to keep "
            "the writes inside the enclave but they won't be reflected outside of the "
            "enclave.");
        return -PAL_ERROR_DENIED;
    }

    /* Sanity checks. */
    if (!addr || !sgx_is_completely_within_enclave(addr, size)) {
        return -PAL_ERROR_INVAL;
    }

    if (g_pal_linuxsgx_state.edmm_enabled) {
        /* Enclave pages will be written to below, so we must add W permission. */
        ret = sgx_edmm_add_pages((uint64_t)addr, size / PAGE_SIZE,
                                 PAL_TO_SGX_PROT(prot | PAL_PROT_WRITE));
        if (ret < 0) {
            return ret;
        }
    } else {
#ifdef ASAN
        asan_unpoison_region((uintptr_t)addr, size);
#endif
    }

    sgx_chunk_hash_t* chunk_hashes = handle->file.chunk_hashes;
    if (chunk_hashes) {
        /* case of trusted file: already mmaped in umem, copy from there into enclave memory and
         * verify hashes along the way */
        off_t end = MIN(offset + size, handle->file.total);
        size_t bytes_filled;
        if ((off_t)offset >= end) {
            /* file is mmapped at offset beyond file size, there are no trusted-file contents to
             * back mmapped enclave pages; this is a legit case, so simply zero out these enclave
             * pages and return success */
            bytes_filled = 0;
        } else {
            off_t aligned_offset = ALIGN_DOWN(offset, TRUSTED_CHUNK_SIZE);
            off_t aligned_end    = ALIGN_UP(end, TRUSTED_CHUNK_SIZE);
            off_t total_size     = aligned_end - aligned_offset;

            if ((uint64_t)total_size > SIZE_MAX) {
                /* for compatibility with 32-bit systems */
                ret = -PAL_ERROR_INVAL;
                goto out;
            }

            ret = copy_and_verify_trusted_file(handle->file.realpath, addr, handle->file.umem,
                                               aligned_offset, aligned_end, offset, end, chunk_hashes,
                                               handle->file.total);
            if (ret < 0) {
                log_error("file_map - copy & verify on trusted file: %s", pal_strerror(ret));
                goto out;
            }

            bytes_filled = end - offset;
        }

        if (size > bytes_filled) {
            /* file ended before all mmapped memory was filled -- remaining memory must be zeroed */
            memset((char*)addr + bytes_filled, 0, size - bytes_filled);
        }
    } else {
        /* case of allowed file: simply read from underlying file descriptor into enclave memory */
        size_t bytes_read = 0;
        while (bytes_read < size) {
            size_t read_size = MIN(size - bytes_read, MAX_READ_SIZE);
            ssize_t bytes = ocall_pread(handle->file.fd, (char*)addr + bytes_read, read_size,
                                        offset + bytes_read);
            if (bytes > 0) {
                bytes_read += bytes;
            } else if (bytes == 0) {
                break; /* EOF */
            } else if (bytes == -EINTR || bytes == -EAGAIN) {
                continue;
            } else {
                log_warning("file_map - ocall_pread on allowed file returned %ld", bytes);
                ret = unix_to_pal_error(bytes);
                goto out;
            }
        }

        if (size > bytes_read) {
            /* file ended before all mmapped memory was filled -- remaining memory must be zeroed */
            memset((char*)addr + bytes_read, 0, size - bytes_read);
        }
    }

    if (g_pal_linuxsgx_state.edmm_enabled && !(prot & PAL_PROT_WRITE)) {
        /* Clear W permission, in case we added it artificially. */
        ret = sgx_edmm_set_page_permissions((uint64_t)addr, size / PAGE_SIZE,
                                            PAL_TO_SGX_PROT(prot));
        if (ret < 0) {
            log_error("failed to remove W bit from pages permissions at %p-%p",
                      (char*)addr, (char*)addr + size);
            goto out;
        }
    }

    ret = 0;

out:
    if (ret < 0) {
        if (g_pal_linuxsgx_state.edmm_enabled) {
            int tmp_ret = sgx_edmm_remove_pages((uint64_t)addr, size / PAGE_SIZE);
            if (tmp_ret < 0) {
                log_error("removing previously allocated pages failed: %s (%d)",
                          pal_strerror(tmp_ret), ret);
                die_or_inf_loop();
            }
        } else {
#ifdef ASAN
            asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
#endif
        }
    }
    return ret;
}

/* 'setlength' operation for file stream. */
static int64_t file_setlength(PAL_HANDLE handle, uint64_t length) {
    int ret = ocall_ftruncate(handle->file.fd, length);
    if (ret < 0)
        return unix_to_pal_error(ret);

    if (handle->file.encrypted) {
        if (handle->file.addr && handle->file.total > 0) {
            ret = ocall_munmap_untrusted(handle->file.addr, handle->file.total);
            if (ret < 0) 
                return unix_to_pal_error(ret);
        }
        
        handle->file.addr = NULL;

        if (length > 0) {
            ret = ocall_mmap_untrusted(&handle->file.addr, length, PROT_READ | PROT_WRITE,
                                       MAP_SHARED, handle->file.fd, 0);
            if (ret < 0) 
                return unix_to_pal_error(ret);
        }
    }

    handle->file.total = length;
    return (int64_t)length;
}

/* 'flush' operation for file stream. */
static int file_flush(PAL_HANDLE handle) {
    int fd = handle->file.fd;
    ocall_fsync(fd);
    return 0;
}

/* 'attrquery' operation for file streams */
static int file_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    if (strcmp(type, URI_TYPE_FILE) && strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    /* open the file with O_NONBLOCK to avoid blocking the current thread if it is actually a FIFO
     * pipe; O_NONBLOCK will be reset below if it is a regular file */
    int fd = ocall_open(uri, O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0)
        return unix_to_pal_error(fd);

    char* path = NULL;
    struct stat stat_buf;
    int ret = ocall_fstat(fd, &stat_buf);

    /* if it failed, return the right error code */
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        goto out;
    }

    file_attrcopy(attr, &stat_buf);

    size_t path_size = strlen(uri) + 1;
    path = malloc(path_size);
    if (!path) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }
    if (!get_norm_path(uri, path, &path_size)) {
        log_warning("Could not normalize path (%s)", uri);
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    ret = 0;

out:
    free(path);
    ocall_close(fd);
    return ret;
}

/* 'attrquerybyhdl' operation for file streams */
static int file_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int fd = handle->file.fd;
    struct stat stat_buf;

    int ret = ocall_fstat(fd, &stat_buf);
    if (ret < 0)
        return unix_to_pal_error(ret);

    file_attrcopy(attr, &stat_buf);

    if (handle->file.encrypted)
        attr->addr = handle->file.addr;

    return 0;
}

static int file_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int fd  = handle->file.fd;
    int ret = ocall_fchmod(fd, attr->share_flags);
    if (ret < 0)
        return unix_to_pal_error(ret);

    if (handle->file.encrypted && (unsigned long)attr->addr < UINTPTR_MAX)
        handle->file.addr = attr->addr;

    return 0;
}

static int file_rename(PAL_HANDLE handle, const char* type, const char* uri) {
    if (strcmp(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    char* tmp = strdup(uri);
    if (!tmp)
        return -PAL_ERROR_NOMEM;

    int ret = ocall_rename(handle->file.realpath, uri);
    if (ret < 0) {
        free(tmp);
        return unix_to_pal_error(ret);
    }

    free(handle->file.realpath);
    handle->file.realpath = tmp;
    return 0;
}

struct handle_ops g_file_ops = {
    .open           = &file_open,
    .read           = &file_read,
    .write          = &file_write,
    .destroy        = &file_destroy,
    .delete         = &file_delete,
    .map            = &file_map,
    .setlength      = &file_setlength,
    .flush          = &file_flush,
    .attrquery      = &file_attrquery,
    .attrquerybyhdl = &file_attrquerybyhdl,
    .attrsetbyhdl   = &file_attrsetbyhdl,
    .rename         = &file_rename,
};

/* 'open' operation for directory stream. Directory stream does not have a
 * specific type prefix, its URI looks the same file streams, plus it
 * ended with slashes. dir_open will be called by file_open. */
static int dir_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                    pal_share_flags_t share, enum pal_create_mode create,
                    pal_stream_options_t options) {
    __UNUSED(access);

    if (strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    if (create == PAL_CREATE_TRY || create == PAL_CREATE_ALWAYS) {
        int ret = ocall_mkdir(uri, share);

        if (ret < 0) {
            if (ret == -EEXIST && create == PAL_CREATE_ALWAYS)
                return -PAL_ERROR_STREAMEXIST;
            if (ret != -EEXIST)
                return unix_to_pal_error(ret);
            assert(ret == -EEXIST && create == PAL_CREATE_TRY);
        }
    }

    int fd = ocall_open(uri, O_DIRECTORY | O_CLOEXEC | PAL_OPTION_TO_LINUX_OPEN(options), 0);
    if (fd < 0)
        return unix_to_pal_error(fd);

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(dir));
    if (!hdl) {
        ocall_close(fd);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(hdl, PAL_TYPE_DIR);

    hdl->flags |= PAL_HANDLE_FD_READABLE;
    hdl->dir.fd = fd;

    char* path = strdup(uri);
    if (!path) {
        ocall_close(fd);
        free(hdl);
        return -PAL_ERROR_NOMEM;
    }

    hdl->dir.realpath    = path;
    hdl->dir.buf         = NULL;
    hdl->dir.ptr         = NULL;
    hdl->dir.end         = NULL;
    hdl->dir.endofstream = false;
    *handle              = hdl;
    return 0;
}

#define DIRBUF_SIZE 1024

/* 'read' operation for directory stream. Directory stream will not
   need a 'write' operation. */
static int64_t dir_read(PAL_HANDLE handle, uint64_t offset, size_t count, void* _buf) {
    size_t bytes_written = 0;
    char* buf            = (char*)_buf;

    if (offset) {
        return -PAL_ERROR_INVAL;
    }

    if (handle->dir.endofstream) {
        return 0;
    }

    while (1) {
        while ((char*)handle->dir.ptr < (char*)handle->dir.end) {
            struct linux_dirent64* dirent = (struct linux_dirent64*)handle->dir.ptr;

            if (is_dot_or_dotdot(dirent->d_name)) {
                goto skip;
            }

            bool is_dir = dirent->d_type == DT_DIR;
            size_t len  = strlen(dirent->d_name);

            if (len + 1 + (is_dir ? 1 : 0) > count) {
                goto out;
            }

            memcpy(buf, dirent->d_name, len);
            if (is_dir) {
                buf[len++] = '/';
            }
            buf[len++] = '\0';

            buf += len;
            bytes_written += len;
            count -= len;
        skip:
            handle->dir.ptr = (char*)handle->dir.ptr + dirent->d_reclen;
        }

        if (!count) {
            /* No space left, returning */
            goto out;
        }

        if (!handle->dir.buf) {
            handle->dir.buf = malloc(DIRBUF_SIZE);
            if (!handle->dir.buf) {
                return -PAL_ERROR_NOMEM;
            }
        }

        int size = ocall_getdents(handle->dir.fd, handle->dir.buf, DIRBUF_SIZE);
        if (size < 0) {
            /*
             * If something was written just return that and pretend no error
             * was seen - it will be caught next time.
             */
            if (bytes_written) {
                return bytes_written;
            }
            return unix_to_pal_error(size);
        }

        if (!size) {
            handle->dir.endofstream = true;
            goto out;
        }

        handle->dir.ptr = handle->dir.buf;
        handle->dir.end = (char*)handle->dir.buf + size;
    }

out:
    return (int64_t)bytes_written;
}

static void dir_destroy(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_DIR);

    int ret = ocall_close(handle->dir.fd);
    if (ret < 0) {
        log_error("closing dir host fd %d failed: %s", handle->dir.fd, unix_strerror(ret));
        /* We cannot do anything about it anyway... */
    }

    free(handle->dir.buf);
    free(handle->dir.realpath);
    free(handle);
}

/* 'delete' operation of directory streams */
static int dir_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    if (delete_mode != PAL_DELETE_ALL)
        return -PAL_ERROR_INVAL;

    int ret = ocall_delete(handle->dir.realpath);

    return ret < 0 ? unix_to_pal_error(ret) : ret;
}

static int dir_rename(PAL_HANDLE handle, const char* type, const char* uri) {
    if (strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    char* tmp = strdup(uri);
    if (!tmp)
        return -PAL_ERROR_NOMEM;

    int ret = ocall_rename(handle->dir.realpath, uri);
    if (ret < 0) {
        free(tmp);
        return unix_to_pal_error(ret);
    }

    free(handle->dir.realpath);
    handle->dir.realpath = tmp;
    return 0;
}

struct handle_ops g_dir_ops = {
    .open           = &dir_open,
    .read           = &dir_read,
    .destroy        = &dir_destroy,
    .delete         = &dir_delete,
    .attrquery      = &file_attrquery,
    .attrquerybyhdl = &file_attrquerybyhdl,
    .attrsetbyhdl   = &file_attrsetbyhdl,
    .rename         = &dir_rename,
};
