/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */
/* Copyright (C) 2020 Intel Labs */

/*
 * Operations to handle devices (with special case of "dev:tty" which is stdin/stdout).
 *
 * TODO: Some devices allow lseek() but typically with device-specific semantics. Gramine currently
 *       emulates lseek() completely in LibOS layer, thus seeking at PAL layer cannot be correctly
 *       implemented (without device-specific changes to LibOS layer).
 */

#include "api.h"
#include "ioctls.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "perm.h"
#include "toml.h"
#include "toml_utils.h"

static int dev_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                    pal_share_flags_t share, enum pal_create_mode create,
                    pal_stream_options_t options) {
    int ret;
    assert(create != PAL_CREATE_IGNORED);

    if (strcmp(type, URI_TYPE_DEV))
        return -PAL_ERROR_INVAL;

    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(dev));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    init_handle_hdr(hdl, PAL_TYPE_DEV);

    if (!strcmp(uri, "tty")) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        hdl->dev.nonblocking = false;

        if (access == PAL_ACCESS_RDONLY) {
            hdl->flags |= PAL_HANDLE_FD_READABLE;
            hdl->dev.fd = 0; /* host stdin */
        } else if (access == PAL_ACCESS_WRONLY) {
            hdl->flags |= PAL_HANDLE_FD_WRITABLE;
            hdl->dev.fd = 1; /* host stdout */
        } else {
            assert(access == PAL_ACCESS_RDWR);
            ret = -PAL_ERROR_INVAL;
            goto fail;
        }
    } else {
        /* other devices must be opened through the host */
        hdl->dev.nonblocking = !!(options & PAL_OPTION_NONBLOCK);

        ret = ocall_open(uri, PAL_ACCESS_TO_LINUX_OPEN(access)  |
                              PAL_CREATE_TO_LINUX_OPEN(create)  |
                              PAL_OPTION_TO_LINUX_OPEN(options) |
                              O_CLOEXEC,
                         share);
        if (ret < 0) {
            ret = unix_to_pal_error(ret);
            goto fail;
        }
        hdl->dev.fd = ret;

        if (access == PAL_ACCESS_RDONLY) {
            hdl->flags |= PAL_HANDLE_FD_READABLE;
        } else if (access == PAL_ACCESS_WRONLY) {
            hdl->flags |= PAL_HANDLE_FD_WRITABLE;
        } else {
            assert(access == PAL_ACCESS_RDWR);
            hdl->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
        }
    }

    *handle = hdl;
    return 0;
fail:
    free(hdl);
    return ret;
}

static int64_t dev_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    if (offset || handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_READABLE))
        return -PAL_ERROR_DENIED;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    ssize_t bytes = ocall_read(handle->dev.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int64_t dev_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    if (offset || handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE))
        return -PAL_ERROR_DENIED;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    ssize_t bytes = ocall_write(handle->dev.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int dev_close(PAL_HANDLE handle) {
    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    /* currently we just assign `0`/`1` FDs without duplicating, so close is a no-op for them */
    int ret = 0;
    if (handle->dev.fd != PAL_IDX_POISON && handle->dev.fd != 0 && handle->dev.fd != 1) {
        ret = ocall_close(handle->dev.fd);
    }
    handle->dev.fd = PAL_IDX_POISON;
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

static int dev_flush(PAL_HANDLE handle) {
    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd != PAL_IDX_POISON) {
        int ret = ocall_fsync(handle->dev.fd);
        if (ret < 0)
            return unix_to_pal_error(ret);
    }
    return 0;
}

static int dev_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    __UNUSED(uri);

    if (strcmp(type, URI_TYPE_DEV))
        return -PAL_ERROR_INVAL;

    if (!strcmp(uri, "tty")) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        attr->share_flags  = PERM_rw_rw_rw_;
        attr->pending_size = 0;
    } else {
        /* other devices must query the host */
        int fd = ocall_open(uri, O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0)
            return unix_to_pal_error(fd);

        struct stat stat_buf;
        int ret = ocall_fstat(fd, &stat_buf);
        if (ret < 0) {
            ocall_close(fd);
            return unix_to_pal_error(ret);
        }

        attr->share_flags  = stat_buf.st_mode & PAL_SHARE_MASK;
        attr->pending_size = stat_buf.st_size;

        ocall_close(fd);
    }

    attr->handle_type  = PAL_TYPE_DEV;
    attr->nonblocking  = false;
    return 0;
}

static int dev_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd == 0 || handle->dev.fd == 1) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        attr->share_flags  = 0;
        attr->pending_size = 0;
    } else {
        /* other devices must query the host */
        struct stat stat_buf;
        int ret = ocall_fstat(handle->dev.fd, &stat_buf);
        if (ret < 0)
            return unix_to_pal_error(ret);

        attr->share_flags  = stat_buf.st_mode & PAL_SHARE_MASK;
        attr->pending_size = stat_buf.st_size;
    }

    attr->handle_type  = PAL_TYPE_DEV;
    attr->nonblocking  = handle->dev.nonblocking;
    return 0;
}

/* this dummy function is implemented to support opening TTY devices with O_TRUNC flag */
static int64_t dev_setlength(PAL_HANDLE handle, uint64_t length) {
    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (!(handle->dev.fd == 0 || handle->dev.fd == 1))
        return -PAL_ERROR_NOTSUPPORT;

    if (length != 0)
        return -PAL_ERROR_INVAL;

    return 0;
}

struct handle_ops g_dev_ops = {
    .open           = &dev_open,
    .read           = &dev_read,
    .write          = &dev_write,
    .close          = &dev_close,
    .setlength      = &dev_setlength,
    .flush          = &dev_flush,
    .attrquery      = &dev_attrquery,
    .attrquerybyhdl = &dev_attrquerybyhdl,
};

int _PalDeviceIoControl(PAL_HANDLE handle, uint32_t cmd, unsigned long arg, int* out_ret) {
    int ret;
    int fd;
    if (handle->hdr.type == PAL_TYPE_DEV)
        fd = handle->dev.fd;
    else if (handle->hdr.type == PAL_TYPE_SOCKET)
        fd = handle->sock.fd;
    else
        return -PAL_ERROR_INVAL;

    if ((PAL_IDX)fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    /* find this IOCTL request in the manifest */
    toml_table_t* manifest_sys = toml_table_in(g_pal_public_state.manifest_root, "sys");
    if (!manifest_sys)
        return -PAL_ERROR_NOTIMPLEMENTED;

    toml_array_t* toml_ioctl_struct = NULL;
    ret = ioctls_get_allowed_ioctl_struct(manifest_sys, cmd, &toml_ioctl_struct);
    if (ret < 0)
        return ret;

    if (!toml_ioctl_struct) {
        /* special case of "no struct needed for IOCTL" -> base-type or ignored IOCTL argument */
        *out_ret = ocall_ioctl(fd, cmd, arg);
        return 0;
    }

    void* host_addr = NULL;
    size_t host_size = 0;

    size_t mem_regions_cnt = MAX_MEM_REGIONS;
    size_t sub_regions_cnt = MAX_SUB_REGIONS;
    struct mem_region* mem_regions = calloc(mem_regions_cnt, sizeof(*mem_regions));
    struct sub_region* sub_regions = calloc(sub_regions_cnt, sizeof(*sub_regions));
    if (!mem_regions || !sub_regions) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    /* deep-copy the IOCTL argument's input data outside of enclave, execute the IOCTL OCALL, and
     * deep-copy the IOCTL argument's output data back into enclave */
    ret = ioctls_collect_sub_regions(manifest_sys, toml_ioctl_struct, (void*)arg, mem_regions,
                                     &mem_regions_cnt, sub_regions, &sub_regions_cnt);
    if (ret < 0) {
        log_error("IOCTL: failed to parse ioctl struct (request code = 0x%x)", cmd);
        goto out;
    }

    for (size_t i = 0; i < sub_regions_cnt; i++) {
        /* overapproximation since alignment doesn't necessarily increase sub-region's size */
        host_size += sub_regions[i].size + sub_regions[i].alignment - 1;
    }

    ret = ocall_mmap_untrusted(&host_addr, ALLOC_ALIGN_UP(host_size),
                               PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, /*fd=*/-1,
                               /*offset=*/0);
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        goto out;
    }
    assert(host_addr);

    /* verify that all collected sub-regions are strictly inside the enclave, and the corresponding
     * host sub-regions are strictly outside the enclave */
    char* cur_host_addr = host_addr;
    for (size_t i = 0; i < sub_regions_cnt; i++) {
        if (!sub_regions[i].size)
            continue;
        cur_host_addr = ALIGN_UP_PTR(cur_host_addr, sub_regions[i].alignment);
        if (!sgx_is_completely_within_enclave(sub_regions[i].gramine_addr, sub_regions[i].size)
                || !sgx_is_valid_untrusted_ptr(cur_host_addr, sub_regions[i].size, 1)) {
            ret = -PAL_ERROR_DENIED;
            goto out;
        }
        cur_host_addr += sub_regions[i].size;
    }

    ret = ioctls_copy_sub_regions_to_host(sub_regions, sub_regions_cnt, host_addr,
                                          sgx_copy_from_enclave);
    if (ret < 0)
        goto out;

    int ioctl_ret = ocall_ioctl(fd, cmd, (unsigned long)host_addr);

    ret = ioctls_copy_sub_regions_to_gramine(sub_regions, sub_regions_cnt, sgx_copy_to_enclave);
    if (ret < 0)
        goto out;

    *out_ret = ioctl_ret;
    ret = 0;
out:
    if (host_addr)
        ocall_munmap_untrusted(host_addr, ALLOC_ALIGN_UP(host_size));
    free(mem_regions);
    free(sub_regions);
    return ret;
}
