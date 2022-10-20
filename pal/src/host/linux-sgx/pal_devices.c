/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */
/* Copyright (C) 2020 Intel Labs */

/*
 * Operations to handle devices.
 *
 * TODO: Some devices allow lseek() but typically with device-specific semantics. Gramine currently
 *       emulates lseek() completely in LibOS layer, thus seeking at PAL layer cannot be correctly
 *       implemented (without device-specific changes to LibOS layer).
 */

#include "api.h"
#include "enclave_tf.h"
#include "ioctls.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "path_utils.h"
#include "perm.h"
#include "toml.h"
#include "toml_utils.h"

static int dev_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                    pal_share_flags_t share, enum pal_create_mode create,
                    pal_stream_options_t options) {
    int ret;
    char* normpath = NULL;

    assert(create != PAL_CREATE_IGNORED);

    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    if (strcmp(type, URI_TYPE_DEV))
        return -PAL_ERROR_INVAL;

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(dev));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    init_handle_hdr(hdl, PAL_TYPE_DEV);

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

    size_t normpath_size = strlen(uri) + 1;
    normpath = malloc(normpath_size);
    if (!normpath) {
        ret = -PAL_ERROR_NOMEM;
        goto fail;
    }
    ret = get_norm_path(uri, normpath, &normpath_size);
    if (ret < 0) {
        log_warning("Could not normalize path (%s): %s", uri, pal_strerror(ret));
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }
    hdl->dev.realpath = normpath;

    struct trusted_file* tf = get_trusted_or_allowed_file(hdl->dev.realpath);
    if (!tf || !tf->allowed) {
        if (get_file_check_policy() != FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG) {
            log_warning("Disallowing access to device '%s'; device is not allowed.",
                        hdl->dev.realpath);
            ret = -PAL_ERROR_DENIED;
            goto fail;
        }
        log_warning("Allowing access to unknown device '%s' due to file_check_policy settings.",
                    hdl->dev.realpath);
    }

    if (access == PAL_ACCESS_RDONLY) {
        hdl->flags |= PAL_HANDLE_FD_READABLE;
    } else if (access == PAL_ACCESS_WRONLY) {
        hdl->flags |= PAL_HANDLE_FD_WRITABLE;
    } else {
        assert(access == PAL_ACCESS_RDWR);
        hdl->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    }

    *handle = hdl;
    return 0;
fail:
    free(hdl);
    free(normpath);
    return ret;
}

static int64_t dev_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    if (offset)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_READABLE))
        return -PAL_ERROR_DENIED;

    ssize_t bytes = ocall_read(handle->dev.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int64_t dev_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    if (offset)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE))
        return -PAL_ERROR_DENIED;

    ssize_t bytes = ocall_write(handle->dev.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static void dev_destroy(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    int ret = ocall_close(handle->dev.fd);
    if (ret < 0) {
        log_error("closing dev host fd %d failed: %s", handle->dev.fd, unix_strerror(ret));
        /* We cannot do anything about it anyway... */
    }

    free(handle);
}

static int dev_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    if (delete_mode != PAL_DELETE_ALL)
        return -PAL_ERROR_INVAL;

    int ret = ocall_delete(handle->dev.realpath);
    return ret < 0 ? unix_to_pal_error(ret) : ret;
}

static int64_t dev_setlength(PAL_HANDLE handle, uint64_t length) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    int ret = ocall_ftruncate(handle->dev.fd, length);
    return ret < 0 ? unix_to_pal_error(ret) : (int64_t)length;
}

static int dev_flush(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    int ret = ocall_fsync(handle->dev.fd);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

static int dev_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    __UNUSED(type);
    assert(strcmp(type, URI_TYPE_DEV) == 0);

    int fd = ocall_open(uri, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return unix_to_pal_error(fd);

    struct stat stat_buf;
    int ret = ocall_fstat(fd, &stat_buf);
    if (ret < 0) {
        ocall_close(fd);
        return unix_to_pal_error(ret);
    }

    ocall_close(fd);

    attr->share_flags  = stat_buf.st_mode & PAL_SHARE_MASK;
    attr->pending_size = stat_buf.st_size;
    attr->handle_type  = PAL_TYPE_DEV;
    attr->nonblocking  = false;
    return 0;
}

static int dev_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    struct stat stat_buf;
    int ret = ocall_fstat(handle->dev.fd, &stat_buf);
    if (ret < 0)
        return unix_to_pal_error(ret);

    attr->share_flags  = stat_buf.st_mode & PAL_SHARE_MASK;
    attr->pending_size = stat_buf.st_size;
    attr->handle_type  = PAL_TYPE_DEV;
    attr->nonblocking  = handle->dev.nonblocking;
    return 0;
}

static int dev_map(PAL_HANDLE handle, void* addr, pal_prot_flags_t prot, uint64_t offset,
                   uint64_t size) {
    assert(handle->hdr.type == PAL_TYPE_DEV);
    assert(IS_ALLOC_ALIGNED(offset) && IS_ALLOC_ALIGNED(size));

    uint64_t dummy;
    if (__builtin_add_overflow(offset, size, &dummy)) {
        return -PAL_ERROR_INVAL;
    }

    if (addr < g_pal_public_state.shared_address_start
            || (uintptr_t)addr + size > (uintptr_t)g_pal_public_state.shared_address_end) {
        log_warning("Could not map a device outside of the shared memory range at %p-%p", addr,
                    addr + size);
        return -PAL_ERROR_DENIED;
    }

    void* mem = addr;
    /* MAP_FIXED is intentional to override a previous mapping */
    int ret = ocall_mmap_untrusted(&mem, size, PAL_PROT_TO_LINUX(prot), MAP_SHARED | MAP_FIXED,
                                   handle->dev.fd, offset);
    assert(mem == addr);
    return ret < 0 ? unix_to_pal_error(ret) : ret;
}

struct handle_ops g_dev_ops = {
    .open           = &dev_open,
    .read           = &dev_read,
    .write          = &dev_write,
    .destroy        = &dev_destroy,
    .delete         = &dev_delete,
    .map            = &dev_map,
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
