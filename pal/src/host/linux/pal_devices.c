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
#include "ioctls.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "perm.h"

static int dev_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                    pal_share_flags_t share, enum pal_create_mode create,
                    pal_stream_options_t options) {
    int ret;
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

    ret = DO_SYSCALL(open, uri, PAL_ACCESS_TO_LINUX_OPEN(access)  |
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

    *handle = hdl;
    return 0;
fail:
    free(hdl);
    return ret;
}

static int64_t dev_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    if (offset)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_READABLE) || handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int64_t bytes = DO_SYSCALL(read, handle->dev.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int64_t dev_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    if (offset)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE) || handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int64_t bytes = DO_SYSCALL(write, handle->dev.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int dev_close(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    if (handle->dev.fd != PAL_IDX_POISON) {
        int ret = DO_SYSCALL(close, handle->dev.fd);
        if (ret < 0)
            return unix_to_pal_error(ret);
    }
    handle->dev.fd = PAL_IDX_POISON;
    return 0;
}

static int dev_flush(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    if (handle->dev.fd != PAL_IDX_POISON) {
        int ret = DO_SYSCALL(fsync, handle->dev.fd);
        if (ret < 0)
            return unix_to_pal_error(ret);
    }
    return 0;
}

static int dev_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    __UNUSED(type);
    assert(strcmp(type, URI_TYPE_DEV) == 0);

    struct stat stat_buf;
    int ret = DO_SYSCALL(stat, uri, &stat_buf);
    if (ret < 0)
        return unix_to_pal_error(ret);

    attr->share_flags  = stat_buf.st_mode & PAL_SHARE_MASK;
    attr->pending_size = stat_buf.st_size;
    attr->handle_type = PAL_TYPE_DEV;
    attr->nonblocking = false;
    return 0;
}

static int dev_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(handle->hdr.type == PAL_TYPE_DEV);

    struct stat stat_buf;
    int ret = DO_SYSCALL(fstat, handle->dev.fd, &stat_buf);
    if (ret < 0)
        return unix_to_pal_error(ret);

    attr->share_flags  = stat_buf.st_mode & PAL_SHARE_MASK;
    attr->pending_size = stat_buf.st_size;
    attr->handle_type  = PAL_TYPE_DEV;
    attr->nonblocking  = handle->dev.nonblocking;
    return 0;
}

struct handle_ops g_dev_ops = {
    .open           = &dev_open,
    .read           = &dev_read,
    .write          = &dev_write,
    .close          = &dev_close,
    .flush          = &dev_flush,
    .attrquery      = &dev_attrquery,
    .attrquerybyhdl = &dev_attrquerybyhdl,
};

static bool memcpy_to_host(void* host_ptr, const void* ptr, size_t size) {
    memcpy(host_ptr, ptr, size);
    return true;
}

static bool memcpy_to_gramine(void* ptr, size_t max_size, const void* host_ptr, size_t host_size) {
    if (host_size > max_size)
        return false;
    memcpy(ptr, host_ptr, host_size);
    return true;
}

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
        *out_ret = DO_SYSCALL(ioctl, fd, cmd, arg);
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

    /* deep-copy the IOCTL argument's input data to `host_addr` region, execute the IOCTL syscall, and
     * deep-copy the IOCTL argument's output data back into Gramine memory (this is redundant in
     * Linux PAL but we do it for uniformity with other PALs, notably Linux-SGX) */
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

    host_addr = calloc(1, ALLOC_ALIGN_UP(host_size));
    if (!host_addr) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    ret = ioctls_copy_sub_regions_to_host(sub_regions, sub_regions_cnt, host_addr, memcpy_to_host);
    if (ret < 0)
        goto out;

    /* note that if the host returned a negative value (typically means an error, but not always
     * since this is completely device-specific), then we still return success and forward the value
     * as-is to the LibOS and ultimately to the app */
    int ioctl_ret = DO_SYSCALL(ioctl, fd, cmd, (unsigned long)host_addr);

    ret = ioctls_copy_sub_regions_to_gramine(sub_regions, sub_regions_cnt, memcpy_to_gramine);
    if (ret < 0)
        goto out;

    *out_ret = ioctl_ret;
    ret = 0;
out:
    free(host_addr);
    free(mem_regions);
    free(sub_regions);
    return ret;
}
