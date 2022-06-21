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

/*
 * Code below describes the TOML syntax of the manifest entries used for deep-copying complex nested
 * objects out and inside the SGX enclave. This syntax is currently used for IOCTL emulation and is
 * generic enough to describe the most common memory layouts for deep copy of IOCTL structs.
 *
 * The high-level description can be found in the "manifest syntax" documentation page.
 *
 * The following example describes the main implementation details:
 *
 *   struct pascal_str { uint8_t len; char str[]; };
 *   struct c_str { char str[]; };
 *   struct root { struct pascal_str* s1;
 *                 struct c_str* s2; uint64_t s2_buf_size;
 *                 int8_t x; int8_t y; };
 *
 *   alignas(128) struct root obj;
 *   ioctl(devfd, DEV_IOCTL_NUMBER, &obj);
 *
 * The example IOCTL takes as a third argument a pointer to an object of type `struct root` that
 * contains two pointers to other objects (pascal-style string and a C-style string) and embeds two
 * integers `x` and `y`. The two strings reside in separate memory regions in enclave memory. Note
 * that the size of the allocated buffer for the C-style string is stored in the `s2_buf_size` field
 * of the root object. The `pascal_str` string is an input to the IOCTL, the `c_str` string and its
 * actual size `s2_buf_size` are the outputs of the IOCTL, and the integers `x` and `y` are also
 * outputs of the IOCTL. Also note that the root object is 128B-aligned (for illustration purposes).
 * This IOCTL could for example be used to convert a Pascal string into a C string (C string will be
 * truncated to user-specified `s2_buf_size` if greater than this limit), and find the indices of
 * the first occurrences of chars "x" and "y" in the Pascal string.
 *
 * The corresponding manifest entries describing these structs look like this:
 *
 *   sgx.ioctl_structs.root = [
 *     { alignment = 128, ptr = [
 *                            { name = "pascal-str-len", size = 1, direction = "out" },
 *                            { name = "pascal-str", size = "pascal-str-len", direction = "out"}
 *                        ] },
 *     { ptr = [
 *           { name = "c-str", size = "c-buf-size", direction = "in" }
 *       ] },
 *     { name = "c-buf-size", size = 8, direction = "inout" },
 *     { size = 2, direction = "in" }  # x and y fields
 *   ]
 *
 *   sgx.allowed_ioctls = [
 *     { request_code = <DEV_IOCTL_NUMER>, struct = "root" }
 *   ]
 *
 * The current TOML syntax has the following rules/limitations:
 *
 *  1. Each separate memory region is represented as a TOML array (`[]`).
 *  2. Each sub-region of one memory region is represented as a TOML table (`{}`).
 *  3. Each sub-region may be a pointer (`ptr`) to another memory region. In this case, the value of
 *     `ptr` is a TOML-array representation of that other memory region or a TOML string with the
 *     name of another memory region. The `ptr` sub-region always has size of 8B (assuming x86-64)
 *     and doesn't have an in/out direction. The `array_len` field specifies the number of adjacent
 *     memory regions that this pointer points to (i.e. the length of the array).
 *  4. Sub-regions can be fixed-size (like the last sub-region containing two bytes `x` and `y`) or
 *     can be flexible-size (like the two strings). In the latter case, the `size` field contains a
 *     name of a sub-region where the actual size is stored. Note that this referenced sub-region
 *     must come *before* (in the Breadth-First-Search sense) the sub-region with such flexible-size
 *     `size` -- TOML representations of typical IOCTL structs always have the size specifier in a
 *     sub-region found before the buffer sub-region, either in the same memory region (e.g. as in
 *     flexible array members in C) or in the "outer" memory region (e.g. the size specifier is
 *     located in the root memory region and the buffer is located in the nested memory region).
 *     This is a limitation of the current parser and could be removed in the future, if need
 *     arises.
 *  5. Sub-regions that store the size of another sub-region must be less than or equal to 8 bytes
 *     in size.
 *  6. Sub-regions may have a name for ease of identification; this is required for "size" /
 *     "array_len" sub-regions but may be omitted for all other kinds of sub-regions.
 *  7. Sub-regions may have one of the four directions: "out" to copy contents of the sub-region out
 *     of the enclave to untrusted memory, "in" to copy from untrusted memory into the enclave,
 *     "inout" to copy in both directions, "none" to not copy at all (useful for e.g. padding).
 *     Note that pointer sub-regions do not have a direction (their values are unconditionally
 *     rewired so as to point to the corresponding region in untrusted memory).
 *  8. The first sub-region (and only the first!) may specify the alignment of the memory region.
 *  9. The total size of a sub-region is calculated as `size * unit + adjustment`. By default `unit`
 *     is 1 byte and `adjustment` is 0. Note that `adjustment` may be a negative number.
 *
 * The diagram below shows how this complex object is copied from enclave memory (left side) to
 * untrusted memory (right side). MR stands for "memory region", SR stands for "sub-region". Note
 * how enclave pointers are copied and rewired to point to untrusted memory regions.
 *
 *      struct root (MR1)                    |       deep-copied struct (aligned at 128B)
 *      +-----------------------+            |       +------------------------------+
 *  +----+ pascal_str* s1       |     SR1    |    +----+ pascal_str* s1       (MR1) |
 *  |   |                       |            |    |  |                              |
 *  |   |  c_str* s2 +------------+   SR2    |    |  |   c_str* s2 +-------------------+
 *  |   |                       | |          |    |  |                              |  |
 *  |   |  uint64_t s2_buf_size | |   SR3    |    |  |   uint64_t s2_buf_size       |  |
 *  |   |                       | |          |    |  |                              |  |
 *  |   |  int8_t x, y          | |   SR4    |    |  |   int8_t x, y                |  |
 *  |   +-----------------------+ |          |    |  +------------------------------+  |
 *  |                             |          |    +->|   uint8_t len          (MR2) |  |
 *  v (MR2)                       |          |       |                              |  |
 * +-------------+                |          |       |   char str[len]              |  |
 * | uint8_t len |                |   SR5    |       +------------------------------+  |
 * |             |                |          |       |  char str[s2_buf_size] (MR3) |<-+
 * | char str[]  |                |   SR6    |       +------------------------------+
 * +-------------+                |          |
 *                       (MR3)    v          |
 *                     +----------+-+        |
 *                     | char str[] | SR7    |
 *                     +------------+        |
 */

/* for simplicity, we limit the number of memory and sub-regions; these limits should be enough for
 * any reasonable IOCTL struct object */
#define MAX_MEM_REGIONS 1024
#define MAX_SUB_REGIONS (10 * 1024)

/* direction of copy: none (used for padding), out of enclave, inside enclave or both;
 * default is DIRECTION_NONE */
enum mem_copy_direction {
    DIRECTION_NONE,
    DIRECTION_OUT,
    DIRECTION_IN,
    DIRECTION_INOUT
};

struct mem_region {
    toml_array_t* toml_mem_region; /* describes contiguous sub-regions in this mem-region */
    void* enclave_addr;            /* base address of this memory region in enclave memory */
    bool adjacent;                 /* memory region adjacent to previous one? (used for arrays) */
};

struct dynamic_value {
    bool is_determined;
    union {
        /* actual value, use only if `is_determined == true` */
        uint64_t value;
        /* sub-region name that determines the value, use only if `is_determined == false`;
         * FIXME: memorize name hash for quicker string comparison? */
        char* sub_region_name;
    };
};

/* total size in bytes of a sub-region is calculated as `size * unit + adjustment` */
struct sub_region {
    enum mem_copy_direction direction; /* direction of copy during OCALL */
    char* name;                     /* may be NULL for unnamed regions */
    struct dynamic_value array_len; /* array length of the sub-region (only for `ptr` regions) */
    size_t size;                    /* size of this sub-region */
    size_t unit;                    /* unit of measurement, used in total size calculation */
    int64_t adjustment;             /* may be negative; used to adjust total size */
    size_t alignment;               /* alignment of this sub-region */
    void* enclave_addr;             /* base address of this sub region in enclave mem */
    void* untrusted_addr;           /* base address of corresponding sub region in untrusted mem */
    toml_array_t* toml_mem_region;  /* for pointers/arrays, specifies pointed-to mem region */
};

static bool strings_equal(const char* s1, const char* s2) {
    if (!s1 || !s2)
        return false;
    return !strcmp(s1, s2);
}

static int copy_value(void* addr, size_t size, uint64_t* out_value) {
    if (!addr || size > sizeof(*out_value))
        return -PAL_ERROR_INVAL;

    /* the copy below assumes little-endian machines (which x86 is) */
    *out_value = 0;
    memcpy(out_value, addr, size);
    return 0;
}

/* finds a sub region with name `sub_region_name` among `all_sub_regions` and returns its index */
static int get_sub_region_idx(struct sub_region* all_sub_regions, size_t all_sub_regions_cnt,
                              const char* sub_region_name, size_t* out_idx) {
    /* it is important to iterate in reverse order because there may be an array of mem regions
     * with same-named sub regions, and we want to find the latest sub region */
    for (size_t i = all_sub_regions_cnt; i > 0; i--) {
        size_t idx = i - 1;
        if (strings_equal(all_sub_regions[idx].name, sub_region_name)) {
            *out_idx = idx;
            return 0;
        }
    }
    log_error("IOCTL: cannot find '%s'", sub_region_name);
    return -PAL_ERROR_INVAL;
}

/* allocates a name string, it is responsibility of the caller to free it after use */
static int get_sub_region_name(const toml_table_t* toml_sub_region, char** out_name) {
    return toml_string_in(toml_sub_region, "name", out_name) < 0 ? -PAL_ERROR_INVAL : 0;
}

static int get_sub_region_direction(const toml_table_t* toml_sub_region,
                                    enum mem_copy_direction* out_direction) {
    char* direction_str;
    int ret = toml_string_in(toml_sub_region, "direction", &direction_str);
    if (ret < 0)
        return -PAL_ERROR_INVAL;

    if (!direction_str) {
        *out_direction = DIRECTION_NONE;
        return 0;
    }

    ret = 0;
    if (!strcmp(direction_str, "out")) {
        *out_direction = DIRECTION_OUT;
    } else if (!strcmp(direction_str, "in")) {
        *out_direction = DIRECTION_IN;
    } else if (!strcmp(direction_str, "inout")) {
        *out_direction = DIRECTION_INOUT;
    } else if (!strcmp(direction_str, "none")) {
        *out_direction = DIRECTION_NONE;
    } else {
        ret = -PAL_ERROR_INVAL;
    }
    free(direction_str);
    return ret;
}

static int get_sub_region_alignment(const toml_table_t* toml_sub_region, size_t* out_alignment) {
    int64_t alignment;
    int ret = toml_int_in(toml_sub_region, "alignment", /*defaultval=*/1, &alignment);
    if (ret < 0 || alignment <= 0)
        return -PAL_ERROR_INVAL;

    *out_alignment = (size_t)alignment;
    return 0;
}

static int get_sub_region_unit(const toml_table_t* toml_sub_region, size_t* out_unit) {
    int64_t unit;
    int ret = toml_int_in(toml_sub_region, "unit", /*defaultval=*/1, &unit);
    if (ret < 0 || unit <= 0)
        return -PAL_ERROR_INVAL;

    *out_unit = (size_t)unit;
    return 0;
}

static int get_sub_region_adjustment(const toml_table_t* toml_sub_region, int64_t* out_adjustment) {
    int ret = toml_int_in(toml_sub_region, "adjustment", /*defaultval=*/0, out_adjustment);
    return ret < 0 ? -PAL_ERROR_INVAL : 0;
}

static int get_toml_nested_mem_region(toml_table_t* toml_sub_region,
                                      toml_array_t** out_toml_mem_region) {
    toml_array_t* toml_mem_region = toml_array_in(toml_sub_region, "ptr");
    if (toml_mem_region) {
        *out_toml_mem_region = toml_mem_region;
        return 0;
    }

    char* ioctl_struct_str;
    int ret = toml_string_in(toml_sub_region, "ptr", &ioctl_struct_str);
    if (ret < 0)
        return -PAL_ERROR_INVAL;

    if (!ioctl_struct_str) {
        /* if we're here, then we didn't find `ptr` field at all */
        *out_toml_mem_region = NULL;
        return 0;
    }

    /* since we're in this function, we are parsing sgx.ioctl_structs list, so we know it exists */
    toml_table_t* manifest_sgx = toml_table_in(g_pal_public_state.manifest_root, "sgx");
    assert(manifest_sgx);
    toml_table_t* toml_ioctl_structs = toml_table_in(manifest_sgx, "ioctl_structs");
    assert(toml_ioctl_structs);

    toml_mem_region = toml_array_in(toml_ioctl_structs, ioctl_struct_str);
    if (!toml_mem_region || toml_array_nelem(toml_mem_region) <= 0) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    *out_toml_mem_region = toml_mem_region;
    ret = 0;
out:
    free(ioctl_struct_str);
    return ret;
}

static int get_sub_region_size(struct sub_region* all_sub_regions, size_t all_sub_regions_cnt,
                               const toml_table_t* toml_sub_region, size_t* out_size) {
    toml_raw_t sub_region_size_raw = toml_raw_in(toml_sub_region, "size");
    if (!sub_region_size_raw) {
        *out_size = 0;
        return 0;
    }

    int64_t size;
    int ret = toml_rtoi(sub_region_size_raw, &size);
    if (ret == 0) {
        /* size is specified as constant */
        if (size <= 0)
            return -PAL_ERROR_INVAL;

        *out_size = (size_t)size;
        return 0;
    }

    /* size must have been specified as string (another sub-region's name) */
    char* sub_region_name = NULL;
    ret = toml_rtos(sub_region_size_raw, &sub_region_name);
    if (ret < 0)
        return -PAL_ERROR_INVAL;

    size_t found_idx;
    ret = get_sub_region_idx(all_sub_regions, all_sub_regions_cnt, sub_region_name, &found_idx);
    free(sub_region_name);
    if (ret < 0)
        return ret;

    void* addr_of_size_field  = all_sub_regions[found_idx].enclave_addr;
    size_t size_of_size_field = all_sub_regions[found_idx].size;
    uint64_t read_size;

    ret = copy_value(addr_of_size_field, size_of_size_field, &read_size);
    if (ret < 0)
        return ret;

    static_assert(sizeof(read_size) == sizeof(*out_size), "wrong types");
    *out_size = (size_t)read_size;
    return 0;
}

/* may allocate an array-len-name string, it is responsibility of the caller to free it after use */
static int get_sub_region_array_len(const toml_table_t* toml_sub_region,
                                    struct dynamic_value* out_array_len) {
    toml_raw_t sub_region_array_len_raw = toml_raw_in(toml_sub_region, "array_len");
    if (!sub_region_array_len_raw) {
        *out_array_len = (struct dynamic_value){
            .is_determined = true,
            .value = 1  /* 1 array item by default */
        };
        return 0;
    }

    int64_t array_len;
    int ret = toml_rtoi(sub_region_array_len_raw, &array_len);
    if (ret == 0) {
        /* array_len is specified as constant */
        if (array_len <= 0)
            return -PAL_ERROR_INVAL;

        *out_array_len = (struct dynamic_value){
            .is_determined = true,
            .value = (uint64_t)array_len
        };
        return 0;
    }

    /* array_len must be specified as string (another sub-region's name) */
    char* sub_region_name = NULL;
    ret = toml_rtos(sub_region_array_len_raw, &sub_region_name);
    if (ret < 0)
        return -PAL_ERROR_INVAL;

    *out_array_len = (struct dynamic_value){
        .is_determined = false,
        .sub_region_name = sub_region_name
    };
    return 0;
}

/* Caller sets `mem_regions_cnt_ptr` to the length of `mem_regions` array; this variable is updated
 * to return the number of actually used `mem_regions`. Similarly with `sub_regions`. */
static int collect_sub_regions(toml_array_t* root_toml_mem_region, void* root_enclave_addr,
                               struct mem_region* mem_regions, size_t* mem_regions_cnt_ptr,
                               struct sub_region* sub_regions, size_t* sub_regions_cnt_ptr) {
    int ret;

    assert(root_toml_mem_region && toml_array_nelem(root_toml_mem_region) > 0);

    size_t max_sub_regions = *sub_regions_cnt_ptr;
    size_t sub_regions_cnt = 0;

    size_t max_mem_regions = *mem_regions_cnt_ptr;
    size_t mem_regions_cnt = 0;

    if (!max_sub_regions || !max_mem_regions)
        return -PAL_ERROR_NOMEM;

    mem_regions[0].toml_mem_region = root_toml_mem_region;
    mem_regions[0].enclave_addr    = root_enclave_addr;
    mem_regions[0].adjacent        = false;
    mem_regions_cnt++;

    /*
     * Collecting memory regions and their sub-regions must use top-to-bottom breadth-first search
     * to dynamically calculate sizes of sub-regions when they are specified via another
     * sub-region's "name". Consider this example (unnecessary fields not shown for simplicity):
     *
     *   ioctl_read = [ { ptr = [ { size = "buf_size" } ] }, { name = "buf_size" } ]
     *
     * Here the field that contains size of the buffer (pointed to by the first sub-region) is
     * located in the second sub-region. Note that the buffer itself is located in the nested memory
     * region. Now, if the search would be depth-first, then the parser would arrive at the buffer
     * before learning its size.
     *
     */
    char* cur_enclave_addr = NULL;
    size_t mem_region_idx = 0;
    while (mem_region_idx < mem_regions_cnt) {
        struct mem_region* cur_mem_region = &mem_regions[mem_region_idx];
        mem_region_idx++;

        if (!cur_mem_region->adjacent)
            cur_enclave_addr = cur_mem_region->enclave_addr;

        size_t cur_mem_region_first_sub_region_idx = sub_regions_cnt;

        assert(toml_array_nelem(cur_mem_region->toml_mem_region) >= 0);
        for (size_t i = 0; i < (size_t)toml_array_nelem(cur_mem_region->toml_mem_region); i++) {
            toml_table_t* toml_sub_region = toml_table_at(cur_mem_region->toml_mem_region, i);
            if (!toml_sub_region) {
                log_error("IOCTL: each memory sub-region must be a TOML table");
                ret = -PAL_ERROR_INVAL;
                goto out;
            }

            if (sub_regions_cnt == max_sub_regions) {
                log_error("IOCTL: too many memory sub-regions (max is %zu)", max_sub_regions);
                ret = -PAL_ERROR_NOMEM;
                goto out;
            }

            struct sub_region* cur_sub_region = &sub_regions[sub_regions_cnt];
            sub_regions_cnt++;

            memset(cur_sub_region, 0, sizeof(*cur_sub_region));

            cur_sub_region->enclave_addr = cur_enclave_addr;
            if (!cur_enclave_addr) {
                /* FIXME: use `is_user_memory_readable()` to check invalid enclave addresses */
                ret = -PAL_ERROR_INVAL;
                goto out;
            }

            if (toml_raw_in(toml_sub_region, "alignment") && i != 0) {
                log_error("IOCTL: 'alignment' may be specified only at beginning of mem region");
                ret = -PAL_ERROR_INVAL;
                goto out;
            }

            if (toml_array_in(toml_sub_region, "ptr") || toml_raw_in(toml_sub_region, "ptr")) {
                if (toml_raw_in(toml_sub_region, "direction")) {
                    log_error("IOCTL: 'ptr' cannot specify 'direction'");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }
                if (toml_raw_in(toml_sub_region, "size")) {
                    log_error("IOCTL: 'ptr' cannot specify 'size' (did you mean 'array_len'?)");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }
            } else if (toml_raw_in(toml_sub_region, "array_len")) {
                    log_error("IOCTL: non-'ptr' field cannot specify 'array_len' (did you mean"
                              " 'size'?)");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
            }

            ret = get_sub_region_name(toml_sub_region, &cur_sub_region->name);
            if (ret < 0) {
                log_error("IOCTL: parsing of 'name' field failed");
                goto out;
            }

            ret = get_sub_region_direction(toml_sub_region, &cur_sub_region->direction);
            if (ret < 0) {
                log_error("IOCTL: parsing of 'direction' field failed");
                goto out;
            }

            ret = get_sub_region_alignment(toml_sub_region, &cur_sub_region->alignment);
            if (ret < 0) {
                log_error("IOCTL: parsing of 'alignment' field failed");
                goto out;
            }

            ret = get_sub_region_unit(toml_sub_region, &cur_sub_region->unit);
            if (ret < 0) {
                log_error("IOCTL: parsing of 'unit' field failed");
                goto out;
            }

            ret = get_sub_region_adjustment(toml_sub_region, &cur_sub_region->adjustment);
            if (ret < 0) {
                log_error("IOCTL: parsing of 'adjustment' field failed");
                goto out;
            }

            ret = get_sub_region_size(sub_regions, sub_regions_cnt, toml_sub_region,
                                      &cur_sub_region->size);
            if (ret < 0) {
                log_error("IOCTL: parsing of 'size' field failed");
                goto out;
            }

            /* for simplicity, we try to get `array_len` field even for non-ptr sub regions; this
             * will always return success (as we have a check on `array_len` existence above) and a
             * dummy default `array_len = 1`, but it will be unused */
            ret = get_sub_region_array_len(toml_sub_region, &cur_sub_region->array_len);
            if (ret < 0) {
                log_error("IOCTL: parsing of 'array_len' field failed");
                goto out;
            }

            ret = get_toml_nested_mem_region(toml_sub_region, &cur_sub_region->toml_mem_region);
            if (ret < 0) {
                log_error("IOCTL: parsing of 'ptr' field failed");
                goto out;
            }

            if (cur_sub_region->toml_mem_region) {
                /* only set size for now, we postpone pointer/array handling for later */
                cur_sub_region->size = sizeof(void*);
            } else {
                if (__builtin_mul_overflow(cur_sub_region->size, cur_sub_region->unit,
                                           &cur_sub_region->size)) {
                    log_error("IOCTL: integer overflow while applying 'unit'");
                    ret = -PAL_ERROR_OVERFLOW;
                    goto out;
                }
                if (__builtin_add_overflow(cur_sub_region->size, cur_sub_region->adjustment,
                                           &cur_sub_region->size)) {
                    log_error("IOCTL: integer overflow while applying 'adjustment'");
                    ret = -PAL_ERROR_OVERFLOW;
                    goto out;
                }
            }

            if (!access_ok(cur_enclave_addr, cur_sub_region->size)) {
                log_error("IOCTL: enclave address overflows");
                ret = -PAL_ERROR_OVERFLOW;
                goto out;
            }
            cur_enclave_addr += cur_sub_region->size;
        }

        /* iterate through collected pointer/array sub regions and add corresponding mem regions */
        for (size_t i = cur_mem_region_first_sub_region_idx; i < sub_regions_cnt; i++) {
            if (!sub_regions[i].toml_mem_region)
                continue;

            if (!sub_regions[i].array_len.is_determined) {
                /* array len was not hard-coded in struct definition, dynamically determine it */
                assert(sub_regions[i].array_len.sub_region_name);

                size_t found_idx;
                ret = get_sub_region_idx(sub_regions, sub_regions_cnt,
                                         sub_regions[i].array_len.sub_region_name, &found_idx);
                if (ret < 0) {
                    log_error("IOCTL: cannot find '%s'", sub_regions[i].array_len.sub_region_name);
                    goto out;
                }

                void* addr_of_array_len_field  = sub_regions[found_idx].enclave_addr;
                size_t size_of_array_len_field = sub_regions[found_idx].size;
                uint64_t array_len;
                ret = copy_value(addr_of_array_len_field, size_of_array_len_field, &array_len);
                if (ret < 0) {
                    log_error("IOCTL: cannot get array len from '%s'",
                              sub_regions[i].array_len.sub_region_name);
                    goto out;
                }

                free(sub_regions[i].array_len.sub_region_name);
                sub_regions[i].array_len = (struct dynamic_value){
                    .is_determined = true,
                    .value = array_len
                };
            }

            /* add nested mem regions only if this pointer/array sub region value is not NULL */
            void* mem_region_addr = *((void**)sub_regions[i].enclave_addr);
            if (mem_region_addr) {
                for (size_t k = 0; k < sub_regions[i].array_len.value; k++) {
                    if (mem_regions_cnt == max_mem_regions) {
                        log_error("IOCTL: too many memory regions (max is %zu)", max_mem_regions);
                        ret = -PAL_ERROR_NOMEM;
                        goto out;
                    }

                    mem_regions[mem_regions_cnt].toml_mem_region = sub_regions[i].toml_mem_region;
                    mem_regions[mem_regions_cnt].enclave_addr    = mem_region_addr;
                    mem_regions[mem_regions_cnt].adjacent        = k > 0;
                    mem_regions_cnt++;
                }
            }
        }
    }

    *mem_regions_cnt_ptr = mem_regions_cnt;
    *sub_regions_cnt_ptr = sub_regions_cnt;
    ret = 0;
out:
    for (size_t i = 0; i < sub_regions_cnt; i++) {
        /* "name" fields are not needed after we collected all sub_regions */
        free(sub_regions[i].name);
        sub_regions[i].name = NULL;
        if (!sub_regions[i].array_len.is_determined) {
            free(sub_regions[i].array_len.sub_region_name);
            sub_regions[i].array_len.sub_region_name = NULL;
        }
    }
    return ret;
}

static int copy_sub_regions_to_untrusted(struct sub_region* sub_regions, size_t sub_regions_cnt,
                                         void* untrusted_addr) {
    /* we rely on the fact that the untrusted memory region was zeroed out: we can simply "jump
     * over" untrusted memory when doing alignment and when direction of copy is `in` or `none` */
    char* cur_untrusted_addr = untrusted_addr;
    for (size_t i = 0; i < sub_regions_cnt; i++) {
        if (!sub_regions[i].size)
            continue;

        assert(sub_regions[i].alignment);
        cur_untrusted_addr = ALIGN_UP_PTR(cur_untrusted_addr, sub_regions[i].alignment);

        if (!sgx_is_completely_within_enclave(sub_regions[i].enclave_addr, sub_regions[i].size)
                || !sgx_is_valid_untrusted_ptr(cur_untrusted_addr, sub_regions[i].size, 1)) {
            return -PAL_ERROR_DENIED;
        }

        if (sub_regions[i].direction == DIRECTION_OUT
                || sub_regions[i].direction == DIRECTION_INOUT) {
            bool ret = sgx_copy_from_enclave(cur_untrusted_addr, sub_regions[i].enclave_addr,
                                             sub_regions[i].size);
            if (!ret)
                return -PAL_ERROR_DENIED;
        }

        sub_regions[i].untrusted_addr = cur_untrusted_addr;
        cur_untrusted_addr += sub_regions[i].size;
    }

    for (size_t i = 0; i < sub_regions_cnt; i++) {
        if (!sub_regions[i].size)
            continue;

        if (sub_regions[i].toml_mem_region) {
            void* enclave_ptr_value = *((void**)sub_regions[i].enclave_addr);
            /* rewire pointer value in untrusted memory to a corresponding untrusted sub-region */
            for (size_t j = 0; j < sub_regions_cnt; j++) {
                if (sub_regions[j].enclave_addr == enclave_ptr_value) {
                    bool ret = sgx_copy_from_enclave(sub_regions[i].untrusted_addr,
                                                     &sub_regions[j].untrusted_addr,
                                                     sizeof(void*));
                    if (!ret)
                        return -PAL_ERROR_DENIED;
                    break;
                }
            }
        }
    }

    return 0;
}

static int copy_sub_regions_to_enclave(struct sub_region* sub_regions, size_t sub_regions_cnt) {
    for (size_t i = 0; i < sub_regions_cnt; i++) {
        if (!sub_regions[i].size)
            continue;

        if (sub_regions[i].direction == DIRECTION_IN
                || sub_regions[i].direction == DIRECTION_INOUT) {
            bool ret = sgx_copy_to_enclave(sub_regions[i].enclave_addr, sub_regions[i].size,
                                           sub_regions[i].untrusted_addr, sub_regions[i].size);
            if (!ret)
                return -PAL_ERROR_DENIED;
        }
    }
    return 0;
}

/* may return `*out_toml_ioctl_struct = NULL` which means "no struct needed for this IOCTL" */
static int get_ioctl_struct(toml_table_t* manifest_sgx, toml_table_t* toml_ioctl_table,
                            toml_array_t** out_toml_ioctl_struct) {
    toml_raw_t toml_ioctl_struct_raw = toml_raw_in(toml_ioctl_table, "struct");
    if (!toml_ioctl_struct_raw) {
        /* no corresponding struct -> base-type or ignored IOCTL argument */
        *out_toml_ioctl_struct = NULL;
        return 0;
    }

    char* ioctl_struct_str = NULL;
    int ret = toml_rtos(toml_ioctl_struct_raw, &ioctl_struct_str);
    if (ret < 0)
        return -PAL_ERROR_INVAL;

    if (strcmp(ioctl_struct_str, "") == 0) {
        /* empty string instead of struct name -> base-type or ignored IOCTL argument */
        *out_toml_ioctl_struct = NULL;
        ret = 0;
        goto out;
    }

    toml_table_t* toml_ioctl_structs = toml_table_in(manifest_sgx, "ioctl_structs");
    if (!toml_ioctl_structs) {
        log_error("There are no IOCTL structs found in manifest");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    toml_array_t* toml_ioctl_struct = toml_array_in(toml_ioctl_structs, ioctl_struct_str);
    if (!toml_ioctl_struct || toml_array_nelem(toml_ioctl_struct) <= 0) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    *out_toml_ioctl_struct = toml_ioctl_struct;
    ret = 0;
out:
    free(ioctl_struct_str);
    return ret;
}

/* may return `*out_toml_ioctl_struct = NULL` which means "no struct needed for this IOCTL" */
static int get_allowed_ioctl_struct(uint32_t cmd, toml_array_t** out_toml_ioctl_struct) {
    int ret;

    /* find this IOCTL request in the manifest */
    toml_table_t* manifest_sgx = toml_table_in(g_pal_public_state.manifest_root, "sgx");
    if (!manifest_sgx)
        return -PAL_ERROR_NOTIMPLEMENTED;

    toml_array_t* toml_allowed_ioctls = toml_array_in(manifest_sgx, "allowed_ioctls");
    if (!toml_allowed_ioctls)
        return -PAL_ERROR_NOTIMPLEMENTED;

    ssize_t toml_allowed_ioctls_cnt = toml_array_nelem(toml_allowed_ioctls);
    if (toml_allowed_ioctls_cnt <= 0)
        return -PAL_ERROR_NOTIMPLEMENTED;

    for (size_t idx = 0; idx < (size_t)toml_allowed_ioctls_cnt; idx++) {
        toml_table_t* toml_ioctl_table = toml_table_at(toml_allowed_ioctls, idx);
        if (!toml_ioctl_table) {
            log_error("Invalid allowed IOCTL #%zu in manifest (not a TOML table)", idx + 1);
            return -PAL_ERROR_INVAL;
        }

        int64_t request_code;
        ret = toml_int_in(toml_ioctl_table, "request_code", /*default_val=*/-1, &request_code);
        if (ret < 0 || request_code < 0) {
            log_error("Invalid request code of allowed IOCTL #%zu in manifest", idx + 1);
            return -PAL_ERROR_INVAL;
        }

        if (request_code == (int64_t)cmd) {
            /* found this IOCTL request in the manifest, now must find the corresponding struct */
            ret = get_ioctl_struct(manifest_sgx, toml_ioctl_table, out_toml_ioctl_struct);
            if (ret < 0) {
                log_error("Invalid struct value of allowed IOCTL #%zu in manifest", idx + 1);
            }
            return ret;
        }
    }

    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalDeviceIoControl(PAL_HANDLE handle, uint32_t cmd, unsigned long arg, int* out_ret) {
    int ret;

    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    toml_array_t* toml_ioctl_struct = NULL;
    ret = get_allowed_ioctl_struct(cmd, &toml_ioctl_struct);
    if (ret < 0)
        return ret;

    if (!toml_ioctl_struct) {
        /* special case of "no struct needed for IOCTL" -> base-type or ignored IOCTL argument */
        *out_ret = ocall_ioctl(handle->dev.fd, cmd, arg);
        return 0;
    }

    void* untrusted_addr = NULL;
    size_t untrusted_size = 0;

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
    ret = collect_sub_regions(toml_ioctl_struct, (void*)arg, mem_regions, &mem_regions_cnt,
                              sub_regions, &sub_regions_cnt);
    if (ret < 0) {
        log_error("IOCTL: failed to parse ioctl struct (request code = 0x%x)", cmd);
        goto out;
    }

    for (size_t i = 0; i < sub_regions_cnt; i++) {
        /* overapproximation since alignment doesn't necessarily increase sub-region's size */
        untrusted_size += sub_regions[i].size + sub_regions[i].alignment - 1;
    }

    ret = ocall_mmap_untrusted(&untrusted_addr, ALLOC_ALIGN_UP(untrusted_size),
                               PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, /*fd=*/-1,
                               /*offset=*/0);
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        goto out;
    }

    assert(untrusted_addr);
    ret = copy_sub_regions_to_untrusted(sub_regions, sub_regions_cnt, untrusted_addr);
    if (ret < 0)
        goto out;

    int ioctl_ret = ocall_ioctl(handle->dev.fd, cmd, (unsigned long)untrusted_addr);

    ret = copy_sub_regions_to_enclave(sub_regions, sub_regions_cnt);
    if (ret < 0)
        goto out;

    *out_ret = ioctl_ret;
    ret = 0;
out:
    if (untrusted_addr)
        ocall_munmap_untrusted(untrusted_addr, ALLOC_ALIGN_UP(untrusted_size));
    free(mem_regions);
    free(sub_regions);
    return ret;
}
