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
 * Code below describes the deep-copy syntax in the TOML manifest used for copying complex nested
 * objects out and inside the SGX enclave. This syntax is currently used for IOCTL emulation. This
 * syntax is generic enough to describe any memory layout for deep copy of IOCTL structs.
 *
 * The following example describes the main implementation details:
 *
 *   struct pascal_str { uint8_t len; char str[]; };
 *   struct c_str { char str[]; };
 *   struct root { struct pascal_str* s1; struct c_str* s2; uint64_t s2_len; int8_t x; int8_t y; };
 *
 *   alignas(128) struct root obj;
 *   ioctl(devfd, _IOWR(DEVICE_MAGIC, DEVICE_FUNC, struct root), &obj);
 *
 * The example IOCTL takes as a third argument a pointer to an object of type `struct root` that
 * contains two pointers to other objects (pascal-style string and a C-style string) and embeds two
 * integers `x` and `y`. The two strings reside in separate memory regions in enclave memory. Note
 * that the max possible length of the C-style string is stored in the `s2_len` field of the root
 * object. The `pascal_str` string is an input to the IOCTL, the `c_str` string and its length
 * `s2_len` are the outputs of the IOCTL, and the integers `x` and `y` are also outputs of the
 * IOCTL. Also note that the root object is 128B-aligned (for illustration purposes). This IOCTL
 * could for example be used to convert a Pascal string into a C string (C string will be truncated
 * to user-specified `s2_len` if greater than this limit), and find the indices of the first
 * occurences of chars "x" and "y" in the Pascal string.
 *
 * The corresponding deep-copy syntax in TOML looks like this:
 *
 *   sgx.ioctl_structs.ROOT_FOR_DEVICE_FUNC = [
 *     { align = 128, ptr = [ {name="pascal-str-len", size=1, direction="out"},
 *                            {name="pascal-str", size="pascal-str-len", direction="out"} ] },
 *     { ptr = [ {name="c-str", size="c-str-len", direction="in"} ], size = 1 },
 *     { name = "c-str-len", size = 8, unit = 1, adjust = 0, direction = "inout" },
 *     { size = 2, direction = "in" }
 *     { size = 2, direction = "in" }
 *   ]
 *
 *   sgx.allowed_ioctls.DEVICE_FUNC.request_code = <DEVICE_MAGIC hex>
 *   sgx.allowed_ioctls.DEVICE_FUNC.struct = "ROOT_FOR_DEVICE_FUNC"
 *
 * One can observe the following rules in this TOML syntax:
 *
 *  1. Each separate memory region is represented as a TOML array (`[]`).
 *  2. Each sub-region of one memory region is represented as a TOML table (`{}`).
 *  3. Each sub-region may be a pointer (`ptr`) to another memory region. In this case, the value of
 *     `ptr` is a TOML-array representation of that other memory region. The `ptr` sub-region always
 *     has size of 8B (assuming x86-64) and doesn't have an in/out direction.  The `size` field of
 *     the `ptr` sub-region has a different meaning than for non-pointer sub-regions: it is the
 *     number of adjacent memory regions that this pointer points to (i.e. it describes an array).
 *  4. Sub-regions can be fixed-size (like the last sub-region containing two bytes `x` and `y`) or
 *     can be flexible-size (like the two strings). In the latter case, the `size` field contains a
 *     name of a sub-region where the actual size is stored.
 *  5. Sub-regions that store the size of another sub-region must be 1, 2, 4, or 8 bytes in size.
 *  6. Sub-regions may have a name for ease of identification; this is required for "size"
 *     sub-regions but may be omitted for all other kinds of sub-regions.
 *  7. Sub-regions may have one of the four directions: "out" to copy contents of the sub-region
 *     outside the enclave to untrusted memory, "in" to copy from untrusted memory to inside the
 *     enclave, "inout" to copy in both directions, "none" to not copy at all (useful for e.g.
 *     padding). Note that pointer sub-regions do not have a direction (their values are
 *     unconditionally rewired so as to point to the copied-out region in untrusted memory).
 *  8. The first sub-region (and only the first!) may specify the alignment of the memory region.
 *  9. The total size of a sub-region is calculated as `size * unit + adjust`. By default `unit` is
 *     1 byte and `adjust` is 0. Note that `adjust` may be a negative number.
 *
 * The diagram below shows how this complex object is copied from enclave memory (left side) to
 * untrusted memory (right side). MR stands for "memory region", SR stands for "sub-region". Note
 * how enclave pointers are copied and rewired to point to untrusted memory regions.
 *
 *       struct root (MR1)              |         deep-copied struct (aligned at 128B)
 *      +------------------+            |       +------------------------+
 *  +----+ pascal_str* s1  |     SR1    |    +----+ pascal_str* s1  (MR1)|
 *  |   |                  |            |    |  |                        |
 *  |   |  c_str* s2 +-------+   SR2    |    |  |   c_str* s2 +-------------+
 *  |   |                  | |          |    |  |                        |  |
 *  |   |  uint64_t s2_len | |   SR3    |    |  |   uint64_t s2_len      |  |
 *  |   |                  | |          |    |  |                        |  |
 *  |   |  int8_t x, y     | |   SR4    |    |  |   int8_t x=0, y=0      |  |
 *  |   +------------------+ |          |    |  +------------------------+  |
 *  |                        |          |    +->|   uint8_t len     (MR2)|  |
 *  v (MR2)                  |          |       |                        |  |
 * +-------------+           |          |       |   char str[len]        |  |
 * | uint8_t len |           |   SR5    |       +------------------------+  |
 * |             |           |          |       |  char str[s2_len] (MR3)|<-+
 * | char str[]  |           |   SR6    |       +------------------------+
 * +-------------+           |          |
 *                  (MR3)    v          |
 *                +----------+-+        |
 *                | char str[] | SR7    |
 *                +------------+        |
 *
 */

/* for simplicity, we limit the number of memory and sub-regions; these limits should be enough for
 * any reasonable IOCTL struct object */
#define MAX_MEM_REGIONS 1024
#define MAX_SUB_REGIONS (10 * 1024)

/* direction of copy: none (used for padding), out of enclave, inside enclave, both or a special
 * "pointer" sub-region; default is COPY_NONE_ENCLAVE */
enum mem_copy_direction {COPY_NONE_ENCLAVE, COPY_OUT_ENCLAVE, COPY_IN_ENCLAVE, COPY_INOUT_ENCLAVE,
                         COPY_PTR_ENCLAVE};

struct mem_region {
    toml_array_t* toml_array; /* describes contigious sub_regions in this mem_region */
    void* encl_addr;          /* base address of this memory region in enclave memory */
    bool adjacent;            /* memory region adjacent to previous one? (used for arrays) */
};

struct sub_region {
    enum mem_copy_direction direction; /* direction of copy during OCALL */
    char* name;               /* may be NULL for unnamed regions */
    uint64_t name_hash;       /* hash of "name" for fast string comparison */
    ssize_t align;            /* alignment of this sub-region */
    ssize_t size;             /* may be dynamically determined from another sub-region */
    char* size_name;          /* needed if "size" sub region is defined after this sub region */
    uint64_t size_name_hash;  /* needed if "size" sub region is defined after this sub region */
    ssize_t unit;             /* total size in bytes is calculated as `size * unit + adjust` */
    ssize_t adjust;           /* may be negative; total size in bytes is `size * unit + adjust` */
    void* encl_addr;          /* base address of this sub region in enclave memory */
    void* untrusted_addr;     /* base address of the corresponding sub region in untrusted memory */
    toml_array_t* mem_ptr;    /* for pointers/arrays, specifies pointed-to mem region */
};

static inline uint64_t hash(char* str) {
    /* simple hash function djb2 by Dan Bernstein, used for quick comparison of strings */
    uint64_t hash = 5381;
    char c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static bool strings_equal(const char* s1, const char* s2, uint64_t s1_hash, uint64_t s2_hash) {
    if (!s1 || !s2 || s1_hash != s2_hash)
        return false;
    assert(s1_hash == s2_hash);
    return !strcmp(s1, s2);
}

/* finds a sub region with name `sub_region_name` among `sub_regions` and returns its index */
static int get_sub_region_idx(struct sub_region* sub_regions, size_t sub_regions_cnt,
                              const char* sub_region_name, uint64_t sub_region_name_hash,
                              size_t* out_idx) {
    /* it is important to iterate in reverse order because there may be an array of mem regions
     * with same-named sub regions, and we want to find the latest sub region */
    for (size_t i = sub_regions_cnt; i > 0; i--) {
        size_t idx = i - 1;
        if (strings_equal(sub_regions[idx].name, sub_region_name,
                          sub_regions[idx].name_hash, sub_region_name_hash)) {
            /* found corresponding sub region */
            if (sub_regions[idx].direction != COPY_PTR_ENCLAVE || !sub_regions[idx].mem_ptr) {
                /* sub region is not a valid pointer to a memory region */
                return -PAL_ERROR_DENIED;
            }
            *out_idx = idx;
            return 0;
        }
    }
    return -PAL_ERROR_NOTDEFINED;
}

/* finds a sub region with name `sub_region_name` among `sub_regions` and reads the value in it */
static int get_sub_region_value(struct sub_region* sub_regions, size_t sub_regions_cnt,
                                const char* sub_region_name, uint64_t sub_region_name_hash,
                                ssize_t* out_value) {
    /* it is important to iterate in reverse order because there may be an array of memory regions
     * with same-named sub regions, and we want to find the "latest value" sub region, i.e. the one
     * belonging to the same memory region */
    for (size_t i = sub_regions_cnt; i > 0; i--) {
        size_t idx = i - 1;
        if (strings_equal(sub_regions[idx].name, sub_region_name,
                          sub_regions[idx].name_hash, sub_region_name_hash)) {
            /* found corresponding sub region, read its value */
            if (!sub_regions[idx].encl_addr || sub_regions[idx].encl_addr == (void*)-1) {
                /* enclave address is invalid, user provided bad struct */
                return -PAL_ERROR_DENIED;
            }

            if (sub_regions[idx].size == sizeof(uint8_t)) {
                *out_value = (ssize_t)(*((uint8_t*)sub_regions[idx].encl_addr));
            } else if (sub_regions[idx].size == sizeof(uint16_t)) {
                *out_value = (ssize_t)(*((uint16_t*)sub_regions[idx].encl_addr));
            } else if (sub_regions[idx].size == sizeof(uint32_t)) {
                *out_value = (ssize_t)(*((uint32_t*)sub_regions[idx].encl_addr));
            } else if (sub_regions[idx].size == sizeof(uint64_t)) {
                *out_value = (ssize_t)(*((uint64_t*)sub_regions[idx].encl_addr));
            } else {
                log_error("Invalid deep-copy syntax (deep-copy sub-entry '%s' must be of "
                          "legitimate size: 1, 2, 4 or 8 bytes)", sub_regions[idx].name);
                return -PAL_ERROR_INVAL;
            }

            return 0;
        }
    }

    return -PAL_ERROR_NOTDEFINED;
}

/* caller sets `sub_regions_cnt_ptr` to maximum number of sub_regions; this variable is updated to
 * return the number of actually used sub_regions */
static int collect_sub_regions(toml_array_t* root_toml_array, void* root_encl_addr,
                               struct sub_region* sub_regions, size_t* sub_regions_cnt_ptr) {
    int ret;

    assert(root_toml_array && toml_array_nelem(root_toml_array) > 0);
    assert(sub_regions && sub_regions_cnt_ptr);

    size_t max_sub_regions = *sub_regions_cnt_ptr;
    size_t sub_regions_cnt = 0;

    assert(pal_get_enclave_tcb()->ioctl_scratch_space);
    struct mem_region* mem_regions = (struct mem_region*)pal_get_enclave_tcb()->ioctl_scratch_space;
    mem_regions[0].toml_array = root_toml_array;
    mem_regions[0].encl_addr  = root_encl_addr;
    mem_regions[0].adjacent   = false;
    size_t mem_regions_cnt = 1;

    /* collecting memory regions and their sub-regions must use breadth-first search to dynamically
     * calculate sizes of sub-regions even if they are specified via another sub-region's "name" */
    char* cur_encl_addr = NULL;
    size_t mem_region_idx = 0;
    while (mem_region_idx < mem_regions_cnt) {
        struct mem_region* cur_mem_region = &mem_regions[mem_region_idx];
        mem_region_idx++;

        if (!cur_mem_region->adjacent)
            cur_encl_addr = cur_mem_region->encl_addr;

        size_t cur_mem_region_first_sub_region = sub_regions_cnt;

        for (size_t i = 0; i < (size_t)toml_array_nelem(cur_mem_region->toml_array); i++) {
            toml_table_t* sub_region_info = toml_table_at(cur_mem_region->toml_array, i);
            if (!sub_region_info) {
                log_error("Invalid deep-copy syntax (each memory subregion must be a TOML "
                          "table)");
                ret = -PAL_ERROR_INVAL;
                goto out;
            }

            if (sub_regions_cnt == max_sub_regions) {
                log_error("Too many memory sub-regions in a deep-copy syntax (maximum "
                          "possible is %lu)", max_sub_regions);
                ret = -PAL_ERROR_NOMEM;
                goto out;
            }

            struct sub_region* cur_sub_region = &sub_regions[sub_regions_cnt];
            sub_regions_cnt++;

            cur_sub_region->untrusted_addr = NULL;
            cur_sub_region->mem_ptr = NULL;

            cur_sub_region->encl_addr = cur_encl_addr;
            if (!cur_encl_addr || cur_encl_addr == (void*)-1) {
                /* enclave address is invalid, user provided bad struct */
                ret = -PAL_ERROR_DENIED;
                goto out;
            }

            toml_raw_t sub_region_name_raw      = toml_raw_in(sub_region_info, "name");
            toml_raw_t sub_region_direction_raw = toml_raw_in(sub_region_info, "direction");
            toml_raw_t sub_region_align_raw     = toml_raw_in(sub_region_info, "align");
            toml_raw_t sub_region_size_raw      = toml_raw_in(sub_region_info, "size");
            toml_raw_t sub_region_unit_raw      = toml_raw_in(sub_region_info, "unit");
            toml_raw_t sub_region_adjust_raw    = toml_raw_in(sub_region_info, "adjust");

            toml_array_t* sub_region_ptr_arr = toml_array_in(sub_region_info, "ptr");
            if (!sub_region_ptr_arr) {
                /* "ptr" to another sub-region doesn't use TOML's inline array syntax, maybe it is a
                 * reference to already-defined sub-region (e.g., `ptr = "my-struct"`) */
                toml_raw_t sub_region_ptr_raw = toml_raw_in(sub_region_info, "ptr");
                if (sub_region_ptr_raw) {
                    char* sub_region_name = NULL;
                    ret = toml_rtos(sub_region_ptr_raw, &sub_region_name);
                    if (ret < 0) {
                        log_error("Invalid deep-copy syntax ('ptr' of a deep-copy sub-entry "
                                  "must be a TOML array or a string surrounded by double quotes)");
                        ret = -PAL_ERROR_INVAL;
                        goto out;
                    }

                    if (!strcmp(sub_region_name, "this")) {
                        /* special case of `{ptr="this"}` -- ptr to object of the IOCTL root type */
                        sub_region_ptr_arr = root_toml_array;
                    } else {
                        size_t idx;
                        ret = get_sub_region_idx(sub_regions, sub_regions_cnt, sub_region_name,
                                hash(sub_region_name), &idx);
                        if (ret < 0) {
                            log_error("Invalid deep-copy syntax (cannot find sub region '%s')",
                                    sub_region_name);
                            free(sub_region_name);
                            goto out;
                        }

                        assert(idx < sub_regions_cnt);
                        assert(sub_regions[idx].direction == COPY_PTR_ENCLAVE);
                        assert(sub_regions[idx].mem_ptr);
                        sub_region_ptr_arr = sub_regions[idx].mem_ptr;
                    }

                    free(sub_region_name);
                }
            }

            if (sub_region_align_raw && i != 0) {
                log_error("Invalid deep-copy syntax ('align' may be specified only for the "
                          "first sub-region of the memory region)");
                ret = -PAL_ERROR_INVAL;
                goto out;
            }

            if (sub_region_direction_raw && sub_region_ptr_arr) {
                log_error("Invalid deep-copy syntax ('ptr' sub-entries cannot specify "
                          "a 'direction'; pointers are never copied directly but rewired)");
                ret = -PAL_ERROR_INVAL;
                goto out;
            }

            cur_sub_region->name = NULL;
            cur_sub_region->name_hash = 0;
            if (sub_region_name_raw) {
                ret = toml_rtos(sub_region_name_raw, &cur_sub_region->name);
                if (ret < 0) {
                    log_error("Invalid deep-copy syntax ('name' of a deep-copy sub-entry "
                              "must be a TOML string surrounded by double quotes)");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }
                cur_sub_region->name_hash = hash(cur_sub_region->name);
            }

            cur_sub_region->direction = COPY_NONE_ENCLAVE;
            if (sub_region_direction_raw) {
                char* direction_str = NULL;
                ret = toml_rtos(sub_region_direction_raw, &direction_str);
                if (ret < 0) {
                    log_error("Invalid deep-copy syntax ('direction' of a deep-copy sub-entry "
                              "must be a TOML string surrounded by double quotes)");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }

                if (!strcmp(direction_str, "out")) {
                    cur_sub_region->direction = COPY_OUT_ENCLAVE;
                } else if (!strcmp(direction_str, "in")) {
                    cur_sub_region->direction = COPY_IN_ENCLAVE;
                } else if (!strcmp(direction_str, "inout")) {
                    cur_sub_region->direction = COPY_INOUT_ENCLAVE;
                } else if (!strcmp(direction_str, "none")) {
                    cur_sub_region->direction = COPY_NONE_ENCLAVE;
                } else {
                    log_error("Invalid deep-copy syntax ('direction' of a deep-copy sub-entry "
                              "must be one of \"out\", \"in\", \"inout\" or \"none\")");
                    free(direction_str);
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }

                free(direction_str);
            }

            cur_sub_region->align = 0;
            if (sub_region_align_raw) {
                ret = toml_rtoi(sub_region_align_raw, &cur_sub_region->align);
                if (ret < 0 || cur_sub_region->align <= 0) {
                    log_error("Invalid deep-copy syntax ('align' of a deep-copy sub-entry "
                              "must be a positive number)");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }
            }

            if (sub_region_ptr_arr) {
                /* only set direction for now, we postpone pointer/array handling for later */
                cur_sub_region->direction = COPY_PTR_ENCLAVE;
                cur_sub_region->mem_ptr   = sub_region_ptr_arr;
            }

            cur_sub_region->size = -1;
            cur_sub_region->size_name = NULL;
            cur_sub_region->size_name_hash = 0;
            if (sub_region_size_raw) {
                ret = toml_rtos(sub_region_size_raw, &cur_sub_region->size_name);
                if (ret == 0) {
                    cur_sub_region->size_name_hash = hash(cur_sub_region->size_name);

                    ssize_t val = -1;
                    /* "sub_regions_cnt - 1" is to exclude myself; do not fail if couldn't find
                     * (we will try later one more time) */
                    ret = get_sub_region_value(sub_regions, sub_regions_cnt - 1,
                                               cur_sub_region->size_name,
                                               cur_sub_region->size_name_hash, &val);
                    if (ret < 0 && ret != -PAL_ERROR_NOTDEFINED) {
                        goto out;
                    }
                    cur_sub_region->size = val;
                } else {
                    /* size is specified not as string (another sub-region's name), then must be
                     * specified explicitly as number of bytes */
                    ret = toml_rtoi(sub_region_size_raw, &cur_sub_region->size);
                    if (ret < 0 || cur_sub_region->size <= 0) {
                        log_error("Invalid deep-copy syntax ('size' of a deep-copy "
                                  "sub-entry must be a TOML string or a positive number)");
                        ret = -PAL_ERROR_INVAL;
                        goto out;
                    }
                }
            }

            cur_sub_region->unit = 1; /* 1 byte by default */
            if (sub_region_unit_raw) {
                ret = toml_rtoi(sub_region_unit_raw, &cur_sub_region->unit);
                if (ret < 0 || cur_sub_region->unit <= 0) {
                    log_error("Invalid deep-copy syntax ('unit' of a deep-copy sub-entry "
                              "must be a positive number)");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }
            }

            cur_sub_region->adjust = 0;
            if (sub_region_adjust_raw) {
                ret = toml_rtoi(sub_region_adjust_raw, &cur_sub_region->adjust);
                if (ret < 0) {
                    log_error("Invalid deep-copy syntax ('adjust' of a deep-copy sub-entry "
                              "is not a valid number)");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }
            }

            if (cur_sub_region->size >= 0) {
                cur_sub_region->size *= cur_sub_region->unit;
                cur_sub_region->size += cur_sub_region->adjust;
            }

            if (cur_sub_region->direction == COPY_PTR_ENCLAVE) {
                cur_encl_addr += sizeof(void*);
            } else {
                assert(cur_sub_region->size >= 0);
                cur_encl_addr += (uintptr_t)cur_sub_region->size;
            }
        }

        /* iterate through collected pointer/array sub regions and add corresponding mem regions */
        for (size_t i = cur_mem_region_first_sub_region; i < sub_regions_cnt; i++) {
            if (sub_regions[i].direction != COPY_PTR_ENCLAVE)
                continue;

            if (sub_regions[i].size >= 0) {
                /* sizes was found in the first swoop, nothing to do here */
            } else if (sub_regions[i].size < 0 && sub_regions[i].size_name) {
                /* pointer/array size was not found in the first swoop, try again */
                ssize_t val = -1;
                ret = get_sub_region_value(sub_regions, sub_regions_cnt, sub_regions[i].size_name,
                                           sub_regions[i].size_name_hash, &val);
                if (ret < 0) {
                    log_error("Invalid deep-copy syntax (cannot find sub region '%s')",
                              sub_regions[i].size_name);
                    goto out;
                }
                if (val < 0) {
                    log_error("Invalid deep-copy syntax (sub region '%s' has negative size)",
                              sub_regions[i].size_name);
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }
                sub_regions[i].size = val;
            } else {
                /* size is not specified at all for this sub region, assume it is 1 item */
                sub_regions[i].size = 1;
            }

            for (size_t k = 0; k < (size_t)sub_regions[i].size; k++) {
                if (mem_regions_cnt == MAX_MEM_REGIONS) {
                    log_error("Too many memory regions in a deep-copy syntax (maximum "
                              "possible is %d)", MAX_MEM_REGIONS);
                    ret = -PAL_ERROR_NOMEM;
                    goto out;
                }

                void* mem_region_addr = *((void**)sub_regions[i].encl_addr);
                if (!mem_region_addr)
                    continue;

                mem_regions[mem_regions_cnt].toml_array = sub_regions[i].mem_ptr;
                mem_regions[mem_regions_cnt].encl_addr  = mem_region_addr;
                mem_regions[mem_regions_cnt].adjacent   = k > 0;
                mem_regions_cnt++;
            }

            sub_regions[i].size = sizeof(void*); /* rewire to actual size of "ptr" sub-region */
        }
    }

    *sub_regions_cnt_ptr = sub_regions_cnt;
    ret = 0;
out:
    for (size_t i = 0; i < sub_regions_cnt; i++) {
        /* "name" fields are not needed after we collected all sub_regions */
        free(sub_regions[i].name);
        free(sub_regions[i].size_name);
        sub_regions[i].name = NULL;
        sub_regions[i].size_name = NULL;
    }
    return ret;
}

static void copy_sub_regions_to_untrusted(struct sub_region* sub_regions, size_t sub_regions_cnt,
                                          void* untrusted_addr) {
    char* cur_untrusted_addr = untrusted_addr;
    for (size_t i = 0; i < sub_regions_cnt; i++) {
        if (sub_regions[i].size <= 0 || !sub_regions[i].encl_addr)
            continue;

        if (sub_regions[i].align > 0) {
            char* aligned_untrusted_addr = ALIGN_UP_PTR(cur_untrusted_addr, sub_regions[i].align);
            memset(cur_untrusted_addr, 0, aligned_untrusted_addr - cur_untrusted_addr);
            cur_untrusted_addr = aligned_untrusted_addr;
        }

        if (sub_regions[i].direction == COPY_OUT_ENCLAVE ||
                sub_regions[i].direction == COPY_INOUT_ENCLAVE) {
            memcpy(cur_untrusted_addr, sub_regions[i].encl_addr, sub_regions[i].size);
        } else {
            memset(cur_untrusted_addr, 0, sub_regions[i].size);
        }

        sub_regions[i].untrusted_addr = cur_untrusted_addr;
        cur_untrusted_addr += sub_regions[i].size;
    }

    for (size_t i = 0; i < sub_regions_cnt; i++) {
        if (sub_regions[i].size <= 0 || !sub_regions[i].encl_addr)
            continue;

        if (sub_regions[i].direction == COPY_PTR_ENCLAVE) {
            void* encl_ptr_value = *((void**)sub_regions[i].encl_addr);
            /* rewire pointer value in untrusted memory to a corresponding untrusted sub-region */
            for (size_t j = 0; j < sub_regions_cnt; j++) {
                if (sub_regions[j].encl_addr == encl_ptr_value) {
                    *((void**)sub_regions[i].untrusted_addr) = sub_regions[j].untrusted_addr;
                    break;
                }
            }
        }
    }
}

static void copy_sub_regions_to_enclave(struct sub_region* sub_regions, size_t sub_regions_cnt) {
    for (size_t i = 0; i < sub_regions_cnt; i++) {
        if (sub_regions[i].size <= 0 || !sub_regions[i].encl_addr)
            continue;

        if (sub_regions[i].direction == COPY_IN_ENCLAVE ||
                sub_regions[i].direction == COPY_INOUT_ENCLAVE)
            memcpy(sub_regions[i].encl_addr, sub_regions[i].untrusted_addr, sub_regions[i].size);
    }
}

/* may return `*out_toml_ioctl_struct = NULL` which means "no struct needed for this IOCTL" */
static int get_ioctl_struct(uint32_t cmd, toml_array_t** out_toml_ioctl_struct) {
    int ret;

    /* find this IOCTL request in the manifest */
    toml_table_t* manifest_sgx = toml_table_in(g_pal_public_state.manifest_root, "sgx");
    if (!manifest_sgx)
        return -PAL_ERROR_NOTIMPLEMENTED;

    toml_table_t* toml_allowed_ioctls = toml_table_in(manifest_sgx, "allowed_ioctls");
    if (!toml_allowed_ioctls)
        return -PAL_ERROR_NOTIMPLEMENTED;

    ssize_t toml_allowed_ioctls_cnt = toml_table_ntab(toml_allowed_ioctls);
    if (toml_allowed_ioctls_cnt <= 0)
        return -PAL_ERROR_NOTIMPLEMENTED;

    for (ssize_t idx = 0; idx < toml_allowed_ioctls_cnt; idx++) {
        const char* toml_allowed_ioctl_key = toml_key_in(toml_allowed_ioctls, idx);
        assert(toml_allowed_ioctl_key);

        toml_table_t* toml_ioctl_table = toml_table_in(toml_allowed_ioctls, toml_allowed_ioctl_key);
        if (!toml_ioctl_table)
            continue;

        toml_raw_t toml_ioctl_request_code_raw = toml_raw_in(toml_ioctl_table, "request_code");
        if (!toml_ioctl_request_code_raw)
            continue;

        int64_t ioctl_request_code = 0x0;
        ret = toml_rtoi(toml_ioctl_request_code_raw, &ioctl_request_code);
        if (ret < 0 || ioctl_request_code == 0x0) {
            log_error("Invalid request code of allowed IOCTL '%s' in manifest",
                      toml_allowed_ioctl_key);
            continue;
        }

        if (ioctl_request_code == (int64_t)cmd) {
            /* found this IOCTL request in the manifest, now must find the corresponding struct */
            toml_raw_t toml_ioctl_struct_raw = toml_raw_in(toml_ioctl_table, "struct");
            if (!toml_ioctl_struct_raw) {
                /* no corresponding struct -> base-type or ignored IOCTL argument */
                *out_toml_ioctl_struct = NULL;
                return 0;
            }

            char* ioctl_struct_str = NULL;
            ret = toml_rtos(toml_ioctl_struct_raw, &ioctl_struct_str);
            if (ret < 0) {
                log_error("Invalid struct value of allowed IOCTL '%s' in manifest "
                          "(sgx.allowed_ioctls.[identifier].struct must be a TOML string)",
                          toml_allowed_ioctl_key);
                return -PAL_ERROR_INVAL;
            }

            if (strcmp(ioctl_struct_str, "") == 0) {
                /* empty string instead of struct name -> base-type or ignored IOCTL argument */
                *out_toml_ioctl_struct = NULL;
                free(ioctl_struct_str);
                return 0;
            }

            toml_table_t* toml_ioctl_structs = toml_table_in(manifest_sgx, "ioctl_structs");
            if (!toml_ioctl_structs) {
                log_error("There are no IOCTL structs found in manifest");
                free(ioctl_struct_str);
                return -PAL_ERROR_INVAL;
            }

            toml_array_t* toml_ioctl_struct = toml_array_in(toml_ioctl_structs, ioctl_struct_str);
            if (!toml_ioctl_struct) {
                log_error("Cannot find struct value '%s' of allowed IOCTL '%s' in "
                          "manifest (or it is not a correctly formatted TOML array)",
                          ioctl_struct_str, toml_allowed_ioctl_key);
                free(ioctl_struct_str);
                return -PAL_ERROR_INVAL;
            }
            free(ioctl_struct_str);

            *out_toml_ioctl_struct = toml_ioctl_struct;
            return 0;
        }
    }

    return -PAL_ERROR_NOTIMPLEMENTED;
}

/*
 * Thread-local scratch space for IOCTL internal data:
 *   1. Memregions array of size MAX_MEM_REGIONS +
 *   2. Subregions array of size MAX_SUB_REGIONS
 *
 * Note that this scratch space is allocated once per thread and never freed. Also, we assume that
 * IOCTLs during signal handling are impossible, so there is no need to protect via atomic variable
 * like `ocall_mmap_untrusted_cache: in_use`.
 */
static int init_ioctl_scratch_space(void) {
    if (pal_get_enclave_tcb()->ioctl_scratch_space)
        return 0;

    size_t total_size = MAX_MEM_REGIONS * sizeof(struct mem_region) +
                            MAX_SUB_REGIONS * sizeof(struct sub_region);
    void* scratch_space = calloc(1, total_size);
    if (!scratch_space)
        return -PAL_ERROR_NOMEM;

    pal_get_enclave_tcb()->ioctl_scratch_space = scratch_space;
    return 0;
}

int _PalDeviceIoControl(PAL_HANDLE handle, uint32_t cmd, unsigned long arg, int* out_ret) {
    int ret;

    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    ret = init_ioctl_scratch_space();
    if (ret < 0)
        return ret;

    toml_array_t* toml_ioctl_struct = NULL;
    ret = get_ioctl_struct(cmd, &toml_ioctl_struct);
    if (ret < 0)
        return ret;

    if (!toml_ioctl_struct || toml_array_nelem(toml_ioctl_struct) == 0) {
        /* special case of "no struct needed for IOCTL" -> base-type or ignored IOCTL argument */
        ret = ocall_ioctl(handle->dev.fd, cmd, arg);
        if (ret < 0)
            return unix_to_pal_error(ret);

        *out_ret = ret;
        return 0;
    }

    size_t sub_regions_cnt = MAX_SUB_REGIONS;
    struct sub_region* sub_regions = (struct sub_region*)pal_get_enclave_tcb()->ioctl_scratch_space +
                                     MAX_MEM_REGIONS * sizeof(struct mem_region);

    /* typical IOCTL case: deep-copy the IOCTL argument's input data outside of enclave, execute the
     * IOCTL OCALL, and deep-copy the IOCTL argument's output data back into enclave */
    ret = collect_sub_regions(toml_ioctl_struct, (void*)arg, sub_regions, &sub_regions_cnt);
    if (ret < 0)
        return ret;

    void* untrusted_addr  = NULL;
    size_t untrusted_size = 0;
    for (size_t i = 0; i < sub_regions_cnt; i++)
        untrusted_size += sub_regions[i].size + sub_regions[i].align;

    ret = ocall_mmap_untrusted(&untrusted_addr, ALLOC_ALIGN_UP(untrusted_size),
                               PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, /*fd=*/-1,
                               /*offset=*/0);
    if (ret < 0)
        return unix_to_pal_error(ret);

    assert(untrusted_addr);
    copy_sub_regions_to_untrusted(sub_regions, sub_regions_cnt, untrusted_addr);

    ret = ocall_ioctl(handle->dev.fd, cmd, (unsigned long)untrusted_addr);
    if (ret < 0) {
        ocall_munmap_untrusted(untrusted_addr, ALLOC_ALIGN_UP(untrusted_size));
        return unix_to_pal_error(ret);
    }

    copy_sub_regions_to_enclave(sub_regions, sub_regions_cnt);

    ocall_munmap_untrusted(untrusted_addr, ALLOC_ALIGN_UP(untrusted_size));

    *out_ret = ret;
    return 0;
}
