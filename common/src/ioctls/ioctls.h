/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This feature implements the TOML syntax of the manifest entries used for deep-copying complex
 * nested objects out and inside the Gramine memory. This syntax is currently used for IOCTL
 * emulation and is generic enough to describe the most common memory layouts for deep copy of IOCTL
 * structs.
 *
 * We distinguish between Gramine memory and host memory. This distinction is only relevant for TEE
 * PALs. E.g. for Linux-SGX PAL, Gramine memory means in-SGX-enclave memory and host memory means
 * outside-SGX-enclave untrusted memory.
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
 * integers `x` and `y`. The two strings reside in separate memory regions in Gramine memory. Note
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
 *   sys.ioctl_structs.root = [
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
 *   sys.allowed_ioctls = [
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
 *     of Gramine memory to host memory, "in" to copy from host memory into Gramine memory, "inout"
 *     to copy in both directions, "none" to not copy at all (useful for e.g. padding).  Note that
 *     pointer sub-regions do not have a direction (their values are unconditionally rewired so as
 *     to point to the corresponding region in host memory).
 *  8. The first sub-region (and only the first!) may specify the alignment of the memory region.
 *  9. The total size of a sub-region is calculated as `size * unit + adjustment`. By default `unit`
 *     is 1 byte and `adjustment` is 0. Note that `adjustment` may be a negative number.
 * 10. Sub-regions may be conditioned using `onlyif = "simple boolean expression"`. The only
 *     currently supported format of expressions are: (`token1` and `token2` may be constant
 *     non-negative integers or sub-region names)
 *       - "token1 == token2"
 *       - "token1 != token2"
 *
 * The diagram below shows how this complex object is copied from Gramine memory (left side) to
 * host memory (right side). MR stands for "memory region", SR stands for "sub-region". Note how
 * Gramine-memory pointers are copied and rewired to point to host-memory regions.
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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "toml.h"

/* for simplicity, we limit the number of memory and sub-regions; these limits should be enough for
 * any reasonable IOCTL struct object */
#define MAX_MEM_REGIONS 1024
#define MAX_SUB_REGIONS (10 * 1024)

/* direction of copy: none (used for padding), out of Gramine memory, inside Gramine memory or both;
 * default is DIRECTION_NONE */
enum mem_copy_direction {
    DIRECTION_NONE,
    DIRECTION_OUT,
    DIRECTION_IN,
    DIRECTION_INOUT
};

struct mem_region {
    toml_array_t* toml_mem_region; /* describes contiguous sub-regions in this mem-region */
    void* gramine_addr;            /* base address of this memory region in Gramine memory */
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
    void* gramine_addr;             /* base address of this sub region in Gramine mem */
    void* host_addr;                /* base address of corresponding sub region in host mem */
    toml_array_t* toml_mem_region;  /* for pointers/arrays, specifies pointed-to mem region */
};

typedef bool (*memcpy_to_host_f)(void* host_ptr, const void* ptr, size_t size);
typedef bool (*memcpy_to_gramine_f)(void* ptr, size_t max_size, const void* host_ptr,
                                    size_t host_size);

int ioctls_get_allowed_ioctl_struct(toml_table_t* manifest_sys, uint32_t cmd,
                                    toml_array_t** out_toml_ioctl_struct);

int ioctls_collect_sub_regions(toml_table_t* manifest_sys, toml_array_t* root_toml_mem_region,
                               void* root_gramine_addr, struct mem_region* mem_regions,
                               size_t* mem_regions_cnt_ptr, struct sub_region* sub_regions,
                               size_t* sub_regions_cnt_ptr);
int ioctls_copy_sub_regions_to_host(struct sub_region* sub_regions, size_t sub_regions_cnt,
                                    void* host_addr, memcpy_to_host_f memcpy_to_host);
int ioctls_copy_sub_regions_to_gramine(struct sub_region* sub_regions, size_t sub_regions_cnt,
                                       memcpy_to_gramine_f memcpy_to_gramine);
