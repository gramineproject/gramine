/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include "api.h"
#include "ioctls.h"
#include "toml.h"
#include "toml_utils.h"

static bool strings_equal(const char* s1, const char* s2) {
    if (!s1 || !s2)
        return false;
    return !strcmp(s1, s2);
}

static int copy_value_to_uint64(void* addr, size_t size, uint64_t* out_value) {
    if (!addr || size > sizeof(*out_value))
        return -PAL_ERROR_INVAL;

#ifdef __x86_64__
    /* the copy below assumes little-endian machines (which x86 is) */
    *out_value = 0;
    memcpy(out_value, addr, size);
    return 0;
#else
#error "Unsupported architecture"
#endif /* __x86_64__ */
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

static int get_toml_nested_mem_region(toml_table_t* toml_ioctl_structs,
                                      toml_table_t* toml_sub_region,
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

    void*  addr_of_size_field = all_sub_regions[found_idx].gramine_addr;
    size_t size_of_size_field = all_sub_regions[found_idx].size;
    uint64_t read_size;

    ret = copy_value_to_uint64(addr_of_size_field, size_of_size_field, &read_size);
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

static int get_sub_region_uint_value(struct sub_region* all_sub_regions, size_t all_sub_regions_cnt,
                                     const char* sub_region_name, uint64_t* out_value) {
    size_t found_idx;
    int ret = get_sub_region_idx(all_sub_regions, all_sub_regions_cnt, sub_region_name, &found_idx);
    if (ret < 0)
        return ret;

    void*  addr_of_value_field = all_sub_regions[found_idx].gramine_addr;
    size_t size_of_value_field = all_sub_regions[found_idx].size;
    uint64_t read_value;

    ret = copy_value_to_uint64(addr_of_value_field, size_of_value_field, &read_value);
    if (ret < 0)
        return ret;

    *out_value = read_value;
    return 0;
}

static int get_sub_region_onlyif(struct sub_region* all_sub_regions, size_t all_sub_regions_cnt,
                                 const toml_table_t* toml_sub_region, bool* out_value) {
    char* expr;
    int ret = toml_string_in(toml_sub_region, "onlyif", &expr);
    if (ret < 0)
        return -PAL_ERROR_INVAL;

    if (!expr) {
        *out_value = true; /* no `onlyif` field, must use this sub-region */
        return 0;
    }

    uint64_t value1;
    uint64_t value2;

    char* cur = expr;
    while (*cur == ' ' || *cur == '\t')
        cur++;

    /* read first token */
    char* token1 = cur;
    while (isalnum(*cur) || *cur == '_' || *cur == '-')
        cur++;
    size_t token1_len = cur - token1;
    while (*cur == ' ' || *cur == '\t')
        cur++;

    /* read comparator */
    char* compar = cur;
    while (*cur == '=' || *cur == '!')
        cur++;
    size_t compar_len = cur - compar;
    while (*cur == ' ' || *cur == '\t')
        cur++;

    /* read second token */
    char* token2 = cur;
    while (isalnum(*cur) || *cur == '_' || *cur == '-')
        cur++;
    size_t token2_len = cur - token2;
    while (*cur == ' ' || *cur == '\t')
        cur++;

    /* make sure the whole string is in allowed format "token1 {== | !=} token2" */
    if (compar_len != 2 || (memcmp(compar, "==", 2) && memcmp(compar, "!=", 2))) {
        log_error("IOCTL: only-if expression '%s' doesn't have '==' or '!=' comparator", expr);
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (*cur != '\0' || !token1_len || !token2_len) {
        log_error("IOCTL: cannot parse only-if expression '%s'", expr);
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    /* get actual values for two tokens */
    char* endptr = NULL;
    char original_symbol = token1[token1_len];
    token1[token1_len] = '\0';
    long long v1 = strtoll(token1, &endptr, /*base=*/0);
    if (endptr == token1 + token1_len) {
        /* constant integer, check it is a legit unsigned int */
        if (v1 < 0) {
            log_error("IOCTL: first value in only-if expression '%s' is negative", expr);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }
        value1 = (uint64_t)v1;
    } else {
        /* could not read the constant integer, the token must be a string-name of a sub region */
        ret = get_sub_region_uint_value(all_sub_regions, all_sub_regions_cnt, token1, &value1);
        if (ret < 0) {
            log_error("IOCTL: cannot find first sub region in only-if expression '%s'", expr);
            goto out;
        }
    }
    token1[token1_len] = original_symbol;

    original_symbol = token2[token2_len];
    token2[token2_len] = '\0';
    long long v2 = strtoll(token2, &endptr, /*base=*/0);
    if (endptr == token2 + token2_len) {
        if (v2 < 0) {
            log_error("IOCTL: second value in only-if expression '%s' is negative", expr);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }
        value2 = (uint64_t)v2;
    } else {
        ret = get_sub_region_uint_value(all_sub_regions, all_sub_regions_cnt, token2, &value2);
        if (ret < 0) {
            log_error("IOCTL: cannot find second sub region in only-if expression '%s'", expr);
            goto out;
        }
    }
    token2[token2_len] = original_symbol;

    if (!memcmp(compar, "==", 2)) {
        *out_value = value1 == value2;
    } else if (!memcmp(compar, "!=", 2)) {
        *out_value = value1 != value2;
    } else {
        BUG();
    }


    ret = 0;
out:
    free(expr);
    return ret;
}

/* Caller sets `mem_regions_cnt_ptr` to the length of `mem_regions` array; this variable is updated
 * to return the number of actually used `mem_regions`. Similarly with `sub_regions`. */
int ioctls_collect_sub_regions(toml_table_t* manifest_sys, toml_array_t* root_toml_mem_region,
                               void* root_gramine_addr, struct mem_region* mem_regions,
                               size_t* mem_regions_cnt_ptr, struct sub_region* sub_regions,
                               size_t* sub_regions_cnt_ptr) {
    int ret;

    assert(root_toml_mem_region && toml_array_nelem(root_toml_mem_region) > 0);

    toml_table_t* toml_ioctl_structs = toml_table_in(manifest_sys, "ioctl_structs");
    if (!toml_ioctl_structs)
        return -PAL_ERROR_DENIED;

    size_t max_sub_regions = *sub_regions_cnt_ptr;
    size_t sub_regions_cnt = 0;

    size_t max_mem_regions = *mem_regions_cnt_ptr;
    size_t mem_regions_cnt = 0;

    if (!max_sub_regions || !max_mem_regions)
        return -PAL_ERROR_NOMEM;

    mem_regions[0].toml_mem_region = root_toml_mem_region;
    mem_regions[0].gramine_addr    = root_gramine_addr;
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
    char* cur_gramine_addr = NULL;
    size_t mem_region_idx = 0;
    while (mem_region_idx < mem_regions_cnt) {
        struct mem_region* cur_mem_region = &mem_regions[mem_region_idx];
        mem_region_idx++;

        if (!cur_mem_region->adjacent)
            cur_gramine_addr = cur_mem_region->gramine_addr;

        size_t cur_mem_region_first_sub_region_idx = sub_regions_cnt;

        assert(toml_array_nelem(cur_mem_region->toml_mem_region) >= 0);
        for (size_t i = 0; i < (size_t)toml_array_nelem(cur_mem_region->toml_mem_region); i++) {
            toml_table_t* toml_sub_region = toml_table_at(cur_mem_region->toml_mem_region, i);
            if (!toml_sub_region) {
                log_error("IOCTL: each memory sub-region must be a TOML table");
                ret = -PAL_ERROR_INVAL;
                goto out;
            }

            bool onlyif_value;
            ret = get_sub_region_onlyif(sub_regions, sub_regions_cnt, toml_sub_region,
                                        &onlyif_value);
            if (ret < 0) {
                log_error("IOCTL: parsing of 'onlyif' field failed");
                goto out;
            }
            if (!onlyif_value) {
                /* onlyif expression is false, we must skip this sub region completely */
                continue;
            }

            if (sub_regions_cnt == max_sub_regions) {
                log_error("IOCTL: too many memory sub-regions (max is %zu)", max_sub_regions);
                ret = -PAL_ERROR_NOMEM;
                goto out;
            }

            struct sub_region* cur_sub_region = &sub_regions[sub_regions_cnt];
            sub_regions_cnt++;

            memset(cur_sub_region, 0, sizeof(*cur_sub_region));

            cur_sub_region->gramine_addr = cur_gramine_addr;
            if (!cur_gramine_addr) {
                /* FIXME: use `is_user_memory_readable()` to check invalid addresses */
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

            ret = get_toml_nested_mem_region(toml_ioctl_structs, toml_sub_region,
                                             &cur_sub_region->toml_mem_region);
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

            if (!access_ok(cur_gramine_addr, cur_sub_region->size)) {
                log_error("IOCTL: address overflows");
                ret = -PAL_ERROR_OVERFLOW;
                goto out;
            }
            cur_gramine_addr += cur_sub_region->size;
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

                void*  addr_of_array_len_field = sub_regions[found_idx].gramine_addr;
                size_t size_of_array_len_field = sub_regions[found_idx].size;
                uint64_t array_len;
                ret = copy_value_to_uint64(addr_of_array_len_field, size_of_array_len_field,
                                           &array_len);
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
            void* mem_region_addr = *((void**)sub_regions[i].gramine_addr);
            if (mem_region_addr) {
                for (size_t k = 0; k < sub_regions[i].array_len.value; k++) {
                    if (mem_regions_cnt == max_mem_regions) {
                        log_error("IOCTL: too many memory regions (max is %zu)", max_mem_regions);
                        ret = -PAL_ERROR_NOMEM;
                        goto out;
                    }

                    mem_regions[mem_regions_cnt].toml_mem_region = sub_regions[i].toml_mem_region;
                    mem_regions[mem_regions_cnt].gramine_addr    = mem_region_addr;
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

int ioctls_copy_sub_regions_to_host(struct sub_region* sub_regions, size_t sub_regions_cnt,
                                    void* host_addr, memcpy_to_host_f memcpy_to_host) {
    /* we rely on the fact that the host memory region was zeroed out: we can simply "jump over"
     * host memory when doing alignment and when direction of copy is `in` or `none` */
    char* cur_host_addr = host_addr;
    for (size_t i = 0; i < sub_regions_cnt; i++) {
        if (!sub_regions[i].size)
            continue;

        assert(sub_regions[i].alignment);
        cur_host_addr = ALIGN_UP_PTR(cur_host_addr, sub_regions[i].alignment);

        if (sub_regions[i].direction == DIRECTION_OUT
                || sub_regions[i].direction == DIRECTION_INOUT) {
            bool ret = memcpy_to_host(cur_host_addr, sub_regions[i].gramine_addr,
                                      sub_regions[i].size);
            if (!ret)
                return -PAL_ERROR_DENIED;
        }

        sub_regions[i].host_addr = cur_host_addr;
        cur_host_addr += sub_regions[i].size;
    }

    for (size_t i = 0; i < sub_regions_cnt; i++) {
        if (!sub_regions[i].size)
            continue;

        if (sub_regions[i].toml_mem_region) {
            void* gramine_ptr_value = *((void**)sub_regions[i].gramine_addr);
            /* rewire pointer value in host memory to a corresponding copied-to-host sub-region */
            for (size_t j = 0; j < sub_regions_cnt; j++) {
                if (sub_regions[j].gramine_addr == gramine_ptr_value) {
                    bool ret = memcpy_to_host(sub_regions[i].host_addr, &sub_regions[j].host_addr,
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

int ioctls_copy_sub_regions_to_gramine(struct sub_region* sub_regions, size_t sub_regions_cnt,
                                       memcpy_to_gramine_f memcpy_to_gramine) {
    for (size_t i = 0; i < sub_regions_cnt; i++) {
        if (!sub_regions[i].size)
            continue;

        if (sub_regions[i].direction == DIRECTION_IN
                || sub_regions[i].direction == DIRECTION_INOUT) {
            bool ret = memcpy_to_gramine(sub_regions[i].gramine_addr, sub_regions[i].size,
                                         sub_regions[i].host_addr, sub_regions[i].size);
            if (!ret)
                return -PAL_ERROR_DENIED;
        }
    }
    return 0;
}

/* may return `*out_toml_ioctl_struct = NULL` which means "no struct needed for this IOCTL" */
static int get_ioctl_struct(toml_table_t* manifest_sys, toml_table_t* toml_ioctl_table,
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

    toml_table_t* toml_ioctl_structs = toml_table_in(manifest_sys, "ioctl_structs");
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
int ioctls_get_allowed_ioctl_struct(toml_table_t* manifest_sys, uint32_t cmd,
                                    toml_array_t** out_toml_ioctl_struct) {
    int ret;

    /* find this IOCTL request in the manifest */
    toml_array_t* toml_allowed_ioctls = toml_array_in(manifest_sys, "allowed_ioctls");
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
            ret = get_ioctl_struct(manifest_sys, toml_ioctl_table, out_toml_ioctl_struct);
            if (ret < 0) {
                log_error("Invalid struct value of allowed IOCTL #%zu in manifest", idx + 1);
            }
            return ret;
        }
    }

    return -PAL_ERROR_NOTIMPLEMENTED;
}

