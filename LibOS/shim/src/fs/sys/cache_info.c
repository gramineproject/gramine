/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/cpu/cpuX/cache` and its
 * sub-directories.
 */

#include "api.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"

int sys_cache_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;

    unsigned int cache_num;
    ret = sys_resource_find(dent, "cache", &cache_num);
    if (ret < 0)
        return ret;

    unsigned int cpu_num;
    ret = sys_resource_find(dent, "cpu", &cpu_num);
    if (ret < 0)
        return ret;

    const char* name = dent->name;
    struct pal_core_cache_info* cache_info =
        &g_pal_public_state->topo_info.core_topo_arr[cpu_num].cache_info_arr[cache_num];
    char str[PAL_SYSFS_MAP_FILESZ] = {'\0'};
    if (strcmp(name, "shared_cpu_map") == 0) {
        ret = sys_convert_ranges_to_cpu_bitmap_str(&cache_info->shared_cpu_map, str, sizeof(str));
    } else if (strcmp(name, "level") == 0) {
        ret = snprintf(str, sizeof(str), "%zu\n", cache_info->level);
    } else if (strcmp(name, "type") == 0) {
        switch (cache_info->type) {
            case CACHE_TYPE_DATA:
                ret = snprintf(str, sizeof(str), "Data\n");
                break;
            case CACHE_TYPE_INSTRUCTION:
                ret = snprintf(str, sizeof(str), "Instruction\n");
                break;
            case CACHE_TYPE_UNIFIED:
                ret = snprintf(str, sizeof(str), "Unified\n");
                break;
            default:
                ret = -ENOENT;
        }
    } else if (strcmp(name, "size") == 0) {
        ret = snprintf(str, sizeof(str), "%zuK\n", cache_info->size >> 10);
    } else if (strcmp(name, "coherency_line_size") == 0) {
        ret = snprintf(str, sizeof(str), "%zu\n", cache_info->coherency_line_size);
    } else if (strcmp(name, "number_of_sets") == 0) {
        ret = snprintf(str, sizeof(str), "%zu\n", cache_info->number_of_sets);
    } else if (strcmp(name, "physical_line_partition") == 0) {
        snprintf(str, sizeof(str), "%zu\n", cache_info->physical_line_partition);
    } else {
        log_debug("unrecognized file: %s", name);
        ret = -ENOENT;
    }

    if (ret < 0)
        return ret;

    return sys_load(str, out_data, out_size);
}
