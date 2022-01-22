/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/node` and its sub-directories.
 */

#include "api.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"

int sys_node_general_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    const char* name = dent->name;
    if (strcmp(name, "online") != 0) {
        log_debug("unrecognized file: %s", name);
        return -ENOENT;
    }

    char str[PAL_SYSFS_BUF_FILESZ] = {'\0'};
    ret = sys_convert_ranges_to_str(&g_pal_public_state->topo_info.online_nodes, ",", str,
                                    sizeof(str));
    if (ret < 0)
        return ret;

    return sys_load(str, out_data, out_size);
}

int sys_node_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    unsigned int node_num;
    ret = sys_resource_find(dent, "node", &node_num);
    if (ret < 0)
        return ret;

    const char* name = dent->name;
    struct pal_numa_topo_info* numa_topo = &g_pal_public_state->topo_info.numa_topo_arr[node_num];
    char str[PAL_SYSFS_MAP_FILESZ] = {'\0'};
    if (strcmp(name, "cpumap" ) == 0) {
        ret = sys_convert_ranges_to_cpu_bitmap_str(&numa_topo->cpumap, str, sizeof(str));
    } else if (strcmp(name, "distance") == 0) {
        ret = sys_convert_ranges_to_str(&numa_topo->distance, " ", str, sizeof(str));
    } else if (strcmp(name, "nr_hugepages") == 0) {
        const char* parent_name = dent->parent->name;
        if (strcmp(parent_name, "hugepages-2048kB") == 0) {
            ret = snprintf(str, sizeof(str), "%zu\n", numa_topo->nr_hugepages[HUGEPAGES_2M]);
        } else if (strcmp(parent_name, "hugepages-1048576kB") == 0) {
            ret = snprintf(str, sizeof(str), "%zu\n", numa_topo->nr_hugepages[HUGEPAGES_1G]);
        } else {
            log_debug("unrecognized hugepage file: %s", parent_name);
            ret = -ENOENT;
        }
    } else {
        log_debug("unrecognized file: %s", name);
        ret = -ENOENT;
    }

    if (ret < 0)
        return ret;

    return sys_load(str, out_data, out_size);
}
