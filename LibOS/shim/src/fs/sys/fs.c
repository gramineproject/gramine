/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/{cpu,node}/` pseudo-filesystem and
 * its sub-directories.
 */

#include <limits.h>

#include "shim_fs.h"
#include "shim_fs_pseudo.h"
#include "stat.h"

int sys_convert_ranges_to_str(const struct pal_res_range_info* resource_range_info, const char* sep,
                              char* str, size_t str_size) {
    size_t ranges_cnt = resource_range_info->ranges_cnt;
    if (!ranges_cnt)
        return -EINVAL;

    str[0] = '\0';
    size_t offset = 0;
    for (size_t i = 0; i < ranges_cnt; i++) {
        if (offset >= str_size)
            return -ENOMEM;

        int ret;
        if (resource_range_info->ranges_arr[i].end == resource_range_info->ranges_arr[i].start) {
            ret = snprintf(str + offset, str_size - offset, "%zu%s",
                           resource_range_info->ranges_arr[i].start,
                           (i + 1 == ranges_cnt) ? "\n" : sep);
        } else {
            ret = snprintf(str + offset, str_size - offset, "%zu-%zu%s",
                           resource_range_info->ranges_arr[i].start,
                           resource_range_info->ranges_arr[i].end,
                           (i + 1 == ranges_cnt) ? "\n" : sep);
        }

        if (ret < 0)
            return ret;

        /* Truncation has occurred */
        if ((size_t)ret >= str_size - offset)
            return -EOVERFLOW;

        offset += ret;
    }
    return 0;
}

int sys_convert_ranges_to_cpu_bitmap_str(const struct pal_res_range_info* resource_range_info,
                                         char* str, size_t str_size) {
    int ret;

    /* Extract cpumask from the ranges */
    size_t possible_logical_cores_cnt =
        g_pal_public_state->topo_info.possible_logical_cores.resource_cnt;
    size_t cpumask_cnt = BITS_TO_UINT32S(possible_logical_cores_cnt);
    assert(cpumask_cnt > 0);

    uint32_t* bitmap = calloc(cpumask_cnt, sizeof(*bitmap));
    if (!bitmap)
        return -ENOMEM;

    for (size_t i = 0; i < resource_range_info->ranges_cnt; i++) {
        size_t start = resource_range_info->ranges_arr[i].start;
        size_t end = resource_range_info->ranges_arr[i].end;

        for (size_t j = start; j <= end; j++) {
            size_t index = j / BITS_IN_TYPE(uint32_t);
            assert(index < cpumask_cnt);

            bitmap[index] |= 1U << (j % BITS_IN_TYPE(uint32_t));
        }
    }

    /* Convert cpumask to strings */
    size_t offset = 0;
    for (size_t j = cpumask_cnt; j > 0; j--) {
        if (offset >= str_size) {
            ret = -ENOMEM;
            goto out;
        }

        /* Linux doesn't print leading zeroes for systems with less than 32 cores, e.g. "fff" for
         * 12 cores; we mimic this behavior. */
        if (possible_logical_cores_cnt >= 32) {
            ret = snprintf(str + offset, str_size - offset, "%08x%s", bitmap[j-1],
                           (j-1 == 0) ? "\n" : ",");
        } else {
            ret = snprintf(str + offset, str_size - offset, "%x%s", bitmap[j-1],
                           (j-1 == 0) ? "\n" : ",");
        }

        if (ret < 0)
            goto out;

        /* Truncation has occurred */
        if ((size_t)ret >= str_size - offset) {
            ret = -EOVERFLOW;
            goto out;
        }

        offset += ret;
    }
    ret = 0;

out:
    free(bitmap);
    return ret;
}

static int sys_resource(struct shim_dentry* parent, const char* name, unsigned int* out_num,
                        readdir_callback_t callback, void* arg) {
    const char* parent_name = parent->name;
    size_t total;
    const char* prefix;

    if (strcmp(parent_name, "node") == 0) {
        total = g_pal_public_state->topo_info.online_nodes.resource_cnt;
        prefix = "node";
    } else if (strcmp(parent_name, "cpu") == 0) {
        total = g_pal_public_state->topo_info.online_logical_cores.resource_cnt;
        prefix = "cpu";
    } else if (strcmp(parent_name, "cache") == 0) {
        total = g_pal_public_state->topo_info.cache_indices_cnt;
        prefix = "index";
    } else {
        log_debug("unrecognized resource: %s", parent_name);
        return -ENOENT;
    }

    if (name) {
        if (total == 0)
            return -ENOENT;

        if (!strstartswith(name, prefix))
            return -ENOENT;
        size_t prefix_len = strlen(prefix);
        unsigned long n;
        if (pseudo_parse_ulong(&name[prefix_len], total - 1, &n) < 0)
            return -ENOENT;

        if (out_num)
            *out_num = n;
        return 0;
    } else {
        for (size_t i = 0; i < total; i++) {
            char ent_name[42];
            snprintf(ent_name, sizeof(ent_name), "%s%zu", prefix, i);
            int ret = callback(ent_name, arg);
            if (ret < 0)
                return ret;
        }
        return 0;
    }
}

int sys_resource_find(struct shim_dentry* dent, const char* name, unsigned int* num) {
    struct shim_dentry* parent = dent->parent;
    while (parent) {
        if (strcmp(parent->name, name) == 0) {
            return sys_resource(parent, dent->name, num, /*callback=*/NULL, /*arg=*/NULL);
        }

        dent = parent;
        parent = parent->parent;
    }
    return -ENOENT;
}

bool sys_resource_name_exists(struct shim_dentry* parent, const char* name) {
    int ret = sys_resource(parent, name, /*num=*/NULL, /*callback=*/NULL, /*arg=*/NULL);
    return ret == 0;
}

int sys_resource_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg) {
    return sys_resource(parent, /*name=*/NULL, /*num=*/NULL, callback, arg);
}

int sys_load(const char* str, char** out_data, size_t* out_size) {
    assert(str);

    /* Use the string (without null terminator) as file data */
    size_t size = strlen(str);
    char* data = malloc(size);
    if (!data)
        return -ENOMEM;
    memcpy(data, str, size);
    *out_data = data;
    *out_size = size;
    return 0;
}

static void init_cpu_dir(struct pseudo_node* cpu) {
    pseudo_add_str(cpu, "online", &sys_cpu_general_load);
    pseudo_add_str(cpu, "possible", &sys_cpu_general_load);

    struct pseudo_node* cpuX = pseudo_add_dir(cpu, NULL);
    cpuX->name_exists = &sys_resource_name_exists;
    cpuX->list_names = &sys_resource_list_names;

    /* Create a node for `cpu/cpuX/online`. We provide name callbacks instead of a hardcoded name,
     * because we want the file to exist for all CPUs *except* `cpu0`. */
    struct pseudo_node* online = pseudo_add_str(cpuX, NULL, &sys_cpu_load);
    online->name_exists = &sys_cpu_online_name_exists;
    online->list_names = &sys_cpu_online_list_names;

    struct pseudo_node* topology = pseudo_add_dir(cpuX, "topology");
    pseudo_add_str(topology, "core_id", &sys_cpu_load);
    pseudo_add_str(topology, "physical_package_id", &sys_cpu_load);
    pseudo_add_str(topology, "core_siblings", &sys_cpu_load);
    pseudo_add_str(topology, "thread_siblings", &sys_cpu_load);

    struct pseudo_node* cache = pseudo_add_dir(cpuX, "cache");
    struct pseudo_node* indexX = pseudo_add_dir(cache, NULL);
    indexX->name_exists = &sys_resource_name_exists;
    indexX->list_names = &sys_resource_list_names;

    pseudo_add_str(indexX, "shared_cpu_map", &sys_cache_load);
    pseudo_add_str(indexX, "level", &sys_cache_load);
    pseudo_add_str(indexX, "type", &sys_cache_load);
    pseudo_add_str(indexX, "size", &sys_cache_load);
    pseudo_add_str(indexX, "coherency_line_size", &sys_cache_load);
    pseudo_add_str(indexX, "number_of_sets", &sys_cache_load);
    pseudo_add_str(indexX, "physical_line_partition", &sys_cache_load);
}

static void init_node_dir(struct pseudo_node* node) {
    pseudo_add_str(node, "online", &sys_node_general_load);

    struct pseudo_node* nodeX = pseudo_add_dir(node, NULL);
    nodeX->name_exists = &sys_resource_name_exists;
    nodeX->list_names = &sys_resource_list_names;

    pseudo_add_str(nodeX, "cpumap", &sys_node_load);
    pseudo_add_str(nodeX, "distance", &sys_node_load);

    struct pseudo_node* hugepages = pseudo_add_dir(nodeX, "hugepages");
    struct pseudo_node* hugepages_2m = pseudo_add_dir(hugepages, "hugepages-2048kB");
    pseudo_add_str(hugepages_2m, "nr_hugepages", &sys_node_load);
    struct pseudo_node* hugepages_1g = pseudo_add_dir(hugepages, "hugepages-1048576kB");
    pseudo_add_str(hugepages_1g, "nr_hugepages", &sys_node_load);
}

int init_sysfs(void) {
    if (!g_pal_public_state->enable_sysfs_topology)
        return 0;

    struct pseudo_node* root = pseudo_add_root_dir("sys");
    struct pseudo_node* devices = pseudo_add_dir(root, "devices");
    struct pseudo_node* system = pseudo_add_dir(devices, "system");

    struct pseudo_node* cpu = pseudo_add_dir(system, "cpu");
    init_cpu_dir(cpu);

    struct pseudo_node* node = pseudo_add_dir(system, "node");
    init_node_dir(node);

    return 0;
}
