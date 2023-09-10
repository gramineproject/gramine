/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/node` and its sub-directories.
 */

#include <stdbool.h>

#include "api.h"
#include "libos_fs.h"
#include "libos_fs_pseudo.h"
#include "libos_vma.h"

static bool is_online(size_t ind, const void* arg) {
    __UNUSED(arg);
    return g_pal_public_state->topo_info.numa_nodes[ind].is_online;
}

static bool return_true(size_t ind, const void* arg) {
    __UNUSED(ind);
    __UNUSED(arg);
    return true;
}

int sys_node_general_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    const struct pal_topo_info* topo = &g_pal_public_state->topo_info;
    const char* name = dent->name;
    char str[PAL_SYSFS_BUF_FILESZ];
    if (strcmp(name, "online") == 0) {
        ret = sys_print_as_ranges(str, sizeof(str), topo->numa_nodes_cnt, is_online, NULL);
    } else if (strcmp(name, "possible") == 0) {
        ret = sys_print_as_ranges(str, sizeof(str), topo->numa_nodes_cnt, return_true, NULL);
    } else {
        log_debug("unrecognized file: %s", name);
        return -ENOENT;
    }

    if (ret < 0)
        return ret;

    return sys_load(str, out_data, out_size);
}

static bool is_in_same_node(size_t idx, const void* _arg) {
    unsigned int arg_node_id = *(const unsigned int*)_arg;
    if (!g_pal_public_state->topo_info.threads[idx].is_online)
        return false;
    size_t core_id = g_pal_public_state->topo_info.threads[idx].core_id;
    size_t node_id = g_pal_public_state->topo_info.cores[core_id].node_id;
    return node_id == arg_node_id;
}

int sys_node_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    unsigned int node_id;
    ret = sys_resource_find(dent, "node", &node_id);
    if (ret < 0)
        return ret;

    const char* name = dent->name;
    const struct pal_topo_info* topo = &g_pal_public_state->topo_info;
    const struct pal_numa_node_info* numa_node = &topo->numa_nodes[node_id];
    if (!numa_node->is_online)
        return -ENOENT;

    char str[PAL_SYSFS_MAP_FILESZ] = {0};
    if (strcmp(name, "cpumap") == 0) {
        ret = sys_print_as_bitmask(str, sizeof(str), topo->threads_cnt, is_in_same_node, &node_id);
    } else if (strcmp(name, "distance") == 0) {
        /* Linux reflects only online nodes in the `distance` file, do the same */
        size_t* distances = topo->numa_distance_matrix + node_id * topo->numa_nodes_cnt;
        size_t str_pos = 0;
        for (size_t i = 0; i < topo->numa_nodes_cnt; i++) {
            if (!topo->numa_nodes[i].is_online)
                continue;
            assert(distances[i]);
            ret = snprintf(str + str_pos, sizeof(str) - str_pos, "%s%zu", str_pos ? " " : "",
                           distances[i]);
            if (ret < 0)
                return ret;
            if ((size_t)ret >= sizeof(str) - str_pos)
                return -EOVERFLOW;
            str_pos += ret;
        }
        if (str_pos >= sizeof(str) - 1)
            return -EOVERFLOW;
        str[str_pos] = '\n';
    } else if (strcmp(name, "nr_hugepages") == 0) {
        const char* parent_name = dent->parent->name;
        if (strcmp(parent_name, "hugepages-2048kB") == 0) {
            ret = snprintf(str, sizeof(str), "%zu\n", numa_node->nr_hugepages[HUGEPAGES_2M]);
        } else if (strcmp(parent_name, "hugepages-1048576kB") == 0) {
            ret = snprintf(str, sizeof(str), "%zu\n", numa_node->nr_hugepages[HUGEPAGES_1G]);
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

int sys_node_meminfo_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    size_t numa_nodes_cnt = g_pal_public_state->topo_info.numa_nodes_cnt;
    /* Simply "mimic" a typical environment: split memory evenly between each NUMA node */
    size_t node_mem_total = g_pal_public_state->mem_total / numa_nodes_cnt;
    size_t node_mem_free = (g_pal_public_state->mem_total - get_total_memory_usage())
                           / numa_nodes_cnt;

    assert(node_mem_total >= node_mem_free);

    unsigned int node_id;
    int ret = sys_resource_find(dent, "node", &node_id);
    if (ret < 0)
        return ret;

    const struct pal_topo_info* topo = &g_pal_public_state->topo_info;
    const struct pal_numa_node_info* numa_node = &topo->numa_nodes[node_id];
    if (!numa_node->is_online)
        return -ENOENT;

    size_t size = 0, max = 256;
    char* str = malloc(max);
    if (!str)
        return -ENOMEM;

    /*
     * Enumerate minimum set of node meminfo stats (the default stats in Linux, without specific
     * `#ifdef CONFIG_xxx`). This set is based on Linux v5.19, see below for details:
     *
     * - https://elixir.bootlin.com/linux/v5.19/source/drivers/base/node.c#L369
    */

    struct {
        const char* fmt;
        unsigned long val;
    } meminfo[] = {
        { "Node %u MemTotal:       %8lu kB\n", node_mem_total / 1024 },
        { "Node %u MemFree:        %8lu kB\n", node_mem_free / 1024 },
        { "Node %u MemUsed:        %8lu kB\n", (node_mem_total - node_mem_free) / 1024 },
        { "Node %u SwapCached:     %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Active:         %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Inactive:       %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Active(anon):   %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Inactive(anon): %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Active(file):   %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Inactive(file): %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Unevictable:    %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Mlocked:        %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Dirty:          %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Writeback:      %8lu kB\n", /*dummy value=*/0 },
        { "Node %u FilePages:      %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Mapped:         %8lu kB\n", /*dummy value=*/0 },
        { "Node %u AnonPages:      %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Shmem:          %8lu kB\n", /*dummy value=*/0 },
        { "Node %u KernelStack:    %8lu kB\n", /*dummy value=*/0 },
        { "Node %u PageTables:     %8lu kB\n", /*dummy value=*/0 },
        { "Node %u NFS_Unstable:   %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Bounce:         %8lu kB\n", /*dummy value=*/0 },
        { "Node %u WritebackTmp:   %8lu kB\n", /*dummy value=*/0 },
        { "Node %u KReclaimable:   %8lu kB\n", /*dummy value=*/0 },
        { "Node %u Slab:           %8lu kB\n", /*dummy value=*/0 },
        { "Node %u SReclaimable:   %8lu kB\n", /*dummy value=*/0 },
        { "Node %u SUnreclaim:     %8lu kB\n", /*dummy value=*/0 },
    };

    size_t i = 0;
    while (i < ARRAY_SIZE(meminfo)) {
        ret = snprintf(str + size, max - size, meminfo[i].fmt, node_id, meminfo[i].val);
        if (ret < 0) {
            free(str);
            return ret;
        }

        if (size + ret >= max) {
            max *= 2;
            size = 0;
            i = 0;
            free(str);
            /* TODO: use `realloc()` once it's available. */
            str = malloc(max);
            if (!str)
                return -ENOMEM;

            continue;
        }

        size += ret;
        i++;
    }

    *out_data = str;
    *out_size = size;
    return 0;
}
