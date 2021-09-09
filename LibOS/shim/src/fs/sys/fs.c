/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/{cpu,node}/` pseudo-filesystem and
 * its sub-directories.
 */

#include <limits.h>

#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"
#include "stat.h"

PAL_TOPO_INFO* g_topo_info = NULL;
int64_t g_num_cores_online;
int64_t g_num_nodes_online;
int64_t g_num_cache_lvls;

int sys_convert_int_to_sizestr(uint64_t val, uint64_t size_mult, char* str, size_t max_size) {
    int ret = 0;

    switch (size_mult) {
        case MULTIPLIER_KB:
            ret = snprintf(str, max_size, "%luK", val);
            break;
        case MULTIPLIER_MB:
            ret = snprintf(str, max_size, "%luM", val);
            break;
        case MULTIPLIER_GB:
            ret = snprintf(str, max_size, "%luG", val);
            break;
        default:
            ret = snprintf(str, max_size, "%lu", val);
            break;
    }
    return ret;
}

int sys_convert_ranges_to_str(const PAL_RES_RANGE_INFO* res_range_info, char* str, size_t max_size,
                              const char* sep) {
    uint64_t range_cnt = res_range_info->range_count;
    size_t offset = 0;
    for (uint64_t i = 0; i < range_cnt; i++) {
        if (offset > max_size)
            return -ENOMEM;

        int ret;
        if (res_range_info->ranges[i].end == res_range_info->ranges[i].start) {
            ret = snprintf(str + offset, max_size - offset, "%lu%s", res_range_info->ranges[i].start,
                           (i + 1 == range_cnt) ? "\0" : sep);
        } else {
            ret = snprintf(str + offset, max_size - offset, "%lu-%lu%s",
                           res_range_info->ranges[i].start, res_range_info->ranges[i].end,
                           (i + 1 == range_cnt) ? "\0" : sep);
        }

        if (ret < 0)
            return ret;

        offset += ret;
    }
    return 0;
}

int sys_convert_ranges_to_cpu_bitmap_str(const PAL_RES_RANGE_INFO* res_range_info, char* str,
                                         size_t max_size) {
    int ret;

    /* Extract cpumask from the ranges */
    uint64_t possible_cores =  g_topo_info->possible_logical_cores.resource_count;
    uint64_t num_cpumask = BITS_TO_INTS(possible_cores);
    uint32_t* bitmap = (uint32_t*)calloc(num_cpumask, sizeof(uint32_t));
    if (!bitmap)
        return -ENOMEM;

    for (uint64_t i = 0; i < res_range_info->range_count; i++) {
        uint64_t start = res_range_info->ranges[i].start;
        uint64_t end = res_range_info->ranges[i].end;
        if (start > INT64_MAX || end > INT64_MAX) {
            ret = -EINVAL;
            goto out;
        }
        for (uint64_t j = start; j <= end; j++) {
            uint64_t index = j / BITS_IN_TYPE(int);
            if (index >= num_cpumask) {
                ret = -EINVAL;
                goto out;
            }
            bitmap[index] |= 1U << (j % BITS_IN_TYPE(int));
        }
    }

    /* Convert cpumask to strings */
    size_t offset = 0;
    for (uint64_t j = num_cpumask; j > 0; j--) {
        if (offset > max_size) {
            ret = -ENOMEM;
            goto out;
        }
        ret = snprintf(str + offset, max_size - offset, "%08x%s", bitmap[j-1], (j-1 == 0) ? "\0" : ",");
        if (ret < 0)
            goto out;
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
    PAL_NUM pal_total;
    unsigned int total;
    const char* prefix;

    if (strcmp(parent_name, "node") == 0) {
        pal_total = g_topo_info->nodes.resource_count;
        prefix = "node";
    } else if (strcmp(parent_name, "cpu") == 0) {
        pal_total = g_topo_info->online_logical_cores.resource_count;
        prefix = "cpu";
    } else if (strcmp(parent_name, "cache") == 0) {
        pal_total = g_topo_info->num_cache_index;
        prefix = "index";
    } else {
        log_debug("unrecognized resource: %s", parent_name);
        return -ENOENT;
    }

    assert(pal_total <= UINT_MAX);
    total = pal_total;

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
        for (unsigned int i = 0; i < total; i++) {
            char ent_name[42];
            snprintf(ent_name, sizeof(ent_name), "%s%u", prefix, i);
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
    struct pseudo_node* root = pseudo_add_root_dir("sys");
    struct pseudo_node* devices = pseudo_add_dir(root, "devices");
    struct pseudo_node* system = pseudo_add_dir(devices, "system");

    struct pseudo_node* cpu = pseudo_add_dir(system, "cpu");
    init_cpu_dir(cpu);

    struct pseudo_node* node = pseudo_add_dir(system, "node");
    init_node_dir(node);

    return 0;
}

BEGIN_CP_FUNC(numa_topology) {
    __UNUSED(size);
    assert(size == sizeof(PAL_NUMA_TOPO_INFO));

    PAL_NUMA_TOPO_INFO* numa_topo = (PAL_NUMA_TOPO_INFO*)obj;
    PAL_NUMA_TOPO_INFO* new_numa_topo = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        size_t numa_topo_sz = g_num_nodes_online * sizeof(PAL_NUMA_TOPO_INFO);
        off = ADD_CP_OFFSET(numa_topo_sz);
        ADD_TO_CP_MAP(obj, off);
        new_numa_topo = (PAL_NUMA_TOPO_INFO*)(base + off);
        memcpy(new_numa_topo, numa_topo, numa_topo_sz);

        for (int64_t idx = 0; idx < g_num_nodes_online; idx++) {
            if (numa_topo[idx].cpumap.range_count > 0) {
                size_t range_sz = numa_topo[idx].cpumap.range_count * sizeof(PAL_RANGE_INFO);
                size_t toff = ADD_CP_OFFSET(range_sz);
                new_numa_topo[idx].cpumap.ranges = (void*)(base + toff);
                memcpy(new_numa_topo[idx].cpumap.ranges, numa_topo[idx].cpumap.ranges, range_sz);
            }

            if (numa_topo[idx].distance.range_count > 0) {
                size_t range_sz = numa_topo[idx].distance.range_count * sizeof(PAL_RANGE_INFO);
                size_t toff = ADD_CP_OFFSET(range_sz);
                new_numa_topo[idx].distance.ranges = (void*)(base + toff);
                memcpy(new_numa_topo[idx].distance.ranges, numa_topo[idx].distance.ranges, range_sz);
            }
        }
        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_numa_topo = (PAL_NUMA_TOPO_INFO*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_numa_topo;
    }
}
END_CP_FUNC_NO_RS(numa_topology)

BEGIN_CP_FUNC(cache) {
    __UNUSED(size);
    assert(size == sizeof(PAL_CORE_CACHE_INFO));

    PAL_CORE_CACHE_INFO* cache = (PAL_CORE_CACHE_INFO*)obj;
    PAL_CORE_CACHE_INFO* new_cache = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        size_t cache_topo_sz = g_num_cache_lvls * sizeof(PAL_CORE_CACHE_INFO);
        off = ADD_CP_OFFSET(cache_topo_sz);
        ADD_TO_CP_MAP(obj, off);
        new_cache = (PAL_CORE_CACHE_INFO*)(base + off);
        memcpy(new_cache, cache, cache_topo_sz);

        for (int64_t idx = 0; idx < g_num_cache_lvls; idx++) {
            if (cache[idx].shared_cpu_map.range_count > 0) {
                size_t range_sz = cache[idx].shared_cpu_map.range_count * sizeof(PAL_RANGE_INFO);
                size_t toff = ADD_CP_OFFSET(range_sz);
                new_cache[idx].shared_cpu_map.ranges = (void*)(base + toff);
                memcpy(new_cache[idx].shared_cpu_map.ranges, cache[idx].shared_cpu_map.ranges,
                       range_sz);
            }
        }
        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_cache = (PAL_CORE_CACHE_INFO*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_cache;
    }
}
END_CP_FUNC_NO_RS(cache)

BEGIN_CP_FUNC(core_topology) {
    __UNUSED(size);
    assert(size == sizeof(PAL_CORE_TOPO_INFO));

    PAL_CORE_TOPO_INFO* core_topo = (PAL_CORE_TOPO_INFO*)obj;
    PAL_CORE_TOPO_INFO* new_core_topo = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        size_t core_topo_sz = g_num_cores_online * sizeof(PAL_CORE_TOPO_INFO);
        off = ADD_CP_OFFSET(core_topo_sz);
        ADD_TO_CP_MAP(obj, off);
        new_core_topo = (PAL_CORE_TOPO_INFO*)(base + off);
        memcpy(new_core_topo, core_topo, core_topo_sz);

        for (int64_t idx = 0; idx < g_num_cores_online; idx++) {
            if (core_topo[idx].core_siblings.range_count > 0) {
                size_t range_sz = core_topo[idx].core_siblings.range_count * sizeof(PAL_RANGE_INFO);
                size_t toff = ADD_CP_OFFSET(range_sz);
                new_core_topo[idx].core_siblings.ranges = (void*)(base + toff);
                memcpy(new_core_topo[idx].core_siblings.ranges, core_topo[idx].core_siblings.ranges,
                       range_sz);
            }

            if (core_topo[idx].thread_siblings.range_count > 0) {
                size_t range_sz = core_topo[idx].thread_siblings.range_count * sizeof(PAL_RANGE_INFO);
                size_t toff = ADD_CP_OFFSET(range_sz);
                new_core_topo[idx].thread_siblings.ranges = (void*)(base + toff);
                memcpy(new_core_topo[idx].thread_siblings.ranges,
                       core_topo[idx].thread_siblings.ranges, range_sz);
            }

            DO_CP(cache, core_topo[idx].cache, &new_core_topo[idx].cache);
        }
        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_core_topo = (PAL_CORE_TOPO_INFO*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_core_topo;
    }
}
END_CP_FUNC_NO_RS(core_topology)

BEGIN_CP_FUNC(topo_info) {
    __UNUSED(size);
    __UNUSED(objp);
    assert(size == sizeof(PAL_TOPO_INFO));

    PAL_TOPO_INFO* topo_info = (PAL_TOPO_INFO*)obj;
    PAL_TOPO_INFO* new_topo_info = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        off = ADD_CP_OFFSET(sizeof(*topo_info));
        ADD_TO_CP_MAP(obj, off);
        new_topo_info = (PAL_TOPO_INFO*)(base + off);
        *new_topo_info = *topo_info;

        if (topo_info->online_logical_cores.range_count > 0) {
            size_t range_sz = topo_info->online_logical_cores.range_count * sizeof(PAL_RANGE_INFO);
            size_t toff = ADD_CP_OFFSET(range_sz);
            new_topo_info->online_logical_cores.ranges = (void*)(base + toff);
            memcpy(new_topo_info->online_logical_cores.ranges,
                   topo_info->online_logical_cores.ranges, range_sz);
        }
        g_num_cores_online = topo_info->online_logical_cores.resource_count;
        g_num_cache_lvls = topo_info->num_cache_index;

        if (topo_info->possible_logical_cores.range_count > 0) {
            size_t range_sz = topo_info->possible_logical_cores.range_count * sizeof(PAL_RANGE_INFO);
            size_t toff = ADD_CP_OFFSET(range_sz);
            new_topo_info->possible_logical_cores.ranges = (void*)(base + toff);
            memcpy(new_topo_info->possible_logical_cores.ranges,
                   topo_info->possible_logical_cores.ranges, range_sz);
        }

        if (topo_info->nodes.range_count > 0) {
            size_t range_sz = topo_info->nodes.range_count * sizeof(PAL_RANGE_INFO);
            size_t toff = ADD_CP_OFFSET(range_sz);
            new_topo_info->nodes.ranges = (void*)(base + toff);
            memcpy(new_topo_info->nodes.ranges, topo_info->nodes.ranges, range_sz);
        }
        g_num_nodes_online = topo_info->nodes.resource_count;

        DO_CP(core_topology, topo_info->core_topology, &new_topo_info->core_topology);
        DO_CP(numa_topology, topo_info->numa_topology, &new_topo_info->numa_topology);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_topo_info = (PAL_TOPO_INFO*)(base + off);
    }

    if (objp)
        *objp = (void*)new_topo_info;
}
END_CP_FUNC(topo_info)

BEGIN_RS_FUNC(topo_info) {
    __UNUSED(offset);
    PAL_TOPO_INFO* topo_info = (void*)(base + GET_CP_FUNC_ENTRY());

    if (topo_info->online_logical_cores.range_count > 0) {
        CP_REBASE(topo_info->online_logical_cores.ranges);
    } else {
        assert(!topo_info->online_logical_cores.ranges);
    }

    if (topo_info->possible_logical_cores.range_count > 0) {
        CP_REBASE(topo_info->possible_logical_cores.ranges);
    } else {
        assert(!topo_info->possible_logical_cores.ranges);
    }

    if (topo_info->nodes.range_count > 0) {
        CP_REBASE(topo_info->nodes.ranges);
    } else {
        assert(!topo_info->nodes.ranges);
    }

    CP_REBASE(topo_info->core_topology);
    for (uint64_t idx = 0; idx < topo_info->online_logical_cores.resource_count; idx++) {
        CP_REBASE(topo_info->core_topology[idx].core_siblings.ranges);
        CP_REBASE(topo_info->core_topology[idx].thread_siblings.ranges);
        CP_REBASE(topo_info->core_topology[idx].cache);
        for (uint64_t lvl = 0; lvl < topo_info->num_cache_index; lvl++) {
            CP_REBASE(topo_info->core_topology[idx].cache[lvl].shared_cpu_map.ranges);
        }
    }
    CP_REBASE(topo_info->numa_topology);
    for (uint64_t idx = 0; idx < topo_info->nodes.resource_count; idx++) {
        CP_REBASE(topo_info->numa_topology[idx].cpumap.ranges);
        CP_REBASE(topo_info->numa_topology[idx].distance.ranges);
    }

    g_topo_info = topo_info;
}
END_RS_FUNC(topo_info)
