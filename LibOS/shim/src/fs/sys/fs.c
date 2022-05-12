/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/{cpu,node}/` pseudo-filesystem and
 * its sub-directories.
 */

#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"

int sys_print_as_ranges(char* buf, size_t buf_size, size_t count,
                        bool (*is_present)(size_t ind, const void* arg), const void* callback_arg) {
    size_t buf_pos = 0;
    const char* sep = "";
    for (size_t i = 0; i < count;) {
        while (i < count && !is_present(i, callback_arg))
            i++;
        size_t range_start = i;
        while (i < count && is_present(i, callback_arg))
            i++;
        size_t range_end = i; // exclusive

        if (range_start == range_end)
            break;
        int ret;
        if (range_start + 1 == range_end) {
            ret = snprintf(buf + buf_pos, buf_size - buf_pos, "%s%zu", sep, range_start);
        } else {
            ret = snprintf(buf + buf_pos, buf_size - buf_pos, "%s%zu-%zu", sep, range_start,
                           range_end - 1);
        }
        sep = ",";
        if (ret < 0)
            return ret;
        if ((size_t)ret >= buf_size - buf_pos)
            return -EOVERFLOW;
        buf_pos += ret;
    }
    if (buf_pos + 2 > buf_size)
        return -EOVERFLOW;
    buf[buf_pos]   = '\n';
    buf[buf_pos+1] = '\0';
    return 0;
}

int sys_print_as_bitmask(char* buf, size_t buf_size, size_t count,
                         bool (*is_present)(size_t ind, const void* arg),
                         const void* callback_arg) {
    if (count == 0)
        return strcpy_static(buf, "0\n", buf_size) ? 0 : -EOVERFLOW;

    size_t buf_pos = 0;
    int ret;
    size_t pos = count - 1;
    uint32_t word = 0;
    while (1) {
        if (is_present(pos, callback_arg))
            word |= 1 << pos % 32;
        if (pos % 32 == 0) {
            if (count <= 32) {
                /* Linux sysfs quirk: small bitmasks are printed without leading zeroes. */
                ret = snprintf(buf, buf_size, "%x\n", word); // pos == 0, loop exits afterwards
            } else {
                ret = snprintf(buf + buf_pos, buf_size - buf_pos,
                               "%08x%c", word, pos != 0 ? ',' : '\n');
            }
            if (ret < 0)
                return ret;
            if ((size_t)ret >= buf_size - buf_pos)
                return -EOVERFLOW;
            buf_pos += ret;
            word = 0;
        }

        if (pos == 0)
            break;
        pos--;
    }
    return 0;
}

static int sys_resource_info(const char* parent_name, size_t* out_total, const char** out_prefix) {
    const struct pal_topo_info* topo = &g_pal_public_state->topo_info;
    if (strcmp(parent_name, "node") == 0) {
        *out_total = topo->numa_nodes_cnt;
        *out_prefix = "node";
        return 0;
    } else if (strcmp(parent_name, "cpu") == 0) {
        *out_total = topo->threads_cnt;
        *out_prefix = "cpu";
        return 0;
    } else if (strcmp(parent_name, "cache") == 0) {
        size_t max = 0;
        /* Find the largest cache index used. */
        for (size_t i = 0; i < topo->threads_cnt; i++) {
            if (topo->threads[i].is_online) {
                for (size_t j = 0; j < MAX_CACHES; j++) {
                    if (topo->threads[i].ids_of_caches[j] != (size_t)-1) {
                        max = MAX(max, j + 1); // +1 to convert max index to elements count
                    }
                }
            }
        }
        *out_total = max;
        *out_prefix = "index";
        return 0;
    } else {
        log_debug("unrecognized resource: %s", parent_name);
        return -ENOENT;
    }
}

int sys_resource_find(struct shim_dentry* dent, const char* parent_name, unsigned int* out_num) {
    size_t total;
    const char* prefix;
    int ret = sys_resource_info(parent_name, &total, &prefix);
    if (ret < 0)
        return ret;

    if (total == 0)
        return -ENOENT;

    /* Search for "{parent_name}/{prefix}N", parse N (must be less than total) */

    struct shim_dentry* parent = dent->parent;
    while (parent) {
        if (strcmp(parent->name, parent_name) == 0) {
            if (!strstartswith(dent->name, prefix))
                return -ENOENT;

            size_t prefix_len = strlen(prefix);
            unsigned long n;
            if (pseudo_parse_ulong(&dent->name[prefix_len], total - 1, &n) < 0)
                return -ENOENT;

            *out_num = n;
            return 0;
        }

        dent = parent;
        parent = parent->parent;
    }
    return -ENOENT;
}

bool sys_resource_name_exists(struct shim_dentry* parent, const char* name) {
    size_t total;
    const char* prefix;
    int ret = sys_resource_info(parent->name, &total, &prefix);
    if (ret < 0)
        return false;

    if (total == 0)
        return false;

    /* Recognize "{prefix}N", check if N is less than total */

    if (!strstartswith(name, prefix))
        return false;

    size_t prefix_len = strlen(prefix);
    unsigned long n;
    if (pseudo_parse_ulong(&name[prefix_len], total - 1, &n) < 0)
        return false;

    return true;
}

int sys_resource_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg) {
    size_t total;
    const char* prefix;
    int ret = sys_resource_info(parent->name, &total, &prefix);
    if (ret < 0)
        return -ENOENT;

    /* Generate "{prefix}N" names for all N less than total */

    for (size_t i = 0; i < total; i++) {
        char ent_name[strlen(prefix) + 22];
        snprintf(ent_name, sizeof(ent_name), "%s%zu", prefix, i);
        int ret = callback(ent_name, arg);
        if (ret < 0)
            return ret;
    }

    return 0;
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

    /* `cpu/cpuX/online` exists for all CPUs *except* `cpu0`. */
    struct pseudo_node* online = pseudo_add_str(cpuX, "online", &sys_cpu_load_online);
    online->name_exists = &sys_cpu_online_name_exists;

    /* `cpu/cpuX/topology` exists only for online CPUs. */
    struct pseudo_node* topology = pseudo_add_dir(cpuX, "topology");
    topology->name_exists = &sys_cpu_exists_only_if_online;
    pseudo_add_str(topology, "core_id", &sys_cpu_load_topology);
    pseudo_add_str(topology, "physical_package_id", &sys_cpu_load_topology);
    pseudo_add_str(topology, "core_siblings", &sys_cpu_load_topology);
    pseudo_add_str(topology, "thread_siblings", &sys_cpu_load_topology);

    /* `cpu/cpuX/cache` exists only for online CPUs. */
    struct pseudo_node* cache = pseudo_add_dir(cpuX, "cache");
    cache->name_exists = &sys_cpu_exists_only_if_online;
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
    pseudo_add_str(node, "possible", &sys_node_general_load);

    struct pseudo_node* nodeX = pseudo_add_dir(node, NULL);
    nodeX->name_exists = &sys_resource_name_exists;
    nodeX->list_names = &sys_resource_list_names;

    pseudo_add_str(nodeX, "cpumap", &sys_node_load);
    pseudo_add_str(nodeX, "distance", &sys_node_load);

    // TODO(mkow): Does this show up for offline nodes? I never succeeded in shutting down one, even
    // after shutting down all CPUs inside the node it shows up as online on `node/online` list.
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

BEGIN_CP_FUNC(caches) {
    __UNUSED(size);
    assert(size == sizeof(struct pal_cache_info));

    struct pal_cache_info* caches = (struct pal_cache_info*)obj;
    struct pal_cache_info* new_caches = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        size_t caches_cnt = g_pal_public_state->topo_info.caches_cnt;
        size_t caches_size = caches_cnt * sizeof(struct pal_cache_info);
        off = ADD_CP_OFFSET(caches_size);
        ADD_TO_CP_MAP(obj, off);
        new_caches = (struct pal_cache_info*)(base + off);
        memcpy(new_caches, caches, caches_size);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_caches = (struct pal_cache_info*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_caches;
    }
}
END_CP_FUNC_NO_RS(caches)

BEGIN_CP_FUNC(threads) {
    __UNUSED(size);
    assert(size == sizeof(struct pal_cpu_thread_info));

    struct pal_cpu_thread_info* threads = (struct pal_cpu_thread_info*)obj;
    struct pal_cpu_thread_info* new_threads = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        size_t threads_cnt = g_pal_public_state->topo_info.threads_cnt;
        size_t threads_size = threads_cnt * sizeof(struct pal_cpu_thread_info);
        off = ADD_CP_OFFSET(threads_size);
        ADD_TO_CP_MAP(obj, off);
        new_threads = (struct pal_cpu_thread_info*)(base + off);
        memcpy(new_threads, threads, threads_size);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_threads = (struct pal_cpu_thread_info*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_threads;
    }
}
END_CP_FUNC_NO_RS(threads)

BEGIN_CP_FUNC(cores) {
    __UNUSED(size);
    assert(size == sizeof(struct pal_cpu_core_info));

    struct pal_cpu_core_info* cores = (struct pal_cpu_core_info*)obj;
    struct pal_cpu_core_info* new_cores = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        size_t cores_cnt = g_pal_public_state->topo_info.cores_cnt;
        size_t cores_size = cores_cnt * sizeof(struct pal_cpu_core_info);
        off = ADD_CP_OFFSET(cores_size);
        ADD_TO_CP_MAP(obj, off);
        new_cores = (struct pal_cpu_core_info*)(base + off);
        memcpy(new_cores, cores, cores_size);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_cores = (struct pal_cpu_core_info*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_cores;
    }
}
END_CP_FUNC_NO_RS(cores)

BEGIN_CP_FUNC(sockets) {
    __UNUSED(size);
    assert(size == sizeof(struct pal_socket_info));

    struct pal_socket_info* sockets = (struct pal_socket_info*)obj;
    struct pal_socket_info* new_sockets = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        size_t sockets_cnt = g_pal_public_state->topo_info.sockets_cnt;
        size_t sockets_size = sockets_cnt * sizeof(struct pal_socket_info);
        off = ADD_CP_OFFSET(sockets_size);
        ADD_TO_CP_MAP(obj, off);
        new_sockets = (struct pal_socket_info*)(base + off);
        memcpy(new_sockets, sockets, sockets_size);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_sockets = (struct pal_socket_info*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_sockets;
    }
}
END_CP_FUNC_NO_RS(sockets)

BEGIN_CP_FUNC(numa_nodes) {
    __UNUSED(size);
    assert(size == sizeof(struct pal_numa_node_info));

    struct pal_numa_node_info* numa_nodes = (struct pal_numa_node_info*)obj;
    struct pal_numa_node_info* new_numa_nodes = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        size_t numa_nodes_cnt = g_pal_public_state->topo_info.numa_nodes_cnt;
        size_t numa_nodes_size = numa_nodes_cnt * sizeof(struct pal_numa_node_info);
        off = ADD_CP_OFFSET(numa_nodes_size);
        ADD_TO_CP_MAP(obj, off);
        new_numa_nodes = (struct pal_numa_node_info*)(base + off);
        memcpy(new_numa_nodes, numa_nodes, numa_nodes_size);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_numa_nodes = (struct pal_numa_node_info*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_numa_nodes;
    }
}
END_CP_FUNC_NO_RS(numa_nodes)

BEGIN_CP_FUNC(numa_distances) {
    __UNUSED(size);
    assert(size == sizeof(size_t));

    size_t* distance_matrix = (size_t*)obj;
    size_t* new_distance_matrix = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        size_t numa_nodes_cnt = g_pal_public_state->topo_info.numa_nodes_cnt;
        size_t distance_size = numa_nodes_cnt * numa_nodes_cnt * sizeof(size_t);
        off = ADD_CP_OFFSET(distance_size);
        ADD_TO_CP_MAP(obj, off);
        new_distance_matrix = (size_t*)(base + off);
        memcpy(new_distance_matrix, distance_matrix, distance_size);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_distance_matrix = (size_t*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_distance_matrix;
    }
}
END_CP_FUNC_NO_RS(numa_distances)

BEGIN_CP_FUNC(topo_info) {
    __UNUSED(size);
    __UNUSED(objp);
    assert(size == sizeof(struct pal_topo_info));

    struct pal_topo_info* topo_info = (struct pal_topo_info*)obj;
    struct pal_topo_info* new_topo_info = NULL;

    size_t off = GET_FROM_CP_MAP(obj);
    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct pal_topo_info));
        ADD_TO_CP_MAP(obj, off);
        new_topo_info = (struct pal_topo_info*)(base + off);
        *new_topo_info = *topo_info;

        DO_CP(caches, topo_info->caches, &new_topo_info->caches);
        DO_CP(threads, topo_info->threads, &new_topo_info->threads);
        DO_CP(cores, topo_info->cores, &new_topo_info->cores);
        DO_CP(sockets, topo_info->sockets, &new_topo_info->sockets);
        DO_CP(numa_nodes, topo_info->numa_nodes, &new_topo_info->numa_nodes);
        DO_CP(numa_distances, topo_info->numa_distance_matrix, &new_topo_info->numa_distance_matrix);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_topo_info = (struct pal_topo_info*)(base + off);
    }

    if (objp)
        *objp = (void*)new_topo_info;
}
END_CP_FUNC(topo_info)

BEGIN_RS_FUNC(topo_info) {
    __UNUSED(offset);
    struct pal_topo_info* topo_info = (void*)(base + GET_CP_FUNC_ENTRY());

    if (topo_info->caches_cnt > 0) {
        CP_REBASE(topo_info->caches);
    } else {
        assert(!topo_info->caches);
    }

    if (topo_info->threads_cnt > 0) {
        CP_REBASE(topo_info->threads);
    } else {
        assert(!topo_info->threads);
    }

    if (topo_info->cores_cnt > 0) {
        CP_REBASE(topo_info->cores);
    } else {
        assert(!topo_info->cores);
    }

    if (topo_info->sockets_cnt > 0) {
        CP_REBASE(topo_info->sockets);
    } else {
        assert(!topo_info->sockets);
    }

    if (topo_info->numa_nodes_cnt > 0) {
        CP_REBASE(topo_info->numa_nodes);
        CP_REBASE(topo_info->numa_distance_matrix);
    } else {
        assert(!topo_info->numa_nodes);
    }

    g_pal_public_state->topo_info.caches_cnt = topo_info->caches_cnt;
    g_pal_public_state->topo_info.caches= topo_info->caches;
    g_pal_public_state->topo_info.threads_cnt = topo_info->threads_cnt;
    g_pal_public_state->topo_info.threads= topo_info->threads;
    g_pal_public_state->topo_info.cores_cnt = topo_info->cores_cnt;
    g_pal_public_state->topo_info.cores= topo_info->cores;
    g_pal_public_state->topo_info.sockets_cnt = topo_info->sockets_cnt;
    g_pal_public_state->topo_info.sockets= topo_info->sockets;
    g_pal_public_state->topo_info.numa_nodes_cnt = topo_info->numa_nodes_cnt;
    g_pal_public_state->topo_info.numa_nodes= topo_info->numa_nodes;
    g_pal_public_state->topo_info.numa_distance_matrix= topo_info->numa_distance_matrix;
}
END_RS_FUNC(topo_info)
