/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#ifndef PAL_TOPOLOGY_H
#define PAL_TOPOLOGY_H

// TODO: drop after removing PAL_NUM from here
typedef uint64_t PAL_NUM;

/* Used to represent plain integers (only numeric values) */
#define PAL_SYSFS_INT_FILESZ 16
/* Used to represent buffers having numeric values with text. E.g "1024576K" */
#define PAL_SYSFS_BUF_FILESZ 64
/* Used to represent cpumaps like "00000000,ffffffff,00000000,ffffffff" */
#define PAL_SYSFS_MAP_FILESZ 256

enum {
    HUGEPAGES_2M = 0,
    HUGEPAGES_1G,
    HUGEPAGES_MAX,
};

/* PAL_CPU_INFO holds /proc/cpuinfo data */
typedef struct PAL_CPU_INFO_ {
    const char* cpu_vendor;
    const char* cpu_brand;
    PAL_NUM cpu_family;
    PAL_NUM cpu_model;
    PAL_NUM cpu_stepping;
    double cpu_bogomips;
    const char* cpu_flags;
} PAL_CPU_INFO;

typedef struct PAL_CORE_CACHE_INFO_ {
    char shared_cpu_map[PAL_SYSFS_MAP_FILESZ];
    char level[PAL_SYSFS_INT_FILESZ];
    char type[PAL_SYSFS_BUF_FILESZ];
    char size[PAL_SYSFS_BUF_FILESZ];
    char coherency_line_size[PAL_SYSFS_INT_FILESZ];
    char number_of_sets[PAL_SYSFS_INT_FILESZ];
    char physical_line_partition[PAL_SYSFS_INT_FILESZ];
} PAL_CORE_CACHE_INFO;

typedef struct PAL_CORE_TOPO_INFO_ {
    /* [0] element is uninitialized because core 0 is always online */
    char is_logical_core_online[PAL_SYSFS_INT_FILESZ];
    char core_id[PAL_SYSFS_INT_FILESZ];
    char core_siblings[PAL_SYSFS_MAP_FILESZ];
    char thread_siblings[PAL_SYSFS_MAP_FILESZ];
    PAL_CORE_CACHE_INFO* cache; /* Array of size cache_index_cnt, owned by this struct */
} PAL_CORE_TOPO_INFO;

typedef struct PAL_NUMA_HUGEPAGE_INFO_ {
    char nr_hugepages[PAL_SYSFS_INT_FILESZ];
} PAL_NUMA_HUGEPAGE_INFO;

typedef struct PAL_NUMA_TOPO_INFO_ {
    char cpumap[PAL_SYSFS_MAP_FILESZ];
    char distance[PAL_SYSFS_BUF_FILESZ];
    PAL_NUMA_HUGEPAGE_INFO hugepages[HUGEPAGES_MAX];
} PAL_NUMA_TOPO_INFO;

/* This struct takes ~1.6KB. On a single socket, 4 logical core system, with 3 cache levels
 * it would take ~8KB in memory. */
// TODO: what does this ^ mean? the struct has constant size, much less than 1.6KB
struct pal_topo_info {
    PAL_CPU_INFO cpu_info; // TODO: should this be moved out to `pal_public_state` or kept here?
                           // We don't need to take this from the untrusted host as a start argument
                           // (but the rest of this struct _is_ used this way).

    PAL_NUM online_logical_cores_cnt; /* Number of logical cores available in the host */
    char online_logical_cores[PAL_SYSFS_BUF_FILESZ];
    int* cpu_to_socket; /* array of "logical core -> socket" mappings; has online_logical_cores_cnt
                         * elements */

    PAL_NUM possible_logical_cores_cnt; /* Max number of logical cores available in the host */
    char possible_logical_cores[PAL_SYSFS_BUF_FILESZ];

    PAL_NUM physical_cores_per_socket; /* Number of physical cores in a socket (physical package) */

    PAL_NUM online_nodes_cnt; /* Number of nodes available in the host */
    char online_nodes[PAL_SYSFS_BUF_FILESZ];

    PAL_NUM cache_index_cnt; /* cache index corresponds to number of cache levels (such as L2 or L3)
                              * available on the host */

    PAL_CORE_TOPO_INFO* core_topology; /* array of logical core topology info, owned by this struct */ // TODO: what size?
    PAL_NUMA_TOPO_INFO* numa_topology; /* array of numa topology info, owned by this struct */ // TODO: what size?
};

#endif /* PAL_TOPOLOGY_H */
