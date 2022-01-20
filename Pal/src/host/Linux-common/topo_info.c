/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the APIs to expose host topology information.
 */

#include <asm/errno.h>
#include <asm/fcntl.h>
#include <limits.h>

#include "api.h"
#include "pal_linux.h"
#include "syscall.h"
#include "topo_info.h"

/* TODO: This shouldn't mix error code and returned value in one variable. */
int get_hw_resource(const char* filename, bool count) {
    int fd = DO_SYSCALL(open, filename, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return fd;

    char buf[64];
    int ret = DO_SYSCALL(read, fd, buf, sizeof(buf) - 1);
    DO_SYSCALL(close, fd);
    if (ret < 0)
        return ret;

    buf[ret] = '\0'; /* ensure null-terminated buf even in partial read */

    char* ptr = buf;
    int resource_cnt = 0;
    int retval = -ENOENT;
    while (*ptr) {
        while (*ptr == ' ' || *ptr == '\t' || *ptr == ',')
            ptr++;

        char* end;
        long firstint = strtol(ptr, &end, 10);
        if (firstint < 0 || firstint > INT_MAX)
            return -ENOENT;

        if (ptr == end)
            break;

        /* caller wants to read an int stored in the file */
        if (!count) {
            if (*end == '\n' || *end == '\0')
                retval = (int)firstint;
            return retval;
        }

        /* caller wants to count the number of HW resources */
        if (*end == '\0' || *end == ',' || *end == '\n') {
            /* single HW resource index, count as one more */
            resource_cnt++;
        } else if (*end == '-') {
            /* HW resource range, count how many HW resources are in range */
            ptr = end + 1;
            long secondint = strtol(ptr, &end, 10);
            if (secondint < 0 || secondint > INT_MAX)
                return -EINVAL;

            if (secondint > firstint) {
                long diff = secondint - firstint;
                long total_cnt;
                if (__builtin_add_overflow(resource_cnt, diff, &total_cnt) || total_cnt >= INT_MAX)
                     return -EINVAL;
                resource_cnt += (int)secondint - (int)firstint + 1; //inclusive (e.g., 0-7, or 8-16)
            }
        }
        ptr = end;
    }

    if (count && resource_cnt > 0)
        retval = resource_cnt;

    return retval;
}

ssize_t read_file_buffer(const char* filename, char* buf, size_t count) {
    int fd = DO_SYSCALL(open, filename, O_RDONLY);
    if (fd < 0)
        return fd;

    ssize_t ret = DO_SYSCALL(read, fd, buf, count);
    DO_SYSCALL(close, fd);
    if (ret < 0)
        return ret;

    return ret;
}

#define READ_FILE_BUFFER(filepath, buf, failure_label)                           \
    ({                                                                           \
        ret = read_file_buffer(filepath, buf, ARRAY_SIZE(buf)-1);                \
        if (ret < 0)                                                             \
            goto failure_label;                                                  \
        buf[ret] = '\0';                                                         \
    })

/* Returns number of cache levels present on this system by counting "indexX" dir entries under
 * `/sys/devices/system/cpu/cpuX/cache` on success and negative UNIX error code on failure. */
/* TODO: This shouldn't mix error code and returned value in one variable. */
static int get_cache_levels_cnt(const char* path) {
    char buf[1024];
    int dirs_cnt = 0;

    int fd = DO_SYSCALL(open, path, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return fd;

    while (true) {
        int nread = DO_SYSCALL(getdents64, fd, buf, 1024);
        if (nread < 0) {
            dirs_cnt = nread;
            goto out;
        }

        if (nread == 0)
            break;

        for (int bpos = 0; bpos < nread;) {
            struct linux_dirent64* dirent64 = (struct linux_dirent64*)(buf + bpos);
            if (dirent64->d_type == DT_DIR && strstartswith(dirent64->d_name, "index"))
                dirs_cnt++;
            bpos += dirent64->d_reclen;
        }
    }

out:
    DO_SYSCALL(close, fd);
    return dirs_cnt ?: -ENOENT;
}

static int get_cache_topo_info(size_t cache_indices_cnt, size_t core_idx,
                               struct pal_core_cache_info** out_cache_info_arr) {
    int ret;
    char filename[128];
    struct pal_core_cache_info* cache_info_arr =
        malloc(cache_indices_cnt * sizeof(*cache_info_arr));
    if (!cache_info_arr) {
        return -ENOMEM;
    }

    for (size_t cache_idx = 0; cache_idx < cache_indices_cnt; cache_idx++) {
        struct pal_core_cache_info* cache_info = &cache_info_arr[cache_idx];
        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%zu/cache/index%zu/shared_cpu_map", core_idx,
                 cache_idx);
        READ_FILE_BUFFER(filename, cache_info->shared_cpu_map, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%zu/cache/index%zu/level", core_idx, cache_idx);
        READ_FILE_BUFFER(filename, cache_info->level, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%zu/cache/index%zu/type", core_idx, cache_idx);
        READ_FILE_BUFFER(filename, cache_info->type, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%zu/cache/index%zu/size", core_idx, cache_idx);
        READ_FILE_BUFFER(filename, cache_info->size, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%zu/cache/index%zu/coherency_line_size", core_idx,
                 cache_idx);
        READ_FILE_BUFFER(filename, cache_info->coherency_line_size, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%zu/cache/index%zu/number_of_sets", core_idx,
                 cache_idx);
        READ_FILE_BUFFER(filename, cache_info->number_of_sets, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%zu/cache/index%zu/physical_line_partition", core_idx,
                 cache_idx);
        READ_FILE_BUFFER(filename, cache_info->physical_line_partition,
                         /*failure_label=*/out_cache);
    }
    *out_cache_info_arr = cache_info_arr;
    return 0;

out_cache:
    free(cache_info_arr);
    return ret;
}

/* Get core topology-related info */
static int get_core_topo_info(struct pal_topo_info* topo_info) {
    int ret;

    /* we cannot use CPUID(0xb) because it counts even disabled-by-BIOS cores (e.g. HT cores);
     * instead we extract info on total number of logical cores, number of physical cores,
     * SMT support etc. by parsing sysfs pseudo-files */

    READ_FILE_BUFFER("/sys/devices/system/cpu/online", topo_info->online_logical_cores,
                     /*failure_label=*/out);

    READ_FILE_BUFFER("/sys/devices/system/cpu/possible", topo_info->possible_logical_cores,
                     /*failure_label=*/out);

    ret = get_hw_resource("/sys/devices/system/cpu/online", /*count=*/true);
    if (ret < 0)
        return ret;
    size_t online_logical_cores_cnt = (size_t)ret;
    topo_info->online_logical_cores_cnt = online_logical_cores_cnt;

    ret = get_cache_levels_cnt("/sys/devices/system/cpu/cpu0/cache");
    if (ret < 0)
        return ret;
    size_t cache_indices_cnt = (size_t)ret;
    topo_info->cache_indices_cnt = cache_indices_cnt;

    ret = get_hw_resource("/sys/devices/system/cpu/possible", /*count=*/true);
    if (ret < 0) {
        return ret;
    }
    size_t possible_logical_cores_cnt = (size_t)ret;
    topo_info->possible_logical_cores_cnt = possible_logical_cores_cnt;

    /* TODO: correctly support offline cores */
    if (possible_logical_cores_cnt > online_logical_cores_cnt) {
        log_warning("some CPUs seem to be offline; Gramine doesn't take this into account which "
                    "may lead to subpar performance");
    }

    ret = get_hw_resource("/sys/devices/system/cpu/cpu0/topology/core_siblings_list",
                          /*count=*/true);
    if (ret < 0) {
        return ret;
    }
    size_t core_siblings_cnt = (size_t)ret;
    ret = get_hw_resource("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list",
                          /*count=*/true);
    if (ret < 0) {
        return ret;
    }
    size_t smt_siblings_cnt = (size_t)ret;
    topo_info->physical_cores_per_socket = core_siblings_cnt / smt_siblings_cnt;

    /* array of "logical core -> socket" mappings */
    size_t* cpu_to_socket_arr = malloc(online_logical_cores_cnt * sizeof(*cpu_to_socket_arr));
    if (!cpu_to_socket_arr) {
        return -ENOMEM;
    }

    char filename[128];
    for (size_t idx = 0; idx < online_logical_cores_cnt; idx++) {
        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%zu/topology/physical_package_id", idx);
        ret = get_hw_resource(filename, /*count=*/false);
        if (ret < 0) {
            log_warning("Cannot read %s", filename);
            goto out_cpu_to_socket;
        }
        cpu_to_socket_arr[idx] = (size_t)ret;
    }
    topo_info->cpu_to_socket_arr = cpu_to_socket_arr;

    struct pal_core_topo_info* core_topology_arr =
        malloc(online_logical_cores_cnt * sizeof(*core_topology_arr));
    if (!core_topology_arr)
        return -ENOMEM;

    for (size_t idx = 0; idx < online_logical_cores_cnt; idx++) {
        /* cpu0 is always online and thus the "online" file is not present. */
        if (idx != 0) {
            snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%zu/online", idx);
            READ_FILE_BUFFER(filename, core_topology_arr[idx].is_logical_core_online,
                             /*failure_label=*/out_topology);
        }

        snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%zu/topology/core_id", idx);
        READ_FILE_BUFFER(filename, core_topology_arr[idx].core_id, /*failure_label=*/out_topology);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%zu/topology/core_siblings", idx);
        READ_FILE_BUFFER(filename, core_topology_arr[idx].core_siblings,
                         /*failure_label=*/out_topology);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%zu/topology/thread_siblings", idx);
        READ_FILE_BUFFER(filename, core_topology_arr[idx].thread_siblings,
                         /*failure_label=*/out_topology);

        ret = get_cache_topo_info(cache_indices_cnt, idx, &core_topology_arr[idx].cache_info_arr);
        if (ret < 0)
            goto out_topology;
    }
    topo_info->core_topology_arr = core_topology_arr;
    return 0;

out_topology:
    free(core_topology_arr);
out_cpu_to_socket:
    free(cpu_to_socket_arr);
out:
    return ret;
}

/* Get NUMA topology-related info */
static int get_numa_topo_info(struct pal_topo_info* topo_info) {
    int ret;
    READ_FILE_BUFFER("/sys/devices/system/node/online", topo_info->online_nodes,
                     /*failure_label=*/out);

    ret = get_hw_resource("/sys/devices/system/node/online", /*count=*/true);
    if (ret < 0)
        return ret;
    size_t online_nodes_cnt = (size_t)ret;
    topo_info->online_nodes_cnt = online_nodes_cnt;

    struct pal_numa_topo_info* numa_topology_arr =
        malloc(online_nodes_cnt * sizeof(*numa_topology_arr));
    if (!numa_topology_arr)
        return -ENOMEM;

    char filename[128];
    for (size_t idx = 0; idx < online_nodes_cnt; idx++) {
        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%zu/cpumap", idx);
        READ_FILE_BUFFER(filename, numa_topology_arr[idx].cpumap, /*failure_label=*/out_topology);

        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%zu/distance", idx);
        READ_FILE_BUFFER(filename, numa_topology_arr[idx].distance, /*failure_label=*/out_topology);

        /* Since our /sys fs doesn't support writes, set persistent hugepages to their default value
         * of zero */
        memcpy(numa_topology_arr[idx].hugepages[HUGEPAGES_2M].nr_hugepages, "0\n", 3);
        memcpy(numa_topology_arr[idx].hugepages[HUGEPAGES_1G].nr_hugepages, "0\n", 3);
    }
    topo_info->numa_topology_arr = numa_topology_arr;
    return 0;

out_topology:
    free(numa_topology_arr);
out:
    return ret;
}

int get_topology_info(struct pal_topo_info* topo_info) {
    /* Get CPU topology information */
    int ret = get_core_topo_info(topo_info);
    if (ret < 0)
        return ret;

    /* Get NUMA topology information */
    ret = get_numa_topo_info(topo_info);
    if (ret < 0)
        return ret;

    return 0;
}
