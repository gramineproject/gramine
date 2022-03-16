/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the main function of the PAL loader, which loads and processes environment,
 * arguments and manifest.
 */

#include <stdint.h>
#include <stdnoreturn.h>

#include "api.h"
#include "enclave_pf.h"
#include "enclave_tf.h"
#include "init.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_rtld.h"
#include "pal_topology.h"
#include "toml.h"
#include "toml_utils.h"

struct pal_linuxsgx_state g_pal_linuxsgx_state;

PAL_SESSION_KEY g_master_key = {0};

/* Limit of PAL memory available for _DkVirtualMemoryAlloc(PAL_ALLOC_INTERNAL) */
size_t g_pal_internal_mem_size = PAL_INITIAL_MEM_SIZE;

const size_t g_page_size = PRESET_PAGESIZE;

void _DkGetAvailableUserAddressRange(void** out_start, void** out_end) {
    *out_start = g_pal_linuxsgx_state.heap_min;
    *out_end   = g_pal_linuxsgx_state.heap_max;

    /* Keep some heap for internal PAL objects allocated at runtime (recall that LibOS does not keep
     * track of PAL memory, so without this limit it could overwrite internal PAL memory). See also
     * `enclave_pages.c`. */
    *out_end = SATURATED_P_SUB(*out_end, g_pal_internal_mem_size, *out_start);

    if (*out_end <= *out_start) {
        log_error("Not enough enclave memory, please increase enclave size!");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
}

/*
 * Takes a pointer+size to an untrusted memory region containing a
 * NUL-separated list of strings. It builds an argv-style list in trusted memory
 * with those strings.
 *
 * It is responsible for handling the access to untrusted memory safely
 * (returns NULL on error) and ensures that all strings are properly
 * terminated. The content of the strings is NOT further sanitized.
 *
 * The argv-style list is allocated on the heap and the caller is responsible
 * to free it (For argv and envp we rely on auto free on termination in
 * practice).
 */
/* This function doesn't clean up resources on failure as we terminate the process anyway. */
static const char** make_argv_list(void* uptr_src, size_t src_size) {
    const char** argv;

    if (src_size == 0) {
        argv = malloc(sizeof(char*));
        if (argv)
            argv[0] = NULL;
        return argv;
    }

    char* data = malloc(src_size);
    if (!data) {
        return NULL;
    }

    if (!sgx_copy_to_enclave(data, src_size, uptr_src, src_size)) {
        goto fail;
    }
    data[src_size - 1] = '\0';

    size_t argc = 0;
    for (size_t i = 0; i < src_size; i++) {
        if (data[i] == '\0') {
            argc++;
        }
    }

    size_t argv_size;
    if (__builtin_mul_overflow(argc + 1, sizeof(char*), &argv_size)) {
        goto fail;
    }
    argv = malloc(argv_size);
    if (!argv) {
        goto fail;
    }
    argv[argc] = NULL;

    size_t data_i = 0;
    for (size_t arg_i = 0; arg_i < argc; arg_i++) {
        argv[arg_i] = &data[data_i];
        while (data[data_i] != '\0') {
            data_i++;
        }
        data_i++;
    }

    return argv;

fail:
    free(data);
    return NULL;
}

/* This function doesn't clean up resources on failure as we terminate the process anyway. */
static int copy_resource_range_to_enclave(struct pal_res_range_info* src,
                                          struct pal_res_range_info* dest) {
    size_t ranges_arr_size;
    if (__builtin_mul_overflow(src->ranges_cnt, sizeof(struct pal_range_info), &ranges_arr_size)) {
        log_error("Overflow detected with size of ranges_arr memory allocation request");
        return -1;
    }

    struct pal_range_info* ranges_arr = malloc(ranges_arr_size);
    if (!ranges_arr) {
        log_error("Range allocation failed");
        return -1;
    }

    /* Even though `src` points to a safe in-enclave object, the `src->ranges_arr` pointer is
     * untrusted and may maliciously point inside the enclave; thus need to use
     * `sgx_copy_to_enclave()` function */
    if (!sgx_copy_to_enclave(ranges_arr, ranges_arr_size,
                             src->ranges_arr, src->ranges_cnt * sizeof(*src->ranges_arr))) {
        log_error("Copying ranges into the enclave failed");
        return -1;
    }

    dest->ranges_arr = ranges_arr;
    dest->ranges_cnt = src->ranges_cnt;
    dest->resource_cnt = src->resource_cnt;
    return 0;
}

/* This function doesn't clean up resources on failure as we terminate the process anyway. */
static int sgx_copy_core_topo_to_enclave(struct pal_core_topo_info* uptr_src,
                                         size_t online_logical_cores_cnt,
                                         size_t cache_indices_cnt,
                                         struct pal_core_topo_info** out_core_topo_arr) {
    assert(out_core_topo_arr);

    struct pal_core_topo_info* temp_core_topo_arr =
        malloc(online_logical_cores_cnt * sizeof(*temp_core_topo_arr));
    if (!temp_core_topo_arr) {
        log_error("Allocation for shallow copy of core_topo_arr failed");
        return -1;
    }

    /* Shallow copy contents of core_topo_arr (uptr_src) into enclave */
    if (!sgx_copy_to_enclave(temp_core_topo_arr,
                             online_logical_cores_cnt * sizeof(*temp_core_topo_arr), uptr_src,
                             online_logical_cores_cnt * sizeof(*uptr_src))) {
        log_error("Shallow copy of core_topo_arr into the enclave failed");
        return -1;
    }

    /* Allocate enclave memory to store core topo info */
    struct pal_core_topo_info* core_topo_arr =
        malloc(online_logical_cores_cnt * sizeof(*core_topo_arr));
    if (!core_topo_arr) {
        log_error("Allocation for core topology array failed");
        return -1;
    }

    for (size_t idx = 0; idx < online_logical_cores_cnt; idx++) {
        core_topo_arr[idx].is_logical_core_online =
            temp_core_topo_arr[idx].is_logical_core_online;
        core_topo_arr[idx].core_id = temp_core_topo_arr[idx].core_id;
        core_topo_arr[idx].socket_id = temp_core_topo_arr[idx].socket_id;

        int ret = copy_resource_range_to_enclave(&temp_core_topo_arr[idx].core_siblings,
                                                 &core_topo_arr[idx].core_siblings);
        if (ret < 0) {
            log_error("Copying core_topo_arr[%zu].core_siblings failed", idx);
            return -1;
        }

        ret = copy_resource_range_to_enclave(&temp_core_topo_arr[idx].thread_siblings,
                                             &core_topo_arr[idx].thread_siblings);
        if (ret < 0) {
            log_error("Copying core_topo_arr[%zu].thread_siblings failed", idx);
            return -1;
        }

        /* Shallow copy contents of cache_info_arr (untrusted pointer) into enclave */
        struct pal_core_cache_info* temp_cache_info_arr =
            malloc(cache_indices_cnt * sizeof(*temp_cache_info_arr));
        if (!temp_cache_info_arr) {
            log_error("Allocation for shallow copy of cache_info_arr failed");
            return -1;
        }

        if (!sgx_copy_to_enclave(temp_cache_info_arr,
                                 cache_indices_cnt * sizeof(*temp_cache_info_arr),
                                 temp_core_topo_arr->cache_info_arr,
                                 cache_indices_cnt *
                                 sizeof(*temp_core_topo_arr->cache_info_arr))) {
            log_error("Shallow copy of cache_info_arr into the enclave failed");
            return -1;
        }

        /* Allocate enclave memory to store cache info */
        struct pal_core_cache_info* cache_info_arr =
            malloc(cache_indices_cnt * sizeof(*cache_info_arr));
        if (!cache_info_arr) {
            log_error("Allocation for cache_info_arr failed");
            return -1;
        }

        for (size_t lvl = 0; lvl < cache_indices_cnt; lvl++) {
            cache_info_arr[lvl].level = temp_cache_info_arr[lvl].level;
            cache_info_arr[lvl].type = temp_cache_info_arr[lvl].type;
            cache_info_arr[lvl].size = temp_cache_info_arr[lvl].size;
            cache_info_arr[lvl].coherency_line_size = temp_cache_info_arr[lvl].coherency_line_size;
            cache_info_arr[lvl].number_of_sets = temp_cache_info_arr[lvl].number_of_sets;
            cache_info_arr[lvl].physical_line_partition =
                 temp_cache_info_arr[lvl].physical_line_partition;

            ret = copy_resource_range_to_enclave(&temp_cache_info_arr[lvl].shared_cpu_map,
                                                 &cache_info_arr[lvl].shared_cpu_map);
            if (ret < 0) {
                log_error("Copying cache_info_arr[%zu].shared_cpu_map failed", lvl);
                return -1;
            }
        }

        core_topo_arr[idx].cache_info_arr = cache_info_arr;
        free(temp_cache_info_arr);
    }

    *out_core_topo_arr = core_topo_arr;

    free(temp_core_topo_arr);
    return 0;
}

/* This function doesn't clean up resources on failure as we terminate the process anyway. */
static int sgx_copy_numa_topo_to_enclave(struct pal_numa_topo_info* uptr_src,
                                         size_t online_nodes_cnt,
                                         struct pal_numa_topo_info** out_numa_topo_arr) {
    assert(out_numa_topo_arr);

    struct pal_numa_topo_info* temp_numa_topo_arr =
        malloc(online_nodes_cnt * sizeof(*temp_numa_topo_arr));
    if (!temp_numa_topo_arr) {
        log_error("Allocation for shallow copy of numa_topo_arr failed");
        return -1;
    }

    /* Shallow copy contents of numa_topo_arr (uptr_src) into enclave */
    if (!sgx_copy_to_enclave(temp_numa_topo_arr,
                             online_nodes_cnt * sizeof(*temp_numa_topo_arr), uptr_src,
                             online_nodes_cnt * sizeof(*uptr_src))) {
        log_error("Shallow copy of numa_topo_arr into the enclave failed");
        return -1;
    }

    struct pal_numa_topo_info* numa_topo_arr = malloc(online_nodes_cnt * sizeof(*numa_topo_arr));
    if (!numa_topo_arr) {
        log_error("Allocation for numa_topo_arr failed");
        return -1;
    }

    for (size_t idx = 0; idx < online_nodes_cnt; idx++) {
        numa_topo_arr[idx].nr_hugepages[HUGEPAGES_2M] =
            temp_numa_topo_arr[idx].nr_hugepages[HUGEPAGES_2M];
        numa_topo_arr[idx].nr_hugepages[HUGEPAGES_1G] =
            temp_numa_topo_arr[idx].nr_hugepages[HUGEPAGES_1G];

        int ret = copy_resource_range_to_enclave(&temp_numa_topo_arr[idx].cpumap,
                                                 &numa_topo_arr[idx].cpumap);
        if (ret < 0) {
            log_error("Copying numa_topo_arr[%zu].cpumap failed", idx);
            return -1;
        }

        ret = copy_resource_range_to_enclave(&temp_numa_topo_arr[idx].distance,
                                             &numa_topo_arr[idx].distance);
        if (ret < 0) {
            log_error("Copying numa_topo_arr[%zu].distance failed", idx);
            return -1;
        }
    }

    *out_numa_topo_arr = numa_topo_arr;

    free(temp_numa_topo_arr);
    return 0;
}

/* This function does the following 3 sanitizations for a given resource range:
 * 1. Ensures the resource as well as range count doesn't exceed limits.
 * 2. Ensures that ranges don't overlap like "1-5, 3-4".
 * 3. Ensures the ranges aren't malformed like "1-5, 7-1".
 * Returns -1 error on failure and 0 on success.
 */
static int sanitize_hw_resource_range(struct pal_res_range_info* res_info, size_t res_min_limit,
                                      size_t res_max_limit, size_t range_min_limit,
                                      size_t range_max_limit) {
    size_t resource_cnt = res_info->resource_cnt;
    if (!IS_IN_RANGE_INCL(resource_cnt, res_min_limit, res_max_limit)) {
        log_error("Invalid resource count: %zu", resource_cnt);
        return -1;
    }

    size_t ranges_cnt = res_info->ranges_cnt;
    if (!IS_IN_RANGE_INCL(ranges_cnt, 1, 1 << 7)) {
        log_error("Invalid range count: %zu", ranges_cnt);
        return -1;
    }

    if (!res_info->ranges_arr)
        return -1;

    bool check_for_overlaps = false;
    size_t previous_end = 0;
    size_t resource_cnt_from_ranges = 0;
    for (size_t i = 0; i < ranges_cnt; i++) {

        size_t start = res_info->ranges_arr[i].start;
        size_t end = res_info->ranges_arr[i].end;

        /* Ensure start and end fall within range limits */
        if (!IS_IN_RANGE_INCL(start, range_min_limit, range_max_limit)) {
            log_error("Invalid start of range: %zu", start);
            return -1;
        }

        if ((start != end) && !IS_IN_RANGE_INCL(end, start + 1, range_max_limit)) {
            log_error("Invalid end of range: %zu", end);
            return -1;
        }

        resource_cnt_from_ranges += end - start + 1;

        /* check for overlaps like "1-5, 3-4". Note: we skip this check for first time as
         *`previous_end` is not yet initialized. */
        if (check_for_overlaps && previous_end >= start) {
            log_error("Overlapping ranges: previous_end = %zu, current start = %zu", previous_end,
                      start);
            return -1;
        }
        previous_end = end;

        /* Start checking for overlaps after the first range */
        check_for_overlaps = true;
    }

    if (resource_cnt_from_ranges != resource_cnt) {
        log_error("Mismatch between resource_cnt and resource_cnt_from_ranges");
        return -1;
    }

    return 0;
}

static int sanitize_cache_topology_info(struct pal_core_cache_info* cache_info_arr,
                                        size_t online_logical_cores_cnt, size_t cache_indices_cnt) {
    for (size_t lvl = 0; lvl < cache_indices_cnt; lvl++) {
        if (cache_info_arr[lvl].type != CACHE_TYPE_DATA &&
            cache_info_arr[lvl].type != CACHE_TYPE_INSTRUCTION &&
            cache_info_arr[lvl].type != CACHE_TYPE_UNIFIED) {
            return -1;
        }

        size_t max_limit;
        if (cache_info_arr[lvl].type == CACHE_TYPE_DATA ||
                cache_info_arr[lvl].type == CACHE_TYPE_INSTRUCTION) {
            /* Taking HT into account */
            max_limit = MAX_HYPERTHREADS_PER_CORE;
        } else {
            /* if unified cache then it can range up to total number of cores. */
            max_limit = online_logical_cores_cnt;
        }

        /* Recall that `shared_cpu_map` shows this core + its siblings (if HT is enabled), for
         * example: /sys/devices/system/cpu/cpu1/cache/index1/shared_cpu_map: 00000000,00000002 */
        int ret = sanitize_hw_resource_range(&cache_info_arr[lvl].shared_cpu_map, 1, max_limit, 0,
                                             online_logical_cores_cnt);
        if (ret < 0) {
            log_error("Invalid cache[%zu].shared_cpu_map", lvl);
            return -1;
        }

        if (!IS_IN_RANGE_INCL(cache_info_arr[lvl].level, 1, MAX_CACHE_LEVELS))
            return -1;

        if (!IS_IN_RANGE_INCL(cache_info_arr[lvl].size, 1, 1 << 30))
            return -1;

        if (!IS_IN_RANGE_INCL(cache_info_arr[lvl].coherency_line_size, 1, 1 << 16))
            return -1;

        if (!IS_IN_RANGE_INCL(cache_info_arr[lvl].number_of_sets, 1, 1 << 30))
            return -1;

        if (!IS_IN_RANGE_INCL(cache_info_arr[lvl].physical_line_partition, 1, 1 << 16))
            return -1;
    }
    return 0;
}

/* For each socket, cross-verify that its set of cores is the same as the core topology's
 * core-siblings:
 * - Pick the first core in the socket.
 * - Find its core-siblings in the core topology.
 * - Verify that the "cores in the socket info" array is exactly the same as "core-siblings
 *   present in core topology" array.
 */
static int sanitize_socket_info(struct pal_core_topo_info* core_topo_arr,
                                struct pal_res_range_info* socket_info_arr, size_t sockets_cnt) {
    for (size_t idx = 0; idx < sockets_cnt; idx++) {
        if (!socket_info_arr[idx].ranges_cnt || !socket_info_arr[idx].ranges_arr) {
            return -1;
        }

        size_t core_in_socket = socket_info_arr[idx].ranges_arr[0].start;
        struct pal_res_range_info* core_siblings = &core_topo_arr[core_in_socket].core_siblings;

        if (core_siblings->ranges_cnt != socket_info_arr[idx].ranges_cnt) {
            return -1;
        }

        for (size_t j = 0; j < core_siblings->ranges_cnt; j++) {
            if (socket_info_arr[idx].ranges_arr[j].start != core_siblings->ranges_arr[j].start ||
                    socket_info_arr[idx].ranges_arr[j].end != core_siblings->ranges_arr[j].end) {
                return -1;
            }
        }
    }

    return 0;
}

/* This function doesn't clean up resources on failure as we terminate the process anyway. */
static int sanitize_core_topology_info(struct pal_core_topo_info* core_topo_arr,
                                       size_t online_logical_cores_cnt, size_t cache_indices_cnt,
                                       size_t sockets_cnt) {
    int ret;

    struct pal_res_range_info* socket_info_arr = calloc(sockets_cnt, sizeof(*socket_info_arr));
    if (!socket_info_arr)
        return -1;

    for (size_t idx = 0; idx < online_logical_cores_cnt; idx++) {
        if (core_topo_arr[idx].core_id > online_logical_cores_cnt - 1) {
            ret = -1;
            goto out;
        }

        ret = sanitize_hw_resource_range(&core_topo_arr[idx].core_siblings, 1,
                                         online_logical_cores_cnt, 0, online_logical_cores_cnt);
        if (ret < 0) {
            log_error("Invalid core_topo_arr[%zu].core_siblings", idx);
            goto out;
        }

        /* Max. SMT siblings currently supported on x86 processors is 4 */
        ret = sanitize_hw_resource_range(&core_topo_arr[idx].thread_siblings, 1,
                                         MAX_HYPERTHREADS_PER_CORE, 0, online_logical_cores_cnt);
        if (ret < 0) {
            log_error("Invalid core_topo_arr[%zu].thread_siblings", idx);
            goto out;
        }

        ret = sanitize_cache_topology_info(core_topo_arr[idx].cache_info_arr,
                                           online_logical_cores_cnt, cache_indices_cnt);
        if (ret < 0) {
            log_error("Invalid core_topo_arr[%zu].cache_info_arr", idx);
            goto out;
        }

        /* To sanitize the socket, there are 2 steps:
         * #1. From the socket_id of each core, create a range of cores present in each socket.
         * #2. Compare array of cores in each socket against the array of core-siblings from
         *     the core topology.
         */
        size_t socket_id = core_topo_arr[idx].socket_id;
        if (socket_id > sockets_cnt - 1) {
            ret = -1;
            goto out;
        }

        /* Step #1 */
        static size_t prev_socket_id = UINT32_MAX;
        if (socket_id != prev_socket_id) {
            socket_info_arr[socket_id].ranges_cnt++;
            size_t new_size = sizeof(struct pal_range_info) * socket_info_arr[socket_id].ranges_cnt;
            size_t old_size = new_size - sizeof(struct pal_range_info);
            /* TODO: Optimize realloc by doing some overestimation and trimming later once the
             * range count is known */
            struct pal_range_info* tmp = malloc(new_size);
            if (!tmp) {
                ret = -1;
                goto out;
            }

            if (socket_info_arr[socket_id].ranges_arr) {
                memcpy(tmp, socket_info_arr[socket_id].ranges_arr, old_size);
                free(socket_info_arr[socket_id].ranges_arr);
            }
            socket_info_arr[socket_id].ranges_arr = tmp;

            size_t range_idx = socket_info_arr[socket_id].ranges_cnt - 1;
            socket_info_arr[socket_id].ranges_arr[range_idx].start = idx;
            socket_info_arr[socket_id].ranges_arr[range_idx].end = idx;
            prev_socket_id = socket_id;
        } else {
            size_t range_idx = socket_info_arr[socket_id].ranges_cnt - 1;
            socket_info_arr[socket_id].ranges_arr[range_idx].end = idx;
        }
    }

    /* Step #2 */
    ret = sanitize_socket_info(core_topo_arr, socket_info_arr, sockets_cnt);
    if (ret < 0)
        goto out;

    ret = 0;
out:
    for (size_t i = 0; i < sockets_cnt; i++) {
        if (socket_info_arr[i].ranges_arr)
            free(socket_info_arr[i].ranges_arr);
    }
    free(socket_info_arr);
    return ret;
}

/* This function doesn't clean up resources on failure as we terminate the process anyway. */
static int sanitize_numa_topology_info(struct pal_numa_topo_info* numa_topo_arr,
                                       size_t online_nodes_cnt, size_t online_logical_cores_cnt,
                                       size_t possible_logical_cores_cnt) {
    int ret;
    size_t cpumask_cnt = BITS_TO_UINT32S(possible_logical_cores_cnt);

    uint32_t* bitmap = calloc(cpumask_cnt, sizeof(*bitmap));
    if (!bitmap)
        return -1;

    size_t total_cores_in_numa = 0;
    for (size_t idx = 0; idx < online_nodes_cnt; idx++) {
        ret = sanitize_hw_resource_range(&numa_topo_arr[idx].cpumap, 1,
                                         online_logical_cores_cnt, 0, online_logical_cores_cnt);
        if (ret < 0) {
            log_error("Invalid numa_topo_arr[%zu].cpumap", idx);
            goto out;
        }

        /* Ensure that each NUMA has unique cores */
        for (size_t i = 0; i < numa_topo_arr[idx].cpumap.ranges_cnt; i++) {
            size_t start = numa_topo_arr[idx].cpumap.ranges_arr[i].start;
            size_t end = numa_topo_arr[idx].cpumap.ranges_arr[i].end;
            for (size_t j = start; j <= end; j++) {
                size_t index = j / BITS_IN_TYPE(uint32_t);
                if (index >= cpumask_cnt) {
                    log_error("Invalid numa topology: Core %zu is beyond CPU mask limit", j);
                    ret = -1;
                    goto out;
                }

                if (bitmap[index] & (1U << (j % BITS_IN_TYPE(uint32_t)))) {
                    log_error("Invalid numa_topology: Core %zu found in multiple numa nodes", j);
                    ret = -1;
                    goto out;
                }
                bitmap[index] |= 1U << (j % BITS_IN_TYPE(uint32_t));
                total_cores_in_numa++;
            }
        }

        size_t distances = numa_topo_arr[idx].distance.resource_cnt;
        if (distances != online_nodes_cnt) {
            log_error("Distance count is not same as the NUMA nodes count");
            ret = -1;
            goto out;
        }
    }

    if (total_cores_in_numa != online_logical_cores_cnt) {
        log_error("Invalid numa_topology: Mismatch between NUMA cores and online cores count");
        ret = -1;
        goto out;
    }

    ret = 0;

out:
    free(bitmap);
    return ret;
}

extern void* g_enclave_base;
extern void* g_enclave_top;
extern bool g_allowed_files_warn;

static int print_warnings_on_insecure_configs(PAL_HANDLE parent_process) {
    int ret;

    if (parent_process) {
        /* Warn only in the first process. */
        return 0;
    }

    bool verbose_log_level    = false;
    bool sgx_debug            = false;
    bool use_cmdline_argv     = false;
    bool use_host_env         = false;
    bool disable_aslr         = false;
    bool allow_eventfd        = false;
    bool allow_all_files      = false;
    bool use_allowed_files    = g_allowed_files_warn;
    bool protected_files_key  = false;
    bool encrypted_files_keys = false;
    bool enable_sysfs_topo    = false;

    char* log_level_str = NULL;
    char* protected_files_key_str = NULL;

    ret = toml_string_in(g_pal_public_state.manifest_root, "loader.log_level", &log_level_str);
    if (ret < 0)
        goto out;
    if (log_level_str && strcmp(log_level_str, "none") && strcmp(log_level_str, "error"))
        verbose_log_level = true;

    ret = toml_bool_in(g_pal_public_state.manifest_root, "sgx.debug",
                       /*defaultval=*/false, &sgx_debug);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_public_state.manifest_root, "loader.insecure__use_cmdline_argv",
                       /*defaultval=*/false, &use_cmdline_argv);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_public_state.manifest_root, "loader.insecure__use_host_env",
                       /*defaultval=*/false, &use_host_env);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_public_state.manifest_root, "loader.insecure__disable_aslr",
                       /*defaultval=*/false, &disable_aslr);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_public_state.manifest_root, "sys.insecure__allow_eventfd",
                       /*defaultval=*/false, &allow_eventfd);
    if (ret < 0)
        goto out;

    if (get_file_check_policy() == FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG)
        allow_all_files = true;

    ret = toml_string_in(g_pal_public_state.manifest_root, "sgx.insecure__protected_files_key",
                         &protected_files_key_str);
    if (ret < 0)
        goto out;
    if (protected_files_key_str)
        protected_files_key = true;

    toml_table_t* manifest_fs = toml_table_in(g_pal_public_state.manifest_root, "fs");
    if (manifest_fs) {
        toml_table_t* manifest_fs_keys = toml_table_in(manifest_fs, "insecure__keys");
        if (manifest_fs_keys) {
            ret = toml_table_nkval(manifest_fs_keys);
            if (ret < 0)
                goto out;

            if (ret > 0)
                encrypted_files_keys = true;
        }
    }

    ret = toml_bool_in(g_pal_public_state.manifest_root, "fs.experimental__enable_sysfs_topology",
                       /*defaultval=*/false, &enable_sysfs_topo);
    if (ret < 0)
        goto out;

    if (!verbose_log_level && !sgx_debug && !use_cmdline_argv && !use_host_env && !disable_aslr &&
            !allow_eventfd && !allow_all_files && !use_allowed_files && !protected_files_key &&
            !encrypted_files_keys && !enable_sysfs_topo) {
        /* there are no insecure configurations, skip printing */
        ret = 0;
        goto out;
    }

    log_always("-------------------------------------------------------------------------------"
               "----------------------------------------");
    log_always("Gramine detected the following insecure configurations:\n");

    if (sgx_debug)
        log_always("  - sgx.debug = true                           "
                   "(this is a debug enclave)");

    if (verbose_log_level)
        log_always("  - loader.log_level = warning|debug|trace|all "
                   "(verbose log level, may leak information)");

    if (use_cmdline_argv)
        log_always("  - loader.insecure__use_cmdline_argv = true   "
                   "(forwarding command-line args from untrusted host to the app)");

    if (use_host_env)
        log_always("  - loader.insecure__use_host_env = true       "
                   "(forwarding environment vars from untrusted host to the app)");

    if (disable_aslr)
        log_always("  - loader.insecure__disable_aslr = true       "
                   "(Address Space Layout Randomization is disabled)");

    if (allow_eventfd)
        log_always("  - sys.insecure__allow_eventfd = true         "
                   "(host-based eventfd is enabled)");

    if (allow_all_files)
        log_always("  - sgx.file_check_policy = allow_all_but_log  "
                   "(all files are passed through from untrusted host without verification)");

    if (use_allowed_files)
        log_always("  - sgx.allowed_files = [ ... ]                "
                   "(some files are passed through from untrusted host without verification)");

    if (protected_files_key)
        log_always("  - sgx.insecure__protected_files_key = \"...\"  "
                   "(key hardcoded in manifest)");

    if (encrypted_files_keys)
        log_always("  - fs.insecure__keys.* = \"...\"                "
                   "(keys hardcoded in manifest)");

    if (enable_sysfs_topo)
        log_always("  - fs.experimental__enable_sysfs_topology = true "
                   "(forwarding sysfs topology from untrusted host to the app)");

    log_always("\nGramine will continue application execution, but this configuration must not be "
               "used in production!");
    log_always("-------------------------------------------------------------------------------"
               "----------------------------------------\n");

    ret = 0;
out:
    free(log_level_str);
    free(protected_files_key_str);
    return ret;
}

static int copy_and_sanitize_topo_info(struct pal_topo_info* uptr_topo_info,
                                       bool enable_sysfs_topology) {
    int ret;

    /* Extract topology information from untrusted pointer. Note this is only a shallow copy
     * and we use this temp variable to do deep copy into `topo_info` struct part of
     * g_pal_public_state */
    struct pal_topo_info temp_topo_info;
    if (!sgx_copy_to_enclave(&temp_topo_info, sizeof(temp_topo_info),
                             uptr_topo_info, sizeof(*uptr_topo_info))) {
        log_error("Copying topo_info into the enclave failed");
        return -1;
    }

    struct pal_topo_info* topo_info = &g_pal_public_state.topo_info;

    ret = copy_resource_range_to_enclave(&temp_topo_info.possible_logical_cores,
                                         &topo_info->possible_logical_cores);
    if (ret < 0) {
        log_error("Copying possible_logical_cores failed");
        return -1;
    }
    ret = sanitize_hw_resource_range(&topo_info->possible_logical_cores, 1, 1 << 16, 0, 1 << 16);
    if (ret < 0) {
        log_error("Invalid possible_logical_cores received from the host");
        return -1;
    }

    ret = copy_resource_range_to_enclave(&temp_topo_info.online_logical_cores,
                                         &topo_info->online_logical_cores);
    if (ret < 0) {
        log_error("Copying online_logical_cores failed");
        return -1;
    }
    ret = sanitize_hw_resource_range(&topo_info->online_logical_cores, 1, 1 << 16, 0, 1 << 16);
    if (ret < 0) {
        log_error("Invalid online_logical_cores received from the host");
        return -1;
    }

    size_t online_logical_cores_cnt = topo_info->online_logical_cores.resource_cnt;
    size_t possible_logical_cores_cnt = topo_info->possible_logical_cores.resource_cnt;
    if (online_logical_cores_cnt > possible_logical_cores_cnt) {
        log_error("Impossible configuration: more online cores (%zu) than possible cores (%zu)",
                   online_logical_cores_cnt, possible_logical_cores_cnt);
        return -1;
    }

    topo_info->physical_cores_per_socket = temp_topo_info.physical_cores_per_socket;
    if (!IS_IN_RANGE_INCL(topo_info->physical_cores_per_socket, 1, 1 << 13)) {
        log_error("Invalid physical_cores_per_socket: %zu received from the host",
                   topo_info->physical_cores_per_socket);
        return -1;
    }

    /* Advanced host topology information */
    if (!enable_sysfs_topology) {
        /* TODO: temporary measure, remove it once sysfs topology is thoroughly validated */
        return 0;
    }

    topo_info->sockets_cnt = temp_topo_info.sockets_cnt;
    /* Virtual environments such as QEMU may assign each core to a separate socket/package with
     * one or more NUMA nodes. So we check against the number of online logical cores. */
    if (!IS_IN_RANGE_INCL(topo_info->sockets_cnt, 1, online_logical_cores_cnt)) {
        log_error("Invalid sockets_cnt: %zu received from the host", topo_info->sockets_cnt);
        return -1;
    }

    topo_info->cache_indices_cnt = temp_topo_info.cache_indices_cnt;
    if (!IS_IN_RANGE_INCL(topo_info->cache_indices_cnt, 1, 1 << 4)) {
        log_error("Invalid cache_indices_cnt: %zu received from the host",
                   topo_info->cache_indices_cnt);
        return -1;
    }

    /* Allocate enclave memory to store core topology info */
    ret = sgx_copy_core_topo_to_enclave(temp_topo_info.core_topo_arr, online_logical_cores_cnt,
                                        topo_info->cache_indices_cnt,
                                        &topo_info->core_topo_arr);
    if (ret < 0) {
        log_error("Copying core_topo_arr into the enclave failed");
        return -1;
    }

    ret = sanitize_core_topology_info(topo_info->core_topo_arr, online_logical_cores_cnt,
                                      topo_info->cache_indices_cnt, topo_info->sockets_cnt);
    if (ret < 0) {
        log_error("Sanitization of core_topology failed");
        return -1;
    }

    ret = copy_resource_range_to_enclave(&temp_topo_info.online_nodes, &topo_info->online_nodes);
    if (ret < 0) {
        log_error("Copying online_nodes into the enclave failed");
        return -1;
    }

    ret = sanitize_hw_resource_range(&topo_info->online_nodes, 1, 1 << 16, 0, 1 << 16);
    if (ret < 0) {
        log_error("Invalid online_nodes received from the host");
        return -1;
    }

    size_t online_nodes_cnt = topo_info->online_nodes.resource_cnt;
    ret = sgx_copy_numa_topo_to_enclave(temp_topo_info.numa_topo_arr, online_nodes_cnt,
                                        &topo_info->numa_topo_arr);
    if (ret < 0) {
        log_error("Copying numa_topo_arr into the enclave failed");
        return -1;
    }

    ret = sanitize_numa_topology_info(topo_info->numa_topo_arr, online_nodes_cnt,
                                      online_logical_cores_cnt, possible_logical_cores_cnt);
    if (ret < 0) {
        log_error("Sanitization of numa_topo_arr failed");
        return -1;
    }

    return 0;
}

__attribute_no_sanitize_address
static void do_preheat_enclave(void) {
    for (uint8_t* i = g_pal_linuxsgx_state.heap_min; i < (uint8_t*)g_pal_linuxsgx_state.heap_max;
             i += g_page_size) {
        READ_ONCE(*(size_t*)i);
    }
}

/* Gramine uses GCC's stack protector that looks for a canary at gs:[0x8], but this function starts
 * with a default canary and then updates it to a random one, so we disable stack protector here */
__attribute_no_stack_protector
noreturn void pal_linux_main(char* uptr_libpal_uri, size_t libpal_uri_len, char* uptr_args,
                             size_t args_size, char* uptr_env, size_t env_size,
                             int parent_stream_fd, unsigned int host_euid, unsigned int host_egid,
                             sgx_target_info_t* uptr_qe_targetinfo,
                             struct pal_topo_info* uptr_topo_info) {
    /* All our arguments are coming directly from the urts. We are responsible to check them. */
    int ret;

    /* Relocate PAL */
    ret = setup_pal_binary();
    if (ret < 0) {
        log_error("Relocation of the PAL binary failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    uint64_t start_time;
    ret = _DkSystemTimeQuery(&start_time);
    if (ret < 0) {
        log_error("_DkSystemTimeQuery() failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    call_init_array();

    /* Initialize alloc_align as early as possible, a lot of PAL APIs depend on this being set. */
    g_pal_public_state.alloc_align = g_page_size;
    assert(IS_POWER_OF_2(g_pal_public_state.alloc_align));

    g_pal_linuxsgx_state.heap_min = GET_ENCLAVE_TLS(heap_min);
    g_pal_linuxsgx_state.heap_max = GET_ENCLAVE_TLS(heap_max);

    /* Skip URI_PREFIX_FILE. */
    if (libpal_uri_len < URI_PREFIX_FILE_LEN) {
        log_error("Invalid libpal_uri length (missing \"%s\" prefix?)", URI_PREFIX_FILE);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    libpal_uri_len -= URI_PREFIX_FILE_LEN;
    uptr_libpal_uri += URI_PREFIX_FILE_LEN;

    /* At this point we don't yet have memory manager, so we cannot allocate memory dynamically. */
    static char libpal_path[1024 + 1];
    if (libpal_uri_len >= sizeof(libpal_path)
            || !sgx_copy_to_enclave(libpal_path, sizeof(libpal_path) - 1, uptr_libpal_uri,
                                    libpal_uri_len)) {
        log_error("Copying libpal_path into the enclave failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    libpal_path[libpal_uri_len] = '\0';

    /* Now that we have `libpal_path`, set name for PAL map */
    set_pal_binary_name(libpal_path);

    /* We can't verify the following arguments from the urts. So we copy them directly but need to
     * be careful when we use them. */
    if (!sgx_copy_to_enclave(&g_pal_linuxsgx_state.qe_targetinfo,
                             sizeof(g_pal_linuxsgx_state.qe_targetinfo),
                             uptr_qe_targetinfo,
                             sizeof(*uptr_qe_targetinfo))) {
        log_error("Copying qe_targetinfo into the enclave failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    g_pal_linuxsgx_state.host_euid = host_euid;
    g_pal_linuxsgx_state.host_egid = host_egid;

    /* Set up page allocator and slab manager. There is no need to provide any initial memory pool,
     * because the slab manager can use normal allocations (`_DkVirtualMemoryAlloc`) right away. */
    init_slab_mgr(/*mem_pool=*/NULL, /*mem_pool_size=*/0);
    init_untrusted_slab_mgr();

    /* initialize enclave properties */
    ret = init_enclave();
    if (ret) {
        log_error("Failed to initialize enclave properties: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if (args_size > MAX_ARGS_SIZE || env_size > MAX_ENV_SIZE) {
        log_error("Invalid args_size (%lu) or env_size (%lu)", args_size, env_size);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    const char** arguments = make_argv_list(uptr_args, args_size);
    if (!arguments) {
        log_error("Creating arguments failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    const char** environments = make_argv_list(uptr_env, env_size);
    if (!environments) {
        log_error("Creating environments failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    SET_ENCLAVE_TLS(ready_for_exceptions, 1UL);

    /* initialize "Invariant TSC" HW feature for fast and accurate gettime and immediately probe
     * RDTSC instruction inside SGX enclave (via dummy get_tsc) -- it is possible that
     * the CPU supports invariant TSC but doesn't support executing RDTSC inside SGX enclave, in
     * this case the SIGILL exception is generated and leads to emulate_rdtsc_and_print_warning()
     * which unsets invariant TSC, and we end up falling back to the slower ocall_gettime() */
    init_tsc();
    (void)get_tsc(); /* must be after `ready_for_exceptions=1` since it may generate SIGILL */

    /* initialize master key (used for pipes' encryption for all enclaves of an application); it
     * will be overwritten below in init_child_process() with inherited-from-parent master key if
     * this enclave is child */
    ret = _DkRandomBitsRead(&g_master_key, sizeof(g_master_key));
    if (ret < 0) {
        log_error("_DkRandomBitsRead failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* if there is a parent, create parent handle */
    PAL_HANDLE parent = NULL;
    uint64_t instance_id = 0;
    if (parent_stream_fd != -1) {
        if ((ret = init_child_process(parent_stream_fd, &parent, &instance_id)) < 0) {
            log_error("Failed to initialize child process: %d", ret);
            ocall_exit(1, /*is_exitgroup=*/true);
        }
    }

    uint64_t manifest_size = GET_ENCLAVE_TLS(manifest_size);
    void* manifest_addr = g_enclave_top - ALIGN_UP_PTR_POW2(manifest_size, g_page_size);

    ret = add_preloaded_range((uintptr_t)manifest_addr, (uintptr_t)manifest_addr + manifest_size,
                              "manifest");
    if (ret < 0) {
        log_error("Failed to initialize manifest preload range: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* TOML parser (for whatever reason) allocates a lot of memory when parsing the manifest into an
     * in-memory struct. We heuristically pre-allocate additional PAL internal memory if the
     * manifest file looks large enough. Hopefully below sizes are sufficient for any manifest.
     *
     * FIXME: this is a quick hack, we need proper memory allocation in PAL. */
    if (manifest_size > 10 * 1024 * 1024) {
        log_always("Detected a huge manifest, preallocating 128MB of internal memory.");
        g_pal_internal_mem_size += 128 * 1024 * 1024; /* 10MB manifest -> 64 + 128 MB PAL mem */
    } else if (manifest_size > 5 * 1024 * 1024) {
        log_always("Detected a huge manifest, preallocating 64MB of internal memory.");
        g_pal_internal_mem_size += 64 * 1024 * 1024; /* 5MB manifest -> 64 + 64 MB PAL mem */
    }

    /* parse manifest */
    char errbuf[256];
    toml_table_t* manifest_root = toml_parse(manifest_addr, errbuf, sizeof(errbuf));
    if (!manifest_root) {
        log_error("PAL failed at parsing the manifest: %s", errbuf);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_common_state.raw_manifest_data = manifest_addr;
    g_pal_public_state.manifest_root = manifest_root;

    /* parse and store host topology info into g_pal_linuxsgx_state struct */
    bool enable_sysfs_topology; /* TODO: remove this manifest option once sysfs topo is stable */
    ret = toml_bool_in(g_pal_public_state.manifest_root, "fs.experimental__enable_sysfs_topology",
                       /*defaultval=*/false, &enable_sysfs_topology);
    if (ret < 0) {
        log_error("Cannot parse 'fs.experimental__enable_sysfs_topology' (the value must be `true` "
                  "or `false`)");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    ret = copy_and_sanitize_topo_info(uptr_topo_info, enable_sysfs_topology);
    if (ret < 0) {
        log_error("Failed to copy and sanitize topology information");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    bool preheat_enclave;
    ret = toml_bool_in(g_pal_public_state.manifest_root, "sgx.preheat_enclave",
                       /*defaultval=*/false, &preheat_enclave);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.preheat_enclave' (the value must be `true` or `false`)");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    if (preheat_enclave)
        do_preheat_enclave();

    /* For backward compatibility, `loader.pal_internal_mem_size` does not include
     * PAL_INITIAL_MEM_SIZE */
    size_t extra_mem_size;
    ret = toml_sizestring_in(g_pal_public_state.manifest_root, "loader.pal_internal_mem_size",
                             /*defaultval=*/0, &extra_mem_size);
    if (ret < 0) {
        log_error("Cannot parse 'loader.pal_internal_mem_size'");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if (extra_mem_size + PAL_INITIAL_MEM_SIZE < g_pal_internal_mem_size) {
        log_error("Too small `loader.pal_internal_mem_size`, need at least %luMB because the "
                  "manifest is large",
                  (g_pal_internal_mem_size - PAL_INITIAL_MEM_SIZE) / 1024 / 1024);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_internal_mem_size = extra_mem_size + PAL_INITIAL_MEM_SIZE;

    /* seal-key material initialization must come before protected-files initialization */
    if ((ret = init_seal_key_material()) < 0) {
        log_error("Failed to initialize SGX sealing key material: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if ((ret = init_file_check_policy()) < 0) {
        log_error("Failed to load the file check policy: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if ((ret = init_allowed_files()) < 0) {
        log_error("Failed to initialize allowed files: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if ((ret = init_trusted_files()) < 0) {
        log_error("Failed to initialize trusted files: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if ((ret = init_protected_files()) < 0) {
        log_error("Failed to initialize protected files: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* this should be placed *after all* initialize-from-manifest routines */
    if ((ret = print_warnings_on_insecure_configs(parent)) < 0) {
        log_error("Cannot parse the manifest (while checking for insecure configurations)");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* set up thread handle */
    PAL_HANDLE first_thread = calloc(1, HANDLE_SIZE(thread));
    if (!first_thread) {
        log_error("Out of memory");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    init_handle_hdr(first_thread, PAL_TYPE_THREAD);
    first_thread->thread.tcs = g_enclave_base + GET_ENCLAVE_TLS(tcs_offset);
    /* child threads are assigned TIDs 2,3,...; see pal_start_thread() */
    first_thread->thread.tid = 1;
    g_pal_public_state.first_thread = first_thread;
    SET_ENCLAVE_TLS(thread, &first_thread->thread);

    uint64_t stack_protector_canary;
    ret = _DkRandomBitsRead(&stack_protector_canary, sizeof(stack_protector_canary));
    if (ret < 0) {
        log_error("_DkRandomBitsRead failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    pal_set_tcb_stack_canary(stack_protector_canary);

    assert(!g_pal_linuxsgx_state.enclave_initialized);
    g_pal_linuxsgx_state.enclave_initialized = true;

    /* call main function */
    pal_main(instance_id, parent, first_thread, arguments, environments);
}
