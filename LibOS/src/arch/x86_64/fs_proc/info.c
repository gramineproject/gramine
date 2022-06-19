/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2022 IBM Corporation
 */

#include "api.h"
#include "pal.h"
#include "shim_fs_proc.h"

#define ADD_INFO(fmt, ...)                                            \
    do {                                                              \
        int ret = print_to_str(str, *size, max, fmt, ##__VA_ARGS__);  \
        if (ret < 0) {                                                \
            return ret;                                               \
        }                                                             \
        *size += ret;                                                 \
    } while (0)

int proc_cpuinfo_display_cpu(char** str, size_t* size, size_t* max,
                             const struct pal_topo_info* topo,
                             const struct pal_cpu_info* cpu, size_t i,
                             struct pal_cpu_thread_info* thread) {
    struct pal_cpu_core_info* core = &topo->cores[thread->core_id];
    /* Below strings must match exactly the strings retrieved from /proc/cpuinfo
     * (see Linux's arch/x86/kernel/cpu/proc.c) */
    ADD_INFO("processor\t: %lu\n",   i);
    ADD_INFO("vendor_id\t: %s\n",    cpu->cpu_vendor);
    ADD_INFO("cpu family\t: %lu\n",  cpu->cpu_family);
    ADD_INFO("model\t\t: %lu\n",     cpu->cpu_model);
    ADD_INFO("model name\t: %s\n",   cpu->cpu_brand);
    ADD_INFO("stepping\t: %lu\n",    cpu->cpu_stepping);
    ADD_INFO("physical id\t: %zu\n", core->socket_id);

    /* Linux keeps this numbering socket-local, but we can use a different one, and it's
     * documented as "hardware platform's identifier (rather than the kernel's)" anyways. */
    ADD_INFO("core id\t\t: %lu\n",   thread->core_id);

    size_t cores_in_socket = 0;
    for (size_t j = 0; j < topo->cores_cnt; j++) { // slow, but shouldn't matter
        if (topo->cores[j].socket_id == core->socket_id)
            cores_in_socket++;
    }
    ADD_INFO("cpu cores\t: %zu\n", cores_in_socket);
    double bogomips = cpu->cpu_bogomips;
    // Apparently Gramine snprintf cannot into floats.
    ADD_INFO("bogomips\t: %lu.%02lu\n", (unsigned long)bogomips,
             (unsigned long)(bogomips * 100.0 + 0.5) % 100);
    ADD_INFO("\n");

    return 0;
}

int proc_cpuinfo_display_tail(char** str, size_t* size, size_t* max,
                              const struct pal_cpu_info* cpu) {
    __UNUSED(str);
    __UNUSED(size);
    __UNUSED(max);
    __UNUSED(cpu);

    return 0;
}
