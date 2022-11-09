#pragma once

#include <stddef.h>

#include "sgx_arch.h"
#include "pal.h"
#include "pal_topology.h"

int ecall_enclave_start(char* libpal_uri, char* args, size_t args_size, char* env, size_t env_size,
                        int parent_stream_fd, sgx_target_info_t* qe_targetinfo,
                        struct pal_topo_info* topo_info, struct pal_dns_host_conf* host_conf,
                        bool edmm_enabled, void* reserved_mem_ranges,
                        size_t reserved_mem_ranges_size);

int ecall_thread_start(void);

int ecall_thread_reset(void);
