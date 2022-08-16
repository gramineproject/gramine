#pragma once

#include <stddef.h>

#include "sgx_arch.h"
#include "pal_ecall_types.h"

int ecall_enclave_start(char* libpal_uri, char* args, size_t args_size, char* env, size_t env_size,
                        int parent_stream_fd, sgx_target_info_t* qe_targetinfo,
                        pal_host_info_t* host_info);

int ecall_thread_start(void);

int ecall_thread_reset(void);
