#include <stddef.h>

#include "sgx_arch.h"

int ecall_enclave_start(char* libpal_uri, char* args, size_t args_size, char* env, size_t env_size,
                        int parent_stream_fd, unsigned int host_euid, unsigned int host_egid,
                        sgx_target_info_t* qe_targetinfo);

int ecall_thread_start(void);

int ecall_thread_reset(void);
