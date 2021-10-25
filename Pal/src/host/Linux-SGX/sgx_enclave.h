#include <stddef.h>
#include <stdint.h>

int ecall_enclave_start(char* libpal_uri, uintptr_t libpal_size, char* args, size_t args_size,
                        char* env, size_t env_size);

int ecall_thread_start(void);

int ecall_thread_reset(void);
