#include <stdbool.h>
#include <stddef.h>

#include "pal.h"

int get_enclave_pages(void* addr, size_t size, pal_prot_flags_t prot);
int update_enclave_page_permissions(void* addr, size_t size, pal_prot_flags_t prot);
int free_enclave_pages(void* addr, size_t size);
