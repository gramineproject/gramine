#pragma once

#include "linux_abi/syscalls_nr_arch.h"

/* Internal LibOS stack size: 7 pages + one guard page normally, 15 pages + one guard page when ASan
 * is enabled (stack sanitization causes functions to take up more space). */
#ifdef ASAN
#define LIBOS_THREAD_LIBOS_STACK_SIZE (15 * PAGE_SIZE + PAGE_SIZE)
#else
#define LIBOS_THREAD_LIBOS_STACK_SIZE (7 * PAGE_SIZE + PAGE_SIZE)
#endif

#define DEFAULT_BRK_MAX_SIZE   (256 * 1024)        /* 256KB */
#define DEFAULT_SYS_STACK_SIZE (256 * 1024)        /* 256KB */

#define DEFAULT_VMA_COUNT 64

/* ELF aux vectors  */
#define REQUIRED_ELF_AUXV       14 /* number of LibOS-supported vectors */
#define REQUIRED_ELF_AUXV_SPACE 16 /* extra memory space (in bytes) */

#define LIBOS_SYSCALL_BOUND __NR_syscalls
