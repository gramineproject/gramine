/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _SHIM_INTERNAL_ARCH_H_
#define _SHIM_INTERNAL_ARCH_H_

#define CALL_ELF_ENTRY(ENTRY, ARGP)           \
    do {                                      \
        __asm__ volatile(                     \
            "pushq $0\r\n"                    \
            "popfq\r\n"                       \
            "movq %%rbx, %%rsp\r\n"           \
            "jmp *%%rax\r\n"                  \
            :                                 \
            : "a"(ENTRY), "b"(ARGP), "d"(0)   \
            : "memory", "cc");                \
        __builtin_unreachable();              \
    } while(0)

#define SHIM_ELF_HOST_MACHINE EM_X86_64

#endif /* _SHIM_INTERNAL_ARCH_H_ */
