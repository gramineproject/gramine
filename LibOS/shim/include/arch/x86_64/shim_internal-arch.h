/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _SHIM_INTERNAL_ARCH_H_
#define _SHIM_INTERNAL_ARCH_H_

#define CALL_ELF_ENTRY(ENTRY, ARGP)         \
    do {                                    \
        __asm__ volatile(                   \
            "movq %1, %%rsp\r\n"            \
            "jmp *%0\r\n"                   \
            :                               \
            : "r"(ENTRY), "r"(ARGP)         \
            : "memory");                    \
        __builtin_unreachable();            \
    } while(0)

#define SHIM_ELF_HOST_MACHINE EM_X86_64

#endif /* _SHIM_INTERNAL_ARCH_H_ */
