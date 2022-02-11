/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _SHIM_INTERNAL_ARCH_H_
#define _SHIM_INTERNAL_ARCH_H_

/*
 * The System V ABI (see section 3.4.1) expects us to set the following before jumping to the entry
 * point:
 *
 * - RDX: function pointer to be registered with `atexit` (we pass 0)
 * - RSP: the initial stack, contains program arguments and environment
 * - FLAGS: should be zeroed out
 */
#define CALL_ELF_ENTRY(ENTRY, ARGP)         \
    do {                                    \
        __asm__ volatile(                   \
            "pushq $0\r\n"                  \
            "popfq\r\n"                     \
            "movq %1, %%rsp\r\n"            \
            "jmp *%0\r\n"                   \
            :                               \
            : "r"(ENTRY), "r"(ARGP), "d"(0) \
            : "memory", "cc");              \
        __builtin_unreachable();            \
    } while(0)

#define SHIM_ELF_HOST_MACHINE EM_X86_64

#endif /* _SHIM_INTERNAL_ARCH_H_ */
