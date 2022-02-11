/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _SHIM_INTERNAL_ARCH_H_
#define _SHIM_INTERNAL_ARCH_H_

/*
 * As explained in glibc (`x86_64/start.S`), the System V ABI expects us to set the following before
 * jumping to the entry point:
 *
 * - RDX: function pointer to be registered with `atexit` (we pass 0)
 * - RSP: the initial stack, which contains program arguments and environment
 */
#define CALL_ELF_ENTRY(ENTRY, ARGP)         \
    do {                                    \
        __asm__ volatile(                   \
            "movq %1, %%rsp\r\n"            \
            "jmp *%0\r\n"                   \
            :                               \
            : "r"(ENTRY), "r"(ARGP), "d"(0) \
            : "memory");                    \
        __builtin_unreachable();            \
    } while(0)

#define SHIM_ELF_HOST_MACHINE EM_X86_64

#endif /* _SHIM_INTERNAL_ARCH_H_ */
