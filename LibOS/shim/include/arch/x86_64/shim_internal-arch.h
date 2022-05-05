/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _SHIM_INTERNAL_ARCH_H_
#define _SHIM_INTERNAL_ARCH_H_

#include "elf.h"

noreturn void call_elf_entry(elf_addr_t entry, void* argp);

#define SHIM_ELF_HOST_MACHINE EM_X86_64

#endif /* _SHIM_INTERNAL_ARCH_H_ */
