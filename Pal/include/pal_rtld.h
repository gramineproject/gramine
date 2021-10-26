/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Labs
 */

#ifndef PAL_RTLD_H
#define PAL_RTLD_H

#include <endian.h>

#include "api.h"
#include "elf/elf.h"

enum elf_object_type { ELF_OBJECT_INTERNAL, ELF_OBJECT_EXEC, ELF_OBJECT_PRELOAD };

/* Loaded shared object. */
struct link_map {
    ElfW(Addr)  l_addr;       /* Address shared object (its first LOAD segment) is loaded at. */
    ElfW(Addr)  l_base;       /* Base address (0x0 for EXECs, same as l_addr for DYNs). */
    const char* l_name;       /* Absolute file name object was found in. */
    ElfW(Dyn)*  l_ld;         /* Dynamic section of the shared object. */
    ElfW(Addr)  l_entry;      /* Entry point location (may be empty, e.g., for libs). */

    /* Chain of all shared objects loaded at startup. */
    struct link_map* l_next;
    struct link_map* l_prev;

    /* Relocation information, taken from DT_STRTAB, DT_SYMTAB and DT_HASH. */
    const char* string_table;
    ElfW(Sym)* symbol_table;
    uint32_t symbol_table_cnt;

    /* Typical case: INTERNAL type is for PAL binary, PRELOAD for LibOS lib, EXEC for PAL test. */
    enum elf_object_type l_type;
};

extern struct link_map* g_loaded_maps;

/* for GDB debugging */
void _DkDebugMapAdd(const char* name, void* addr);
void _DkDebugMapRemove(void* addr);

/* loading ELF binaries */
int load_elf_object(const char* uri, enum elf_object_type type);
int setup_pal_binary(struct link_map* pal_map);
int find_string_and_symbol_tables(ElfW(Addr) ehdr_addr, ElfW(Addr) base_addr,
                                  const char** out_string_table, ElfW(Sym)** out_symbol_table,
                                  uint32_t* out_symbol_table_cnt);

noreturn void start_execution(const char** arguments, const char** environs);

#endif /* PAL_RTLD_H */
