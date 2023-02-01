/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Labs */

#include "api.h"
#include "elf/elf.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_rtld.h"

/* iterate through ELF's program headers to find dynamic section (for dynamic linking) */
elf_dyn_t* find_dynamic_section(elf_addr_t ehdr_addr, elf_addr_t base_diff) {
    const elf_ehdr_t* header = (const elf_ehdr_t*)ehdr_addr;
    const elf_phdr_t* phdr   = (const elf_phdr_t*)(ehdr_addr + header->e_phoff);

    elf_dyn_t* dynamic_section = NULL;
    for (const elf_phdr_t* ph = phdr; ph < &phdr[header->e_phnum]; ph++) {
        if (ph->p_type == PT_DYNAMIC) {
            dynamic_section = (elf_dyn_t*)(ph->p_vaddr + base_diff);
            break;
        }
    }

    return dynamic_section;
}

int find_string_and_symbol_tables(elf_addr_t ehdr_addr, elf_addr_t base_diff,
                                  const char** out_string_table, elf_sym_t** out_symbol_table,
                                  uint32_t* out_symbol_table_cnt) {
    const char* string_table  = NULL;
    elf_sym_t* symbol_table   = NULL;
    uint32_t symbol_table_cnt = 0;

    elf_dyn_t* dynamic_section = find_dynamic_section(ehdr_addr, base_diff);
    if (!dynamic_section) {
        log_error("Loaded binary doesn't have dynamic section (required for symbol resolution)");
        return -PAL_ERROR_DENIED;
    }

    /* iterate through ELF's dynamic section to find the string table and the symbol table */
    elf_dyn_t* dynamic_section_entry = dynamic_section;
    while (dynamic_section_entry->d_tag != DT_NULL) {
        switch (dynamic_section_entry->d_tag) {
            case DT_STRTAB:
                string_table = (const char*)(dynamic_section_entry->d_un.d_ptr + base_diff);
                break;
            case DT_SYMTAB:
                symbol_table = (elf_sym_t*)(dynamic_section_entry->d_un.d_ptr + base_diff);
                break;
            case DT_HASH: {
                /* symbol table size can only be found via ELF hash table's nchain (which is the
                 * second word in the ELF hash table struct) */
                elf_word_t* ht = (elf_word_t*)(dynamic_section_entry->d_un.d_ptr + base_diff);
                symbol_table_cnt = ht[1];
                break;
            }
        }
        dynamic_section_entry++;
    }

    if (!string_table || !symbol_table || !symbol_table_cnt) {
        log_error("Loaded binary doesn't have string table, symbol table and/or hash table");
        return -PAL_ERROR_DENIED;
    }

    *out_string_table     = string_table;
    *out_symbol_table     = symbol_table;
    *out_symbol_table_cnt = symbol_table_cnt;
    return 0;
}
