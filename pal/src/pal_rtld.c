/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Labs
 */

/*
 * This file contains utilities to load ELF binaries into the memory and link them against each
 * other. Note that PAL loads only two kinds of ELF binaries: the LibOS shared library and the PAL
 * regression tests. Both these kinds of ELF binaries are assumed to have specific ELF config:
 *
 *   - They must be linked with Full RELRO (Relocation Read-Only); this simplifies relocation
 *     because only R_X86_64_RELATIVE, R_X86_64_GLOB_DAT and R_X86_64_JUMP_SLOT reloc schemes are
 *     used. If we add support for archs other than x86_64 in future, we need to add more reloc
 *     schemes. Corresponding linker flags are `-Wl,-zrelro -Wl,-znow`.
 *
 *   - They must be linked with immediate binding (in contrast to the linker's default lazy
 *     binding). Our code performs relocations immediately, i.e., all relocations are processed
 *     before passing control to the loaded object. Corresponding linker flag is `-Wl,-znow`.
 *     Note that some linkers generate DT_BIND_NOW entry and some generate the DF_BIND_NOW flag.
 *
 *   - They must have old-style hash (DT_HASH) table; our code doesn't use the hash table itself but
 *     only reads the number of available dynamic symbols from this table and then simply iterates
 *     over all loaded ELF binaries and all their dynamic symbols. This is not efficient, but our
 *     PAL binaries currently have less than 50 symbols, so the overhead is negligible. Note that we
 *     cannot read the number of dynamic symbols from SHT_SYMTAB section because sections are
 *     non-loadable and may be missing from final binaries (i.e., in vDSO).
 *     Corresponding linker flag is `-Wl,--hash-style=sysv`.
 *
 *  - They must have DYN or EXEC object file type. Notice that virtual addresses (p_vaddr) in DYN
 *    binaries are actually offsets from the address where DYN is loaded at and thus need adjustment
 *    (via `l_base_diff`), whereas virtual addresses in EXEC binaries are hard-coded and do not need
 *    any adjustment (thus `l_base_diff == 0x0`).
 */

#include "api.h"
#include "elf/elf.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_rtld.h"

/* ELF header address (load address of the PAL binary); modern linkers define this magic symbol
 * unconditionally; see e.g. https://github.com/bminor/glibc/commit/302247c8.
 *
 * Note that with `visibility("hidden")`, the compiler prefers to use RIP-relative addressing with
 * known offset (not a reference to GOT) for the `&__ehdr_start` operation, so this operation
 * doesn't require relocation. */
extern const elf_ehdr_t __ehdr_start __attribute__((visibility("hidden")));

static const char* g_pal_soname = NULL;
static struct link_map g_pal_map;
static struct link_map g_entrypoint_map;

static const unsigned char g_expected_elf_header[EI_NIDENT] = {
    [EI_MAG0] = ELFMAG0,
    [EI_MAG1] = ELFMAG1,
    [EI_MAG2] = ELFMAG2,
    [EI_MAG3] = ELFMAG3,
    [EI_CLASS] = ELF_NATIVE_CLASS,
#if __BYTE_ORDER == __BIG_ENDIAN
    [EI_DATA] = ELFDATA2MSB,
#else
    [EI_DATA] = ELFDATA2LSB,
#endif
    [EI_VERSION] = EV_CURRENT,
    [EI_OSABI] = 0,
};

struct loadcmd {
    /*
     * Load command for a single segment. The following properties are true:
     *
     *   - start <= data_end <= map_end <= alloc_end
     *   - start, map_end, alloc_end are page-aligned
     *   - map_off is page-aligned
     *
     *   The addresses are not relocated (i.e. you need to add l_base_diff to them).
     *
     *   The same struct is used also in libos/src/libos_rtld.c code.
     */

    /* Start of memory area */
    elf_addr_t start;

    /* End of file data (data_end .. alloc_end should be zeroed out) */
    elf_addr_t data_end;

    /* End of mapped file data (data_end rounded up to page size, so that we can mmap
     * start .. map_end) */
    elf_addr_t map_end;

    /* End of memory area */
    elf_addr_t alloc_end;

    /* Offset from the beginning of file at which the first byte of the segment resides */
    elf_off_t map_off;

    /* Permissions for memory area */
    pal_prot_flags_t prot;
};

static pal_prot_flags_t elf_segment_prot_to_pal_prot(int elf_segment_prot) {
    pal_prot_flags_t pal_prot = 0;
    pal_prot |= (elf_segment_prot & PF_R) ? PAL_PROT_READ : 0;
    pal_prot |= (elf_segment_prot & PF_W) ? PAL_PROT_WRITE : 0;
    pal_prot |= (elf_segment_prot & PF_X) ? PAL_PROT_EXEC : 0;
    return pal_prot;
}

/* iterate through DSO's program headers to find dynamic section (for dynamic linking) */
static elf_dyn_t* find_dynamic_section(elf_addr_t ehdr_addr, elf_addr_t base_diff) {
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

    /* iterate through DSO's dynamic section to find the string table and the symbol table */
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

static int find_symbol_in_loaded_maps(struct link_map* map, elf_rela_t* rela,
                                      elf_addr_t* out_symbol_addr) {
    elf_xword_t symbol_idx = ELF_R_SYM(rela->r_info);
    if (symbol_idx >= (elf_xword_t)map->symbol_table_cnt)
        return -PAL_ERROR_DENIED;

    const char* symbol_name = map->string_table + map->symbol_table[symbol_idx].st_name;

    /* first try to find in this ELF object itself */
    if (map->symbol_table[symbol_idx].st_value &&
            map->symbol_table[symbol_idx].st_shndx != SHN_UNDEF) {
        *out_symbol_addr = map->symbol_table[symbol_idx].st_value + map->l_base_diff;
        return 0;
    }

    if (map == &g_pal_map) {
        /* PAL ELF object tried to find symbol in itself but couldn't */
        log_error("Could not resolve symbol %s in PAL ELF object", symbol_name);
        return -PAL_ERROR_DENIED;
    }

    /* next try to find in PAL ELF object */
    for (uint32_t i = 0; i < g_pal_map.symbol_table_cnt; i++) {
        if (g_pal_map.symbol_table[i].st_shndx == SHN_UNDEF)
            continue;

        const char* pal_symbol_name = g_pal_map.string_table + g_pal_map.symbol_table[i].st_name;
        if (!strcmp(symbol_name, pal_symbol_name)) {
            /* NOTE: we currently don't take into account weak symbols and return the first symbol
             *       found (we don't have weak symbols in PAL) */
            *out_symbol_addr = g_pal_map.symbol_table[i].st_value + g_pal_map.l_base_diff;
            return 0;
        }
    }

    /* this could happen if e.g. LibOS and PAL binaries are out of sync */
    log_error("Could not resolve symbol %s needed by binary %s", symbol_name, map->l_name);
    return -PAL_ERROR_DENIED;
}

static int verify_dynamic_entries(struct link_map* map) {
    elf_addr_t base_diff = map->l_base_diff;
    elf_dyn_t* dynamic_section_entry = map->l_ld;

    const char* string_table = NULL;
    elf_xword_t string_table_size = 0;

    /* DT_NEEDED entries contain offsets into the string table (DT_STRTAB) */
    elf_xword_t needed_offset = 0;
    bool needed_offset_found  = false;

    while (dynamic_section_entry->d_tag != DT_NULL) {
        switch (dynamic_section_entry->d_tag) {
            case DT_RELACOUNT:
            case DT_RELA:
            case DT_RELASZ:
            case DT_JMPREL:
            case DT_PLTRELSZ:
                /* recognized relocation types, used in perform_relocations() */
                break;
            case DT_RELENT:
                if (dynamic_section_entry->d_un.d_val != sizeof(elf_rel_t)) {
                    log_error("Unexpected DT_RELENT (size of one Rel reloc)");
                    return -PAL_ERROR_DENIED;
                }
                break;
            case DT_RELAENT:
                if (dynamic_section_entry->d_un.d_val != sizeof(elf_rela_t)) {
                    log_error("Unexpected DT_RELAENT (size of one Rela reloc)");
                    return -PAL_ERROR_DENIED;
                }
                break;
            case DT_RELRENT:
                if (dynamic_section_entry->d_un.d_val != sizeof(elf_relr_t)) {
                    log_error("Unexpected DT_RELRENT (size of one Relr reloc)");
                    return -PAL_ERROR_DENIED;
                }
                break;
            case DT_SYMENT:
                if (dynamic_section_entry->d_un.d_val != sizeof(elf_sym_t)) {
                    log_error("Unexpected DT_SYMENT (size of one symbol table entry)");
                    return -PAL_ERROR_DENIED;
                }
                break;
            case DT_PLTREL:
                if (dynamic_section_entry->d_un.d_val != DT_RELA) {
                    log_error("Unexpected DT_PLTREL (type of relocs in PLT must be Rela)");
                    return -PAL_ERROR_DENIED;
                }
                break;
            case DT_NEEDED:
                if (needed_offset_found) {
                    log_error("Loaded binary has more than one dependency (must be only one "
                              "dependency -- the PAL binary)");
                    return -PAL_ERROR_DENIED;
                }
                needed_offset = dynamic_section_entry->d_un.d_val;
                needed_offset_found = true;
                break;
            case DT_BIND_NOW:
                /* unused, our code always uses immediate binding (doesn't support lazy binding) */
                break;
            case DT_SONAME:
                /* unused, semantically a no-op (for PAL binary, extracted in setup_pal_binary()) */
                break;
            case DT_DEBUG:
                /* unused, semantically a no-op */
                break;
            case DT_PLTGOT:
                /* address of PLT -- unused because Rela relocs include this addr in the offset */
            case DT_FLAGS:
            case DT_FLAGS_1:
                /* additional linker flags -- unclear how to verify them so currently ignore */
            case DT_VERDEF:
            case DT_VERDEFNUM:
            case DT_VERNEED:
            case DT_VERNEEDNUM:
            case DT_VERSYM:
                /* versioning entries -- unclear how to verify them so currently ignore */
                break;
            case DT_INIT_ARRAY:
            case DT_FINI_ARRAY:
            case DT_INIT_ARRAYSZ:
            case DT_FINI_ARRAYSZ:
                /* init/fini routines -- used by AddressSanitizer; unclear how to verify them */
                break;
            case DT_STRTAB:
                string_table = (const char*)(dynamic_section_entry->d_un.d_ptr + base_diff);
                break;
            case DT_STRSZ:
                string_table_size = dynamic_section_entry->d_un.d_val;
                break;
            case DT_HASH:
            case DT_SYMTAB:
                /* used in find_string_and_symbol_tables() */
                break;
            case DT_RELR:
            case DT_RELRSZ:
                /* be explicit about unsupported RELR relocation type */
                log_error("Unsupported relocation type DT_RELR; you may need to rebuild Gramine "
                          "with `-Wl,-z,nopack-relative-relocs` linker option");
                return -PAL_ERROR_DENIED;
            default:
                log_error("Unrecognized dynamic entry (DT_*) %ld", dynamic_section_entry->d_tag);
                return -PAL_ERROR_DENIED;

            }
        dynamic_section_entry++;
    }

    if (!string_table || !string_table_size) {
        log_error("Loaded binary doesn't have string table or it is empty (DT_STRTAB/DT_STRSZ)");
        return -PAL_ERROR_DENIED;
    }

    /* verify DT_NEEDED: LibOS and PAL tests have PAL lib; PAL doesn't have this entry */
    if (needed_offset_found) {
        const char* needed = string_table + needed_offset;
        if (strcmp(needed, g_pal_soname) != 0) {
            log_error("Unexpected DT_NEEDED (must be name of the PAL library)");
            return -PAL_ERROR_DENIED;
        }
    }

    return 0;
}

static int perform_relocations(struct link_map* map) {
    int ret;

    elf_addr_t base_diff = map->l_base_diff;
    elf_dyn_t* dynamic_section_entry = map->l_ld;

    elf_rela_t* relas_addr = NULL;
    elf_xword_t relas_size = 0;

    elf_rela_t* plt_relas_addr = NULL;
    elf_xword_t plt_relas_size = 0;

    elf_xword_t relas_count = 0;
    elf_xword_t expected_relas_count = 0;

    while (dynamic_section_entry->d_tag != DT_NULL) {
        switch (dynamic_section_entry->d_tag) {
            case DT_RELACOUNT:
                expected_relas_count = dynamic_section_entry->d_un.d_val;
                break;
            case DT_RELA:
                relas_addr = (elf_rela_t*)(dynamic_section_entry->d_un.d_ptr + base_diff);
                break;
            case DT_RELASZ:
                relas_size = dynamic_section_entry->d_un.d_val;
                break;
            case DT_JMPREL:
                plt_relas_addr = (elf_rela_t*)(dynamic_section_entry->d_un.d_ptr + base_diff);
                break;
            case DT_PLTRELSZ:
                plt_relas_size = dynamic_section_entry->d_un.d_val;
                break;
            }
        dynamic_section_entry++;
    }

    if (!relas_addr && relas_size) {
        log_error("Incorrect relocations (no relocs found but size is non-zero)");
        return -PAL_ERROR_DENIED;
    }

    /* perform relocs: supported binaries may have only R_X86_64_RELATIVE/R_X86_64_GLOB_DAT relas */
    elf_rela_t* relas_addr_end = (elf_rela_t*)((uintptr_t)relas_addr + relas_size);
    for (elf_rela_t* rela = relas_addr; rela < relas_addr_end; rela++) {
        if (ELF_R_TYPE(rela->r_info) == R_X86_64_RELATIVE) {
            elf_addr_t* addr_to_relocate = (elf_addr_t*)(rela->r_offset + base_diff);
            *addr_to_relocate = *addr_to_relocate + base_diff;
            relas_count++;
        } else if (ELF_R_TYPE(rela->r_info) == R_X86_64_GLOB_DAT) {
            elf_addr_t symbol_addr;
            ret = find_symbol_in_loaded_maps(map, rela, &symbol_addr);
            if (ret < 0)
                return ret;

            elf_addr_t* addr_to_relocate = (elf_addr_t*)(rela->r_offset + base_diff);
            *addr_to_relocate = symbol_addr + rela->r_addend;
        } else {
            log_error("Unrecognized relocation type; PAL loader currently supports only "
                      "R_X86_64_RELATIVE and R_X86_64_GLOB_DAT relocations");
            return -PAL_ERROR_DENIED;
        }
    }

    if (!plt_relas_addr && plt_relas_size) {
        log_error("Incorrect PLT relocations (no relocs found but size is non-zero)");
        return -PAL_ERROR_DENIED;
    }

    /* perform PLT relocs: supported binaries may have only R_X86_64_JUMP_SLOT relas */
    elf_rela_t* plt_relas_addr_end = (void*)plt_relas_addr + plt_relas_size;
    for (elf_rela_t* plt_rela = plt_relas_addr; plt_rela < plt_relas_addr_end; plt_rela++) {
        if (ELF_R_TYPE(plt_rela->r_info) != R_X86_64_JUMP_SLOT) {
            log_error("Unrecognized relocation type; PAL loader currently supports only "
                      "R_X86_64_JUMP_SLOT relocations");
            return -PAL_ERROR_DENIED;
        }

        elf_addr_t symbol_addr;
        ret = find_symbol_in_loaded_maps(map, plt_rela, &symbol_addr);
        if (ret < 0)
            return ret;

        elf_addr_t* addr_to_relocate = (elf_addr_t*)(plt_rela->r_offset + base_diff);
        *addr_to_relocate = symbol_addr + plt_rela->r_addend;
    }

    if (relas_count != expected_relas_count) {
        log_error("Expected %ld Rela relocs but got %ld", expected_relas_count, relas_count);
        return -PAL_ERROR_DENIED;
    }

    return 0;
}

static int create_and_relocate_entrypoint(const char* uri, const char* elf_file_buf) {
    int ret;
    struct loadcmd* loadcmds = NULL;

    elf_addr_t l_relro_addr = 0x0;
    size_t l_relro_size = 0;

    if (!strstartswith(uri, URI_PREFIX_FILE))
        return -PAL_ERROR_INVAL;

    g_entrypoint_map.l_name = strdup(uri + URI_PREFIX_FILE_LEN);
    if (!g_entrypoint_map.l_name) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    elf_ehdr_t* ehdr = (elf_ehdr_t*)elf_file_buf;
    elf_phdr_t* phdr = (elf_phdr_t*)(elf_file_buf + ehdr->e_phoff);

    g_entrypoint_map.l_entry = ehdr->e_entry;

    loadcmds = malloc(sizeof(*loadcmds) * ehdr->e_phnum);
    if (!loadcmds) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    /* scan the program headers table, collecting segments to load; record addresses verbatim (as
     * offsets) as we'll add the ELF-object base address later */
    size_t loadcmds_cnt = 0;
    for (const elf_phdr_t* ph = phdr; ph < &phdr[ehdr->e_phnum]; ph++) {
        switch (ph->p_type) {
            case PT_DYNAMIC:
                g_entrypoint_map.l_ld = (elf_dyn_t*)ph->p_vaddr;
                break;

            case PT_LOAD:
                if (!IS_ALIGNED_POW2(ph->p_vaddr - ph->p_offset, ph->p_align)) {
                    log_error("ELF loadable program segment not aligned");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }

                struct loadcmd* c = &loadcmds[loadcmds_cnt++];
                c->start     = ALLOC_ALIGN_DOWN(ph->p_vaddr);
                c->map_end   = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_filesz);
                c->map_off   = ALLOC_ALIGN_DOWN(ph->p_offset);
                c->data_end  = ph->p_vaddr + ph->p_filesz;
                c->alloc_end = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_memsz);
                c->prot      = elf_segment_prot_to_pal_prot(ph->p_flags);

                /* this is our parser's simplification, not a requirement of the ELF spec */
                if (loadcmds_cnt == 1 && c->map_off) {
                    log_error("ELF first loadable program segment has non-zero offset");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }

                if (loadcmds_cnt == 1 && ehdr->e_type == ET_DYN && c->start) {
                    log_error("DYN ELF first loadable program segment has non-zero map address");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }

                if (c->start >= c->map_end) {
                    log_error("ELF loadable program segment has impossible memory region to map");
                    ret = -PAL_ERROR_INVAL;
                    goto out;
                }
                break;

            case PT_GNU_RELRO:
                l_relro_addr = ph->p_vaddr;
                l_relro_size = ph->p_memsz;
                break;
        }
    }

    if (!loadcmds_cnt) {
        log_error("ELF file has no loadable segments");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (ehdr->e_type == ET_DYN) {
        /*
         * This is a position-independent shared object, bookkeep a memory area to determine
         * load address. This area will be populated (possibly partially) with LOAD segments in
         * the below loop. We never free this memory, so we don't bother with removing parts that
         * are bookkept, but not allocated.
         *
         * Note that we bookkeep memory to cover LOAD segments starting from offset 0, not from the
         * first segment's p_vaddr. This is to ensure that l_base_diff will not be less than 0.
         */
        uintptr_t map_addr;
        ret = pal_internal_memory_bkeep(loadcmds[loadcmds_cnt - 1].alloc_end, &map_addr);
        if (ret < 0) {
            log_error("Failed to bookkeep memory for all LOAD segments of DYN ELF file");
            goto out;
        }

        g_entrypoint_map.l_base_diff = (elf_addr_t)map_addr;
    } else {
        /* for EXEC (executables), force PAL memory allocator to use hard-coded segment addresses */
        g_entrypoint_map.l_base_diff = 0x0;
    }

    g_entrypoint_map.l_map_start = loadcmds[0].start + g_entrypoint_map.l_base_diff;

    for (size_t i = 0; i < loadcmds_cnt; i++) {
        struct loadcmd* c = &loadcmds[i];

        void*  map_addr = (void*)(c->start + g_entrypoint_map.l_base_diff);
        size_t map_size = c->alloc_end - c->start;
        size_t cpy_size = c->data_end - c->start;
        assert(cpy_size <= map_size);

        assert(IS_ALLOC_ALIGNED_PTR(map_addr));
        assert(IS_ALLOC_ALIGNED(map_size));

        ret = _PalVirtualMemoryAlloc(map_addr, map_size, c->prot | PAL_PROT_WRITE);
        if (ret < 0) {
            log_error("Failed to prepare mapping for segment from ELF file");
            goto out;
        }
        memcpy(map_addr, elf_file_buf + c->map_off, cpy_size);
        ret = _PalVirtualMemoryProtect(map_addr, map_size, c->prot);
        if (ret < 0) {
            log_error("Failed to remove write memory protection off the segment from ELF file");
            goto out;
        }

        /* adjust segment's virtual addresses (p_vaddr) to actual virtual addresses in memory */
        c->start     += g_entrypoint_map.l_base_diff;
        c->map_end   += g_entrypoint_map.l_base_diff;
        c->data_end  += g_entrypoint_map.l_base_diff;
        c->alloc_end += g_entrypoint_map.l_base_diff;
    }

    /* adjust shared object's virtual addresses (p_vaddr) to actual virtual addresses in memory */
    g_entrypoint_map.l_entry = g_entrypoint_map.l_entry + g_entrypoint_map.l_base_diff;
    g_entrypoint_map.l_ld = (elf_dyn_t*)((elf_addr_t)g_entrypoint_map.l_ld +
                                         g_entrypoint_map.l_base_diff);

    ret = verify_dynamic_entries(&g_entrypoint_map);
    if (ret < 0)
        goto out;

    ret = find_string_and_symbol_tables(g_entrypoint_map.l_map_start, g_entrypoint_map.l_base_diff,
                                        &g_entrypoint_map.string_table,
                                        &g_entrypoint_map.symbol_table,
                                        &g_entrypoint_map.symbol_table_cnt);
    if (ret < 0)
        goto out;

    /* perform relocations on loaded segments (need to first change memory permissions to writable
     * and then revert permissions back) */
    for (size_t i = 0; i < loadcmds_cnt; i++) {
        struct loadcmd* c = &loadcmds[i];
        ret = _PalVirtualMemoryProtect((void*)c->start, c->alloc_end - c->start,
                                       c->prot | PAL_PROT_WRITE);
        if (ret < 0) {
            log_error("Failed to add write memory protection on the segment from ELF file");
            goto out;
        }
    }

    ret = perform_relocations(&g_entrypoint_map);
    if (ret < 0) {
        log_error("Failed to perform relocations on ELF file");
        goto out;
    }

    for (size_t i = 0; i < loadcmds_cnt; i++) {
        struct loadcmd* c = &loadcmds[i];
        ret = _PalVirtualMemoryProtect((void*)c->start, c->alloc_end - c->start, c->prot);
        if (ret < 0) {
            log_error("Failed to revert write memory protection on the segment from ELF file");
            goto out;
        }
    }

    if (l_relro_size != 0) {
        l_relro_addr += g_entrypoint_map.l_base_diff;
        elf_addr_t start = ALLOC_ALIGN_DOWN(l_relro_addr);
        elf_addr_t end   = ALLOC_ALIGN_UP(l_relro_addr + l_relro_size);
        ret = _PalVirtualMemoryProtect((void*)start, end - start, PAL_PROT_READ);
        if (ret < 0) {
            log_error("Failed to apply read-only memory protection on the RELRO memory area");
            goto out;
        }
    }

    ret = 0;
out:
    if (ret < 0) {
        free((void*)g_entrypoint_map.l_name);
        g_entrypoint_map.l_name = NULL;
    }
    free(loadcmds);
    return ret;
}

int load_entrypoint(const char* uri) {
    int ret;
    PAL_HANDLE handle;
    char* buf = NULL;

    ret = _PalStreamOpen(&handle, uri, PAL_ACCESS_RDONLY, /*share_flags=*/0, PAL_CREATE_NEVER,
                         /*options=*/0);
    if (ret < 0)
        return ret;

    PAL_STREAM_ATTR attr;
    ret = _PalStreamAttributesQueryByHandle(handle, &attr);
    if (ret < 0) {
        log_error("Getting size of loader entrypoint binary failed");
        goto out;
    }

    buf = malloc(attr.pending_size);
    if (!buf) {
        log_error("Allocating buffer to hold loader entrypoint binary of size %lu failed",
                  attr.pending_size);
        goto out;
    }

    size_t buf_offset = 0;
    size_t remaining = attr.pending_size;
    while (remaining > 0) {
        int64_t read = _PalStreamRead(handle, buf_offset, remaining, buf + buf_offset);
        if (read == -PAL_ERROR_INTERRUPTED || read == -PAL_ERROR_TRYAGAIN)
            continue;
        if (read <= 0) {
            log_error("Reading loader entrypoint binary failed");
            ret = read < 0 ? read : -PAL_ERROR_DENIED;
            goto out;
        }

        assert((size_t)read <= remaining);
        remaining -= (size_t)read;
        buf_offset += (size_t)read;
    }
    assert(remaining == 0);

    ret = _PalValidateEntrypoint(buf, attr.pending_size);
    if (ret < 0) {
        log_error("Validating loader entrypoint binary failed");
        goto out;
    }

    elf_ehdr_t* ehdr = (elf_ehdr_t*)buf;
    if (attr.pending_size < sizeof(elf_ehdr_t)) {
        log_error("Loader entrypoint binary is too small (cannot read the ELF header)");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (memcmp(ehdr->e_ident, g_expected_elf_header, EI_OSABI)) {
        log_error("Loader entrypoint binary has unexpected ELF header (unexpected first 7 bytes)");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (ehdr->e_ident[EI_OSABI] != ELFOSABI_SYSV && ehdr->e_ident[EI_OSABI] != ELFOSABI_LINUX) {
        log_error("Loader entrypoint binary has unexpected OS/ABI: PAL loader currently supports "
                  "only SYS-V and LINUX");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC) {
        log_error("Loader entrypoint binary has unexpected type: PAL loader currently supports "
                  "only DYN and EXEC");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (attr.pending_size < ehdr->e_phoff + ehdr->e_phnum * sizeof(elf_phdr_t)) {
        log_error("Read too few bytes from loader entrypoint binary (not all program headers)");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    ret = create_and_relocate_entrypoint(uri, buf);
    if (ret < 0) {
        log_error("Could not map loader entrypoint binary into memory and then relocate it");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

#ifdef DEBUG
    assert(g_entrypoint_map.l_name);
    _PalDebugMapAdd(g_entrypoint_map.l_name, (void*)g_entrypoint_map.l_base_diff);
#endif

out:
    _PalObjectDestroy(handle);
    free(buf);
    return ret;
}

/* PAL binary must be DYN (shared object file) or EXEC (non-PIE executable) */
int setup_pal_binary(void) {
    int ret;

    g_pal_map.l_prev = NULL;
    g_pal_map.l_next = NULL;

    elf_ehdr_t* ehdr = (elf_ehdr_t*)&__ehdr_start;

    /* In case of DYN PAL binary, it must have the first loadable segment with `p_vaddr == 0`, thus
     * pal_base_diff is the same as the address where the PAL binary is loaded (== beginning of ELF
     * header). In case of EXEC PAL binary, the first loadable segment has `p_vaddr` with a
     * hard-coded address, thus pal_base_diff is zero. */
    elf_addr_t pal_binary_addr = (elf_addr_t)&__ehdr_start;
    elf_addr_t pal_base_diff   = (ehdr->e_type == ET_EXEC) ? 0x0 : pal_binary_addr;

    elf_dyn_t* dynamic_section = find_dynamic_section(pal_binary_addr, pal_base_diff);
    if (!dynamic_section) {
        log_error("PAL binary doesn't have dynamic section (required for symbol resolution)");
        return -PAL_ERROR_DENIED;
    }

    g_pal_map.l_name = NULL; /* will be overwritten later with argv[0] */
    g_pal_map.l_map_start = pal_binary_addr;
    g_pal_map.l_base_diff = pal_base_diff;
    g_pal_map.l_ld = dynamic_section;

    ret = verify_dynamic_entries(&g_pal_map);
    if (ret < 0)
        return ret;

    ret = find_string_and_symbol_tables(g_pal_map.l_map_start, g_pal_map.l_base_diff,
                                        &g_pal_map.string_table, &g_pal_map.symbol_table,
                                        &g_pal_map.symbol_table_cnt);
    if (ret < 0)
        return ret;

    /* find soname of PAL binary -- will be used during DT_NEEDED verification of other binaries */
    elf_dyn_t* dynamic_section_entry = dynamic_section;
    elf_xword_t soname_offset = 0;
    bool soname_offset_found  = false;
    while (dynamic_section_entry->d_tag != DT_NULL) {
        if (dynamic_section_entry->d_tag == DT_SONAME) {
            soname_offset = dynamic_section_entry->d_un.d_val;
            soname_offset_found = true;
            break;
        }
        dynamic_section_entry++;
    }
    if (!soname_offset_found) {
        log_error("Did not find DT_SONAME for PAL binary (name of the PAL library)");
        return -PAL_ERROR_DENIED;
    }
    g_pal_soname = g_pal_map.string_table + soname_offset;

    ret = perform_relocations(&g_pal_map);
    return ret;
}

void set_pal_binary_name(const char* name) {
    g_pal_map.l_name = name;
}

/*
 * NOTE: This function assumes that a "file:" URI describes a path that can be opened on a host
 * directly (e.g. by GDB or other tools). This is mostly true, except for LibOS encrypted files. As
 * a result, if we load a binary that is an encrypted file, it will be reported here, but GDB (and
 * other tools) will fail to load it.
 */
void PalDebugMapAdd(const char* uri, void* start_addr) {
#ifndef DEBUG
    __UNUSED(uri);
    __UNUSED(start_addr);
#else
    if (!strstartswith(uri, URI_PREFIX_FILE))
        return;

    const char* realname = uri + URI_PREFIX_FILE_LEN;

    _PalDebugMapAdd(realname, start_addr);
#endif
}

void PalDebugMapRemove(void* start_addr) {
#ifndef DEBUG
    __UNUSED(start_addr);
#else
    _PalDebugMapRemove(start_addr);
#endif
}

void PalDebugDescribeLocation(uintptr_t addr, char* buf, size_t buf_size) {
    pal_describe_location(addr, buf, buf_size);
}

void pal_describe_location(uintptr_t addr, char* buf, size_t buf_size) {
#ifdef DEBUG
    if (_PalDebugDescribeLocation(addr, buf, buf_size) == 0)
        return;
#endif
    default_describe_location(addr, buf, buf_size);
}

/* Disable AddressSanitizer for this function: it uses the `stack_entries` array as the beginning of
 * new stack, so we don't want any redzone around it, or ASan-specific stack frame handling. */
__attribute_no_sanitize_address
noreturn void start_execution(const char** arguments, const char** environs) {
    /* Our PAL loader invokes LibOS entrypoint with the following stack:
     *
     *   RSP + 0                     argc
     *   RSP + 8+8*0                 argv[0]
     *   RSP + 8+8*1                 argv[1]
     *   ...
     *   RSP + 8+8*argc              argv[argc] = NULL
     *   RSP + 8+8*argc + 8+8*0      envp[0]
     *   RSP + 8+8*argc + 8+8*1      envp[1]
     *   ...
     *   RSP + 8+8*argc + 8+8*n      envp[n] = NULL
     *   RSP + 8+8*argc + 8+8*n + 8  auxv[0] = AT_NULL
     *
     * See also the corresponding LibOS entrypoint: libos/src/arch/x86_64/start.S
     */
    size_t arguments_num = 0;
    for (size_t i = 0; arguments[i]; i++)
        arguments_num++;

    size_t environs_num = 0;
    for (size_t i = 0; environs[i]; i++)
        environs_num++;

    /* 1 for argc stack entry, 1 for argv[argc] == NULL, 1 for envp[n] == NULL */
    size_t stack_entries_size = 3 * sizeof(void*);
    stack_entries_size += (arguments_num + environs_num) * sizeof(void*);
    stack_entries_size += 1 * sizeof(elf_auxv_t);

    const void** stack_entries = __alloca(stack_entries_size);

    size_t idx = 0;
    stack_entries[idx++] = (void*)arguments_num;
    for (size_t i = 0; i < arguments_num; i++)
        stack_entries[idx++] = arguments[i];
    stack_entries[idx++] = NULL;
    for (size_t i = 0; i < environs_num; i++)
        stack_entries[idx++] = environs[i];
    stack_entries[idx++] = NULL;

    /* NOTE: LibOS implements its own ELF aux vectors. Any info from host's aux vectors must be
     * passed in `struct pal_public_state`. Here we pass an empty list of aux vectors for sanity. */
    elf_auxv_t* auxv = (elf_auxv_t*)&stack_entries[idx];
    auxv[0].a_type     = AT_NULL;
    auxv[0].a_un.a_val = 0;

    assert(g_entrypoint_map.l_entry);
#ifdef __x86_64__
    __asm__ volatile("movq %1, %%rsp\n"
                     "jmp *%0\n"
                     :
                     : "r"(g_entrypoint_map.l_entry), "r"(stack_entries)
                     : "memory");
#else
#error "unsupported architecture"
#endif
    __builtin_unreachable();
}
