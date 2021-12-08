/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Labs
 */

/*
 * This file contains utilities to load ELF binaries into the memory and link them against each
 * other. Note that PAL loads only two kinds of ELF binaries: the LibOS shared library and the PAL
 * regression tests. Both these kinds of ELF binaries are assumed to have specific ELF config:
 *
 *   - They must be linked with RELRO (Relocation Read-Only); this simplifies relocation because
 *     only R_X86_64_RELATIVE, R_X86_64_GLOB_DAT and R_X86_64_JUMP_SLOT reloc schemes are used. If
 *     we add support for archs other than x86_64 in future, we need to add more reloc schemes.
 *     Corresponding linker flags are `-Wl,-zrelro -Wl,-znow`.
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

#include <stdbool.h>

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
extern const ElfW(Ehdr) __ehdr_start __attribute__((visibility("hidden")));

static struct link_map g_pal_map;
static struct link_map g_entrypoint_map;

static const unsigned char g_expected_elf_header[EI_NIDENT] = {
    [EI_MAG0] = ELFMAG0,
    [EI_MAG1] = ELFMAG1,
    [EI_MAG2] = ELFMAG2,
    [EI_MAG3] = ELFMAG3,
    [EI_CLASS] = ELFW(CLASS),
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
     *   The same struct is used also in LibOS/shim/src/shim_rtld.c code.
     */

    /* Start of memory area */
    ElfW(Addr) start;

    /* End of file data (data_end .. alloc_end should be zeroed out) */
    ElfW(Addr) data_end;

    /* End of mapped file data (data_end rounded up to page size, so that we can mmap
     * start .. map_end) */
    ElfW(Addr) map_end;

    /* End of memory area */
    ElfW(Addr) alloc_end;

    /* Offset from the beginning of file at which the first byte of the segment resides */
    ElfW(Off) map_off;

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
static ElfW(Dyn)* find_dynamic_section(ElfW(Addr) ehdr_addr, ElfW(Addr) base_diff) {
    const ElfW(Ehdr)* header = (const ElfW(Ehdr)*)ehdr_addr;
    const ElfW(Phdr)* phdr   = (const ElfW(Phdr)*)(ehdr_addr + header->e_phoff);

    ElfW(Dyn)* dynamic_section = NULL;
    for (const ElfW(Phdr)* ph = phdr; ph < &phdr[header->e_phnum]; ph++) {
        if (ph->p_type == PT_DYNAMIC) {
            dynamic_section = (ElfW(Dyn)*)(ph->p_vaddr + base_diff);
            break;
        }
    }

    return dynamic_section;
}

int find_string_and_symbol_tables(ElfW(Addr) ehdr_addr, ElfW(Addr) base_diff,
                                  const char** out_string_table, ElfW(Sym)** out_symbol_table,
                                  uint32_t* out_symbol_table_cnt) {
    const char* string_table  = NULL;
    ElfW(Sym)* symbol_table   = NULL;
    uint32_t symbol_table_cnt = 0;

    ElfW(Dyn)* dynamic_section = find_dynamic_section(ehdr_addr, base_diff);
    if (!dynamic_section) {
        log_error("Loaded binary doesn't have dynamic section (required for symbol resolution)");
        return -PAL_ERROR_DENIED;
    }

    /* iterate through DSO's dynamic section to find the string table and the symbol table */
    ElfW(Dyn)* dynamic_section_entry = dynamic_section;
    while (dynamic_section_entry->d_tag != DT_NULL) {
        switch (dynamic_section_entry->d_tag) {
            case DT_STRTAB:
                string_table = (const char*)(dynamic_section_entry->d_un.d_ptr + base_diff);
                break;
            case DT_SYMTAB:
                symbol_table = (ElfW(Sym)*)(dynamic_section_entry->d_un.d_ptr + base_diff);
                break;
            case DT_HASH: {
                /* symbol table size can only be found via ELF hash table's nchain (which is the
                 * second word in the ELF hash table struct) */
                ElfW(Word)* ht = (ElfW(Word)*)(dynamic_section_entry->d_un.d_ptr + base_diff);
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

static int find_symbol_in_loaded_maps(struct link_map* map, ElfW(Rela)* rela,
                                      ElfW(Addr)* out_symbol_addr) {
    ElfW(Xword) symbol_idx = ELFW(R_SYM)(rela->r_info);
    if (symbol_idx >= (ElfW(Xword))map->symbol_table_cnt)
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

static int perform_relocations(struct link_map* map) {
    int ret;

    ElfW(Addr) base_diff = map->l_base_diff;
    ElfW(Dyn)* dynamic_section_entry = map->l_ld;

    ElfW(Rela)* relas_addr = NULL;
    ElfW(Xword) relas_size = 0;

    ElfW(Rela)* plt_relas_addr = NULL;
    ElfW(Xword) plt_relas_size = 0;

    while (dynamic_section_entry->d_tag != DT_NULL) {
        switch (dynamic_section_entry->d_tag) {
            case DT_RELA:
                relas_addr = (ElfW(Rela)*)(dynamic_section_entry->d_un.d_ptr + base_diff);
                break;
            case DT_RELASZ:
                relas_size = dynamic_section_entry->d_un.d_val;
                break;
            case DT_JMPREL:
                plt_relas_addr = (ElfW(Rela)*)(dynamic_section_entry->d_un.d_ptr + base_diff);
                break;
            case DT_PLTRELSZ:
                plt_relas_size = dynamic_section_entry->d_un.d_val;
                break;
            }
        dynamic_section_entry++;
    }

    /* perform relocs: supported binaries may have only R_X86_64_RELATIVE/R_X86_64_GLOB_DAT relas */
    ElfW(Rela)* relas_addr_end = (ElfW(Rela)*)((uintptr_t)relas_addr + relas_size);
    for (ElfW(Rela)* rela = relas_addr; rela < relas_addr_end; rela++) {
        if (ELFW(R_TYPE)(rela->r_info) == R_X86_64_RELATIVE) {
            ElfW(Addr)* addr_to_relocate = (ElfW(Addr)*)(rela->r_offset + base_diff);
            *addr_to_relocate = *addr_to_relocate + base_diff;
        } else if (ELFW(R_TYPE)(rela->r_info) == R_X86_64_GLOB_DAT) {
            ElfW(Addr) symbol_addr;
            ret = find_symbol_in_loaded_maps(map, rela, &symbol_addr);
            if (ret < 0)
                return ret;

            ElfW(Addr)* addr_to_relocate = (ElfW(Addr)*)(rela->r_offset + base_diff);
            *addr_to_relocate = symbol_addr + rela->r_addend;
        } else {
            log_error("Unrecognized relocation type; PAL loader currently supports only "
                      "R_X86_64_RELATIVE and R_X86_64_GLOB_DAT relocations");
            return -PAL_ERROR_DENIED;
        }

    }

    if (!plt_relas_size)
        return 0;

    /* perform PLT relocs: supported binaries may have only R_X86_64_JUMP_SLOT relas */
    ElfW(Rela)* plt_relas_addr_end = (void*)plt_relas_addr + plt_relas_size;
    for (ElfW(Rela)* plt_rela = plt_relas_addr; plt_rela < plt_relas_addr_end; plt_rela++) {
        if (ELFW(R_TYPE)(plt_rela->r_info) != R_X86_64_JUMP_SLOT) {
            log_error("Unrecognized relocation type; PAL loader currently supports only "
                      "R_X86_64_JUMP_SLOT relocations");
            return -PAL_ERROR_DENIED;
        }

        ElfW(Addr) symbol_addr;
        ret = find_symbol_in_loaded_maps(map, plt_rela, &symbol_addr);
        if (ret < 0)
            return ret;

        ElfW(Addr)* addr_to_relocate = (ElfW(Addr)*)(plt_rela->r_offset + base_diff);
        *addr_to_relocate = symbol_addr + plt_rela->r_addend;
    }

    return 0;
}

/* `elf_file_buf` contains the beginning of ELF file (at least ELF header and all program headers);
 * we don't bother undoing _DkStreamMap() and _DkVirtualMemoryAlloc() in case of failure. */
static int create_and_relocate_entrypoint(PAL_HANDLE handle, const char* elf_file_buf) {
    int ret;
    struct loadcmd* loadcmds = NULL;

    ElfW(Addr) l_relro_addr = 0x0;
    size_t l_relro_size = 0;

    const char* name = _DkStreamRealpath(handle);
    if (!name)
        return -PAL_ERROR_INVAL;

    g_entrypoint_map.l_name = strdup(name);
    if (!g_entrypoint_map.l_name) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)elf_file_buf;
    ElfW(Phdr)* phdr = (ElfW(Phdr)*)(elf_file_buf + ehdr->e_phoff);

    g_entrypoint_map.l_entry = ehdr->e_entry;

    loadcmds = malloc(sizeof(*loadcmds) * ehdr->e_phnum);
    if (!loadcmds) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    /* scan the program headers table, collecting segments to load; record addresses verbatim (as
     * offsets) as we'll add the ELF-object base address later */
    size_t loadcmds_cnt = 0;
    for (const ElfW(Phdr)* ph = phdr; ph < &phdr[ehdr->e_phnum]; ph++) {
        switch (ph->p_type) {
            case PT_DYNAMIC:
                g_entrypoint_map.l_ld = (ElfW(Dyn)*)ph->p_vaddr;
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
         * This is a position-independent shared object, allocate a dummy memory area to determine
         * load address. This area will be populated (overwritten) with LOAD segments in the below
         * loop.
         *
         * Note that we allocate memory to cover LOAD segments starting from offset 0, not from the
         * first segment's p_vaddr. This is to ensure that l_base_diff will not be less than 0.
         *
         * FIXME: We (ab)use _DkStreamMap() because _DkVirtualMemoryAlloc() cannot be used to
         *        allocate memory at PAL-chosen address (it expects `map_addr` to be fixed). Note
         *        that `PAL_PROT_WRITECOPY` is specified to prevent allocating memory in untrusted
         *        memory in case of Linux-SGX PAL (see Linux-SGX/db_files.c:file_map).
         */
        void* map_addr = NULL;
        ret = _DkStreamMap(handle, &map_addr, /*prot=*/PAL_PROT_WRITECOPY, /*offset=*/0,
                           loadcmds[loadcmds_cnt - 1].alloc_end);
        if (ret < 0) {
            log_error("Failed to allocate memory for all LOAD segments of DYN ELF file");
            goto out;
        }

        g_entrypoint_map.l_base_diff = (ElfW(Addr))map_addr;
    } else {
        /* for EXEC (executables), force PAL memory allocator to use hard-coded segment addresses */
        g_entrypoint_map.l_base_diff = 0x0;
    }

    g_entrypoint_map.l_map_start = loadcmds[0].start + g_entrypoint_map.l_base_diff;

    for (size_t i = 0; i < loadcmds_cnt; i++) {
        struct loadcmd* c = &loadcmds[i];

        void*  map_addr = (void*)(c->start + g_entrypoint_map.l_base_diff);
        size_t map_size = c->map_end - c->start;

        ret = _DkStreamMap(handle, &map_addr, c->prot | PAL_PROT_WRITECOPY, c->map_off, map_size);
        if (ret < 0) {
            log_error("Failed to map segment from ELF file");
            goto out;
        }

        /* adjust segment's virtual addresses (p_vaddr) to actual virtual addresses in memory */
        c->start     += g_entrypoint_map.l_base_diff;
        c->map_end   += g_entrypoint_map.l_base_diff;
        c->data_end  += g_entrypoint_map.l_base_diff;
        c->alloc_end += g_entrypoint_map.l_base_diff;

        if (c->alloc_end == c->map_end)
            continue;

        void* map_rest = (void*)c->map_end;
        ret = _DkVirtualMemoryAlloc(&map_rest, c->alloc_end - c->map_end, /*alloc_type=*/0, c->prot);
        if (ret < 0) {
            log_error("Failed to zero-fill the rest of segment from ELF file");
            goto out;
        }
    }

    /* adjust shared object's virtual addresses (p_vaddr) to actual virtual addresses in memory */
    g_entrypoint_map.l_entry = g_entrypoint_map.l_entry + g_entrypoint_map.l_base_diff;
    g_entrypoint_map.l_ld = (ElfW(Dyn)*)((ElfW(Addr))g_entrypoint_map.l_ld +
                                         g_entrypoint_map.l_base_diff);

    ret = find_string_and_symbol_tables(g_entrypoint_map.l_map_start, g_entrypoint_map.l_base_diff,
                                        &g_entrypoint_map.string_table,
                                        &g_entrypoint_map.symbol_table,
                                        &g_entrypoint_map.symbol_table_cnt);
    if (ret < 0)
        return ret;

    /* zero out the unused parts of loaded segments and perform relocations on loaded segments
     * (need to first change memory permissions to writable and then revert permissions back) */
    for (size_t i = 0; i < loadcmds_cnt; i++) {
        struct loadcmd* c = &loadcmds[i];
        ret = _DkVirtualMemoryProtect((void*)c->start, c->alloc_end - c->start,
                                      c->prot | PAL_PROT_WRITE);
        if (ret < 0) {
            log_error("Failed to add write memory protection on the segment from ELF file");
            goto out;
        }

        /* zero out uninitialized but allocated part of the loaded segment (note that part of
         * segment allocated via _DkVirtualMemoryAlloc() is already zeroed out) */
        if (ALLOC_ALIGN_UP(c->data_end) > c->data_end)
            memset((void*)c->data_end, 0, ALLOC_ALIGN_UP(c->data_end) - c->data_end);
    }

    ret = perform_relocations(&g_entrypoint_map);
    if (ret < 0) {
        log_error("Failed to perform relocations on ELF file");
        goto out;
    }

    for (size_t i = 0; i < loadcmds_cnt; i++) {
        struct loadcmd* c = &loadcmds[i];
        ret = _DkVirtualMemoryProtect((void*)c->start, c->alloc_end - c->start, c->prot);
        if (ret < 0) {
            log_error("Failed to revert write memory protection on the segment from ELF file");
            goto out;
        }
    }

    if (l_relro_size != 0) {
        l_relro_addr += g_entrypoint_map.l_base_diff;
        ElfW(Addr) start = ALLOC_ALIGN_DOWN(l_relro_addr);
        ElfW(Addr) end   = ALLOC_ALIGN_UP(l_relro_addr + l_relro_size);
        ret = _DkVirtualMemoryProtect((void*)start, end - start, PAL_PROT_READ);
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

    char buf[1024]; /* must be enough to hold ELF header and all its program headers */
    ret = _DkStreamOpen(&handle, uri, PAL_ACCESS_RDONLY, /*share_flags=*/0, PAL_CREATE_NEVER,
                        /*options=*/0);
    if (ret < 0)
        return ret;

    ret = _DkStreamRead(handle, 0, sizeof(buf), buf, NULL, 0);
    if (ret < 0) {
        log_error("Reading ELF file failed");
        goto out;
    }

    size_t bytes_read = (size_t)ret;

    ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)&buf;
    if (bytes_read < sizeof(ElfW(Ehdr))) {
        log_error("ELF file is too small (cannot read the ELF header)");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (memcmp(ehdr->e_ident, g_expected_elf_header, EI_OSABI)) {
        log_error("ELF file has unexpected header (unexpected first 7 bytes)");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (ehdr->e_ident[EI_OSABI] != ELFOSABI_SYSV && ehdr->e_ident[EI_OSABI] != ELFOSABI_LINUX) {
        log_error("ELF file has unexpected OS/ABI: PAL loader currently supports only SYS-V and "
                  "LINUX");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC) {
        log_error("ELF file has unexpected type: PAL loader currently supports only DYN and EXEC");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (bytes_read < ehdr->e_phoff + ehdr->e_phnum * sizeof(ElfW(Phdr))) {
        log_error("Read too few bytes from the ELF file (not all program headers)");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    ret = create_and_relocate_entrypoint(handle, buf);
    if (ret < 0) {
        log_error("Could not map the ELF file into memory and then relocate it");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

#ifdef DEBUG
    assert(g_entrypoint_map.l_name);
    _DkDebugMapAdd(g_entrypoint_map.l_name, (void*)g_entrypoint_map.l_base_diff);
#endif

out:
    _DkObjectClose(handle);
    return ret;
}

/* PAL binary must be DYN (shared object file) or EXEC (non-PIE executable) */
int setup_pal_binary(void) {
    int ret;

    g_pal_map.l_prev = NULL;
    g_pal_map.l_next = NULL;

    ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)&__ehdr_start;

    /* In case of DYN PAL binary, it must have the first loadable segment with `p_vaddr == 0`, thus
     * pal_base_diff is the same as the address where the PAL binary is loaded (== beginning of ELF
     * header). In case of EXEC PAL binary, the first loadable segment has `p_vaddr` with a
     * hard-coded address, thus pal_base_diff is zero. */
    ElfW(Addr) pal_binary_addr = (ElfW(Addr))&__ehdr_start;
    ElfW(Addr) pal_base_diff   = (ehdr->e_type == ET_EXEC) ? 0x0 : pal_binary_addr;

    ElfW(Dyn)* dynamic_section = find_dynamic_section(pal_binary_addr, pal_base_diff);
    if (!dynamic_section) {
        log_error("PAL binary doesn't have dynamic section (required for symbol resolution)");
        return -PAL_ERROR_DENIED;
    }

    g_pal_map.l_name = NULL; /* will be overwritten later with argv[0] */
    g_pal_map.l_map_start = pal_binary_addr;
    g_pal_map.l_base_diff = pal_base_diff;
    g_pal_map.l_ld = dynamic_section;

    ret = find_string_and_symbol_tables(g_pal_map.l_map_start, g_pal_map.l_base_diff,
                                        &g_pal_map.string_table, &g_pal_map.symbol_table,
                                        &g_pal_map.symbol_table_cnt);
    if (ret < 0)
        return ret;

    ret = perform_relocations(&g_pal_map);
    return ret;
}

void set_pal_binary_name(const char* name) {
    g_pal_map.l_name = name;
}

/*
 * TODO: This function assumes that a "file:" URI describes a path that can be opened on a host
 * directly (e.g. by GDB or other tools). This is mostly true, except for protected files in
 * Linux-SGX, which are stored encrypted. As a result, if we load a binary that is a protected file,
 * we will (incorrectly) report the encrypted file as the actual binary, and code that tries to
 * parse this file will trip up.
 *
 * For now, this doesn't seem worth fixing, as there's no use case for running binaries from
 * protected files system, and a workaround would be ugly. Instead, the protected files system needs
 * rethinking.
 */
void DkDebugMapAdd(const char* uri, PAL_PTR start_addr) {
#ifndef DEBUG
    __UNUSED(uri);
    __UNUSED(start_addr);
#else
    if (!strstartswith(uri, URI_PREFIX_FILE))
        return;

    const char* realname = uri + URI_PREFIX_FILE_LEN;

    _DkDebugMapAdd(realname, start_addr);
#endif
}

void DkDebugMapRemove(PAL_PTR start_addr) {
#ifndef DEBUG
    __UNUSED(start_addr);
#else
    _DkDebugMapRemove(start_addr);
#endif
}

void DkDebugDescribeLocation(uintptr_t addr, char* buf, size_t buf_size) {
    pal_describe_location(addr, buf, buf_size);
}

void pal_describe_location(uintptr_t addr, char* buf, size_t buf_size) {
#ifdef DEBUG
    if (_DkDebugDescribeLocation(addr, buf, buf_size) == 0)
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
     * See also the corresponding LibOS entrypoint: LibOS/shim/src/arch/x86_64/start.S
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
    stack_entries_size += 1 * sizeof(ElfW(auxv_t));

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
    ElfW(auxv_t)* auxv = (ElfW(auxv_t)*)&stack_entries[idx];
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
