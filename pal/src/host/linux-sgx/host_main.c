/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 * Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include <asm/errno.h>
#include <asm/fcntl.h>
#include <linux/fs.h>

#include "asan.h"
#include "cpu.h"
#include "debug_map.h"
#include "etc_host_info.h"
#include "gdb_integration/sgx_gdb.h"
#include "host_ecalls.h"
#include "host_internal.h"
#include "host_log.h"
#include "host_process.h"
#include "host_sgx_driver.h"
#include "linux_utils.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"
#include "pal_rpc_queue.h"
#include "pal_rtld.h"
#include "pal_tcb.h"
#include "toml.h"
#include "toml_utils.h"
#include "topo_info.h"

const size_t g_page_size = PRESET_PAGESIZE;

char* g_pal_loader_path = NULL;
char* g_libpal_path = NULL;
pid_t g_host_pid;

bool g_vtune_profile_enabled = false;

struct pal_enclave g_pal_enclave;

static int read_file_fragment(int fd, void* buf, size_t size, off_t offset) {
    ssize_t ret;

    ret = DO_SYSCALL(lseek, fd, offset, SEEK_SET);
    if (ret < 0)
        return ret;

    return read_all(fd, buf, size);
}

static int load_elf_headers(int fd, elf_ehdr_t* out_ehdr, elf_phdr_t** out_phdr) {
    elf_ehdr_t ehdr;

    int ret = read_file_fragment(fd, &ehdr, sizeof(ehdr), /*offset=*/0);
    if (ret < 0)
        return ret;

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
        return -ENOEXEC;

    size_t phdr_size = ehdr.e_phnum * sizeof(elf_phdr_t);
    elf_phdr_t* phdr = malloc(phdr_size);
    if (!phdr)
        return -ENOMEM;

    ret = read_file_fragment(fd, phdr, phdr_size, ehdr.e_phoff);
    if (ret < 0) {
        free(phdr);
        return ret;
    }
    *out_ehdr = ehdr;
    *out_phdr = phdr;
    return 0;
}

static int scan_enclave_binary(int fd, unsigned long* base, unsigned long* size,
                               unsigned long* entry) {
    int ret;
    elf_ehdr_t ehdr;
    elf_phdr_t* phdr;

    ret = load_elf_headers(fd, &ehdr, &phdr);
    if (ret < 0)
        return ret;

    struct loadcmd {
        elf_addr_t mapstart, mapend;
    } loadcmds[16], *c;
    int nloadcmds = 0;

    const elf_phdr_t* ph;
    for (ph = phdr; ph < &phdr[ehdr.e_phnum]; ph++)
        if (ph->p_type == PT_LOAD) {
            if (nloadcmds == 16) {
                ret = -EINVAL;
                goto out;
            }

            c = &loadcmds[nloadcmds++];
            c->mapstart = ALLOC_ALIGN_DOWN(ph->p_vaddr);
            c->mapend   = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_memsz);
        }

    *base = loadcmds[0].mapstart;
    *size = loadcmds[nloadcmds - 1].mapend - loadcmds[0].mapstart;
    if (entry)
        *entry = ehdr.e_entry;
    ret = 0;

out:
    free(phdr);
    return ret;
}

static int load_enclave_binary(sgx_arch_secs_t* secs, int fd, unsigned long base,
                               unsigned long prot) {
    int ret;
    elf_ehdr_t ehdr;
    elf_phdr_t* phdr;

    ret = load_elf_headers(fd, &ehdr, &phdr);
    if (ret < 0)
        return ret;

    struct loadcmd {
        elf_addr_t mapstart, mapend, datastart, dataend, allocend;
        unsigned int mapoff;
        int prot;
    } loadcmds[16], *c;
    int nloadcmds = 0;

    elf_phdr_t* ph;
    for (ph = phdr; ph < &phdr[ehdr.e_phnum]; ph++)
        if (ph->p_type == PT_LOAD) {
            if (nloadcmds == 16) {
                ret = -EINVAL;
                goto out;
            }

            c = &loadcmds[nloadcmds++];
            c->mapstart  = ALLOC_ALIGN_DOWN(ph->p_vaddr);
            c->mapend    = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_filesz);
            c->datastart = ph->p_vaddr;
            c->dataend   = ph->p_vaddr + ph->p_filesz;
            c->allocend  = ph->p_vaddr + ph->p_memsz;
            c->mapoff    = ALLOC_ALIGN_DOWN(ph->p_offset);
            c->prot = (ph->p_flags & PF_R ? PROT_READ : 0) | (ph->p_flags & PF_W ? PROT_WRITE : 0) |
                      (ph->p_flags & PF_X ? PROT_EXEC : 0) | prot;
        }

    base -= loadcmds[0].mapstart;
    for (c = loadcmds; c < &loadcmds[nloadcmds]; c++) {
        elf_addr_t zero     = c->dataend;
        elf_addr_t zeroend  = ALLOC_ALIGN_UP(c->allocend);
        elf_addr_t zeropage = ALLOC_ALIGN_UP(zero);

        if (zeroend < zeropage)
            zeropage = zeroend;

        if (c->mapend > c->mapstart) {
            void* addr = (void*)DO_SYSCALL(mmap, NULL, c->mapend - c->mapstart,
                                           PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, c->mapoff);

            if (IS_PTR_ERR(addr)) {
                ret = PTR_TO_ERR(addr);
                goto out;
            }

            if (c->datastart > c->mapstart)
                memset(addr, 0, c->datastart - c->mapstart);

            if (zeropage > zero)
                memset(addr + zero - c->mapstart, 0, zeropage - zero);

            ret = add_pages_to_enclave(secs, (void*)base + c->mapstart, addr,
                                       c->mapend - c->mapstart,
                                       SGX_PAGE_TYPE_REG, c->prot, /*skip_eextend=*/false,
                                       (c->prot & PROT_EXEC) ? "code" : "data");

            DO_SYSCALL(munmap, addr, c->mapend - c->mapstart);

            if (ret < 0)
                goto out;
        }

        if (zeroend > zeropage) {
            ret = add_pages_to_enclave(secs, (void*)base + zeropage, NULL, zeroend - zeropage,
                                       SGX_PAGE_TYPE_REG, c->prot, false, "bss");
            if (ret < 0)
                goto out;
        }
    }
    ret = 0;

out:
    free(phdr);
    return ret;
}

#if defined(CONFIG_SGX_DRIVER_OOT)
static int get_enclave_token(sgx_arch_token_t* enclave_token, sgx_sigstruct_t* enclave_sigstruct) {
    __UNUSED(enclave_sigstruct);
    char* token_path = NULL;
    int token_fd = -1;
    int ret;

    token_path = alloc_concat(g_pal_enclave.application_path, -1, ".token", -1);
    if (!token_path) {
        ret = -ENOMEM;
        goto out;
    }

    token_fd = DO_SYSCALL(open, token_path, O_RDONLY | O_CLOEXEC, 0);
    if (token_fd < 0) {
        log_error("Cannot open token %s. Use gramine-sgx-get-token on the runtime host to create "
                  "the token file.", token_path);
        ret = -EINVAL;
        goto out;
    }
    log_debug("Token file: %s", token_path);

    ret = read_enclave_token(token_fd, enclave_token);
    if (ret < 0) {
        log_error("Reading enclave token failed: %s", unix_strerror(ret));
        goto out;
    }

    ret = 0;
out:
    if (token_fd >= 0)
        DO_SYSCALL(close, token_fd);
    free(token_path);
    return ret;
}
#elif defined(CONFIG_SGX_DRIVER_UPSTREAM)
static int get_enclave_token(sgx_arch_token_t* enclave_token, sgx_sigstruct_t* enclave_sigstruct) {
    return create_dummy_enclave_token(enclave_sigstruct, enclave_token);
}
#else
    #error This config should be unreachable.
#endif

static int initialize_enclave(struct pal_enclave* enclave, const char* manifest_to_measure) {
    int ret = 0;
    int enclave_image = -1;
    sgx_arch_token_t enclave_token;
    sgx_sigstruct_t enclave_sigstruct;
    sgx_arch_secs_t enclave_secs;
    unsigned long enclave_entry_addr;
    unsigned long enclave_heap_min;
    char* sig_path = NULL;
    int sigfile_fd = -1;
    size_t areas_size = 0;
    struct mem_area* areas = NULL;

    void** tcs_addrs = (void**)malloc(sizeof(void*) * enclave->thread_num);
    if (!tcs_addrs) {
        return -ENOMEM;
    }

    enclave_image = DO_SYSCALL(open, enclave->libpal_uri + URI_PREFIX_FILE_LEN,
                               O_RDONLY | O_CLOEXEC, 0);
    if (enclave_image < 0) {
        log_error("Cannot find enclave image: %s", enclave->libpal_uri);
        ret = enclave_image;
        goto out;
    }

    /* set up enclave address space so that it works also for non-PIE binaries: enclave base address
     * must cover code segment loaded at some hardcoded address (usually 0x400000), and heap cannot
     * start at zero (modern OSes do not allow this) */
    enclave->baseaddr = DEFAULT_ENCLAVE_BASE;
    enclave_heap_min  = MMAP_MIN_ADDR;

    sig_path = alloc_concat(g_pal_enclave.application_path, -1, ".sig", -1);
    if (!sig_path) {
        ret = -ENOMEM;
        goto out;
    }

    sigfile_fd = DO_SYSCALL(open, sig_path, O_RDONLY | O_CLOEXEC, 0);
    if (sigfile_fd < 0) {
        log_error("Cannot open sigstruct file %s", sig_path);
        ret = -EINVAL;
        goto out;
    }

    ret = read_enclave_sigstruct(sigfile_fd, &enclave_sigstruct);
    if (ret < 0) {
        log_error("Reading enclave sigstruct failed: %s", unix_strerror(ret));
        goto out;
    }

    ret = get_enclave_token(&enclave_token, &enclave_sigstruct);
    if (ret < 0) {
        log_error("Reading enclave token failed: %s", unix_strerror(ret));
        goto out;
    }

#ifdef DEBUG
    if (enclave->profile_enable) {
        if (!(enclave_token.body.attributes.flags & SGX_FLAGS_DEBUG)) {
            log_error("Cannot use 'sgx.profile' with a production enclave");
            ret = -EINVAL;
            goto out;
        }

        ret = sgx_profile_init();
        if (ret < 0)
            goto out;

        /* Report all ELFs already loaded (host part of PAL and dynamic libraries used by it) */
        struct debug_map* map = g_debug_map;
        while (map) {
            sgx_profile_report_elf(map->name, map->addr);
            map = map->next;
        }
    }
#endif

    memset(&enclave_secs, 0, sizeof(enclave_secs));
    enclave_secs.base = enclave->baseaddr;
    enclave_secs.size = enclave->size;
    ret = create_enclave(&enclave_secs, &enclave_token);
    if (ret < 0) {
        log_error("Creating enclave failed: %s", unix_strerror(ret));
        goto out;
    }

    /* SECS contains SSA frame size in pages, convert to size in bytes */
    enclave->ssa_frame_size = enclave_secs.ssa_frame_size * g_page_size;

    /* Start populating enclave memory */
    struct mem_area {
        const char* desc;
        bool skip_eextend;

        enum {
            ELF_FD, // read from `fd` and parse as ELF
            ZERO,
            BUF,
            TCS,
            TLS
        } data_src;
        union {
            int fd; // valid iff data_src == ELF_FD
            struct { // valid iff data_src == BUF
                const char* buf;
                size_t buf_size;
            };
        };

        unsigned long addr, size, prot;
        enum sgx_page_type type;
    };

    /*
     * 10 for manifest, SSA, TCS, etc
     * + enclave->thread_num for normal stack
     * + enclave->thread_num for signal stack
     */
    areas_size = ALIGN_UP_POW2(sizeof(*areas) * (10 + enclave->thread_num * 2), PRESET_PAGESIZE);
    areas = (struct mem_area*)DO_SYSCALL(mmap, NULL, areas_size, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (IS_PTR_ERR(areas)) {
        log_error("Allocating memory failed: %s", unix_strerror(PTR_TO_ERR(areas)));
        areas = NULL;
        ret = -ENOMEM;
        goto out;
    }

    int area_num = 0;

    /* The manifest needs to be allocated at the upper end of the enclave
     * memory. That's used by pal_linux_main to find the manifest area. So add
     * it first to the list with memory areas. */
    size_t manifest_size = strlen(manifest_to_measure) + 1;
    areas[area_num] = (struct mem_area){.desc         = "manifest",
                                        .skip_eextend = false,
                                        .data_src     = BUF,
                                        .buf          = manifest_to_measure,
                                        .buf_size     = manifest_size,
                                        .addr         = 0,
                                        .size         = ALLOC_ALIGN_UP(manifest_size),
                                        .prot         = PROT_READ,
                                        .type         = SGX_PAGE_TYPE_REG};
    area_num++;

    areas[area_num] =
        (struct mem_area){.desc         = "ssa",
                          .skip_eextend = false,
                          .data_src     = ZERO,
                          .addr         = 0,
                          .size         = enclave->thread_num * enclave->ssa_frame_size *
                                              SSA_FRAME_NUM,
                          .prot         = PROT_READ | PROT_WRITE,
                          .type         = SGX_PAGE_TYPE_REG};
    struct mem_area* ssa_area = &areas[area_num++];

    areas[area_num] = (struct mem_area){.desc = "tcs",
                                        .skip_eextend = false,
                                        .data_src     = TCS,
                                        .addr         = 0,
                                        .size         = enclave->thread_num * g_page_size,
                                        .prot         = PROT_READ | PROT_WRITE,
                                        .type         = SGX_PAGE_TYPE_TCS};
    struct mem_area* tcs_area = &areas[area_num++];

    areas[area_num] = (struct mem_area){.desc         = "tls",
                                        .skip_eextend = false,
                                        .data_src     = TLS,
                                        .addr         = 0,
                                        .size         = enclave->thread_num * g_page_size,
                                        .prot         = PROT_READ | PROT_WRITE,
                                        .type         = SGX_PAGE_TYPE_REG};
    struct mem_area* tls_area = &areas[area_num++];

    struct mem_area* stack_areas = &areas[area_num]; /* memorize for later use */
    for (size_t t = 0; t < enclave->thread_num; t++) {
        areas[area_num] = (struct mem_area){.desc         = "stack",
                                            .skip_eextend = false,
                                            .data_src     = ZERO,
                                            .addr         = 0,
                                            .size         = ENCLAVE_STACK_SIZE,
                                            .prot         = PROT_READ | PROT_WRITE,
                                            .type         = SGX_PAGE_TYPE_REG};
        area_num++;
    }

    struct mem_area* sig_stack_areas = &areas[area_num]; /* memorize for later use */
    for (size_t t = 0; t < enclave->thread_num; t++) {
        areas[area_num] = (struct mem_area){.desc         = "sig_stack",
                                            .skip_eextend = false,
                                            .data_src     = ZERO,
                                            .addr         = 0,
                                            .size         = ENCLAVE_SIG_STACK_SIZE,
                                            .prot         = PROT_READ | PROT_WRITE,
                                            .type         = SGX_PAGE_TYPE_REG};
        area_num++;
    }

    areas[area_num] = (struct mem_area){.desc         = "pal",
                                        .skip_eextend = false,
                                        .data_src     = ELF_FD,
                                        .fd           = enclave_image,
                                        /* `addr` and `size` are set below */
                                        .prot         = 0,
                                        .type         = SGX_PAGE_TYPE_REG};
    struct mem_area* pal_area = &areas[area_num++];

    ret = scan_enclave_binary(enclave_image, &pal_area->addr, &pal_area->size, &enclave_entry_addr);
    if (ret < 0) {
        log_error("Scanning PAL binary (%s) failed: %s", enclave->libpal_uri, unix_strerror(ret));
        goto out;
    }

    uintptr_t last_populated_addr = enclave->baseaddr + enclave->size;
    for (int i = 0; i < area_num; i++) {
        if (areas[i].addr)
            continue;
        areas[i].addr = last_populated_addr - areas[i].size;
        last_populated_addr = areas[i].addr;
    }

    enclave_entry_addr += pal_area->addr;

    struct mem_area* free_area = NULL;
    if (last_populated_addr > enclave_heap_min) {
        areas[area_num] = (struct mem_area){.desc         = "free",
                                            .skip_eextend = true,
                                            .data_src     = ZERO,
                                            .addr         = enclave_heap_min,
                                            .size         = last_populated_addr - enclave_heap_min,
                                            .prot         = PROT_READ | PROT_WRITE | PROT_EXEC,
                                            .type         = SGX_PAGE_TYPE_REG};
        free_area = &areas[area_num++];
    }

    log_debug("Adding pages to SGX enclave, this may take some time...");
    for (int i = 0; i < area_num; i++) {
        if (areas[i].data_src == ELF_FD) {
            ret = load_enclave_binary(&enclave_secs, areas[i].fd, areas[i].addr, areas[i].prot);
            if (ret < 0) {
                log_error("Loading enclave binary failed: %s", unix_strerror(ret));
                goto out;
            }
            continue;
        }

        if (areas[i].skip_eextend && enclave->edmm_enabled) {
            assert(areas[i].data_src == ZERO);
            /* If EDMM is enabled, no need to add non-measured zero pages. */
            continue;
        }

        void* data = NULL;
        if (areas[i].data_src != ZERO) {
            data = (void*)DO_SYSCALL(mmap, NULL, areas[i].size, PROT_READ | PROT_WRITE,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            if (IS_PTR_ERR(data) || data == NULL) {
                /* Note that Gramine currently doesn't handle 0x0 addresses */
                log_error("Allocating memory failed");
                ret = -ENOMEM;
                goto out;
            }
        }

        if (areas[i].data_src == TLS) {
            for (size_t t = 0; t < enclave->thread_num; t++) {
                struct pal_enclave_tcb* gs = data + g_page_size * t;
                memset(gs, 0, g_page_size);
                assert(sizeof(*gs) <= g_page_size);
                gs->common.self = (PAL_TCB*)(tls_area->addr + g_page_size * t);
                gs->common.stack_protector_canary = STACK_PROTECTOR_CANARY_DEFAULT;
                gs->enclave_size = enclave->size;
                gs->tcs_offset = tcs_area->addr - enclave->baseaddr + g_page_size * t;
                gs->initial_stack_addr = stack_areas[t].addr + ENCLAVE_STACK_SIZE;
                gs->sig_stack_low = sig_stack_areas[t].addr;
                gs->sig_stack_high = sig_stack_areas[t].addr + ENCLAVE_SIG_STACK_SIZE;
                gs->ssa = (void*)ssa_area->addr + enclave->ssa_frame_size * SSA_FRAME_NUM * t;
                gs->gpr = gs->ssa + enclave->ssa_frame_size - sizeof(sgx_pal_gpr_t);
                gs->manifest_size = manifest_size;
                gs->heap_min = (void*)enclave_heap_min;
                gs->heap_max = (void*)pal_area->addr;
                gs->thread = NULL;
            }
        } else if (areas[i].data_src == TCS) {
            for (size_t t = 0; t < enclave->thread_num; t++) {
                sgx_arch_tcs_t* tcs = data + g_page_size * t;
                memset(tcs, 0, g_page_size);
                // .ossa, .oentry, .ofs_base and .ogs_base are offsets from enclave base, not VAs.
                tcs->ossa      = ssa_area->addr - enclave->baseaddr
                                 + enclave->ssa_frame_size * SSA_FRAME_NUM * t;
                tcs->nssa      = SSA_FRAME_NUM;
                tcs->oentry    = enclave_entry_addr - enclave->baseaddr;
                tcs->ofs_base  = 0;
                tcs->ogs_base  = tls_area->addr - enclave->baseaddr + t * g_page_size;
                tcs->ofs_limit = 0xfff;
                tcs->ogs_limit = 0xfff;
                tcs_addrs[t] = (void*)tcs_area->addr + g_page_size * t;
            }
        } else if (areas[i].data_src == BUF) {
            memcpy(data, areas[i].buf, areas[i].buf_size);
        } else {
            assert(areas[i].data_src == ZERO);
        }

        ret = add_pages_to_enclave(&enclave_secs, (void*)areas[i].addr, data, areas[i].size,
                                   areas[i].type, areas[i].prot, areas[i].skip_eextend,
                                   areas[i].desc);

        if (data)
            DO_SYSCALL(munmap, data, areas[i].size);

        if (ret < 0) {
            log_error("Adding pages (%s) to enclave failed: %s", areas[i].desc,
                      unix_strerror(ret));
            goto out;
        }
    }
    log_debug("Added all pages to SGX enclave");

    ret = init_enclave(&enclave_secs, &enclave_sigstruct, &enclave_token);
    if (ret < 0) {
        log_error("Initializing enclave failed: %s", unix_strerror(ret));
        goto out;
    }

    ret = create_tcs_mapper((void*)tcs_area->addr, enclave->thread_num);
    if (ret < 0) {
        log_error("Create tcs mapper failed: %s", unix_strerror(ret));
        goto out;
    }

    struct enclave_dbginfo* dbg = (void*)DO_SYSCALL(mmap, DBGINFO_ADDR,
                                                    sizeof(struct enclave_dbginfo),
                                                    PROT_READ | PROT_WRITE,
                                                    MAP_PRIVATE | MAP_ANONYMOUS
                                                        | MAP_FIXED_NOREPLACE,
                                                    /*fd=*/-1,
                                                    /*offset=*/0);
    if (IS_PTR_ERR(dbg)) {
        log_warning("Cannot allocate debug information (GDB will not work)");
    } else {
        assert(dbg == (void*)DBGINFO_ADDR);
        dbg->pid            = g_host_pid;
        dbg->base           = enclave->baseaddr;
        dbg->size           = enclave->size;
        dbg->ssa_frame_size = enclave->ssa_frame_size;
        dbg->aep            = async_exit_pointer;
        dbg->eresume        = eresume_pointer;
        dbg->thread_tids[0] = dbg->pid;
        for (size_t t = 0; t < enclave->thread_num; t++)
            dbg->tcs_addrs[t] = tcs_addrs[t];
    }

    ret = set_tcs_debug_flag_if_debugging(tcs_addrs, enclave->thread_num);
    if (ret < 0) {
        goto out;
    }

#ifdef DEBUG
    /*
     * Report libpal map. All subsequent files will be reported via PalDebugMapAdd(), but this
     * one has to be handled separately.
     *
     * We report it here, before enclave start (as opposed to setup_pal_binary()), because we want
     * both GDB integration and profiling to be active from the very beginning of enclave execution.
     */
    debug_map_add(enclave->libpal_uri + URI_PREFIX_FILE_LEN, (void*)pal_area->addr);
    sgx_profile_report_elf(enclave->libpal_uri + URI_PREFIX_FILE_LEN, (void*)pal_area->addr);
#endif

#ifdef ASAN
    if (free_area && !enclave->edmm_enabled)
        asan_poison_region(free_area->addr, free_area->size, ASAN_POISON_USER);
#else
    __UNUSED(free_area);
#endif

    ret = 0;

out:
    free(tcs_addrs);
    if (enclave_image >= 0)
        DO_SYSCALL(close, enclave_image);
    if (sigfile_fd >= 0)
        DO_SYSCALL(close, sigfile_fd);
    if (areas)
        DO_SYSCALL(munmap, areas, areas_size);
    free(sig_path);
    return ret;
}

/* Parses only the information needed by the untrusted PAL to correctly initialize the enclave. */
static int parse_loader_config(char* manifest, struct pal_enclave* enclave_info,
                               bool* extra_runtime_domain_names_conf) {
    int ret = 0;
    toml_table_t* manifest_root = NULL;
    char* dummy_sigfile_str = NULL;
    char* profile_str = NULL;
#ifdef DEBUG
    char* profile_mode_str = NULL;
#endif
    char* log_level_str = NULL;
    char* log_file = NULL;
    char errbuf[256];

    manifest_root = toml_parse(manifest, errbuf, sizeof(errbuf));
    if (!manifest_root) {
        log_error("PAL failed at parsing the manifest: %s", errbuf);
        ret = -EINVAL;
        goto out;
    }

    ret = toml_sizestring_in(manifest_root, "sgx.enclave_size", /*defaultval=*/0,
                             &enclave_info->size);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.enclave_size'");
        ret = -EINVAL;
        goto out;
    }

    ret = toml_bool_in(manifest_root, "sgx.edmm_enable", /*defaultval=*/false,
                       &enclave_info->edmm_enabled);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.edmm_enable'");
        ret = -EINVAL;
        goto out;
    }

    if (!enclave_info->size || !IS_POWER_OF_2(enclave_info->size)) {
        log_error("Enclave size not a power of two (an SGX-imposed requirement)");
        ret = -EINVAL;
        goto out;
    }

    int64_t thread_num_int64;
    ret = toml_int_in(manifest_root, "sgx.max_threads", /*defaultval=*/-1, &thread_num_int64);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.max_threads'");
        ret = -EINVAL;
        goto out;
    }

    if (thread_num_int64 < 0) {
        log_error("'sgx.max_threads' not found in the manifest");
        ret = -EINVAL;
        goto out;
    }

    if (!thread_num_int64) {
        log_error("'sgx.max_threads' must be a positive number");
        ret = -EINVAL;
        goto out;
    }
    if (thread_num_int64 > MAX_DBG_THREADS) {
        log_error("Too large 'sgx.max_threads', maximum allowed is %d", MAX_DBG_THREADS);
        ret = -EINVAL;
        goto out;
    }
    enclave_info->thread_num = thread_num_int64;

    int64_t rpc_thread_num_int64;
    ret = toml_int_in(manifest_root, "sgx.insecure__rpc_thread_num", /*defaultval=*/0,
                      &rpc_thread_num_int64);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.insecure__rpc_thread_num'");
        ret = -EINVAL;
        goto out;
    }

    if (rpc_thread_num_int64 < 0) {
        log_error("Negative 'sgx.insecure__rpc_thread_num' is impossible");
        ret = -EINVAL;
        goto out;
    }

    if (rpc_thread_num_int64 > MAX_RPC_THREADS) {
        log_error("Too large 'sgx.insecure__rpc_thread_num', maximum allowed is %d",
                  MAX_RPC_THREADS);
        ret = -EINVAL;
        goto out;
    }
    enclave_info->rpc_thread_num = rpc_thread_num_int64;

    if (enclave_info->rpc_thread_num && enclave_info->thread_num > RPC_QUEUE_SIZE) {
        log_error("Too many threads for exitless feature (more than capacity of RPC queue)");
        ret = -EINVAL;
        goto out;
    }

    ret = toml_bool_in(manifest_root, "sgx.enable_stats", /*defaultval=*/false,
                       &g_sgx_enable_stats);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.enable_stats' (the value must be `true` or `false`)");
        ret = -EINVAL;
        goto out;
    }

    ret = toml_string_in(manifest_root, "sgx.sigfile", &dummy_sigfile_str);
    if (ret < 0 || dummy_sigfile_str) {
        log_error("sgx.sigfile is not supported anymore. Please update your manifest according to "
                  "the current documentation.");
        ret = -EINVAL;
        goto out;
    }

    ret = parse_attestation_type(manifest_root, &enclave_info->attestation_type);
    if (ret < 0) {
        /* error is already printed by the called func */
        goto out;
    }

    ret = toml_string_in(manifest_root, "sgx.profile.enable", &profile_str);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.profile.enable' "
                  "(the value must be \"none\", \"main\" or \"all\")");
        ret = -EINVAL;
        goto out;
    }

    ret = toml_bool_in(manifest_root, "sgx.vtune_profile", /*defaultval=*/false, &g_vtune_profile_enabled);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.vtune_profile' (the value must be `true` or `false`)");
        ret = -EINVAL;
        goto out;
    }

#ifndef SGX_VTUNE_PROFILE
    if (g_vtune_profile_enabled)
        log_always("Gramine was not built with VTune profiling support, "
                   "'sgx.vtune_profile' manifest option has no impact.");
#endif

#ifdef DEBUG
    enclave_info->profile_enable = false;
    enclave_info->profile_filename[0] = '\0';

    if (!profile_str || !strcmp(profile_str, "none")) {
        // do not enable
    } else if (!strcmp(profile_str, "main")) {
        if (enclave_info->is_first_process) {
            snprintf(enclave_info->profile_filename, ARRAY_SIZE(enclave_info->profile_filename),
                     SGX_PROFILE_FILENAME);
            enclave_info->profile_enable = true;
        }
    } else if (!strcmp(profile_str, "all")) {
        enclave_info->profile_enable = true;
        snprintf(enclave_info->profile_filename, ARRAY_SIZE(enclave_info->profile_filename),
                 SGX_PROFILE_FILENAME_WITH_PID, (int)g_host_pid);
    } else {
        log_error("Invalid 'sgx.profile.enable' "
                  "(the value must be \"none\", \"main\" or \"all\")");
        ret = -EINVAL;
        goto out;
    }

    ret = toml_string_in(manifest_root, "sgx.profile.mode", &profile_mode_str);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.profile.mode' "
                  "(the value must be \"aex\", \"ocall_inner\" or \"ocall_outer\")");
        ret = -EINVAL;
        goto out;
    }
    if (!profile_mode_str) {
        enclave_info->profile_mode = SGX_PROFILE_MODE_AEX;
    } else if (!strcmp(profile_mode_str, "aex")) {
        enclave_info->profile_mode = SGX_PROFILE_MODE_AEX;
    } else if (!strcmp(profile_mode_str, "ocall_inner")) {
        enclave_info->profile_mode = SGX_PROFILE_MODE_OCALL_INNER;
    } else if (!strcmp(profile_mode_str, "ocall_outer")) {
        enclave_info->profile_mode = SGX_PROFILE_MODE_OCALL_OUTER;
    } else {
        log_error("Invalid 'sgx.profile.mode' "
                  "(the value must be \"aex\", \"ocall_inner\" or \"ocall_outer\")");
        ret = -EINVAL;
        goto out;
    }

    bool profile_with_stack;
    ret = toml_bool_in(manifest_root, "sgx.profile.with_stack", /*defaultval=*/false,
                       &profile_with_stack);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.profile.with_stack' (the value must be `true` or `false`)");
        ret = -EINVAL;
        goto out;
    }
    enclave_info->profile_with_stack = profile_with_stack;

    if (enclave_info->profile_with_stack &&
        enclave_info->profile_mode == SGX_PROFILE_MODE_OCALL_OUTER) {

        log_error("Invalid 'sgx.profile.mode' and 'sgx.profile.with_stack' combination "
                  "(\"ocall_outer\" mode cannot be used with stack)");
        ret = -EINVAL;
        goto out;
    }

    int64_t profile_frequency;
    ret = toml_int_in(manifest_root, "sgx.profile.frequency", SGX_PROFILE_DEFAULT_FREQUENCY,
                      &profile_frequency);
    if (ret < 0 || !(0 < profile_frequency && profile_frequency <= SGX_PROFILE_MAX_FREQUENCY)) {
        log_error("Cannot parse 'sgx.profile.frequency' (the value must be between 1 and %d)",
                  SGX_PROFILE_MAX_FREQUENCY);
        ret = -EINVAL;
        goto out;
    }
    enclave_info->profile_frequency = profile_frequency;
#else
    if (profile_str && strcmp(profile_str, "none")) {
        log_error("Invalid 'sgx.profile.enable' "
                  "(SGX profiling works only when Gramine is compiled in debug mode)");
        ret = -EINVAL;
        goto out;
    }
#endif

    int log_level = PAL_LOG_DEFAULT_LEVEL;
    ret = toml_string_in(manifest_root, "loader.log_level", &log_level_str);
    if (ret < 0) {
        log_error("Cannot parse 'loader.log_level'");
        ret = -EINVAL;
        goto out;
    }
    if (log_level_str) {
        if (!strcmp(log_level_str, "none")) {
            log_level = LOG_LEVEL_NONE;
        } else if (!strcmp(log_level_str, "error")) {
            log_level = LOG_LEVEL_ERROR;
        } else if (!strcmp(log_level_str, "warning")) {
            log_level = LOG_LEVEL_WARNING;
        } else if (!strcmp(log_level_str, "debug")) {
            log_level = LOG_LEVEL_DEBUG;
        } else if (!strcmp(log_level_str, "trace")) {
            log_level = LOG_LEVEL_TRACE;
        } else if (!strcmp(log_level_str, "all")) {
            log_level = LOG_LEVEL_ALL;
        } else {
            log_error("Unknown 'loader.log_level'");
            ret = -EINVAL;
            goto out;
        }
    }

    ret = toml_string_in(manifest_root, "loader.log_file", &log_file);
    if (ret < 0) {
        log_error("Cannot parse 'loader.log_file'");
        ret = -EINVAL;
        goto out;
    }
    if (log_level > LOG_LEVEL_NONE && log_file) {
        ret = host_log_init(log_file);

        if (ret < 0) {
            log_error("Cannot open log file: %s", unix_strerror(ret));
            goto out;
        }
    }
    g_host_log_level = log_level;

    ret = toml_bool_in(manifest_root, "sys.enable_extra_runtime_domain_names_conf",
                       /*defaultval=*/false, extra_runtime_domain_names_conf);
    if (ret < 0) {
        log_error("Cannot parse 'sys.enable_extra_runtime_domain_names_conf'");
        goto out;
    }

    ret = 0;

out:
    free(dummy_sigfile_str);
    free(profile_str);
#ifdef DEBUG
    free(profile_mode_str);
#endif
    free(log_level_str);
    free(log_file);
    toml_free(manifest_root);
    return ret;
}

/* Warning: This function does not free up resources on failure - it assumes that the whole process
 * exits after this function's failure. */
static int load_enclave(struct pal_enclave* enclave, char* args, size_t args_size, char* env,
                        size_t env_size, int parent_stream_fd,
                        void* reserved_mem_ranges, size_t reserved_mem_ranges_size) {
    int ret;
    struct timeval tv;
    struct pal_topo_info topo_info = {0};
    struct pal_dns_host_conf dns_conf = {0};
    bool extra_runtime_domain_names_conf;
    uint64_t start_time;
    DO_SYSCALL(gettimeofday, &tv, NULL);
    start_time = tv.tv_sec * 1000000UL + tv.tv_usec;

    if (parent_stream_fd < 0) {
        /* only print during main process's startup (note that this message is always printed) */
        log_always("Gramine is starting. Parsing TOML manifest file, this may take some time...");
    }
    ret = parse_loader_config(enclave->raw_manifest_data, enclave, &extra_runtime_domain_names_conf);
    if (ret < 0) {
        log_error("Parsing manifest failed");
        return -EINVAL;
    }
    log_debug("Gramine parsed TOML manifest file successfully");

    ret = open_sgx_driver();
    if (ret < 0)
        return ret;

    if (!is_wrfsbase_supported())
        return -EPERM;

    /* Get host information and topology only for the first process. This information will be
     * checkpointed and restored during forking of the child process(es). */
    if (parent_stream_fd < 0) {
        ret = get_topology_info(&topo_info);
        if (ret < 0)
            return ret;

        if (extra_runtime_domain_names_conf) {
            ret = parse_resolv_conf(&dns_conf);
            if (ret < 0) {
                log_error("Unable to parse host's /etc/resolv.conf");
                return ret;
            }
            ret = get_hosts_hostname(dns_conf.hostname, sizeof(dns_conf.hostname));
            if (ret < 0) {
                log_error("Unable to get host's hostname");
                return ret;
            }
        }
    }

    enclave->libpal_uri = alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, g_libpal_path, -1);
    if (!enclave->libpal_uri) {
        log_error("Out of memory for enclave->libpal_uri");
        return -ENOMEM;
    }

    if (enclave->libpal_uri[URI_PREFIX_FILE_LEN] != '/') {
        log_error("Path to in-enclave PAL (%s) must be absolute", enclave->libpal_uri);
        return -EINVAL;
    }

    if (enclave->edmm_enabled) {
        uint32_t values[4];
        cpuid(INTEL_SGX_LEAF, 0, values);
        if (!(values[CPUID_WORD_EAX] & (1u << 1))) {
            log_error("EDMM feature was requested in manifest, but CPU doesn't support it");
            return -EPERM;
        }

        bool edmm_supported;
        ret = edmm_supported_by_driver(&edmm_supported);
        if (ret < 0) {
            log_error("Failed to check support for EDMM feature: %s", unix_strerror(ret));
            return ret;
        }
        if (!edmm_supported) {
            log_error("EDMM feature was requested in manifest, but SGX driver doesn't support it");
            return -EPERM;
        }
    }

    ret = initialize_enclave(enclave, enclave->raw_manifest_data);
    if (ret < 0)
        return ret;

    ret = sgx_signal_setup();
    if (ret < 0)
        return ret;

    sgx_target_info_t qe_targetinfo = {0};
    if (enclave->attestation_type != SGX_ATTESTATION_NONE) {
        /* initialize communication with Quoting Enclave only if app requests attestation */
        log_debug("Using SGX attestation type \"%s\"",
                  attestation_type_to_str(enclave->attestation_type));
        bool is_epid = enclave->attestation_type == SGX_ATTESTATION_EPID;
        ret = init_quoting_enclave_targetinfo(is_epid, &qe_targetinfo);
        if (ret < 0)
            return ret;
    }

    void* alt_stack = (void*)DO_SYSCALL(mmap, NULL, ALT_STACK_SIZE, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (IS_PTR_ERR(alt_stack))
        return -ENOMEM;

    /* initialize TCB at the top of the alternative stack */
    PAL_HOST_TCB* tcb = alt_stack + ALT_STACK_SIZE - sizeof(PAL_HOST_TCB);
    /* main thread uses the stack provided by Linux */
    pal_host_tcb_init(tcb, /*stack=*/NULL, alt_stack);
    ret = pal_thread_init(tcb);
    if (ret < 0)
        return ret;

    uint64_t end_time;
    DO_SYSCALL(gettimeofday, &tv, NULL);
    end_time = tv.tv_sec * 1000000UL + tv.tv_usec;

    if (g_sgx_enable_stats) {
        /* This shows the time for Gramine + the Intel SGX driver to initialize the untrusted
         * PAL, config and create the SGX enclave, add enclave pages, measure and init it.
         */
        log_always("----- SGX enclave loading time = %10lu microseconds -----",
                   end_time - start_time);
    }

    /* start running trusted PAL */
    ecall_enclave_start(enclave->libpal_uri, args, args_size, env, env_size, parent_stream_fd,
                        &qe_targetinfo, &topo_info, &dns_conf, enclave->edmm_enabled,
                        reserved_mem_ranges, reserved_mem_ranges_size);

    unmap_my_tcs();
    DO_SYSCALL(munmap, alt_stack, ALT_STACK_SIZE);
    DO_SYSCALL(exit, 0);
    die_or_inf_loop();
}

noreturn static void print_usage_and_exit(const char* argv_0) {
    const char* self = argv_0 ?: "<this program>";
    log_always("USAGE:\n"
               "\tFirst process: %s <path to libpal.so> init <application> args...\n"
               "\tChildren:      %s <path to libpal.so> child <parent_stream_fd> args...",
               self, self);
    log_always("This is an internal interface. Use gramine-sgx wrapper to launch applications in "
               "Gramine.");
    DO_SYSCALL(exit_group, 1);
    die_or_inf_loop();
}

static int get_aux_value(char** envp, uint64_t type, uint64_t* out_value) {
    while (*envp)
        envp++;

    for (elf_auxv_t* auxv = (elf_auxv_t*)(envp + 1); auxv->a_type != AT_NULL; auxv++) {
        if (auxv->a_type == type) {
            *out_value = auxv->a_un.a_val;
            return 0;
        }
    }
    return -1;
}

#ifdef ASAN
/*
 * HACK: `setup_asan` is not called inside `main`, but defined as a constructor with a priority of
 * 0, which is normally reserved. This is because we need to run it before module constructors
 * generated by ASan itself (which have a priority of 1).
 *
 * Note that this is necessary only because we're in an executable linked against Glibc. In other
 * cases, we invoke the constructors from `.init_array` directly, so we have full control over
 * initialization.
 */
__attribute((constructor(0)))
__attribute_no_sanitize_address
static void setup_asan(void) {
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE;
    void* addr = (void*)DO_SYSCALL(mmap, (void*)ASAN_SHADOW_START, ASAN_SHADOW_LENGTH, prot, flags,
                                   /*fd=*/-1, /*offset=*/0);
    if (IS_PTR_ERR(addr) || addr != (void*)ASAN_SHADOW_START) {
        int err = PTR_TO_ERR(addr);
        log_error("asan: error setting up shadow memory: %s", unix_strerror(err));
        DO_SYSCALL(exit_group, unix_to_pal_error(err));
        die_or_inf_loop();
    }
}
#endif

static int verify_hw_requirements(char* envp[]) {
    uint64_t at_hwcap2;
    if (get_aux_value(envp, AT_HWCAP2, &at_hwcap2) != 0 || !(at_hwcap2 & 0x2)) {
        log_error("Gramine with Linux-SGX backend requires support for FSGSBASE CPU instructions "
                  "in the host kernel. Please update your system.");
        return -EINVAL;
    }

    unsigned int values[4];
    cpuid(FEATURE_FLAGS_LEAF, /*unused*/0, values);
    const char* missing = NULL;
    if (!(values[CPUID_WORD_ECX] & (1 << 25)))
        missing = "AES-NI";
    else if (!(values[CPUID_WORD_ECX] & (1 << 26)))
        missing = "XSAVE";
    else if (!(values[CPUID_WORD_ECX] & (1 << 30)))
        missing = "RDRAND";
    if (missing) {
        log_error("Gramine with Linux-SGX backend requires %s CPU instruction(s). "
                  "Please upgrade your hardware.", missing);
        return -EINVAL;
    }
    return 0;
}

__attribute_no_sanitize_address
int main(int argc, char* argv[], char* envp[]) {
    char* manifest_path = NULL;
    int ret = 0;
    char* manifest = NULL;
    void* reserved_mem_ranges = NULL;
    size_t reserved_mem_ranges_size = 0;

#ifdef DEBUG
    ret = debug_map_init_from_proc_maps();
    if (ret < 0) {
        log_error("Failed to init debug maps");
        return unix_to_pal_error(ret);
    }
#endif

    /* Grow the stack of the main thread to THREAD_STACK_SIZE by probing each stack page above
     * the current stack pointer (Linux dynamically grows the stack of the main thread but gets
     * confused with huge-jump stack accesses coming from within the enclave). Note that other,
     * non-main threads do not have growing stacks and thus do not need this hack. */
    static_assert(THREAD_STACK_SIZE % PAGE_SIZE == 0, "");
    probe_stack(THREAD_STACK_SIZE / PAGE_SIZE);

    if (argc < 4)
        print_usage_and_exit(argv[0]);

    g_host_pid = DO_SYSCALL(getpid);

    g_pal_loader_path = get_main_exec_path();
    if (!g_pal_loader_path) {
        return -ENOMEM;
    }

    ret = verify_hw_requirements(envp);
    if (ret < 0)
        return ret;

    g_libpal_path = strdup(argv[1]);
    if (!g_libpal_path) {
        return -ENOMEM;
    }

    // Are we the first in this Gramine's instance?
    bool first_process = !strcmp(argv[2], "init");
    if (!first_process && strcmp(argv[2], "child")) {
        print_usage_and_exit(argv[0]);
    }

    int parent_stream_fd = -1;

    if (first_process) {
        g_pal_enclave.is_first_process = true;

        g_pal_enclave.application_path = argv[3];
        manifest_path = alloc_concat(g_pal_enclave.application_path, -1, ".manifest.sgx", -1);
        if (!manifest_path) {
            return -ENOMEM;
        }

        log_debug("Manifest file: %s", manifest_path);
        ret = read_text_file_to_cstr(manifest_path, &manifest);
        if (ret < 0) {
            log_error("Reading manifest failed");
            return ret;
        }
        free(manifest_path);
        manifest_path = NULL;
    } else {
        /* We're one of the children spawned to host new processes started inside Gramine. */
        g_pal_enclave.is_first_process = false;

        /* We'll receive our argv and config via IPC. */
        parent_stream_fd = atoi(argv[3]);
        ret = DO_SYSCALL(fcntl, parent_stream_fd, F_SETFD, FD_CLOEXEC);
        if (ret < 0) {
            return ret;
        }

        ret = sgx_init_child_process(parent_stream_fd, &g_pal_enclave.application_path, &manifest,
                                     &reserved_mem_ranges, &reserved_mem_ranges_size);
        if (ret < 0)
            return ret;
    }
    g_pal_enclave.raw_manifest_data = manifest;

    /*
     * While C does not guarantee that the argv[i] and envp[i] strings are
     * continuous we know that we are running on Linux, which does this. This
     * saves us creating a copy of all argv and envp strings.
     */
    char* args;
    size_t args_size;
    if (first_process) {
        args = argv[3];
        args_size = argc > 3 ? (argv[argc - 1] - args) + strlen(argv[argc - 1]) + 1 : 0;
    } else {
        args = argv[4];
        args_size = argc > 4 ? (argv[argc - 1] - args) + strlen(argv[argc - 1]) + 1 : 0;
    }

    size_t envc = 0;
    while (envp[envc] != NULL) {
        envc++;
    }
    char* env = envp[0];
    size_t env_size = envc > 0 ? (envp[envc - 1] - envp[0]) + strlen(envp[envc - 1]) + 1 : 0;

    ret = load_enclave(&g_pal_enclave, args, args_size, env, env_size, parent_stream_fd,
                       reserved_mem_ranges, reserved_mem_ranges_size);
    if (ret < 0) {
        log_error("load_enclave() failed with error: %s", unix_strerror(ret));
        return ret;
    }
    return 0;
}
