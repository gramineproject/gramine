/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains the main function of the PAL loader, which loads and processes environment,
 * arguments and manifest.
 */

#include <asm/errno.h>
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <linux/personality.h>

#include "api.h"
#include "asan.h"
#include "debug_map.h"
#include "elf/elf.h"
#include "init.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_rtld.h"
#include "toml.h"
#include "toml_utils.h"

char* g_pal_loader_path = NULL;
/* Currently content of this variable is only passed as an argument while spawning new processes
 * - this is to keep uniformity with other PALs. */
char* g_libpal_path = NULL;

struct pal_linux_state g_pal_linux_state;

/* for internal PAL objects, Gramine first uses pre-allocated g_mem_pool and then falls back to
 * _DkVirtualMemoryAlloc(PAL_ALLOC_INTERNAL); the amount of available PAL internal memory is limited
 * by the variable below */
size_t g_pal_internal_mem_size = 0;
char* g_pal_internal_mem_addr = NULL;

const size_t g_page_size = PRESET_PAGESIZE;

static void read_info_from_stack(void* initial_rsp, int* out_argc, const char*** out_argv,
                                 const char*** out_envp, int* out_host_euid, int* out_host_egid,
                                 ElfW(Addr)* out_sysinfo_ehdr) {
    /* The stack layout on program entry is:
     *
     *            argc                  <-- `initial_rsp` points here
     *            argv[0]
     *            ...
     *            argv[argc - 1]
     *            argv[argc] = NULL
     *            envp[0]
     *            ...
     *            envp[n - 1] = NULL
     *            auxv[0]
     *            ...
     *            auxv[m - 1] = AT_NULL
     */
    const char** stack = (const char**)initial_rsp;
    int argc = (uintptr_t)stack[0];
    const char** argv = &stack[1];
    const char** envp = argv + argc + 1;
    assert(argv[argc] == NULL);

    const char** e = envp;
    for (; *e; e++) {}

    bool host_euid_set = false;
    bool host_egid_set = false;
    *out_sysinfo_ehdr = 0;
    for (ElfW(auxv_t)* av = (ElfW(auxv_t)*)(e + 1); av->a_type != AT_NULL; av++) {
        switch (av->a_type) {
            case AT_PAGESZ:
                if (av->a_un.a_val != g_page_size) {
                    INIT_FAIL(PAL_ERROR_INVAL, "Unexpected AT_PAGESZ auxiliary vector");
                }
                break;
            case AT_EUID:
                *out_host_euid = av->a_un.a_val;
                host_euid_set = true;
                break;
            case AT_EGID:
                *out_host_egid = av->a_un.a_val;
                host_egid_set = true;
                break;
            case AT_SYSINFO_EHDR:
                *out_sysinfo_ehdr = av->a_un.a_val;
                break;
        }
    }
    if (!host_euid_set || !host_egid_set) {
        INIT_FAIL(PAL_ERROR_INVAL, "Missing AT_EUID or AT_EGID in auxiliary vector");
    }

    *out_argc = argc;
    *out_argv = argv;
    *out_envp = envp;
}

void _DkGetAvailableUserAddressRange(PAL_PTR* start, PAL_PTR* end) {
    void* end_addr = (void*)ALLOC_ALIGN_DOWN_PTR(TEXT_START);
    void* start_addr = (void*)MMAP_MIN_ADDR;

    assert(IS_ALLOC_ALIGNED_PTR(start_addr) && IS_ALLOC_ALIGNED_PTR(end_addr));

    while (1) {
        if (start_addr >= end_addr)
            INIT_FAIL(PAL_ERROR_NOMEM, "no user memory available");

        void* mem = (void*)DO_SYSCALL(mmap, start_addr, g_pal_public_state.alloc_align, PROT_NONE,
                                      MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (!IS_PTR_ERR(mem)) {
            DO_SYSCALL(munmap, mem, g_pal_public_state.alloc_align);
            if (mem == start_addr)
                break;
        }

        start_addr = (void*)((unsigned long)start_addr << 1);
    }

    *end   = (PAL_PTR)end_addr;
    *start = (PAL_PTR)start_addr;
}

noreturn static void print_usage_and_exit(const char* argv_0) {
    const char* self = argv_0 ?: "<this program>";
    log_always("USAGE:\n"
               "\tFirst process: %s <path to libpal.so> init <application> args...\n"
               "\tChildren:      %s <path to libpal.so> child <parent_stream_fd> args...",
               self, self);
    log_always("This is an internal interface. Use pal_loader to launch applications in Gramine.");
    _DkProcessExit(1);
}

#ifdef ASAN
__attribute_no_stack_protector
__attribute_no_sanitize_address
static void setup_asan(void) {
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED;
    void* addr = (void*)DO_SYSCALL(mmap, (void*)ASAN_SHADOW_START, ASAN_SHADOW_LENGTH, prot, flags,
                                   /*fd=*/-1, /*offset=*/0);
    if (IS_PTR_ERR(addr)) {
        /* We are super early in the init sequence, TCB is not yet set, we probably should not call
         * any logging functions. */
        DO_SYSCALL(exit_group, PAL_ERROR_NOMEM);
        die_or_inf_loop();
    }
}
#endif

/* Gramine uses GCC's stack protector that looks for a canary at gs:[0x8], but this function starts
 * with no TCB in the GS register, so we disable stack protector here */
__attribute_no_stack_protector
__attribute_no_sanitize_address
noreturn void pal_linux_main(void* initial_rsp, void* fini_callback) {
    __UNUSED(fini_callback);  // TODO: We should call `fini_callback` at the end.
    int ret;

#ifdef ASAN
    setup_asan();
#endif

    /* we don't yet have a TCB in the GS register, but GCC's stack protector will look for a canary
     * at gs:[0x8] in functions called below, so let's install a dummy TCB with a default canary */
    PAL_TCB_LINUX dummy_tcb_for_stack_protector = { 0 };
    dummy_tcb_for_stack_protector.common.self = &dummy_tcb_for_stack_protector.common;
    pal_tcb_set_stack_canary(&dummy_tcb_for_stack_protector.common, STACK_PROTECTOR_CANARY_DEFAULT);
    ret = pal_set_tcb(&dummy_tcb_for_stack_protector.common);
    if (ret < 0) {
        /* We failed to install a TCB (and haven't applied relocations yet), so no other code will
         * work anyway */
        DO_SYSCALL(exit_group, PAL_ERROR_DENIED);
        die_or_inf_loop();
    }

    /* relocate PAL */
    ret = setup_pal_binary();
    if (ret < 0)
        INIT_FAIL(-ret, "Relocation of the PAL binary failed");

    uint64_t start_time;
    ret = _DkSystemTimeQuery(&start_time);
    if (ret < 0)
        INIT_FAIL(-ret, "_DkSystemTimeQuery() failed");

    call_init_array();

    /* Initialize alloc_align as early as possible, a lot of PAL APIs depend on this being set. */
    g_pal_public_state.alloc_align = g_page_size;
    assert(IS_POWER_OF_2(g_pal_public_state.alloc_align));

    ret = init_random();
    if (ret < 0)
        INIT_FAIL(-ret, "init_random() failed");

    int argc;
    const char** argv;
    const char** envp;
    int host_euid = -1, host_egid = -1; // has to be set, otherwise GCC erroneously emits a warning
    ElfW(Addr) sysinfo_ehdr;
    read_info_from_stack(initial_rsp, &argc, &argv, &envp, &host_euid, &host_egid, &sysinfo_ehdr);

    if (argc < 4)
        print_usage_and_exit(argv[0]);  // may be NULL!

    /* Now that we have `argv`, set name for PAL map */
    set_pal_binary_name(argv[0]);

    // Are we the first in this Gramine's namespace?
    bool first_process = !strcmp(argv[2], "init");
    if (!first_process && strcmp(argv[2], "child")) {
        print_usage_and_exit(argv[0]);
    }

    if (first_process) {
        ret = DO_SYSCALL(personality, 0xffffffffu);
        if (ret < 0) {
            INIT_FAIL(unix_to_pal_error(-ret), "retrieving personality failed");
        }
        if (!(ret & ADDR_NO_RANDOMIZE)) {
            /* Gramine fork() emulation does fork()+execve() on host and then sends all necessary
             * data, including memory content, to the child process. Disable ASLR to prevent memory
             * colliding with PAL executable (as it would get a new random address in the child). */
            ret = DO_SYSCALL(personality, (unsigned int)ret | ADDR_NO_RANDOMIZE);
            if (ret < 0) {
                INIT_FAIL(unix_to_pal_error(-ret), "setting personality failed");
            }
            ret = DO_SYSCALL(execve, "/proc/self/exe", argv, envp);
            INIT_FAIL(unix_to_pal_error(-ret), "execve to disable ASLR failed");
        }
    }

    g_pal_linux_state.host_environ = envp;

    /* Prepare an initial memory pool for the slab allocator. This is necessary because we cannot
     * allocate the PAL-internal range yet: we need to parse the manifest to know its size. */
    size_t init_pool_size = PAL_INITIAL_MEM_SIZE;
    void* init_pool_addr = (void*)DO_SYSCALL(mmap, /*addr=*/NULL, init_pool_size,
                                             PROT_READ | PROT_WRITE,
                                             MAP_ANONYMOUS | MAP_PRIVATE, /*fd=*/-1, /*offset=*/0);
    if (IS_PTR_ERR(init_pool_addr)) {
        INIT_FAIL(PAL_ERROR_NOMEM, "Cannot allocate initial memory pool");
    }

    init_slab_mgr(init_pool_addr, init_pool_size);

    ret = add_preloaded_range((uintptr_t)init_pool_addr,
                              (uintptr_t)init_pool_addr + init_pool_size,
                              "pal_init_pool");
    if (ret < 0) {
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    }

#ifdef ASAN
    ret = add_preloaded_range(ASAN_SHADOW_START, ASAN_SHADOW_START + ASAN_SHADOW_LENGTH,
                              "asan_shadow");
    if (ret < 0) {
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    }
#endif

#ifdef DEBUG
    ret = debug_map_init_from_proc_maps();
    if (ret < 0)
        INIT_FAIL(-unix_to_pal_error(ret), "failed to init debug maps");
#endif

    g_pal_loader_path = get_main_exec_path();
    g_libpal_path = strdup(argv[1]);
    if (!g_pal_loader_path || !g_libpal_path) {
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    }

    PAL_HANDLE first_thread = malloc(HANDLE_SIZE(thread));
    if (!first_thread)
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    init_handle_hdr(HANDLE_HDR(first_thread), PAL_TYPE_THREAD);
    first_thread->thread.tid = DO_SYSCALL(gettid);

    void* alt_stack = calloc(1, ALT_STACK_SIZE);
    if (!alt_stack)
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    first_thread->thread.stack = alt_stack;

    // Initialize TCB at the top of the alternative stack.
    PAL_TCB_LINUX* tcb = alt_stack + ALT_STACK_SIZE - sizeof(PAL_TCB_LINUX);
    pal_tcb_linux_init(tcb, first_thread, alt_stack, /*callback=*/NULL, /*param=*/NULL);
    ret = pal_thread_init(tcb);
    if (ret < 0)
        INIT_FAIL(unix_to_pal_error(-ret), "pal_thread_init() failed");

    if (sysinfo_ehdr) {
        ret = setup_vdso(sysinfo_ehdr);
        if (ret < 0)
            INIT_FAIL(-ret, "Setup of VDSO failed");
    }

    uintptr_t vdso_start = 0;
    uintptr_t vdso_end = 0;
    uintptr_t vvar_start = 0;
    uintptr_t vvar_end = 0;
    ret = get_vdso_and_vvar_ranges(&vdso_start, &vdso_end, &vvar_start, &vvar_end);
    if (ret < 0) {
        INIT_FAIL(-ret, "getting vdso and vvar ranges failed");
    }

    if (vdso_start || vdso_end) {
        /* Override the range retrieved by parsing vdso: the actual mapped range might be bigger. */
        g_vdso_start = vdso_start;
        g_vdso_end = vdso_end;
    }

    if (g_vdso_start || g_vdso_end) {
        ret = add_preloaded_range(g_vdso_start, g_vdso_end, "vdso");
        if (ret < 0) {
            INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
        }
    } else {
        INIT_FAIL(PAL_ERROR_DENIED, "vdso address range not preloaded, is your system missing "
                                    "vdso?!");
    }
    if (vvar_start || vvar_end) {
        ret = add_preloaded_range(vvar_start, vvar_end, "vvar");
        if (ret < 0) {
            INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
        }
    } else {
        log_warning("vvar address range not preloaded, is your system missing vvar?!");
    }

    g_pal_linux_state.host_pid = DO_SYSCALL(getpid);
    g_pal_linux_state.host_euid = host_euid;
    g_pal_linux_state.host_egid = host_egid;

    PAL_HANDLE parent = NULL;
    char* manifest = NULL;
    uint64_t instance_id = 0;
    if (first_process) {
        const char* application_path = argv[3];
        char* manifest_path = alloc_concat(application_path, -1, ".manifest", -1);
        if (!manifest_path)
            INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");

        ret = read_text_file_to_cstr(manifest_path, &manifest);
        if (ret < 0) {
            INIT_FAIL(unix_to_pal_error(-ret), "Reading manifest failed");
        }
    } else {
        // Children receive their argv and config via IPC.
        int parent_stream_fd = atoi(argv[3]);
        init_child_process(parent_stream_fd, &parent, &manifest, &instance_id);
    }
    assert(manifest);

    /* This depends on `g_vdso_start` and `g_vdso_end`, so it must be called only after they were
     * initialized. */
    signal_setup(first_process, g_vdso_start, g_vdso_end);

    g_pal_common_state.raw_manifest_data = manifest;

    char errbuf[256];
    g_pal_public_state.manifest_root = toml_parse(manifest, errbuf, sizeof(errbuf));
    if (!g_pal_public_state.manifest_root)
        INIT_FAIL_MANIFEST(PAL_ERROR_DENIED, errbuf);

    ret = toml_sizestring_in(g_pal_public_state.manifest_root, "loader.pal_internal_mem_size",
                             /*defaultval=*/g_page_size, &g_pal_internal_mem_size);
    if (ret < 0) {
        INIT_FAIL(PAL_ERROR_INVAL, "Cannot parse 'loader.pal_internal_mem_size'");
    }

    void* internal_mem_addr = (void*)DO_SYSCALL(mmap, NULL, g_pal_internal_mem_size,
                                                PROT_READ | PROT_WRITE,
                                                MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (IS_PTR_ERR(internal_mem_addr)) {
        INIT_FAIL(PAL_ERROR_NOMEM, "Cannot allocate PAL internal memory pool");
    }

    ret = add_preloaded_range((uintptr_t)internal_mem_addr,
                              (uintptr_t)internal_mem_addr + g_pal_internal_mem_size,
                              "pal_internal_mem");
    if (ret < 0) {
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    }
    g_pal_internal_mem_addr = internal_mem_addr;

    /* call to main function */
    pal_main(instance_id, parent, first_thread, first_process ? argv + 3 : argv + 4, envp);
}
