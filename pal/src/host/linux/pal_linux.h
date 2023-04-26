/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#pragma once

#include <asm/fcntl.h>
#include <asm/stat.h>
#include <linux/mman.h>
#include <sigset.h>
#include <stdbool.h>
#include <stdint.h>

#include "list.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"
#include "pal_rtld.h"
#include "stat.h"
#include "syscall.h"

struct timespec;
struct timeval;

/* Part of Linux PAL private state which is not shared with other PALs. */
extern struct pal_linux_state {
    const char** host_environ;
    unsigned int host_pid;
    unsigned long memory_quota;
    long int (*vdso_clock_gettime)(long int clk, struct timespec* tp);
} g_pal_linux_state;

#define DEFAULT_BACKLOG 2048

/* PAL main function */
noreturn void pal_linux_main(void* initial_rsp, void* fini_callback);

int init_random(void);

extern const size_t g_page_size;

extern uintptr_t g_vdso_start;
extern uintptr_t g_vdso_end;
bool is_in_vdso(uintptr_t addr);
/* Parse "/proc/self/maps" and bookkeep all found address ranges. */
int init_memory_bookkeeping(void);
int init_reserved_ranges(int reserved_ranges_fd);

int setup_vdso(elf_addr_t base_addr);

/* set/unset CLOEXEC flags of all fds in a handle */
int handle_set_cloexec(PAL_HANDLE handle, bool enable);

/* serialize/deserialize a handle into/from a malloc'ed buffer */
int handle_serialize(PAL_HANDLE handle, void** data);
int handle_deserialize(PAL_HANDLE* handle, const void* data, size_t size);
void fixup_socket_handle_after_deserialization(PAL_HANDLE handle);

void init_child_process(int parent_stream_fd, PAL_HANDLE* parent, char** manifest_out,
                        uint64_t* instance_id);

void cpuid(unsigned int leaf, unsigned int subleaf, unsigned int words[static 4]);
int block_async_signals(bool block);
void signal_setup(bool is_first_process, uintptr_t vdso_start, uintptr_t vdso_end);

extern char __text_start, __text_end, __data_start, __data_end;
#define TEXT_START ((void*)(&__text_start))
#define TEXT_END   ((void*)(&__text_end))
#define DATA_START ((void*)(&__data_start))
#define DATA_END   ((void*)(&__data_end))

#define ADDR_IN_PAL_OR_VDSO(addr) \
        (((void*)(addr) > TEXT_START && (void*)(addr) < TEXT_END) || is_in_vdso(addr))

typedef struct pal_linux_tcb {
    PAL_TCB common;
    struct {
        /* private to Linux PAL */
        PAL_HANDLE handle;
        void*      alt_stack;
        int        (*callback)(void*);
        void*      param;
    };
} PAL_LINUX_TCB;

int pal_thread_init(void* tcbptr);

static inline void pal_linux_tcb_init(PAL_LINUX_TCB* tcb, PAL_HANDLE handle, void* alt_stack,
                                      int (*callback)(void*), void* param) {
    tcb->common.self = &tcb->common;
    tcb->handle      = handle;
    tcb->alt_stack   = alt_stack; // Stack bottom
    tcb->callback    = callback;
    tcb->param       = param;
}

static inline PAL_LINUX_TCB* pal_get_linux_tcb(void) {
    return (PAL_LINUX_TCB*)pal_get_tcb();
}

__attribute_no_stack_protector
static inline void pal_tcb_set_stack_canary(PAL_TCB* tcb, uint64_t canary) {
    ((char*)&canary)[0] = 0; /* prevent C-string-based stack leaks from exposing the cookie */
    pal_tcb_arch_set_stack_canary(tcb, canary);
}
struct linux_dirent64 {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

#define DT_UNKNOWN 0
#define DT_FIFO    1
#define DT_CHR     2
#define DT_DIR     4
#define DT_BLK     6
#define DT_REG     8
#define DT_LNK     10
#define DT_SOCK    12
#define DT_WHT     14

#define DIRBUF_SIZE 1024

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif // MAP_FIXED_NOREPLACE
