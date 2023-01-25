/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 *                    Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>
 */

#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "pal.h"
#include "pal_regression.h"

static void (*g_mem_exec_func)(void);

static bool g_exec_failed;
static bool g_write_failed;
static bool g_read_failed;

void mem_write(void* addr, uint8_t val) __attribute__((visibility("internal")));
uint8_t mem_read(void* addr) __attribute__((visibility("internal")));
static bool is_pc_at_func(uintptr_t pc, void (*func)(void));
static void fixup_context_after_write(PAL_CONTEXT* context);
static void fixup_context_after_read(PAL_CONTEXT* context);

#ifdef __x86_64__
void ret(void) __attribute__((visibility("internal")));
void end_of_ret(void) __attribute__((visibility("internal")));
__asm__ (
".pushsection .text\n"
".type mem_write, @function\n"
".type mem_read, @function\n"
".type ret, @function\n"
".type end_of_ret, @function\n"
"mem_write:\n"
    "movb %sil, (%rdi)\n"
    "ret\n"
"mem_read:\n"
    "movb (%rdi), %al\n"
    "ret\n"
"ret:\n"
    "ret\n"
"end_of_ret:\n"
".popsection\n"
);

static bool is_pc_at_func(uintptr_t pc, void (*func)(void)) {
    return pc == (uintptr_t)func;
}

static void fixup_context_after_exec(PAL_CONTEXT* context) {
    pal_context_set_ip(context, (uintptr_t)ret);
}

static void fixup_context_after_write(PAL_CONTEXT* context) {
    pal_context_set_ip(context, (uintptr_t)ret);
}

static void fixup_context_after_read(PAL_CONTEXT* context) {
    pal_context_set_ip(context, (uintptr_t)ret);
    pal_context_set_retval(context, 0);
}

#else
#error Unsupported architecture
#endif

static void memfault_handler(bool is_in_pal, uintptr_t addr, PAL_CONTEXT* context) {
    uintptr_t pc = pal_context_get_ip(context);
    if (is_pc_at_func(pc, g_mem_exec_func)) {
        fixup_context_after_exec(context);
        g_exec_failed = true;
        return;
    } else if (is_pc_at_func(pc, (void (*)(void))mem_write)) {
        fixup_context_after_write(context);
        g_write_failed = true;
        return;
    } else if (is_pc_at_func(pc, (void (*)(void))mem_read)) {
        fixup_context_after_read(context);
        g_read_failed = true;
        return;
    }

    log_error("Unexpected memory fault at: %#lx (pc: %#lx, in_pal: %d)", addr, pc, is_in_pal);
    PalProcessExit(1);
}

/* Disable AddressSanitizer: this code tries to trigger a memory fault by accessing memory that's
 * supposed to be inaccessible, but SGX PAL poisons such memory. */
__attribute_no_sanitize_address
int main(void) {
    size_t total_mem = PalGetPalPublicState()->mem_total;
    if (total_mem == 0) {
        log_error("no memory???");
        PalProcessExit(1);
    }
    pal_printf("Total Memory: %#lx\n", total_mem);

    PalSetExceptionHandler(memfault_handler, PAL_EVENT_MEMFAULT);

    void* addr1 = NULL;
    CHECK(memory_alloc(PAGE_SIZE * 3, PAL_PROT_READ | PAL_PROT_WRITE | PAL_PROT_EXEC, &addr1));

    memcpy(addr1, ret, (uintptr_t)end_of_ret - (uintptr_t)ret);
    g_mem_exec_func = (void (*)(void))addr1;

    g_exec_failed = false;
    COMPILER_BARRIER();
    g_mem_exec_func();
    COMPILER_BARRIER();
    if (g_exec_failed) {
        log_error("exec on RWX mem at %p failed", addr1);
        PalProcessExit(1);
    }

    CHECK(PalVirtualMemoryProtect(addr1, PAGE_SIZE * 3, PAL_PROT_READ | PAL_PROT_WRITE));

    g_exec_failed = false;
    COMPILER_BARRIER();
    g_mem_exec_func();
    COMPILER_BARRIER();
    if (!g_exec_failed) {
        log_error("exec on RW mem at %p unexpectedly succeeded", addr1);
        PalProcessExit(1);
    }

    memset(addr1, 0, (uintptr_t)end_of_ret - (uintptr_t)ret);
    g_mem_exec_func = NULL;

    g_write_failed = false;
    COMPILER_BARRIER();
    mem_write(addr1, 42);
    COMPILER_BARRIER();
    if (g_write_failed) {
        log_error("write to RW mem at %p failed", addr1);
        PalProcessExit(1);
    }

    g_read_failed = false;
    COMPILER_BARRIER();
    uint8_t x = mem_read(addr1);
    COMPILER_BARRIER();
    if (g_read_failed) {
        log_error("read from RW mem at %p failed", addr1);
        PalProcessExit(1);
    }
    if (x != 42) {
        log_error("read from RW mem at %p returned wrong value: %hhu (!= 42)", addr1, x);
        PalProcessExit(1);
    }

    uint8_t* addr2 = (uint8_t*)addr1 + PAGE_SIZE;
    *addr2 = 43;
    CHECK(PalVirtualMemoryProtect(addr2, PAGE_SIZE, PAL_PROT_READ));

    g_write_failed = false;
    COMPILER_BARRIER();
    mem_write(addr2, 0);
    COMPILER_BARRIER();
    if (!g_write_failed) {
        log_error("write to R mem at %p unexpectedly succeeded", addr2);
        PalProcessExit(1);
    }

    g_read_failed = false;
    COMPILER_BARRIER();
    x = mem_read(addr2);
    COMPILER_BARRIER();
    if (g_read_failed) {
        log_error("read from R mem at %p failed", addr2);
        PalProcessExit(1);
    }
    if (x != 43) {
        log_error("read from R mem at %p returned wrong value: %hhu (!= 43)", addr2, x);
        PalProcessExit(1);
    }

    uint8_t* addr3 = (uint8_t*)addr2 + PAGE_SIZE;
    *addr3 = 44;
    CHECK(PalVirtualMemoryProtect(addr3, PAGE_SIZE, /*prot=*/0));

    g_write_failed = false;
    COMPILER_BARRIER();
    mem_write(addr3, 0);
    COMPILER_BARRIER();
    if (!g_write_failed) {
        log_error("write to mem with no permissions at %p unexpectedly succeeded", addr3);
        PalProcessExit(1);
    }

    g_read_failed = false;
    COMPILER_BARRIER();
    x = mem_read(addr3);
    COMPILER_BARRIER();
    if (!g_read_failed) {
        log_error("read from mem with no permissions at %p unexpectedly succeeded", addr3);
        PalProcessExit(1);
    }

    CHECK(memory_free(addr1, PAGE_SIZE * 3));

    pal_printf("TEST OK\n");
    return 0;
}
