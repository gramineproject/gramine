/* XXX: What on earth is this supposed to be, an attempt to fit most UBs in one file?
 * XXX: +1, please someone rm rf this file. */

#include <stdbool.h>

#include "api.h"
#include "pal.h"
#include "pal_regression.h"

#define UNIT (PalGetPalPublicState()->alloc_align)

static volatile int count = 0;

static void handler(bool is_in_pal, uintptr_t addr, PAL_CONTEXT* context) {
    __UNUSED(is_in_pal);
    __UNUSED(addr);

    count++;
    pal_printf("Memory Fault %d\n", count);

#if defined(__i386__) || defined(__x86_64__)
    while (*(unsigned char*)context->rip != 0x90) {
        context->rip++;
    }
#else
#error Unsupported architecture
#endif
}

/* Disable AddressSanitizer: this code tries to trigger a memory fault by accessing memory that's
 * supposed to be inaccessible, but SGX PAL poisons such memory. */
__attribute_no_sanitize_address
int main(int argc, char** argv, char** envp) {
    volatile int c;
    PalSetExceptionHandler(handler, PAL_EVENT_MEMFAULT);

    void* mem1 = NULL;
    int ret = PalVirtualMemoryAlloc(&mem1, UNIT * 4, PAL_ALLOC_INTERNAL,
                                    PAL_PROT_READ | PAL_PROT_WRITE);

    if (!ret && mem1)
        pal_printf("Memory Allocation OK\n");

    void* mem2 = NULL;
    ret = PalVirtualMemoryAlloc(&mem2, UNIT, PAL_ALLOC_INTERNAL,
                                PAL_PROT_READ | PAL_PROT_WRITE);

    if (!ret && mem2) {
        c                    = count;
        *(volatile int*)mem2 = 0;
        pal_printf("(int *) %p = %d\n", mem2, *(volatile int*)mem2);
        if (c == count)
            pal_printf("Memory Allocation Protection (RW) OK\n");

        if (PalVirtualMemoryProtect(mem2, UNIT, PAL_PROT_READ) < 0) {
            pal_printf("PalVirtualMemoryProtect on `mem2` failed\n");
            return 1;
        }
        c                    = count;
        *(volatile int*)mem2 = 0;
        __asm__ volatile("nop");
        if (c == count - 1)
            pal_printf("Memory Protection (R) OK\n");

        if (PalVirtualMemoryFree(mem2, UNIT) < 0) {
            pal_printf("PalVirtualMemoryFree on `mem2` failed\n");
            return 1;
        }
        c                    = count;
        *(volatile int*)mem2 = 0;
        __asm__ volatile("nop");
        if (c == count - 1)
            pal_printf("Memory Deallocation OK\n");
    }

    /* TODO: This does not take into account `PalGetPalPublicState()->preloaded_ranges`; we are
     * not allowed to ask for memory overlapping with these ranges */
    void* mem3 = (void*)PalGetPalPublicState()->user_address_start;
    void* mem4 = (void*)PalGetPalPublicState()->user_address_start + UNIT;

    int ret2 = PalVirtualMemoryAlloc(&mem3, UNIT, 0, PAL_PROT_READ | PAL_PROT_WRITE);
    ret = PalVirtualMemoryAlloc(&mem4, UNIT, 0, PAL_PROT_READ | PAL_PROT_WRITE);

    if (!ret && !ret2 && mem3 && mem4)
        pal_printf("Memory Allocation with Address OK\n");

    /* Testing total memory */
    pal_printf("Total Memory: %lu\n", PalGetPalPublicState()->mem_total);

    /* Testing available memory (must be within valid range) */
    size_t avail = PalMemoryAvailableQuota();
    if (avail > 0 && avail < PalGetPalPublicState()->mem_total)
        pal_printf("Get Memory Available Quota OK\n");

    return 0;
}
