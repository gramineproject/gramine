#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#ifndef __x86_64__
# error This test is 64-bit only
#endif

#define LOOPS (10 * 1000 * 1000)

#define XFEATURE_XTILECFG   17
#define XFEATURE_XTILEDATA  18
#define XFEATURE_MASK_XTILECFG  (1 << XFEATURE_XTILECFG)
#define XFEATURE_MASK_XTILEDATA (1 << XFEATURE_XTILEDATA)
#define XFEATURE_MASK_XTILE (XFEATURE_MASK_XTILECFG | XFEATURE_MASK_XTILEDATA)

#define XSTATE_CPUID                0xd
#define XSTATE_USER_STATE_SUBLEAVE  0x0

#define XSAVE_HDR_OFFSET    512

static uint32_t xsave_size;
static uint32_t xsave_xtiledata_offset;
static uint32_t xsave_xtiledata_size;
static void* xsave_buffer;

static inline uint64_t  __xgetbv(uint32_t index) {
    uint32_t eax, edx;

    asm volatile("xgetbv;"
             : "=a" (eax), "=d" (edx)
             : "c" (index));
    return eax + ((uint64_t)edx << 32);
}

static inline void __cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    asm volatile("cpuid;"
             : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
             : "0" (*eax), "2" (*ecx));
}

static inline void __xsave(void *buffer, uint32_t lo, uint32_t hi) {
    asm volatile("xsave (%%rdi)"
             : : "D" (buffer), "a" (lo), "d" (hi)
             : "memory");
}

static inline void __xrstor(void *buffer, uint32_t lo, uint32_t hi) {
    asm volatile("xrstor (%%rdi)"
             : : "D" (buffer), "a" (lo), "d" (hi));
}

static inline bool check_xsave_capability(void) {
    if (__xgetbv(0) & XFEATURE_MASK_XTILEDATA) {
        return true;
    }
    return false;
}

static void check_cpuid(void) {
    uint32_t eax, ebx, ecx, edx;

    eax = XSTATE_CPUID;
    ecx = XSTATE_USER_STATE_SUBLEAVE;

    __cpuid(&eax, &ebx, &ecx, &edx);
    if (!ebx)
        err(1, "xstate cpuid: xsave size");

    xsave_size = ebx;

    eax = XSTATE_CPUID;
    ecx = XFEATURE_XTILECFG;

    __cpuid(&eax, &ebx, &ecx, &edx);
    if (!eax || !ebx)
        err(1, "xstate cpuid: tile config state");

    eax = XSTATE_CPUID;
    ecx = XFEATURE_XTILEDATA;

    __cpuid(&eax, &ebx, &ecx, &edx);
    if (!eax || !ebx)
        err(1, "xstate cpuid: tile data state");

    xsave_xtiledata_size = eax;
    xsave_xtiledata_offset = ebx;
}

static inline uint64_t get_xstatebv(void *xsave) {
    return *(uint64_t *)(xsave + XSAVE_HDR_OFFSET);
}

static inline void set_xstatebv(void *xsave, uint64_t bv) {
    *(uint64_t *)(xsave + XSAVE_HDR_OFFSET) = bv;
}

static void set_tiledata(void *tiledata) {
    int *ptr = tiledata;
    int data = rand();

    for (size_t i = 0; i < xsave_xtiledata_size / sizeof(int); i++, ptr++)
        *ptr  = data;
}

static bool xrstor(void *buffer, uint32_t lo, uint32_t hi) {
    __xrstor(buffer, lo, hi);
    return true;
}

static int init_amx_random(void) {
    if (!check_xsave_capability()) {
        printf("XSAVE disabled/Tile data not available.\n");
        return 1;
    }

    check_cpuid();

    xsave_buffer = aligned_alloc(64, xsave_size);
    if (!xsave_buffer)
        err(1, "aligned_alloc()");

    set_xstatebv(xsave_buffer, XFEATURE_MASK_XTILE);
    set_tiledata(xsave_buffer + xsave_xtiledata_offset);

    unsigned int mxcsr;
    __asm__ ("stmxcsr %0" : "=m"(mxcsr));

    if (!xrstor(xsave_buffer, -1, -1)) {
        printf("[FAIL]\tXRSTOR failed (loading tile data).\n");
        return 1;
    }

    __asm__ ("ldmxcsr %0" : : "m"(mxcsr));

    free(xsave_buffer);
    return 0;
}

int main(int argc, char** argv) {
    int ret;
    (void)argv[0];

    if (argc > 1) {
        ret = init_amx_random();
        if (ret) {
            printf("AMX initialization failed\n");
            return ret;
        }
        printf("Initialized AMX to a random tile\n");
    }

    printf("Starting micro-benchmark... ");

    clock_t begin = clock();
    for (long i = 0; i < LOOPS; i++) {
        /* below syscall has 1:1 mapping to host syscall in Gramine-SGX (i.e., each sched_yield
         * leads to one EENTER and one EEXIT) */
        ret = sched_yield();
        if (ret) {
            printf("sched_yield failed?!\n");
            return ret;
        }
    }
    clock_t end = clock();

    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    printf("done in %f seconds\n", time_spent);
    return 0;
}
