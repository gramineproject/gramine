/* SPDX-License-Identifier: LGPL-3.0-or-later */

#pragma once

#include <stdint.h>
#include <stdnoreturn.h>

#define PAGE_SIZE       (1ul << 12)
#define PRESET_PAGESIZE PAGE_SIZE

enum CPUID_WORD {
    CPUID_WORD_EAX = 0,
    CPUID_WORD_EBX = 1,
    CPUID_WORD_ECX = 2,
    CPUID_WORD_EDX = 3,
    CPUID_WORD_NUM = 4,
};

enum cpu_extension {
    X87, SSE, AVX, MPX_BNDREGS, MPX_BNDCSR, AVX512_OPMASK, AVX512_ZMM256, AVX512_ZMM512,
    PKRU = 9,
    AMX_TILECFG = 17, AMX_TILEDATA,
    LAST_CPU_EXTENSION,
};

/* Enumerations of extended state (XSTATE) sub leafs, CPUID.(EAX=0DH, ECX=n):
 * n = 0: bitmap of all the user state components that can be managed using the XSAVE feature set
 * n = 1: bitmap of extensions of XSAVE feature set
 * n > 1: details (size and offset) of each state component, where n corresponds to
 *        `enum cpu_extension`
 * For more information, see CPUID description in Intel SDM, Vol. 2A, Chapter 3.2. */
enum extended_state_sub_leaf {
    EXTENDED_STATE_SUBLEAF_FEATURES = 0,
    EXTENDED_STATE_SUBLEAF_EXTENSIONS = 1,
};

#define CPU_VENDOR_LEAF                         0x0
#define FEATURE_FLAGS_LEAF                      0x1
#define THERMAL_AND_POWER_INFO_LEAF             0x6
#define EXTENDED_FEATURE_FLAGS_LEAF             0x7
#define EXTENDED_STATE_LEAF                     0xD /* Extended state (XSTATE) */
#define INTEL_SGX_LEAF                         0x12 /* Intel SGX Capabilities */
#define TSC_FREQ_LEAF                          0x15
#define PROC_FREQ_LEAF                         0x16
#define AMX_TILE_INFO_LEAF                     0x1D
#define AMX_TMUL_INFO_LEAF                     0x1E
#define HYPERVISOR_INFO_LEAF             0x40000000
#define HYPERVISOR_TIME_LEAF             0x40000010
#define MAX_INPUT_EXT_VALUE_LEAF         0x80000000
#define EXT_SIGNATURE_AND_FEATURES_LEAF  0x80000001
#define CPU_BRAND_LEAF                   0x80000002
#define CPU_BRAND_CNTD_LEAF              0x80000003
#define CPU_BRAND_CNTD2_LEAF             0x80000004
#define INVARIANT_TSC_LEAF               0x80000007

static inline void cpuid(unsigned int leaf, unsigned int subleaf, unsigned int words[static 4]) {
    __asm__("cpuid"
            : "=a"(words[CPUID_WORD_EAX]),
              "=b"(words[CPUID_WORD_EBX]),
              "=c"(words[CPUID_WORD_ECX]),
              "=d"(words[CPUID_WORD_EDX])
            : "a"(leaf),
              "c"(subleaf));
}

static inline uint64_t get_tsc(void) {
    unsigned long lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return lo | ((uint64_t)hi << 32);
}

/*!
 * \brief Low-level wrapper around RDRAND instruction (get hardware-generated random value).
 */
static inline uint32_t rdrand(void) {
    uint32_t ret;
    __asm__ volatile(
        "1: .byte 0x0f, 0xc7, 0xf0\n" /* RDRAND %EAX */
        "jnc 1b\n"
        :"=a"(ret)
        :: "cc");
    return ret;
}

/*!
 * \brief Low-level wrapper around RDFSBASE instruction (read FS register; allowed in enclaves).
 */
static inline uint64_t rdfsbase(void) {
    uint64_t fsbase;
    __asm__ volatile(
        ".byte 0xf3, 0x48, 0x0f, 0xae, 0xc0\n" /* RDFSBASE %RAX */
        : "=a"(fsbase) :: "memory");
    return fsbase;
}

/*!
 * \brief Low-level wrapper around WRFSBASE instruction (modify FS register; allowed in enclaves).
 */
static inline void wrfsbase(uint64_t addr) {
    __asm__ volatile(
        ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd7\n" /* WRFSBASE %RDI */
        :: "D"(addr) : "memory");
}

static inline noreturn void die_or_inf_loop(void) {
    __asm__ volatile (
        "1: \n"
        "ud2 \n"
        "jmp 1b \n"
    );
    __builtin_unreachable();
}

#define CPU_RELAX() __asm__ volatile("pause")

/* some non-Intel clones support out of order store; WMB() ceases to be a nop for these */
#define MB()  __asm__ __volatile__("mfence" ::: "memory")
#define RMB() __asm__ __volatile__("lfence" ::: "memory")
#define WMB() __asm__ __volatile__("sfence" ::: "memory")
