#pragma once

#include <stdint.h>

#include "pal.h"

/* adopt Linux x86-64 structs for FP layout: self-contained definition is needed for LibOS, so
 * define the exact same layout with `libos_` prefix; taken from
 * https://elixir.bootlin.com/linux/v5.9/source/arch/x86/include/uapi/asm/sigcontext.h */
#define LIBOS_FP_XSTATE_MAGIC1      0x46505853U
#define LIBOS_FP_XSTATE_MAGIC2      0x46505845U
#define LIBOS_FP_XSTATE_MAGIC2_SIZE (sizeof(LIBOS_FP_XSTATE_MAGIC2))

#define LIBOS_XSTATE_ALIGN 64

enum LIBOS_XFEATURE {
    LIBOS_XFEATURE_FP,
    LIBOS_XFEATURE_SSE,
    LIBOS_XFEATURE_YMM,
    LIBOS_XFEATURE_BNDREGS,
    LIBOS_XFEATURE_BNDCSR,
    LIBOS_XFEATURE_OPMASK,
    LIBOS_XFEATURE_ZMM_Hi256,
    LIBOS_XFEATURE_Hi16_ZMM,
    LIBOS_XFEATURE_PT,
    LIBOS_XFEATURE_PKRU,
};

#define LIBOS_XFEATURE_MASK_FP        (1UL << LIBOS_XFEATURE_FP)
#define LIBOS_XFEATURE_MASK_SSE       (1UL << LIBOS_XFEATURE_SSE)
#define LIBOS_XFEATURE_MASK_YMM       (1UL << LIBOS_XFEATURE_YMM)
#define LIBOS_XFEATURE_MASK_BNDREGS   (1UL << LIBOS_XFEATURE_BNDREGS)
#define LIBOS_XFEATURE_MASK_BNDCSR    (1UL << LIBOS_XFEATURE_BNDCSR)
#define LIBOS_XFEATURE_MASK_OPMASK    (1UL << LIBOS_XFEATURE_OPMASK)
#define LIBOS_XFEATURE_MASK_ZMM_Hi256 (1UL << LIBOS_XFEATURE_ZMM_Hi256)
#define LIBOS_XFEATURE_MASK_Hi16_ZMM  (1UL << LIBOS_XFEATURE_Hi16_ZMM)
#define LIBOS_XFEATURE_MASK_PT        (1UL << LIBOS_XFEATURE_PT)
#define LIBOS_XFEATURE_MASK_PKRU      (1UL << LIBOS_XFEATURE_PKRU)

#define LIBOS_XFEATURE_MASK_FPSSE     (LIBOS_XFEATURE_MASK_FP | LIBOS_XFEATURE_MASK_SSE)
#define LIBOS_XFEATURE_MASK_AVX512    (LIBOS_XFEATURE_MASK_OPMASK | LIBOS_XFEATURE_MASK_ZMM_Hi256 \
                                       | LIBOS_XFEATURE_MASK_Hi16_ZMM)

/* Bytes 464..511 in the 512B layout of the FXSAVE/FXRSTOR frame are reserved for SW usage. On
 * CPUs supporting XSAVE/XRSTOR, these bytes are used to extend the fpstate pointer in the
 * sigcontext, which includes the extended state information along with fpstate information. */
struct libos_fpx_sw_bytes {
    uint32_t magic1;        /*!< LIBOS_FP_XSTATE_MAGIC1 (it is an xstate context) */
    uint32_t extended_size; /*!< g_libos_xsave_size + LIBOS_FP_STATE_MAGIC2_SIZE */
    uint64_t xfeatures;     /*!< XSAVE features (feature bit mask, including FP/SSE/extended) */
    uint32_t xstate_size;   /*!< g_libos_xsave_size (XSAVE area size as reported by CPUID) */
    uint32_t padding[7];    /*!< for future use */
};

/* 64-bit FPU frame (FXSAVE format, 512B total size) */
struct libos_fpstate {
    uint16_t cwd;
    uint16_t swd;
    uint16_t twd;
    uint16_t fop;
    uint64_t rip;
    uint64_t rdp;
    uint32_t mxcsr;
    uint32_t mxcr_mask;
    uint32_t st_space[32];  /*  8x  FP registers, 16 bytes each */
    uint32_t xmm_space[64]; /* 16x XMM registers, 16 bytes each */
    uint32_t reserved2[12];
    union {
        uint32_t reserved3[12];
        struct libos_fpx_sw_bytes sw_reserved; /* potential extended state is encoded here */
    };
};

struct libos_xstate_header {
    uint64_t xfeatures;
    uint64_t reserved1[2];
    uint64_t reserved2[5];
};

struct libos_xstate {
    struct libos_fpstate fpstate;          /* 512B legacy FXSAVE/FXRSTOR frame (FP and XMM regs) */
    struct libos_xstate_header xstate_hdr; /* 64B header for newer XSAVE/XRSTOR frame */
    /* rest is filled with extended regs (YMM, ZMM, ...) by HW + 4B of MAGIC2 value by SW */
} __attribute__((aligned(LIBOS_XSTATE_ALIGN)));

#define LIBOS_TCB_GET(member)                                           \
    ({                                                                  \
        libos_tcb_t* tcb;                                               \
        __typeof__(tcb->member) ret;                                    \
        static_assert(sizeof(ret) == 8 ||                               \
                      sizeof(ret) == 4 ||                               \
                      sizeof(ret) == 2 ||                               \
                      sizeof(ret) == 1,                                 \
                      "LIBOS_TCB_GET can be used only for "             \
                      "8, 4, 2, or 1-byte(s) members");                 \
        __asm__("mov %%gs:%c1, %0\n"                                    \
                : "=r"(ret)                                             \
                : "i" (offsetof(PAL_TCB, libos_tcb) +                   \
                       offsetof(libos_tcb_t, member))                   \
                : "memory");                                            \
        ret;                                                            \
    })

#define LIBOS_TCB_SET(member, value)                                    \
    do {                                                                \
        libos_tcb_t* tcb;                                               \
        static_assert(sizeof(tcb->member) == 8 ||                       \
                      sizeof(tcb->member) == 4 ||                       \
                      sizeof(tcb->member) == 2 ||                       \
                      sizeof(tcb->member) == 1,                         \
                      "LIBOS_TCB_SET can be used only for "             \
                      "8, 4, 2, or 1-byte(s) members");                 \
        switch (sizeof(tcb->member)) {                                  \
        case 8:                                                         \
            __asm__("movq %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(libos_tcb_t, member))                 \
                    : "memory");                                        \
            break;                                                      \
        case 4:                                                         \
            __asm__("movl %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(libos_tcb_t, member))                 \
                    : "memory");                                        \
            break;                                                      \
        case 2:                                                         \
            __asm__("movw %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(libos_tcb_t, member))                 \
                    : "memory");                                        \
            break;                                                      \
        case 1:                                                         \
            __asm__("movb %0, %%gs:%c1\n"                               \
                    :: "ir"(value),                                     \
                     "i"(offsetof(PAL_TCB, libos_tcb) +                 \
                         offsetof(libos_tcb_t, member))                 \
                    : "memory");                                        \
            break;                                                      \
        }                                                               \
    } while (0)

static inline void set_tls(uintptr_t tls) {
    PalSegmentBaseSet(PAL_SEGMENT_FS, tls);
}

static inline void set_default_tls(void) {
    set_tls(0);
}

static inline uintptr_t get_tls(void) {
    uintptr_t addr = 0;
    (void)PalSegmentBaseGet(PAL_SEGMENT_FS, &addr);
    return addr;
}
