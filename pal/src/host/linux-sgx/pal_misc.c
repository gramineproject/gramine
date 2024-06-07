/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for miscellaneous use.
 */

#include <asm/fcntl.h>
#include <stdint.h>

#include "api.h"
#include "cpu.h"
#include "crypto.h"
#include "enclave_api.h"
#include "hex.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "seqlock.h"
#include "sgx_attest.h"
#include "spinlock.h"
#include "toml_utils.h"
#include "topo_info.h"

/* The timeout of 50ms was found to be a safe TSC drift correction periodicity based on results
 * from multiple systems. Any higher or lower could pose risks of negative time drift or
 * performance hit respectively.
 */
#define TSC_REFINE_INIT_TIMEOUT_USECS 50000

uint64_t g_tsc_hz = 0; /* TSC frequency for fast and accurate time ("invariant TSC" HW feature) */
static uint64_t g_start_tsc = 0;
static uint64_t g_start_usec = 0;
static seqlock_t g_tsc_lock = INIT_SEQLOCK_UNLOCKED;

static bool is_tsc_usable(void) {
    uint32_t words[CPUID_WORD_NUM];
    _PalCpuIdRetrieve(INVARIANT_TSC_LEAF, 0, words);
    return words[CPUID_WORD_EDX] & (1 << 8);
}

/* return TSC frequency or 0 if invariant TSC is not supported */
static uint64_t get_tsc_hz_baremetal(void) {
    uint32_t words[CPUID_WORD_NUM];

    /*
     * Based on "Time Stamp Counter and Nominal Core Crystal Clock Information" leaf, calculate TSC
     * frequency as ECX * EBX / EAX, where
     *   - EAX is denominator of the TSC/"core crystal clock" ratio,
     *   - EBX is numerator of the TSC/"core crystal clock" ratio,
     *   - ECX is core crystal clock (nominal) frequency in Hz.
     */
    _PalCpuIdRetrieve(TSC_FREQ_LEAF, 0, words);
    if (!words[CPUID_WORD_EAX] || !words[CPUID_WORD_EBX]) {
        /* TSC/core crystal clock ratio is not enumerated, can't use RDTSC for accurate time */
        return 0;
    }

    if (words[CPUID_WORD_ECX] > 0) {
        /* cast to 64-bit first to prevent integer overflow */
        return (uint64_t)words[CPUID_WORD_ECX] * words[CPUID_WORD_EBX] / words[CPUID_WORD_EAX];
    }

    /* some Intel CPUs do not report nominal frequency of crystal clock, let's calculate it
     * based on Processor Frequency Information Leaf (CPUID 16H); this leaf always exists if
     * TSC Frequency Leaf exists; logic is taken from Linux 5.11's arch/x86/kernel/tsc.c */
    _PalCpuIdRetrieve(PROC_FREQ_LEAF, 0, words);
    if (!words[CPUID_WORD_EAX]) {
        /* processor base frequency (in MHz) is not enumerated, can't calculate frequency */
        return 0;
    }

    /* processor base frequency is in MHz but we need to return TSC frequency in Hz; cast to 64-bit
     * first to prevent integer overflow */
    return (uint64_t)words[CPUID_WORD_EAX] * 1000000;
}

/* return TSC frequency or 0 if invariant TSC is not supported */
static uint64_t get_tsc_hz_hypervisor(void) {
    uint32_t words[CPUID_WORD_NUM];

    /*
     * We rely on the Generic CPUID space for hypervisors:
     *   - 0x40000000: EAX: The maximum input value for CPUID supported by the hypervisor
     *   -             EBX, ECX, EDX: Hypervisor vendor ID signature (hypervisor_id)
     *
     * If we detect QEMU/KVM or Cloud Hypervisor/KVM (hypervisor_id = "KVMKVMKVM") or VMWare
     * ("VMwareVMware"), then we assume that leaf 0x40000010 contains virtual TSC frequency in kHz
     * in EAX. We check hypervisor_id because leaf 0x40000010 is not standardized and e.g. Microsoft
     * Hyper-V may use it for other purposes.
     *
     * Relevant materials:
     * - https://github.com/qemu/qemu/commit/9954a1582e18b03ddb66f6c892dccf2c3508f4b2
     * - qemu/target/i386/cpu.h, qemu/target/i386/cpu.c, qemu/target/i386/kvm/kvm.c sources
     * - https://github.com/freebsd/freebsd-src/blob/9df6eea/sys/x86/x86/identcpu.c#L1372-L1377 (for
     *   the list of hypervisor_id values)
     */
    _PalCpuIdRetrieve(HYPERVISOR_INFO_LEAF, 0, words);

    bool is_kvm    = words[CPUID_WORD_EBX] == 0x4b4d564b
                         && words[CPUID_WORD_ECX] == 0x564b4d56
                         && words[CPUID_WORD_EDX] == 0x0000004d;
    bool is_vmware = words[CPUID_WORD_EBX] == 0x61774d56
                         && words[CPUID_WORD_ECX] == 0x4d566572
                         && words[CPUID_WORD_EDX] == 0x65726177;

    if (!is_kvm && !is_vmware) {
        /* not a hypervisor that contains "virtual TSC frequency" in leaf 0x40000010 */
        return 0;
    }

    if (words[CPUID_WORD_EAX] < HYPERVISOR_VMWARE_TIME_LEAF) {
        /* virtual TSC frequency is not available */
        return 0;
    }

    _PalCpuIdRetrieve(HYPERVISOR_VMWARE_TIME_LEAF, 0, words);
    if (!words[CPUID_WORD_EAX]) {
        /* TSC frequency (in kHz) is not enumerated, can't calculate frequency */
        return 0;
    }

    /* TSC frequency is in kHz but we need to return TSC frequency in Hz; cast to 64-bit first to
     * prevent integer overflow */
    return (uint64_t)words[CPUID_WORD_EAX] * 1000;
}

/* initialize the data structures used for date/time emulation using TSC */
void init_tsc(void) {
    if (!is_tsc_usable())
        return;

    g_tsc_hz = get_tsc_hz_baremetal();
    if (g_tsc_hz)
        return;

    /* hypervisors may not expose crystal-clock frequency CPUID leaves, so instead try
     * hypervisor-special synthetic CPUID leaf 0x40000010 (VMWare-style Timing Information) */
    g_tsc_hz = get_tsc_hz_hypervisor();
    if (g_tsc_hz)
        return;
}

int _PalSystemTimeQuery(uint64_t* out_usec) {
    int ret;

    if (!g_tsc_hz) {
        /* RDTSC is not allowed or no Invariant TSC feature -- fallback to the slow ocall */
        return ocall_gettime(out_usec);
    }

    uint32_t seq;
    uint64_t start_tsc;
    uint64_t start_usec;
    do {
        seq = read_seqbegin(&g_tsc_lock);
        start_tsc  = g_start_tsc;
        start_usec = g_start_usec;
    } while (read_seqretry(&g_tsc_lock, seq));

    uint64_t usec = 0;
    /* Last seen RDTSC-calculated time value. This guards against time rewinding. */
    static uint64_t last_usec = 0;
    if (start_tsc > 0 && start_usec > 0) {
        /* baseline TSC/usec pair was initialized, can calculate time via RDTSC (but should be
         * careful with integer overflow during calculations) */
        uint64_t diff_tsc = get_tsc() - start_tsc;
        if (diff_tsc < UINT64_MAX / 1000000) {
            uint64_t diff_usec = diff_tsc * 1000000 / g_tsc_hz;
            if (diff_usec < TSC_REFINE_INIT_TIMEOUT_USECS) {
                /* less than TSC_REFINE_INIT_TIMEOUT_USECS passed from the previous update of
                 * TSC/usec pair (time drift is contained), use the RDTSC-calculated time */
                usec = start_usec + diff_usec;
                if (usec < start_usec)
                    return PAL_ERROR_OVERFLOW;

                /* It's simply `last_usec = max(last_usec, usec)`, but executed atomically. */
                uint64_t expected_usec = __atomic_load_n(&last_usec, __ATOMIC_ACQUIRE);
                while (expected_usec < usec) {
                    if (__atomic_compare_exchange_n(&last_usec, &expected_usec, usec,
                                                    /*weak=*/true, __ATOMIC_RELEASE,
                                                    __ATOMIC_ACQUIRE)) {
                        break;
                    }
                }

                *out_usec = MAX(usec, expected_usec);
                return 0;
            }
        }
    }

    /* if we are here, either the baseline TSC/usec pair was not yet initialized or too much time
     * passed since the previous TSC/usec update, so let's refresh them to contain the time drift */
    uint64_t tsc_cyc1 = get_tsc();
    ret = ocall_gettime(&usec);
    if (ret < 0)
        return PAL_ERROR_DENIED;
    uint64_t tsc_cyc2 = get_tsc();

    uint64_t last_recorded_rdtsc = __atomic_load_n(&last_usec, __ATOMIC_ACQUIRE);
    if (usec < last_recorded_rdtsc) {
        /* new OCALL-obtained timestamp (`usec`) is "back in time" than the last recorded timestamp
         * from RDTSC (`last_recorded_rdtsc`); this can happen if the actual host time drifted
         * backwards compared to the RDTSC time. */
         usec = last_recorded_rdtsc;
    }

    /* we need to match the OCALL-obtained timestamp (`usec`) with the RDTSC-obtained number of
     * cycles (`tsc_cyc`); since OCALL is a time-consuming operation, we estimate `tsc_cyc` as a
     * mid-point between the RDTSC values obtained right-before and right-after the OCALL. */
    uint64_t tsc_cyc = tsc_cyc1 + (tsc_cyc2 - tsc_cyc1) / 2;
    if (tsc_cyc < tsc_cyc1)
        return PAL_ERROR_OVERFLOW;

    /* refresh the baseline data if no other thread updated g_start_tsc */
    write_seqbegin(&g_tsc_lock);
    if (g_start_tsc < tsc_cyc) {
        g_start_tsc  = tsc_cyc;
        g_start_usec = usec;
    }
    write_seqend(&g_tsc_lock);

    *out_usec = usec;
    return 0;
}

static uint32_t g_extended_feature_flags_max_supported_sub_leaves = 0;

#define CPUID_CACHE_SIZE 64 /* cache only 64 distinct CPUID entries; sufficient for most apps */
static struct pal_cpuid {
    unsigned int leaf, subleaf;
    unsigned int values[4];
} g_pal_cpuid_cache[CPUID_CACHE_SIZE];

static int g_pal_cpuid_cache_top = 0;
static spinlock_t g_cpuid_cache_lock = INIT_SPINLOCK_UNLOCKED;

static int get_cpuid_from_cache(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    int ret = PAL_ERROR_DENIED;

    spinlock_lock(&g_cpuid_cache_lock);
    for (int i = 0; i < g_pal_cpuid_cache_top; i++) {
        if (g_pal_cpuid_cache[i].leaf == leaf && g_pal_cpuid_cache[i].subleaf == subleaf) {
            values[0] = g_pal_cpuid_cache[i].values[0];
            values[1] = g_pal_cpuid_cache[i].values[1];
            values[2] = g_pal_cpuid_cache[i].values[2];
            values[3] = g_pal_cpuid_cache[i].values[3];
            ret = 0;
            break;
        }
    }
    spinlock_unlock(&g_cpuid_cache_lock);
    return ret;
}

static void add_cpuid_to_cache(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    spinlock_lock(&g_cpuid_cache_lock);

    struct pal_cpuid* chosen = NULL;
    if (g_pal_cpuid_cache_top < CPUID_CACHE_SIZE) {
        for (int i = 0; i < g_pal_cpuid_cache_top; i++) {
            if (g_pal_cpuid_cache[i].leaf == leaf && g_pal_cpuid_cache[i].subleaf == subleaf) {
                /* this CPUID entry is already present in the cache, no need to add */
                break;
            }
        }
        chosen = &g_pal_cpuid_cache[g_pal_cpuid_cache_top++];
    }

    if (chosen) {
        chosen->leaf      = leaf;
        chosen->subleaf   = subleaf;
        chosen->values[0] = values[0];
        chosen->values[1] = values[1];
        chosen->values[2] = values[2];
        chosen->values[3] = values[3];
    }

    spinlock_unlock(&g_cpuid_cache_lock);
}

static inline uint32_t extension_enabled(uint32_t xfrm, uint32_t bit_idx) {
    uint32_t feature_bit = 1U << bit_idx;
    return xfrm & feature_bit;
}

/*!
 * \brief Sanitize untrusted CPUID inputs.
 *
 * \param         leaf     CPUID leaf.
 * \param         subleaf  CPUID subleaf.
 * \param[in,out] values   untrusted result to sanitize.
 *
 * The basic idea is that there are only a handful of extensions and we know the size needed to
 * store each extension's state. Use this to sanitize host's untrusted cpuid output. We also know
 * through xfrm what extensions are enabled inside the enclave.
 */
static void sanitize_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t values[static 4]) {
    uint64_t xfrm = g_pal_linuxsgx_state.enclave_info.attributes.xfrm;

    if (leaf == CPU_VENDOR_LEAF) {
        /* hardcode the only possible values for SGX PAL */
        values[CPUID_WORD_EBX] = 0x756e6547; /* 'Genu' */
        values[CPUID_WORD_EDX] = 0x49656e69; /* 'ineI' */
        values[CPUID_WORD_ECX] = 0x6c65746e; /* 'ntel' */
    } else if (leaf == FEATURE_FLAGS_LEAF) {
        /* We have to enforce these feature bits, otherwise some crypto libraries (e.g. mbedtls)
         * silently switch to side-channel-prone software implementations of crypto algorithms.
         *
         * On hosts which really don't support these, the untrusted PAL should emit an error and
         * refuse to start.
         */
        values[CPUID_WORD_ECX] |= 1 << 25; // AESNI
        values[CPUID_WORD_ECX] |= 1 << 26; // XSAVE (this one is for Gramine code, it relies on it)
        values[CPUID_WORD_ECX] |= 1 << 30; // RDRAND
    } else if (leaf == EXTENDED_FEATURE_FLAGS_LEAF) {
        if (subleaf == 0x0) {
            values[CPUID_WORD_EAX] = g_extended_feature_flags_max_supported_sub_leaves;
            values[CPUID_WORD_EBX] |= 1U << 0; /* CPUs with SGX always support FSGSBASE */
            values[CPUID_WORD_EBX] |= 1U << 2; /* CPUs with SGX always report the SGX bit */
        }
    } else if (leaf == EXTENDED_STATE_LEAF) {
        switch (subleaf) {
            case X87:
                /* From the SDM: "EDX:EAX is a bitmap of all the user state components that can be
                 * managed using the XSAVE feature set. A bit can be set in XCR0 if and only if the
                 * corresponding bit is set in this bitmap. Every processor that supports the XSAVE
                 * feature set will set EAX[0] (x87 state) and EAX[1] (SSE state)."
                 *
                 * On EENTER/ERESUME, the system installs xfrm into XCR0. Hence, we return xfrm here
                 * in EAX.
                 */
                values[CPUID_WORD_EAX] = xfrm;

                /* From the SDM: "EBX enumerates the size (in bytes) required by the XSAVE
                 * instruction for an XSAVE area containing all the user state components
                 * corresponding to bits currently set in XCR0."
                 */
                uint32_t xsave_size = 0;
                /* Start from AVX since x87 and SSE are always captured using XSAVE. Also, x87 and
                 * SSE state size is implicitly included in the extension's offset, e.g., AVX's
                 * offset is 576 which includes x87 and SSE state as well as the XSAVE header. */
                for (int i = AVX; i < LAST_CPU_EXTENSION; i++) {
                    if (extension_enabled(xfrm, i)) {
                        xsave_size = g_cpu_extension_offsets[i] + g_cpu_extension_sizes[i];
                    }
                }
                values[CPUID_WORD_EBX] = xsave_size;

                /* From the SDM: "ECX enumerates the size (in bytes) required by the XSAVE
                 * instruction for an XSAVE area containing all the user state components supported
                 * by this processor."
                 *
                 * We are assuming here that inside the enclave, ECX and EBX for leaf 0xD and
                 * subleaf 0x1 should always be identical, while outside they can potentially be
                 * different. Also, outside of SGX EBX can change at runtime, while ECX is a static
                 * property.
                 */
                values[CPUID_WORD_ECX] = values[CPUID_WORD_EBX];
                values[CPUID_WORD_EDX] = 0;

                break;
            case SSE: {
                const uint32_t xsave_legacy_size = 512;
                const uint32_t xsave_header = 64;
                uint32_t save_size_bytes = xsave_legacy_size + xsave_header;

                /* Start with AVX, since x87 and SSE state is already included when initializing
                 * `save_size_bytes`. */
                for (int i = AVX; i < LAST_CPU_EXTENSION; i++) {
                    if (extension_enabled(xfrm, i)) {
                        save_size_bytes += g_cpu_extension_sizes[i];
                    }
                }
                /* EBX reports the actual size occupied by those extensions irrespective of their
                 * offsets within the xsave area.
                 */
                values[CPUID_WORD_EBX] = save_size_bytes;

                break;
            }
            case AVX:
            case MPX_BNDREGS:
            case MPX_BNDCSR:
            case AVX512_OPMASK:
            case AVX512_ZMM256:
            case AVX512_ZMM512:
            case PKRU:
            case AMX_TILECFG:
            case AMX_TILEDATA:
                /*
                 * Sanitize ECX:
                 *   - bit 0 is always clear because all features are user state (in XCR0)
                 *   - bit 1 is always set because all features are located on 64B boundary
                 *   - bit 2 is set only for AMX_TILEDATA (support for XFD faulting)
                 *   - bits 3-31 are reserved and are zeros
                 */
                values[CPUID_WORD_ECX] = 0x2;
                if (subleaf == AMX_TILEDATA)
                    values[CPUID_WORD_ECX] |= 0x4;

                if (values[CPUID_WORD_EDX] != 0) {
                    log_error("Non-null EDX value in Processor Extended State Enum CPUID leaf");
                    _PalProcessExit(1);
                }

                if (extension_enabled(xfrm, subleaf)) {
                    if (values[CPUID_WORD_EAX] != g_cpu_extension_sizes[subleaf] ||
                            values[CPUID_WORD_EBX] != g_cpu_extension_offsets[subleaf]) {
                        log_error("Unexpected values in Processor Extended State Enum CPUID leaf");
                        _PalProcessExit(1);
                    }
                } else {
                    /* SGX enclave doesn't use this CPU extension, pretend it doesn't exist by
                     * forcing EAX ("size in bytes of the save area for an extended state feature")
                     * and EBX ("offset in bytes of this extended state component's save area from
                     * the beginning of the XSAVE/XRSTOR area") to zero */
                    values[CPUID_WORD_EAX] = 0;
                    values[CPUID_WORD_EBX] = 0;
                }
                break;
        }
    } else if (leaf == AMX_TILE_INFO_LEAF) {
        if (subleaf == 0x0) {
            /* EAX = 1DH, ECX = 0: special subleaf, returns EAX=max_palette, EBX=ECX=EDX=0 */
            if (!IS_IN_RANGE_INCL(values[CPUID_WORD_EAX], 1, 16) || values[CPUID_WORD_EBX] != 0
                    || values[CPUID_WORD_ECX] != 0 || values[CPUID_WORD_EDX] != 0) {
                log_error("Unexpected values in Tile Information CPUID Leaf (subleaf=0x0)");
                _PalProcessExit(1);
            }
        } else {
            /* EAX = 1DH, ECX > 0: subleaf for each supported palette, returns palette limits */
            uint32_t total_tile_bytes = values[CPUID_WORD_EAX] & 0xFFFF;
            uint32_t bytes_per_tile = values[CPUID_WORD_EAX] >> 16;
            uint32_t bytes_per_row = values[CPUID_WORD_EBX] & 0xFFFF;
            uint32_t max_names = values[CPUID_WORD_EBX] >> 16; /* (# of tile regs) */
            uint32_t max_rows = values[CPUID_WORD_ECX] & 0xFFFF;
            if (!IS_IN_RANGE_INCL(total_tile_bytes, 1, 0xFFFF)
                    || !IS_IN_RANGE_INCL(bytes_per_tile, 1, 0xFFFF)
                    || !IS_IN_RANGE_INCL(bytes_per_row, 1, 0xFFFF)
                    || !IS_IN_RANGE_INCL(max_names, 1, 256)
                    || !IS_IN_RANGE_INCL(max_rows, 1, 256)
                    || (values[CPUID_WORD_ECX] >> 16) != 0 || values[CPUID_WORD_EDX] != 0) {
                log_error("Unexpected values in Tile Information CPUID Leaf (subleaf=%#x)",
                          subleaf);
                _PalProcessExit(1);
            }
        }
    } else if (leaf == AMX_TMUL_INFO_LEAF) {
        /* EAX = 1EH, ECX = 0: returns TMUL hardware unit limits */
        uint32_t tmul_maxk = values[CPUID_WORD_EBX] & 0xFF; /* (rows or columns) */
        uint32_t tmul_maxn = (values[CPUID_WORD_EBX] >> 8) & 0xFFFF;
        if (!IS_IN_RANGE_INCL(tmul_maxk, 1, 0xFF)
                || !IS_IN_RANGE_INCL(tmul_maxn, 1, 0xFFFF)
                || (values[CPUID_WORD_EBX] >> 24) != 0
                || values[CPUID_WORD_EAX] != 0
                || values[CPUID_WORD_ECX] != 0
                || values[CPUID_WORD_EDX] != 0) {
            log_error("Unexpected values in TMUL Information CPUID Leaf");
            _PalProcessExit(1);
        }
    }
}

struct cpuid_leaf {
    unsigned int leaf;
    bool zero_subleaf; /* if subleaf is not used by this leaf, then CPUID instruction expects it to
                        * be explicitly zeroed out (see _PalCpuIdRetrieve() implementation below) */
    bool cache;        /* if leaf + subleaf pair is constant across all cores and sockets, then we
                        * can add the returned CPUID values of this pair to the local cache (see
                        * _PalCpuIdRetrieve() implementation below) */
};

/* NOTE: some CPUID leaves/subleaves may theoretically return different values when accessed from
 *       different sockets in a multisocket system and thus should not be declared with
 *       `.cache = true` below, but we don't know of any such systems and currently ignore this */
static const struct cpuid_leaf cpuid_known_leaves[] = {
    /* basic CPUID leaf functions start here */
    {.leaf = 0x00, .zero_subleaf = true,  .cache = true},  /* Highest Func Param and Manufacturer */
    {.leaf = 0x01, .zero_subleaf = true,  .cache = false}, /* Processor Info and Feature Bits */
    {.leaf = 0x02, .zero_subleaf = true,  .cache = true},  /* Cache and TLB Descriptor */
    {.leaf = 0x03, .zero_subleaf = true,  .cache = true},  /* Processor Serial Number */
    {.leaf = 0x04, .zero_subleaf = false, .cache = false}, /* Deterministic Cache Parameters */
    {.leaf = 0x05, .zero_subleaf = true,  .cache = true},  /* MONITOR/MWAIT */
    {.leaf = 0x06, .zero_subleaf = true,  .cache = true},  /* Thermal and Power Management */
    {.leaf = 0x07, .zero_subleaf = false, .cache = true},  /* Structured Extended Feature Flags */
    /* NOTE: 0x08 leaf is reserved, see code below */
    {.leaf = 0x09, .zero_subleaf = true,  .cache = true},  /* Direct Cache Access Information */
    {.leaf = 0x0A, .zero_subleaf = true,  .cache = true},  /* Architectural Performance Monitoring */
    {.leaf = 0x0B, .zero_subleaf = false, .cache = false}, /* Extended Topology Enumeration */
    /* NOTE: 0x0C leaf is reserved, see code below */
    {.leaf = 0x0D, .zero_subleaf = false, .cache = true},  /* Processor Extended State Enumeration */
    /* NOTE: 0x0E leaf is reserved, see code below */
    {.leaf = 0x0F, .zero_subleaf = false, .cache = true},  /* Intel RDT Monitoring */
    {.leaf = 0x10, .zero_subleaf = false, .cache = true},  /* RDT/L2/L3 Cache Allocation Tech */
    /* NOTE: 0x11 leaf is reserved, see code below */
    {.leaf = 0x12, .zero_subleaf = false, .cache = true},  /* Intel SGX Capability */
    /* NOTE: 0x13 leaf is reserved, see code below */
    {.leaf = 0x14, .zero_subleaf = false, .cache = true},  /* Intel Processor Trace Enumeration */
    {.leaf = 0x15, .zero_subleaf = true,  .cache = true},  /* Time Stamp Counter/Core Clock */
    {.leaf = 0x16, .zero_subleaf = true,  .cache = true},  /* Processor Frequency Information */
    {.leaf = 0x17, .zero_subleaf = false, .cache = true},  /* System-On-Chip Vendor Attribute */
    {.leaf = 0x18, .zero_subleaf = false, .cache = true},  /* Deterministic Address Translation */
    {.leaf = 0x19, .zero_subleaf = true,  .cache = true},  /* Key Locker */
    {.leaf = 0x1A, .zero_subleaf = true,  .cache = false}, /* Hybrid Information Enumeration */
    {.leaf = 0x1B, .zero_subleaf = false, .cache = false}, /* PCONFIG Information */
    /* NOTE: 0x1C leaf is not recognized, see code below */
    {.leaf = 0x1D, .zero_subleaf = false, .cache = true},  /* Tile Information Main Leaf (AMX) */
    {.leaf = 0x1E, .zero_subleaf = false, .cache = true},  /* TMUL Information Main Leaf (AMX) */
    {.leaf = 0x1F, .zero_subleaf = false, .cache = false}, /* Intel V2 Ext Topology Enumeration */
    /* basic CPUID leaf functions end here */

    /* hypervisor-specific CPUID leaf functions (0x40000000 - 0x400000FF) start here */
    {.leaf = 0x40000000, .zero_subleaf = true, .cache = true},  /* CPUID Info */
    {.leaf = 0x40000010, .zero_subleaf = true, .cache = true},  /* VMWare-style Timing Info */
    /* NOTE: currently only the above two leaves are used, see also get_tsc_hz_hypervisor() */

    /* invalid CPUID leaf functions (no existing or future CPU will return any meaningful
     * information in these leaves) occupy 0x40000100 - 0x4FFFFFFF -- they are treated the same as
     * unrecognized leaves, see code below */

    /* extended CPUID leaf functions start here */
    {.leaf = 0x80000000, .zero_subleaf = true, .cache = true}, /* Get Highest Extended Function */
    {.leaf = 0x80000001, .zero_subleaf = true, .cache = true}, /* Extended Processor Info */
    {.leaf = 0x80000002, .zero_subleaf = true, .cache = true}, /* Processor Brand String 1 */
    {.leaf = 0x80000003, .zero_subleaf = true, .cache = true}, /* Processor Brand String 2 */
    {.leaf = 0x80000004, .zero_subleaf = true, .cache = true}, /* Processor Brand String 3 */
    {.leaf = 0x80000005, .zero_subleaf = true, .cache = true}, /* L1 Cache and TLB Identifiers */
    {.leaf = 0x80000006, .zero_subleaf = true, .cache = true}, /* Extended L2 Cache Features */
    {.leaf = 0x80000007, .zero_subleaf = true, .cache = true}, /* Advanced Power Management */
    {.leaf = 0x80000008, .zero_subleaf = true, .cache = true}, /* Virtual/Physical Address Sizes */
    /* extended CPUID leaf functions end here */
};

int _PalCpuIdRetrieve(uint32_t leaf, uint32_t subleaf, uint32_t values[4]) {
    uint64_t xfrm = g_pal_linuxsgx_state.enclave_info.attributes.xfrm;

    /* A few basic leaves are considered reserved and always return zeros; see corresponding EAX
     * cases in the "Operation" section of CPUID description in Intel SDM, Vol. 2A, Chapter 3.2.
     *
     * NOTE: Leaves 0x11 and 0x13 are not marked as reserved in Intel SDM but the actual CPUs return
     *       all-zeros on them (as if these leaves are reserved). It is unclear why this discrepancy
     *       exists, but we decided to emulate how actual CPUs behave. */
    if (leaf == 0x08 || leaf == 0x0C || leaf == 0x0E || leaf == 0x11 || leaf == 0x13) {
        values[CPUID_WORD_EAX] = 0;
        values[CPUID_WORD_EBX] = 0;
        values[CPUID_WORD_ECX] = 0;
        values[CPUID_WORD_EDX] = 0;
        return 0;
    }

    /* leaf 0x7 (Structured Extended Feature Flags) must return all-zeros if the subleaf contains an
     * invalid index (larger than max supported) */
    if (leaf == EXTENDED_FEATURE_FLAGS_LEAF &&
            subleaf > g_extended_feature_flags_max_supported_sub_leaves) {
        values[CPUID_WORD_EAX] = 0;
        values[CPUID_WORD_EBX] = 0;
        values[CPUID_WORD_ECX] = 0;
        values[CPUID_WORD_EDX] = 0;
        return 0;
    }

    const struct cpuid_leaf* known_leaf = NULL;
    for (size_t i = 0; i < ARRAY_SIZE(cpuid_known_leaves); i++) {
        if (leaf == cpuid_known_leaves[i].leaf) {
            known_leaf = &cpuid_known_leaves[i];
            break;
        }
    }

    if ((!extension_enabled(xfrm, AMX_TILECFG) || !extension_enabled(xfrm, AMX_TILEDATA)) &&
            (leaf == AMX_TILE_INFO_LEAF || leaf == AMX_TMUL_INFO_LEAF)) {
        /* the Intel AMX feature is disabled, so we pretend that the CPU doesn't support it at all
         * (by marking the TILE_INFO and TMUL_INFO AMX-related leaves as unrecognized) */
        known_leaf = NULL;
    }

    if (!known_leaf) {
        /* leaf is not recognized (EAX value is outside of recongized range for CPUID), return info
         * for highest basic information leaf (see cpuid_known_leaves table); also if the highest
         * basic information leaf data depend on the ECX input value (subleaf), ECX is honored; see
         * the DEFAULT case in the "Operation" section of CPUID description in Intel SDM, Vol. 2A,
         * Chapter 3.2 */
        leaf = 0x1F;
        for (size_t i = 0; i < ARRAY_SIZE(cpuid_known_leaves); i++) {
            if (leaf == cpuid_known_leaves[i].leaf) {
                known_leaf = &cpuid_known_leaves[i];
                break;
            }
        }
    }

    /* FIXME: these leaves may have more subleaves in the future, we need a better way of
     *        restricting subleaves (e.g., decide based on CPUID leaf 0x01) */
    if ((leaf == 0x0F && subleaf != 0 && subleaf != 1) ||
        (leaf == 0x10 && subleaf != 0 && subleaf != 1 && subleaf != 2 && subleaf != 3) ||
        (leaf == 0x14 && subleaf != 0 && subleaf != 1)) {
        /* leaf-specific checks: some leaves have only specific subleaves */
        goto fail;
    }

    if (known_leaf->zero_subleaf)
        subleaf = 0;

    if (known_leaf->cache && !get_cpuid_from_cache(leaf, subleaf, values))
        return 0;

    if (ocall_cpuid(leaf, subleaf, values) < 0)
        return PAL_ERROR_DENIED;

    sanitize_cpuid(leaf, subleaf, values);

    if (known_leaf->cache)
        add_cpuid_to_cache(leaf, subleaf, values);

    return 0;
fail:
    log_error("Unrecognized leaf/subleaf in CPUID (EAX=0x%x, ECX=0x%x). Exiting...", leaf, subleaf);
    _PalProcessExit(1);
}

int init_cpuid(void) {
    uint32_t values[4];
    if (ocall_cpuid(EXTENDED_FEATURE_FLAGS_LEAF, 0x0, values) < 0)
        return PAL_ERROR_DENIED;

    if (values[CPUID_WORD_EAX] > 2) {
        /* max value for supported sub-leaves of "Extended Feature Flags" leaf is 2 */
        return PAL_ERROR_DENIED;
    }

    g_extended_feature_flags_max_supported_sub_leaves = values[CPUID_WORD_EAX];
    return 0;
}

int _PalAttestationReport(const void* user_report_data, size_t* user_report_data_size,
                          void* target_info, size_t* target_info_size, void* report,
                          size_t* report_size) {
    __sgx_mem_aligned sgx_report_data_t stack_report_data = {0};
    __sgx_mem_aligned sgx_target_info_t stack_target_info = {0};
    __sgx_mem_aligned sgx_report_t stack_report = {0};

    if (!user_report_data_size || !target_info_size || !report_size)
        return PAL_ERROR_INVAL;

    if (*user_report_data_size != sizeof(stack_report_data) ||
        *target_info_size != sizeof(stack_target_info) || *report_size != sizeof(stack_report)) {
        /* inform the caller of SGX sizes for user_report_data, target_info, and report */
        goto out;
    }

    if (!user_report_data || !target_info) {
        /* cannot produce report without user_report_data or target_info */
        goto out;
    }

    bool populate_target_info = false;
    if (!memcmp(target_info, &stack_target_info, sizeof(stack_target_info))) {
        /* caller supplied all-zero target_info, wants to get this enclave's target info */
        populate_target_info = true;
    }

    memcpy(&stack_report_data, user_report_data, sizeof(stack_report_data));
    memcpy(&stack_target_info, target_info, sizeof(stack_target_info));

    int ret = sgx_report(&stack_target_info, &stack_report_data, &stack_report);
    if (ret < 0) {
        /* caller already provided reasonable sizes, so just error out without updating them */
        return PAL_ERROR_INVAL;
    }

    if (populate_target_info) {
        sgx_report_body_to_target_info(&stack_report.body, target_info);
    }

    if (report) {
        /* report may be NULL if caller only wants to know the size of target_info and/or report */
        memcpy(report, &stack_report, sizeof(stack_report));
    }

out:
    *user_report_data_size = sizeof(stack_report_data);
    *target_info_size      = sizeof(stack_target_info);
    *report_size           = sizeof(stack_report);
    return 0;
}

int _PalAttestationQuote(const void* user_report_data, size_t user_report_data_size,
                         void* quote, size_t* quote_size) {
    int ret;

    if (user_report_data_size != sizeof(sgx_report_data_t))
        return PAL_ERROR_INVAL;

    enum sgx_attestation_type attestation_type;
    sgx_spid_t spid;
    bool linkable;

    ret = parse_attestation_type(g_pal_public_state.manifest_root, &attestation_type);
    if (ret < 0) {
        /* error was already printed by the called func */
        return unix_to_pal_error(ret);
    }

    if (attestation_type == SGX_ATTESTATION_EPID) {
        ret = parse_attestation_epid_params(g_pal_public_state.manifest_root, &spid, &linkable);
        if (ret < 0) {
            /* error was already printed by the called func */
            return unix_to_pal_error(ret);
        }
    }

    sgx_quote_nonce_t nonce;
    ret = _PalRandomBitsRead(&nonce, sizeof(nonce));
    if (ret < 0)
        return ret;

    char* pal_quote = NULL;
    size_t pal_quote_size = 0;
    ret = sgx_get_quote(attestation_type == SGX_ATTESTATION_EPID ? &spid : NULL, &nonce,
                        user_report_data, linkable, &pal_quote, &pal_quote_size);
    if (ret < 0)
        return ret;

    if (*quote_size < pal_quote_size) {
        *quote_size = pal_quote_size;
        free(pal_quote);
        return PAL_ERROR_NOMEM;
    }

    if (quote) {
        /* quote may be NULL if caller only wants to know the size of the quote */
        assert(pal_quote);
        memcpy(quote, pal_quote, pal_quote_size);
    }

    *quote_size = pal_quote_size;
    free(pal_quote);
    return 0;
}

int _PalGetSpecialKey(const char* name, void* key, size_t* key_size) {
    sgx_key_128bit_t sgx_key;

    if (*key_size < sizeof(sgx_key))
        return PAL_ERROR_INVAL;

    int ret;
    if (!strcmp(name, PAL_KEY_NAME_SGX_MRENCLAVE)) {
        ret = sgx_get_seal_key(SGX_KEYPOLICY_MRENCLAVE, &sgx_key);
    } else if (!strcmp(name, PAL_KEY_NAME_SGX_MRSIGNER)) {
        ret = sgx_get_seal_key(SGX_KEYPOLICY_MRSIGNER, &sgx_key);
    } else {
        return PAL_ERROR_NOTIMPLEMENTED;
    }
    if (ret < 0)
        return ret;

    memcpy(key, &sgx_key, sizeof(sgx_key));
    *key_size = sizeof(sgx_key);
    return 0;
}

ssize_t read_file_buffer(const char* filename, char* buf, size_t buf_size) {
    int fd;

    fd = ocall_open(filename, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return fd;

    ssize_t n = ocall_read(fd, buf, buf_size);
    ocall_close(fd);

    return n;
}

int _PalRandomBitsRead(void* buffer, size_t size) {
    uint32_t rand;
    for (size_t i = 0; i < size; i += sizeof(rand)) {
        rand = rdrand();
        memcpy(buffer + i, &rand, MIN(sizeof(rand), size - i));
    }
    return 0;
}

int _PalSegmentBaseGet(enum pal_segment_reg reg, uintptr_t* addr) {
    switch (reg) {
        case PAL_SEGMENT_FS:
            *addr = GET_ENCLAVE_TCB(fsbase);
            return 0;
        case PAL_SEGMENT_GS:
            /* GS is internally used, deny any access to it */
            return PAL_ERROR_DENIED;
        default:
            return PAL_ERROR_INVAL;
    }
}

int _PalSegmentBaseSet(enum pal_segment_reg reg, uintptr_t addr) {
    switch (reg) {
        case PAL_SEGMENT_FS:
            SET_ENCLAVE_TCB(fsbase, addr);
            wrfsbase((uint64_t)addr);
            return 0;
        case PAL_SEGMENT_GS:
            /* GS is internally used, deny any access to it */
            return PAL_ERROR_DENIED;
        default:
            return PAL_ERROR_INVAL;
    }
}

int _PalValidateEntrypoint(const void* buf, size_t size) {
    int ret;
    uint8_t manifest_sha256_bytes[32];
    uint8_t computed_sha256_bytes[32];

    char* entrypoint_sha256_str = NULL;
    ret = toml_string_in(g_pal_public_state.manifest_root, "loader.entrypoint.sha256",
                         &entrypoint_sha256_str);
    if (ret < 0) {
        log_error("Cannot parse 'loader.entrypoint.sha256' from manifest");
        return PAL_ERROR_INVAL;
    }

    if (!entrypoint_sha256_str) {
        log_error("Cannot find 'loader.entrypoint.sha256' in manifest");
        return PAL_ERROR_INVAL;
    }

    if (strlen(entrypoint_sha256_str) != sizeof(manifest_sha256_bytes) * 2) {
        log_error("Hash in 'loader.entrypoint.sha256' is not a SHA256 hash");
        ret = PAL_ERROR_INVAL;
        goto out;
    }

    char* bytes = hex2bytes(entrypoint_sha256_str, strlen(entrypoint_sha256_str),
                            manifest_sha256_bytes, sizeof(manifest_sha256_bytes));
    if (!bytes) {
        log_error("Could not parse hash in 'loader.entrypoint.sha256'");
        ret = PAL_ERROR_INVAL;
        goto out;
    }

    LIB_SHA256_CONTEXT entrypoint_sha;
    ret = lib_SHA256Init(&entrypoint_sha);
    if (ret < 0)
        goto out;
    ret = lib_SHA256Update(&entrypoint_sha, buf, size);
    if (ret < 0)
        goto out;
    ret = lib_SHA256Final(&entrypoint_sha, computed_sha256_bytes);
    if (ret < 0)
        goto out;

    if (memcmp(computed_sha256_bytes, manifest_sha256_bytes, sizeof(computed_sha256_bytes))) {
        log_error("Hash of entrypoint does not match with the reference hash in manifest");
        ret = PAL_ERROR_DENIED;
        goto out;
    }

    ret = 0;
out:
    free(entrypoint_sha256_str);
    return ret;
}
