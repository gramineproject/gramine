/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#pragma once

#define RED_ZONE_SIZE 128

#ifndef __ASSEMBLER__

#ifdef USE_STDLIB
#include <assert.h>
#else
#include "assert.h"
#endif

#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)

#define __sgx_mem_aligned __attribute__((aligned(512)))

#define SE_KEY_SIZE      384
#define SE_EXPONENT_SIZE 4

#define SGX_HASH_SIZE 32
#define SGX_MAC_SIZE  16

typedef struct _sgx_measurement_t {
    uint8_t m[SGX_HASH_SIZE];
} sgx_measurement_t;

typedef uint8_t sgx_mac_t[SGX_MAC_SIZE];

typedef struct _sgx_attributes_t {
    uint64_t flags;
    uint64_t xfrm;
} sgx_attributes_t;

#define SGX_CPUSVN_SIZE      16
#define SGX_CONFIGID_SIZE    64
#define SGX_KEYID_SIZE       32
#define SGX_REPORT_DATA_SIZE 64

typedef struct _sgx_cpu_svn_t {
    uint8_t svn[SGX_CPUSVN_SIZE];
} sgx_cpu_svn_t;

typedef uint8_t  sgx_cet_attributes_t;
typedef uint32_t sgx_misc_select_t;
typedef uint16_t sgx_prod_id_t;
typedef uint16_t sgx_isv_svn_t;
typedef uint16_t sgx_config_svn_t;
typedef struct {
    uint8_t data[SGX_CONFIGID_SIZE];
} sgx_config_id_t;

#define SGX_ISVEXT_PROD_ID_SIZE 16
#define SGX_ISV_FAMILY_ID_SIZE  16

typedef uint8_t sgx_isvext_prod_id_t[SGX_ISVEXT_PROD_ID_SIZE];
typedef uint8_t sgx_isvfamily_id_t[SGX_ISV_FAMILY_ID_SIZE];

#define SGX_FLAGS_INITIALIZED   0x01ULL
#define SGX_FLAGS_DEBUG         0x02ULL
#define SGX_FLAGS_MODE64BIT     0x04ULL
#define SGX_FLAGS_PROVISION_KEY 0x10ULL
#define SGX_FLAGS_LICENSE_KEY   0x20ULL

/* EINIT must verify *all* SECS.ATTRIBUTES[63..0] bits (FLAGS bits) against
 * SIGSTRUCT.ATTRIBUTES[63..0].
 *
 * Notes:
 *   - Two instances of the same enclave with even one-bit difference in attributes-flags (e.g., one
 *     with DEBUG == 0 and another with DEBUG == 1) will have two different SIGSTRUCTs.
 *   - Important consequence of the above: a debug version of the enclave requires a different
 *     SIGSTRUCT file than a production version of the enclave.
 *   - CET and KSS bits are not yet reflected in Gramine, i.e., Gramine doesn't support Intel CET
 *     technology and Key Separation and Sharing feature.
 */
#define SGX_FLAGS_MASK_CONST 0xffffffffffffffffUL

/* Note that XFRM follows XCR0 register format. Also note that XFRM bits 0 (x87 support) and 1 (SSE
 * support) must be always set in Intel SGX (otherwise EINIT instruction fails). This is why these
 * two bits are called "legacy" here.
 *
 * From Intel SDM, Section 41.7.2.1: "Because bits 0 and 1 of XFRM must always be set, the use of
 * Intel SGX requires that SSE be enabled (CR4.OSFXSR = 1)." */
#define SGX_XFRM_LEGACY   0x03ULL
#define SGX_XFRM_AVX      0x04ULL
#define SGX_XFRM_MPX      0x18ULL
#define SGX_XFRM_AVX512   0xe4ULL
#define SGX_XFRM_PKRU     0x200ULL
#define SGX_XFRM_AMX      0x60000ULL
#define SGX_XFRM_RESERVED (~(SGX_XFRM_LEGACY | SGX_XFRM_AVX | SGX_XFRM_MPX | SGX_XFRM_AVX512 | \
                             SGX_XFRM_PKRU | SGX_XFRM_AMX))

/* EINIT must verify most of the SECS.ATTRIBUTES[127..64] bits (XFRM/XCR0 bits) against
 * SIGSTRUCT.ATTRIBUTES[127..64].
 *
 * This default XFRM mask may be modified via the manifest options `sgx.cpu_features.[feature]`. If
 * the manifest option for some feature is set to "required" or "disabled", then the corresponding
 * bits in the XFRM mask are set. If the manifest option is set to "unspecified", then the
 * corresponding bits are unset.
 *
 * Notes:
 *   - Verified bits include: bit 0 + bit 1 (X87 + SSE, always enabled in SGX), bit 3 + bit 4
 *     (BNDREG + BNDCSR, enables Intel MPX), bit 9 (PKRU, enables Intel MPK), and all reserved bits.
 *   - Not-verified bits include: bit 2 (AVX), bit 5 + bit 6 + bit 7 (AVX-512), bit 17 + bit 18
 *     (AMX). These bits are considered not security-critical.
 *   - Two instances of the same enclave with difference in X87, SSE, MPX, MPK bits (e.g., one
 *     with PKRU == 0 and another with PKRU == 1) will have two different SIGSTRUCTs. However,
 *     difference in AVX/AVX-512/AMX bits does not lead to different SIGSTRUCTs.
 *   - Important consequence of the above: the same enclave (with the same SIGSTRUCT) may run on
 *     machines with and without AVX/AVX-512/AMX, but e.g. a PKRU-requiring enclave may run only on
 *     machine with PKRU.
 *   - CET bits are not yet reflected in Gramine, i.e., Gramine doesn't support Intel CET.
  */
#define SGX_XFRM_MASK_CONST 0xfffffffffff9ff1bUL

#define SGX_MISCSELECT_EXINFO 0x01UL

/* EINIT must verify *all* SECS.MISCSELECT bits against SIGSTRUCT.MISCSELECT.
 *
 * Notes:
 *   - Two instances of the same enclave (one with EXINFO == 0 and another with EXINFO == 1) will
 *     have two different SIGSTRUCTs.
 *   - CPINFO bit is not yet reflected in Gramine, i.e., information about control protection
 *     exception (#CP) will not be reported on AEX.
  */
#define SGX_MISCSELECT_MASK_CONST 0xffffffffUL

/* Note that fields ISVEXTPRODID and ISVFAMILYID (and some others) are part of `reserved4`; they are
 * considered a micro-architectural detail and thus don't have a specific offset. */
typedef struct {
    uint64_t             size;
    uint64_t             base;
    uint32_t             ssa_frame_size;
    sgx_misc_select_t    misc_select;
    uint8_t              cet_legacy_bitmap_offset[8]; /* must not be used */
    sgx_cet_attributes_t cet_attributes;
    uint8_t              reserved1[15];
    sgx_attributes_t     attributes;
    sgx_measurement_t    mr_enclave;
    uint8_t              reserved2[32];
    sgx_measurement_t    mr_signer;
    uint8_t              reserved3[32];
    sgx_config_id_t      config_id;
    sgx_prod_id_t        isv_prod_id;
    sgx_isv_svn_t        isv_svn;
    sgx_config_svn_t     config_svn;
    uint8_t              reserved4[3834];
} sgx_arch_secs_t;

typedef struct {
    uint64_t reserved0;
    uint64_t flags;
    uint64_t ossa;
    uint32_t cssa;
    uint32_t nssa;
    uint64_t oentry;
    uint64_t reserved1;
    uint64_t ofs_base;
    uint64_t ogs_base;
    uint32_t ofs_limit;
    uint32_t ogs_limit;
    uint8_t  reserved3[4024];
} sgx_arch_tcs_t;
static_assert(sizeof(sgx_arch_tcs_t) == 4096, "incorrect struct size");

#define TCS_FLAGS_DBGOPTIN (01ULL)

typedef struct {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t rip;
    uint64_t ursp;
    uint64_t urbp;
    uint32_t exitinfo;
    uint32_t reserved;
    uint64_t fsbase;
    uint64_t gsbase;
} sgx_pal_gpr_t;

typedef struct {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t rip;
} sgx_cpu_context_t;

// Required by _restore_sgx_context, see enclave_entry.S.
static_assert(offsetof(sgx_cpu_context_t, rip) - offsetof(sgx_cpu_context_t, rflags) ==
                  sizeof(((sgx_cpu_context_t){0}).rflags),
              "rip must be directly after rflags in sgx_cpu_context_t");
static_assert(offsetof(sgx_cpu_context_t, rip) - offsetof(sgx_cpu_context_t, r15) <= RED_ZONE_SIZE,
              "r15 needs to be within red zone distance from rip");
static_assert(offsetof(sgx_cpu_context_t, rip) - offsetof(sgx_cpu_context_t, rsp) <= RED_ZONE_SIZE,
              "rsp needs to be within red zone distance from rip");

/* These numbers match x86 trap numbers. */
enum sgx_arch_exception_vector {
    SGX_EXCEPTION_VECTOR_DE = 0,    /* Divider exception */
    SGX_EXCEPTION_VECTOR_DB = 1,    /* Debug exception */
    SGX_EXCEPTION_VECTOR_BP = 3,    /* Breakpoint exception */
    SGX_EXCEPTION_VECTOR_BR = 5,    /* Bound range exceeded exception */
    SGX_EXCEPTION_VECTOR_UD = 6,    /* Invalid opcode exception */
    SGX_EXCEPTION_VECTOR_GP = 13,   /* #GP exception. Only reported if SECS.MISCSELECT.EXINFO = 1 */
    SGX_EXCEPTION_VECTOR_PF = 14,   /* #PF exception. Only reported if SECS.MISCSELECT.EXINFO = 1 */
    SGX_EXCEPTION_VECTOR_MF = 16,   /* x87 FPU floating-point error */
    SGX_EXCEPTION_VECTOR_AC = 17,   /* Alignment check exceptions */
    SGX_EXCEPTION_VECTOR_XM = 19,   /* SIMD floating-point exceptions */
    SGX_EXCEPTION_VECTOR_CP = 21,   /* #CP exception. Only reported if SECS.MISCSELECT.CPINFO = 1 */
};

typedef struct {
    enum sgx_arch_exception_vector vector : 8;
    uint32_t exit_type : 3;
    uint32_t reserved : 20;
    uint32_t valid : 1;
} sgx_arch_exit_info_t;
static_assert(sizeof(sgx_arch_exit_info_t) == 4, "invalid size");

typedef struct {
    uint64_t maddr;
    union {
        struct {
            uint32_t p:1;
            uint32_t w:1;
            uint32_t u:1;
            uint32_t rsvd:1;
            uint32_t i:1;
            uint32_t pk:1;
            uint32_t reserved1:9;
            uint32_t sgx:1;
            uint32_t reserved2:16;
        } errcd;
        uint32_t error_code_val;
    };
    uint32_t reserved;
} sgx_arch_exinfo_t;
static_assert(sizeof(sgx_arch_exinfo_t) == 16, "invalid size");

typedef struct {
    uint64_t lin_addr;
    uint64_t src_pge;
    uint64_t sec_info;
    uint64_t secs;
} sgx_arch_page_info_t;

typedef struct {
    uint64_t flags;
    uint64_t reserved[7];
} sgx_arch_sec_info_t;

enum sgx_page_type {
    SGX_PAGE_TYPE_SECS,
    SGX_PAGE_TYPE_TCS,
    SGX_PAGE_TYPE_REG,
    SGX_PAGE_TYPE_VA,
    SGX_PAGE_TYPE_TRIM,
};

#define SGX_SECINFO_FLAGS_R         (1 << 0)
#define SGX_SECINFO_FLAGS_W         (1 << 1)
#define SGX_SECINFO_FLAGS_X         (1 << 2)
#define SGX_SECINFO_FLAGS_PENDING   (1 << 3)
#define SGX_SECINFO_FLAGS_MODIFIED  (1 << 4)
#define SGX_SECINFO_FLAGS_PR        (1 << 5)
#define SGX_SECINFO_FLAGS_TYPE_SHIFT 8

typedef struct {
    uint8_t              header[16];
    uint32_t             vendor;
    uint32_t             date;
    uint8_t              header2[16];
    uint32_t             swdefined;
    uint8_t              reserved1[84];
    uint8_t              modulus[SE_KEY_SIZE];
    uint8_t              exponent[SE_EXPONENT_SIZE];
    uint8_t              signature[SE_KEY_SIZE];
    sgx_misc_select_t    misc_select;
    sgx_misc_select_t    misc_mask;
    sgx_cet_attributes_t cet_attributes;
    sgx_cet_attributes_t cet_attributes_mask;
    uint8_t              reserved2[2];
    sgx_isvfamily_id_t   isv_family_id;
    sgx_attributes_t     attributes;
    sgx_attributes_t     attribute_mask;
    sgx_measurement_t    enclave_hash;
    uint8_t              reserved3[16];
    sgx_isvext_prod_id_t isvext_prod_id;
    sgx_prod_id_t        isv_prod_id;
    sgx_isv_svn_t        isv_svn;
    uint8_t              reserved4[12];
    uint8_t              q1[SE_KEY_SIZE];
    uint8_t              q2[SE_KEY_SIZE];
} sgx_sigstruct_t;
static_assert(sizeof(sgx_sigstruct_t) == 1808, "incorrect struct size");

typedef struct _sgx_key_id_t {
    uint8_t id[SGX_KEYID_SIZE];
} sgx_key_id_t;

typedef struct {
    uint32_t          valid;
    uint32_t          reserved1[11];
    sgx_attributes_t  attributes;
    sgx_measurement_t mr_enclave;
    uint8_t           reserved2[32];
    sgx_measurement_t mr_signer;
    uint8_t           reserved3[32];
} launch_body_t;

typedef struct {
    launch_body_t     body;
    sgx_cpu_svn_t     cpu_svn_le;
    sgx_prod_id_t     isv_prod_id_le;
    sgx_isv_svn_t     isv_svn_le;
    uint8_t           reserved2[24];
    sgx_misc_select_t masked_misc_select_le;
    sgx_attributes_t  attributes_le;
    sgx_key_id_t      key_id;
    sgx_mac_t         mac;
} sgx_arch_token_t;

typedef struct _sgx_report_data_t {
    uint8_t d[SGX_REPORT_DATA_SIZE];
} sgx_report_data_t;

typedef struct _report_body_t {
    sgx_cpu_svn_t        cpu_svn;
    sgx_misc_select_t    misc_select;
    sgx_cet_attributes_t cet_attributes;
    uint8_t              reserved1[11];
    sgx_isvext_prod_id_t isv_ext_prod_id;
    sgx_attributes_t     attributes;
    sgx_measurement_t    mr_enclave;
    uint8_t              reserved2[32];
    sgx_measurement_t    mr_signer;
    uint8_t              reserved3[32];
    sgx_config_id_t      config_id;
    sgx_prod_id_t        isv_prod_id;
    sgx_isv_svn_t        isv_svn;
    sgx_config_svn_t     config_svn;
    uint8_t              reserved4[42];
    sgx_isvfamily_id_t   isv_family_id;
    sgx_report_data_t    report_data;
} sgx_report_body_t;

typedef struct _report_t {
    sgx_report_body_t body;
    sgx_key_id_t      key_id;
    sgx_mac_t         mac;
} sgx_report_t;

#define SGX_REPORT_ACTUAL_SIZE 432

typedef struct {
    sgx_measurement_t    mr_enclave;
    sgx_attributes_t     attributes;
    sgx_cet_attributes_t cet_attributes;
    uint8_t              reserved1;
    sgx_config_svn_t     config_svn;
    sgx_misc_select_t    misc_select;
    uint8_t              reserved2[8];
    sgx_config_id_t      config_id;
    uint8_t              reserved3[384];
} sgx_target_info_t;
static_assert(sizeof(sgx_target_info_t) == 512, "incorrect struct size");

typedef struct _key_request_t {
    uint16_t          key_name;
    uint16_t          key_policy;
    sgx_isv_svn_t     isv_svn;
    uint16_t          reserved1;
    sgx_cpu_svn_t     cpu_svn;
    sgx_attributes_t  attribute_mask;
    sgx_key_id_t      key_id;
    sgx_misc_select_t misc_mask;
    sgx_config_svn_t  config_svn;
    uint8_t           reserved2[434];
    // struct is 512-bytes in size, alignment is required for EGETKEY
} sgx_key_request_t;
static_assert(sizeof(sgx_key_request_t) == 512, "incorrect struct size");

typedef uint8_t sgx_key_128bit_t[16];

static inline int enclu(uint32_t eax, uint64_t rbx, uint64_t rcx, uint64_t rdx) {
    __asm__ volatile (
        "enclu"
        : "+a"(eax)
        : "b"(rbx), "c"(rcx), "d"(rdx)
        : "memory", "cc"
    );
    return (int)eax;
}

#endif /* !__ASSEMBLER__ */

#define EREPORT     0
#define EGETKEY     1
#define EENTER      2
#define ERESUME     3
#define EEXIT       4
#define EACCEPT     5
#define EMODPE      6
#define EACCEPTCOPY 7

#define SGX_LAUNCH_KEY         0
#define SGX_PROVISION_KEY      1
#define SGX_PROVISION_SEAL_KEY 2
#define SGX_REPORT_KEY         3
#define SGX_SEAL_KEY           4

/* KEYREQUEST.KEYPOLICY field is a 16-bit bitmask, currently we use only bits 0 (use MRENCLAVE
 * measurement) and 1 (use MRSIGNER measurement) */
#define SGX_KEYPOLICY_MRENCLAVE 0x1
#define SGX_KEYPOLICY_MRSIGNER  0x2

#define RFLAGS_DF (1 << 10)
#define RFLAGS_AC (1 << 18)

#pragma pack(pop)
