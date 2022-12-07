#include <asm/errno.h>

#include "generated_offsets_build.h"
#include "host_sgx_driver.h"
#include "pal.h"
#include "pal_ecall_types.h"
#include "pal_linux_defs.h"
#include "pal_ocall_types.h"
#include "pal_tcb.h"
#include "sgx_arch.h"

const char* generated_offsets_name = "PAL_SGX";

const struct generated_offset generated_offsets[] = {
    /* defines from sgx_arch.h */
    DEFINE(SGX_FLAGS_DEBUG, SGX_FLAGS_DEBUG),
    DEFINE(SGX_FLAGS_MODE64BIT, SGX_FLAGS_MODE64BIT),
    DEFINE(SGX_XFRM_LEGACY, SGX_XFRM_LEGACY),
    DEFINE(SGX_XFRM_AVX, SGX_XFRM_AVX),
    DEFINE(SGX_XFRM_MPX, SGX_XFRM_MPX),
    DEFINE(SGX_XFRM_AVX512, SGX_XFRM_AVX512),
    DEFINE(SGX_XFRM_PKRU, SGX_XFRM_PKRU),
    DEFINE(SGX_XFRM_AMX, SGX_XFRM_AMX),
    DEFINE(SGX_MISCSELECT_EXINFO, SGX_MISCSELECT_EXINFO),
    DEFINE(SE_KEY_SIZE, SE_KEY_SIZE),

    DEFINE(SGX_FLAGS_MASK_CONST, SGX_FLAGS_MASK_CONST),
    DEFINE(SGX_XFRM_MASK_CONST, SGX_XFRM_MASK_CONST),
    DEFINE(SGX_MISCSELECT_MASK_CONST, SGX_MISCSELECT_MASK_CONST),

    /* defines from pal-arch.h */
    DEFINE(STACK_PROTECTOR_CANARY_DEFAULT, STACK_PROTECTOR_CANARY_DEFAULT),

    /* sgx_measurement_t */
    DEFINE(SGX_HASH_SIZE, sizeof(sgx_measurement_t)),

    /* sgx_pal_gpr_t */
    OFFSET_T(SGX_GPR_RAX, sgx_pal_gpr_t, rax),
    OFFSET_T(SGX_GPR_RCX, sgx_pal_gpr_t, rcx),
    OFFSET_T(SGX_GPR_RDX, sgx_pal_gpr_t, rdx),
    OFFSET_T(SGX_GPR_RBX, sgx_pal_gpr_t, rbx),
    OFFSET_T(SGX_GPR_RSP, sgx_pal_gpr_t, rsp),
    OFFSET_T(SGX_GPR_RBP, sgx_pal_gpr_t, rbp),
    OFFSET_T(SGX_GPR_RSI, sgx_pal_gpr_t, rsi),
    OFFSET_T(SGX_GPR_RDI, sgx_pal_gpr_t, rdi),
    OFFSET_T(SGX_GPR_R8, sgx_pal_gpr_t, r8),
    OFFSET_T(SGX_GPR_R9, sgx_pal_gpr_t, r9),
    OFFSET_T(SGX_GPR_R10, sgx_pal_gpr_t, r10),
    OFFSET_T(SGX_GPR_R11, sgx_pal_gpr_t, r11),
    OFFSET_T(SGX_GPR_R12, sgx_pal_gpr_t, r12),
    OFFSET_T(SGX_GPR_R13, sgx_pal_gpr_t, r13),
    OFFSET_T(SGX_GPR_R14, sgx_pal_gpr_t, r14),
    OFFSET_T(SGX_GPR_R15, sgx_pal_gpr_t, r15),
    OFFSET_T(SGX_GPR_RFLAGS, sgx_pal_gpr_t, rflags),
    OFFSET_T(SGX_GPR_RIP, sgx_pal_gpr_t, rip),
    OFFSET_T(SGX_GPR_EXITINFO, sgx_pal_gpr_t, exitinfo),
    DEFINE(SGX_GPR_SIZE, sizeof(sgx_pal_gpr_t)),

    /* sgx_cpu_context_t */
    OFFSET_T(SGX_CPU_CONTEXT_RAX, sgx_cpu_context_t, rax),
    OFFSET_T(SGX_CPU_CONTEXT_RCX, sgx_cpu_context_t, rcx),
    OFFSET_T(SGX_CPU_CONTEXT_RDX, sgx_cpu_context_t, rdx),
    OFFSET_T(SGX_CPU_CONTEXT_RBX, sgx_cpu_context_t, rbx),
    OFFSET_T(SGX_CPU_CONTEXT_RSP, sgx_cpu_context_t, rsp),
    OFFSET_T(SGX_CPU_CONTEXT_RBP, sgx_cpu_context_t, rbp),
    OFFSET_T(SGX_CPU_CONTEXT_RSI, sgx_cpu_context_t, rsi),
    OFFSET_T(SGX_CPU_CONTEXT_RDI, sgx_cpu_context_t, rdi),
    OFFSET_T(SGX_CPU_CONTEXT_R8, sgx_cpu_context_t, r8),
    OFFSET_T(SGX_CPU_CONTEXT_R9, sgx_cpu_context_t, r9),
    OFFSET_T(SGX_CPU_CONTEXT_R10, sgx_cpu_context_t, r10),
    OFFSET_T(SGX_CPU_CONTEXT_R11, sgx_cpu_context_t, r11),
    OFFSET_T(SGX_CPU_CONTEXT_R12, sgx_cpu_context_t, r12),
    OFFSET_T(SGX_CPU_CONTEXT_R13, sgx_cpu_context_t, r13),
    OFFSET_T(SGX_CPU_CONTEXT_R14, sgx_cpu_context_t, r14),
    OFFSET_T(SGX_CPU_CONTEXT_R15, sgx_cpu_context_t, r15),
    OFFSET_T(SGX_CPU_CONTEXT_RFLAGS, sgx_cpu_context_t, rflags),
    OFFSET_T(SGX_CPU_CONTEXT_RIP, sgx_cpu_context_t, rip),
    DEFINE(SGX_CPU_CONTEXT_SIZE, sizeof(sgx_cpu_context_t)),
    DEFINE(SGX_CPU_CONTEXT_XSTATE_ALIGN_SUB, sizeof(sgx_cpu_context_t) % PAL_XSTATE_ALIGN),

    /* struct pal_enclave_tcb */
    OFFSET(SGX_COMMON_SELF, pal_enclave_tcb, common.self),
    OFFSET(SGX_COMMON_STACK_PROTECTOR_CANARY, pal_enclave_tcb, common.stack_protector_canary),
    OFFSET(SGX_ENCLAVE_SIZE, pal_enclave_tcb, enclave_size),
    OFFSET(SGX_TCS_OFFSET, pal_enclave_tcb, tcs_offset),
    OFFSET(SGX_INITIAL_STACK_ADDR, pal_enclave_tcb, initial_stack_addr),
    OFFSET(SGX_TMP_RIP, pal_enclave_tcb, tmp_rip),
    OFFSET(SGX_ECALL_RETURN_ADDR, pal_enclave_tcb, ecall_return_addr),
    OFFSET(SGX_SIG_STACK_LOW, pal_enclave_tcb, sig_stack_low),
    OFFSET(SGX_SIG_STACK_HIGH, pal_enclave_tcb, sig_stack_high),
    OFFSET(SGX_SSA, pal_enclave_tcb, ssa),
    OFFSET(SGX_GPR, pal_enclave_tcb, gpr),
    OFFSET(SGX_EXIT_TARGET, pal_enclave_tcb, exit_target),
    OFFSET(SGX_FSBASE, pal_enclave_tcb, fsbase),
    OFFSET(SGX_PRE_OCALL_STACK, pal_enclave_tcb, pre_ocall_stack),
    OFFSET(SGX_USTACK_TOP, pal_enclave_tcb, ustack_top),
    OFFSET(SGX_USTACK, pal_enclave_tcb, ustack),
    OFFSET(SGX_THREAD, pal_enclave_tcb, thread),
    OFFSET(SGX_OCALL_EXIT_CALLED, pal_enclave_tcb, ocall_exit_called),
    OFFSET(SGX_THREAD_STARTED, pal_enclave_tcb, thread_started),
    OFFSET(SGX_READY_FOR_EXCEPTIONS, pal_enclave_tcb, ready_for_exceptions),
    OFFSET(SGX_MANIFEST_SIZE, pal_enclave_tcb, manifest_size),
    OFFSET(SGX_HEAP_MIN, pal_enclave_tcb, heap_min),
    OFFSET(SGX_HEAP_MAX, pal_enclave_tcb, heap_max),
    OFFSET(SGX_CLEAR_CHILD_TID, pal_enclave_tcb, clear_child_tid),

    /* struct pal_host_tcb aka PAL_HOST_TCB */
    OFFSET(PAL_HOST_TCB_TCS, pal_host_tcb, tcs),
    OFFSET(PAL_HOST_TCB_IN_AEX_PROF, pal_host_tcb, is_in_aex_profiling),
    OFFSET(PAL_HOST_TCB_EENTER_CNT, pal_host_tcb, eenter_cnt),
    OFFSET(PAL_HOST_TCB_EEXIT_CNT, pal_host_tcb, eexit_cnt),
    OFFSET(PAL_HOST_TCB_AEX_CNT, pal_host_tcb, aex_cnt),
    OFFSET(PAL_HOST_TCB_LAST_ASYNC_EVENT, pal_host_tcb, last_async_event),

    /* sgx_arch_tcs_t */
    OFFSET_T(TCS_FLAGS, sgx_arch_tcs_t, flags),
    OFFSET_T(TCS_OSSA, sgx_arch_tcs_t, ossa),
    OFFSET_T(TCS_CSSA, sgx_arch_tcs_t, cssa),
    OFFSET_T(TCS_NSSA, sgx_arch_tcs_t, nssa),
    OFFSET_T(TCS_OENTRY, sgx_arch_tcs_t, oentry),
    OFFSET_T(TCS_OFS_BASE, sgx_arch_tcs_t, ofs_base),
    OFFSET_T(TCS_OGS_BASE, sgx_arch_tcs_t, ogs_base),
    OFFSET_T(TCS_OFS_LIMIT, sgx_arch_tcs_t, ofs_limit),
    OFFSET_T(TCS_OGS_LIMIT, sgx_arch_tcs_t, ogs_limit),
    DEFINE(TCS_SIZE, sizeof(sgx_arch_tcs_t)),

    /* sgx_attributes_t */
    OFFSET_T(SGX_ATTRIBUTES_XFRM, sgx_attributes_t, xfrm),

    /* sgx_sigstruct_t */
    OFFSET_T(SGX_ARCH_SIGSTRUCT_HEADER, sgx_sigstruct_t, header),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_VENDOR, sgx_sigstruct_t, vendor),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_DATE, sgx_sigstruct_t, date),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_HEADER2, sgx_sigstruct_t, header2),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_SWDEFINED, sgx_sigstruct_t, swdefined),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_MODULUS, sgx_sigstruct_t, modulus),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_EXPONENT, sgx_sigstruct_t, exponent),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_SIGNATURE, sgx_sigstruct_t, signature),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_MISC_SELECT, sgx_sigstruct_t, misc_select),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_MISC_MASK, sgx_sigstruct_t, misc_mask),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_CET_ATTRIBUTES, sgx_sigstruct_t, cet_attributes),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_CET_ATTRIBUTES_MASK, sgx_sigstruct_t, cet_attributes_mask),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_ISV_FAMILY_ID, sgx_sigstruct_t, isv_family_id),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_ATTRIBUTES, sgx_sigstruct_t, attributes),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_ATTRIBUTE_MASK, sgx_sigstruct_t, attribute_mask),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_ENCLAVE_HASH, sgx_sigstruct_t, enclave_hash),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_ISVEXT_PROD_ID, sgx_sigstruct_t, isvext_prod_id),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_ISV_PROD_ID, sgx_sigstruct_t, isv_prod_id),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_ISV_SVN, sgx_sigstruct_t, isv_svn),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_Q1, sgx_sigstruct_t, q1),
    OFFSET_T(SGX_ARCH_SIGSTRUCT_Q2, sgx_sigstruct_t, q2),
    DEFINE(SGX_ARCH_SIGSTRUCT_SIZE, sizeof(sgx_sigstruct_t)),

    /* pal_linux_def.h */
    DEFINE(SSA_FRAME_NUM, SSA_FRAME_NUM),
    DEFINE(SSA_FRAME_SIZE, SSA_FRAME_SIZE),
    DEFINE(SSA_MISC_EXINFO_SIZE, SSA_MISC_EXINFO_SIZE),
    DEFINE(ENCLAVE_STACK_SIZE, ENCLAVE_STACK_SIZE),
    DEFINE(ENCLAVE_SIG_STACK_SIZE, ENCLAVE_SIG_STACK_SIZE),
    DEFINE(DEFAULT_ENCLAVE_BASE, DEFAULT_ENCLAVE_BASE),
    DEFINE(MMAP_MIN_ADDR, MMAP_MIN_ADDR),

    /* pal_linux.h */
    DEFINE(PAGESIZE, PRESET_PAGESIZE),

    /* pal.h */
    DEFINE(PAL_EVENT_NO_EVENT, PAL_EVENT_NO_EVENT),
    DEFINE(PAL_EVENT_NUM_BOUND, PAL_EVENT_NUM_BOUND),

    /* errno */
    DEFINE(EINTR, EINTR),

    /* Ecall numbers */
    DEFINE(ECALL_ENCLAVE_START, ECALL_ENCLAVE_START),
    DEFINE(ECALL_THREAD_START, ECALL_THREAD_START),
    DEFINE(ECALL_THREAD_RESET, ECALL_THREAD_RESET),

    /* Ocall Index */
    DEFINE(OCALL_EXIT, OCALL_EXIT),

    /* fp regs */
    OFFSET_T(XSAVE_HEADER_OFFSET, PAL_XREGS_STATE, header),
    DEFINE(PAL_XSTATE_ALIGN, PAL_XSTATE_ALIGN),
    DEFINE(PAL_FP_XSTATE_MAGIC2_SIZE, PAL_FP_XSTATE_MAGIC2_SIZE),

    /* driver type */
#ifdef CONFIG_SGX_DRIVER_OOT
    DEFINE(CONFIG_SGX_DRIVER_OOT, 1),
#endif
#ifdef CONFIG_SGX_DRIVER_UPSTREAM
    DEFINE(CONFIG_SGX_DRIVER_UPSTREAM, 1),
#endif

    OFFSET_END,
};
