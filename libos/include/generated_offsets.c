#include "generated_offsets_build.h"
#include "libos_internal.h"
#include "libos_tcb.h"

const char* generated_offsets_name = "LIBOS";

const struct generated_offset generated_offsets[] = {
    OFFSET_T(LIBOS_TCB_OFF, PAL_TCB, libos_tcb),
    OFFSET_T(LIBOS_TCB_LIBOS_STACK_OFF, libos_tcb_t, libos_stack_bottom),
    OFFSET_T(LIBOS_TCB_SCRATCH_PC_OFF, libos_tcb_t, syscall_scratch_pc),

    OFFSET_T(PAL_CONTEXT_FPREGS_OFF, struct PAL_CONTEXT, fpregs),
    OFFSET_T(PAL_CONTEXT_MXCSR_OFF, struct PAL_CONTEXT, mxcsr),
    OFFSET_T(PAL_CONTEXT_FPCW_OFF, struct PAL_CONTEXT, fpcw),
    OFFSET_T(PAL_CONTEXT_FPREGS_USED_OFF, struct PAL_CONTEXT, is_fpregs_used),

    DEFINE(LIBOS_XSTATE_ALIGN, LIBOS_XSTATE_ALIGN),
    DEFINE(RED_ZONE_SIZE, RED_ZONE_SIZE),

    OFFSET_END,
};
