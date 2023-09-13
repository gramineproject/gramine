
 # Generates code that consumes `n` cycles by repeatedly moving from register
 # `r` to itself.
.macro CYCLE_DELAY n r
    lea (\r), \r
.if \n-1
CYCLE_DELAY "(\n-1)" \r
.endif
.endm

    .data
    .align 0x1000   /* 4KB */
.globl aex_notify_c3_cache
aex_notify_c3_cache:
    .space 0x1000 /* 4KB */


# This file contains in-enclave flows -- upon EENTER and for EEXIT:
#
#     - First-time enclave entry ECALLs (label prefix `cssa0_ecall_`):
#         - ECALL_ENCLAVE_START
#         - ECALL_THREAD_START
#         - ECALL_THREAD_RESET
#
#     - OCALLs (label prefix `cssa0_ocall_`)
#         - enclave requests OCALL via EEXIT (`sgx_ocall()` PAL function)
#         - untrusted runtime returns from OCALL via EENTER (label prefix `cssa0_ocall_return`)
#
#     - Exception handling (label prefix `cssa1_exception_`)
#
# There are two entry points in this file:
#
#     - enclave_entry() -- where EENTER jumps to (address in TCS.OENTRY, taken from the libpal.so
#                                                 enclave's ELF entry point)
#
#     - sgx_ocall()     -- called by SGX PAL, to perform OCALLs
#
# There are several helper functions in this file:
#
#     - _restore_sgx_context()
#     - save_xregs() and its no-stack version __save_xregs()
#     - restore_xregs() and its no-stack version __restore_xregs()
#     - __morestack() -- GDB helper
#
# Label names in this file follow this pattern:
#
#    [TCS.CSSA number] [ecall/ocall/exception] [action/flow]
#
# For example, `.Lcssa0_ecall_thread_reset` means that the code under this label runs in frame
# SSA[0] ("regular context") and it processes ECALL_THREAD_RESET ecall.
#
# As another example, `.Lcssa1_exception_during_ocall_flows` means that the code under this label
# runs in frame SSA[1] ("stage-1 exception handler") in response to AEX that occured during
# in-enclave OCALL preparation/finalization flows. The code under this label is supposed to set up
# the stage-2 exception handler that will run in frame SSA[0] before returning to regular context.
#
# Note that stage-1 exception handler has only minimal asm code and doesn't call any C functions.
# Its sole purpose is to prepare the stage-2 handler by:
#   - copying the interrupted SSA[0] context on the stack ("CPU context")
#   - rewiring the SSA[0] context to point to _PalExceptionHandler()
#   - invoking EEXIT (so that untrusted runtime can perform ERESUME)

#include "sgx_arch.h"
#include "asm-offsets.h"

    .text

# In some cases, like bogus parameters passed to enclave_entry, it's tricky to return cleanly
# (passing the correct return address to EEXIT, OCALL_EXIT can be interrupted, etc.). Since those
# cases should only ever happen with a malicious host, just go into an endless loop.
.macro FAIL_LOOP
.Lfail_loop\@:
    jmp .Lfail_loop\@
.endm

.macro CHECK_IF_SIGNAL_STACK_IS_USED stack_reg, label_on_stack, label_out_of_stack
    cmpq %gs:SGX_SIG_STACK_LOW, \stack_reg
    jb \label_out_of_stack
    cmpq %gs:SGX_SIG_STACK_HIGH, \stack_reg
    ja \label_out_of_stack
    jmp \label_on_stack
.endm


    .global enclave_entry
    .type enclave_entry, @function
enclave_entry:
    .cfi_startproc

    # PAL convention on EENTER:
    #   RAX - current SSA index (aka CSSA), can be 0 (`cssa0_`) or 1 (`cssa1_`)
    #   RBX - address of TCS
    #   RCX - address of IP following EENTER
    #   [ other regs are not trusted ]
    #
    # The following code is hardened to defend attacks from untrusted host. Any states given by the
    # host instead of the ISA must be assumed potentially malicious.
    #
    # This thread can be interrupted but then the below check branches to .Lcssa1_exception (because
    # on interrupt, CSSA = 1). So the outside can't re-enter the checks below in the middle.

    # x86-64 SysV ABI requires RFLAGS.DF = 0 on entry to function call.
    cld

    # CSSA = 1 -- this is a "stage-1 exception handler" flow
    cmpq $0, %rax
    jne .Lcssa1_exception

    # RCX contains ECALL return address (filled by EENTER hardware flow)
    movq %rcx, %gs:SGX_ECALL_RETURN_ADDR

    # OCALL stack was prepared previously -- this is a "return from OCALL" flow
    cmpq $0, %gs:SGX_PRE_OCALL_STACK
    jne .Lcssa0_ocall_return

    # CSSA = 0 and it's not an OCALL -- this is an "ECALL" flow
    jmp .Lcssa0_ecall

.Lcssa0_ecall:
    # PAL convention:
    #   RDI - ECALL number
    #   RSI - pointer to ecall arguments
    #   RDX - exit target
    #   RCX - enclave base

    cmpq $ECALL_THREAD_RESET, %rdi
    je .Lcssa0_ecall_thread_reset

    # Except ECALL_THREAD_RESET, ecalls are only used to start a thread (main or additional
    # threads). We already checked for case of ECALL_THREAD_RESET, so at this point we should only
    # get exactly one ecall per thread.
    cmpq $0, %gs:SGX_THREAD_STARTED
    je .Lcssa0_ecall_enclave_or_thread_start
    FAIL_LOOP

.Lcssa0_ecall_enclave_or_thread_start:
    movq $1, %gs:SGX_THREAD_STARTED

    # calculate enclave base = RBX (trusted) - GS:SGX_TCS_OFFSET
    mov %rbx, %rcx
    subq %gs:SGX_TCS_OFFSET, %rcx

    # switch to enclave stack
    movq %gs:SGX_INITIAL_STACK_ADDR, %rsp

    # clear the rest of register states
    xorq %rax, %rax
    xorq %rbx, %rbx
    xorq %r8, %r8
    xorq %r9,  %r9
    xorq %r10, %r10
    xorq %r11, %r11
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15

    # clear the Alignment Check flag (RFLAGS.AC) to prevent #AC-fault side channel; this overrides
    # 8B on enclave stack but stack is not used at this point anyway
    pushfq
    andq $(~RFLAGS_AC), (%rsp)
    popfq

    # Clear "extended" state (FPU aka x87, SSE, AVX, ...).
    # TODO: We currently clear only state covered by FXRSTOR but not by XRSTOR (e.g., no clearing of
    #       YMM/ZMM regs). This is because we didn't read the value of XFRM yet, so we don't know
    #       whether XRSTOR is safe at this point.
    leaq g_xsave_reset_state(%rip), %rax
    fxrstor (%rax)
    xorq %rax, %rax

    # register states need to be carefully checked, so we move handling to handle_ecall() in C code
    callq handle_ecall

    # handle_ecall() will only return when invalid parameters has been passed
    FAIL_LOOP

.Lcssa0_ecall_thread_reset:
    # clear TLS variables for thread reuse
    movq $0, %gs:SGX_READY_FOR_EXCEPTIONS

    # Assertion: thread is reset only after special-case OCALL_EXIT.
    cmpq $0, %gs:SGX_OCALL_EXIT_CALLED
    jne 1f
    FAIL_LOOP
1:

    # At this point, the thread has completely exited from the point of view of LibOS. We can now
    # set *clear_child_tid to 0, which will trigger async worker thread in LibOS, which will wake up
    # parent thread if any.
    cmpq $0, %gs:SGX_CLEAR_CHILD_TID
    je 1f
    movq %gs:SGX_CLEAR_CHILD_TID, %rbx
    movl $0, (%rbx)

1:
    # Signals are impossible at this point: benign untrusted runtime blocks all signals (see
    # sgx_ocall_exit()), and even if malicious one doesn't block them, signals are ignored due to
    # SGX_READY_FOR_EXCEPTIONS = 0.
    movq $0, %gs:SGX_THREAD_STARTED
    movq $0, %gs:SGX_OCALL_EXIT_CALLED
    movq $0, %gs:SGX_PRE_OCALL_STACK

    # Instead of jumping to .Lcssa0_ocall_or_cssa1_exception_eexit, simply perform EEXIT
    # because there is no modified state to clear in this "thread-reset" code path.
    movq %gs:SGX_ECALL_RETURN_ADDR, %rbx
    movq $EEXIT, %rax
    enclu

.Lcssa1_exception:
    # PAL convention:
    #   RDI - external event

    # Nested exceptions at the host-OS level are disallowed:
    #   - Synchronous exceptions are assumed to never happen during .Lcssa1_exception;
    #   - Asynchronous signals are not nested by benign host OS because we mask asynchronous signals
    #     on signal handler.
    #
    # If malicious host OS injects a nested signal, CSSA != 1 and we go into FAIL_LOOP. Currently
    # this check is assertion only because it is also enforced by EENTER since enclave is created
    # with NSSA=2.

    cmpq $1, %rax
    je 1f
    FAIL_LOOP
1:

    # SGX_GPR is a base pointer to the SSA[0].GPRSGX region
    movq %gs:SGX_GPR, %rbx

    # first check SSA[0].GPRSGX.EXITINFO -- if VALID bit (0x80000000) is set, then use trusted
    # SSA[0].GPRSGX.EXITINFO.VECTOR (first 8 bits of EXITINFO) instead of possibly-malicious
    # "external event" value in RDI
    movq %rdi, %rsi
    xorq %rdi, %rdi
    movl SGX_GPR_EXITINFO(%rbx), %edi
    testl $0x80000000, %edi
    jnz .Lcssa1_exception_determine_when

    # VALID bit in SSA[0].GPRSGX.EXITINFO is clear, some unknown-to-SGX exception occured, use the
    # possibly-malicious "external event" value in RDI (only the first 8 bits count)
    movl %esi, %edi
    andl $0xff, %edi
    cmpl $0, %edi
    jne .Lcssa1_exception_determine_when

    # definitely-malicious exception (correct untrusted runtime would never generate "0" event)
    FAIL_LOOP

.Lcssa1_exception_determine_when:
    # If this enclave thread has not been initialized yet, we should not try to call an event
    # handler yet.
    cmpq $0, %gs:SGX_READY_FOR_EXCEPTIONS
    jne 1f
    FAIL_LOOP
1:
    # Beware of races between host signal delivery and handling RSP in this entry code. Consider
    # the following scenario:
    #
    # 1. We are inside the enclave but RSP isn't restored yet to something inside the enclave.
    #    That's for example the case when returning from an ocall.
    # 2. The enclave gets interrupted. The not restored RSP is pushed into SGX_GPR_RSP by the CPU.
    # 3. The host enters the enclave again and indicates that there's a new signal.
    # 4. SGX_GPR_RSP points to the untrusted stack.
    #
    # The below code should be fine since it detects an interrupted ocall and restores RSP from
    # SGX_PRE_OCALL_STACK before exception handling (see below for full details).
    #
    # The stack swap logic does not need to be atomic because nested exceptions are disallowed by
    # SGX due to TCS.NSSA == 2 (thus, .Lcssa1_exception_determine_when logic cannot be nested).

    # Check if interrupted during an ocall case (except OCALL_EXIT), i.e. SGX_PRE_OCALL_STACK is set
    movq %gs:SGX_PRE_OCALL_STACK, %rsi
    cmpq $0, %rsi
    jne .Lcssa1_exception_during_ocall_flows

    # If this is not the case, check if OCALL_EXIT has been called. If this is not the case, setup
    # the exception handler for the non-ocall case.
    cmpq $0, %gs:SGX_OCALL_EXIT_CALLED
    je .Lcssa1_exception_during_enclave_run

    # We are interrupted during the never-returning OCALL_EXIT. Because the thread is going to exit
    # anyway, we can ignore this exception.
    movq %rdx, %rbx    # upon EENTER the exit address was in RDX, mov it to RBX for EEXIT
    movq $EEXIT, %rax
    ENCLU

.Lcssa1_exception_during_ocall_flows:
    # At this point, we are in the stage-1 exception handler (CSSA=1) and
    # SGX_PRE_OCALL_STACK=<trusted pointer to enclave stack>. I.e. we are interrupted during
    # handling of enclave's sgx_ocall/Lcssa0_ocall_return assembly code.
    #
    # Calling the stage-2 exception handler (CSSA=0) while SGX_PRE_OCALL_STACK != 0 would be
    # problematic because stage-2 handler could issue nested OCALLs. This would mean the
    # SGX_PRE_OCALL_STACK logic would need to handle nesting. So we don't set up the stage-2 handler
    # (i.e, the _PalExceptionHandler() function).
    #
    # Instead if we're in such situation, we emulate it as if RIP reached to the safe point,
    # .Lcssa0_ocall_return_after_stack_restore. In other words, the stage-1 handler jumps to the
    # regular returning-from-OCALL flow (CSSA=0) with RSI=<external event> which forces that flow
    # to call _PalHandleExternalEvent() before proceeding with normal enclave code.
    #
    # Ocall sequence:
    #  1. call sgx_ocall()
    #  2. SGX_PRE_OCALL_STACK=RSP: save trusted stack
    #  3. EEXIT
    #  4. untrusted PAL which issues real host system call
    #  5. EENTER (and start from enclave_entry)
    #  6. .Lcssa0_ocall_return:
    #  7. (RSP, SGX_STACK) = (SGX_STACK, 0): restore trusted stack
    #  8. .Lcssa0_ocall_return_after_stack_restore:
    #  9. call _PalHandleExternalEvent() if interrupted
    # 10. return from sgx_ocall() to the caller
    #
    # It is also required that sgx_ocall() be atomic wrt async exception. When host async signal
    # arrives, sgx_ocall() should result in EINTR.
    #
    # There are three possibilities when exactly host async signal arrives:
    #
    # A. before exiting enclave to perform host syscall
    # B. after exiting enclave and before re-entering enclave (i.e., during untrusted execution of
    #    host syscall)
    # C. after re-entering enclave but before returning to sgx_ocall().
    #
    # Note that Case A didn't even issue host syscall, Case B may have interrupted host syscall (but
    # maybe interrupt came after successful host syscall), and Case C was interrupted after
    # successful host syscall. In Case C, the result of host system call must be preserved to be
    # replayed in later invocation.
    #
    # On host async signal we treat these cases as follows:
    #
    # A. right-before EEXIT (2. in above sequence):
    #        - set EINTR and forward RIP to exception handler
    # B. during untrusted PAL (3. - 4. in above sequence):
    #        - code in untrusted PAL handles this case
    # C. right-after EENTER (5. - 7. in above sequence):
    #        - ocall succeeded, forward RIP to exception handler

    # Find out which of cases A, B, or C happened:
    #   - copy RIP at which the enclave was interrupted into RAX,
    #   - copy the boundaries between cases A, B, and C into R11,
    #   - compare enclave's RIP against these boundaries (RAX vs R11).

    movq SGX_GPR_RIP(%rbx), %rax
    leaq .Lcssa0_ocall_eexit_prepare(%rip), %r11
    cmpq %r11, %rax
    jb .Lcssa1_exception_during_ocall_flows_case_c
    leaq .Lcssa0_ocall_eexit_done(%rip), %r11
    cmpq %r11, %rax
    jae .Lcssa1_exception_during_ocall_flows_case_c

    # CASE A. We are right-before EEXIT for ocall in between [.Lcssa0_ocall_eexit_prepare,
    #         .Lcssa0_ocall_eexit_done) -- skip EEXIT as if ocall returned EINTR.
    #
    # If there is a registered signal handler for the current exception, _PalHandleExternalEvent()
    # will be called (and thus we need to save RDI = <external event>) before returning from ocall.

    movq $-EINTR, SGX_GPR_RDI(%rbx)    # return value for .Lcssa0_ocall_return
    # fallthrough to Case C

    # CASE B. This code cannot land in Case B because:
    #
    # (1) this code path is triggered only if we haven't yet exited enclave when signal arrived, and
    # (2) in Case B, we exited the enclave and signal arrived while in untrusted code.
    #
    # The two conditions cannot be true at the same time, so Case B never happens here (Case B
    # results in Lcssa0_ocall_return code path below).

.Lcssa1_exception_during_ocall_flows_case_c:
    # CASE C. We are right-after EENTER returning from successful ocall.
    #
    # Set RSI = <external event> and move RIP to .Lcssa0_ocall_return_after_stack_restore, such
    # that regular returning-from-OCALL flow (CSSA=0) will notice the external event and will call
    # _PalHandleExternalEvent() to handle the exception.
    #
    # Note that either we fell-through from Case A and RDI was already set to the -EINTR return
    # value, or we are indeed in Case C and RDI already contains the successful OCALL result.

    movq %rdi, SGX_GPR_RSI(%rbx)      # external event for .Lcssa0_ocall_return

    leaq .Lcssa0_ocall_return_after_stack_restore(%rip), %rax
    movq %rax, SGX_GPR_RIP(%rbx)

    movq %rsi, SGX_GPR_RSP(%rbx)
    movq $0, %gs:SGX_PRE_OCALL_STACK
    andq $(~(RFLAGS_DF | RFLAGS_AC)), SGX_GPR_RFLAGS(%rbx)

    jmp .Lcssa1_exception_eexit       # cases A, B and C in stage-1 handler done

.Lcssa1_exception_during_enclave_run:
    # The thread got interrupted outside of ocall handling (see above for that special case). We
    # inject a call to _PalExceptionHandler() into the interrupted thread to handle exception in
    # stage-2 handler (on ERESUME).

    # The last instructions of _restore_sgx_context() need to be atomic for the code below (see
    # _restore_sgx_context for more details). So emulate this if we were interrupted there.
    leaq .Lrestore_sgx_context_inst0(%rip), %rax
    cmpq %rax, SGX_GPR_RIP(%rbx)
    je .Lcssa1_exception_emulate_restore_sgx_context_inst0

    leaq .Lrestore_sgx_context_inst1(%rip), %rax
    cmpq %rax, SGX_GPR_RIP(%rbx)
    je .Lcssa1_exception_emulate_restore_sgx_context_inst1

    leaq .Lrestore_sgx_context_inst2(%rip), %rax
    cmpq %rax, SGX_GPR_RIP(%rbx)
    je .Lcssa1_exception_emulate_restore_sgx_context_inst2

    jmp .Lcssa1_exception_rewire_ssa0_to_handler

.Lcssa1_exception_emulate_restore_sgx_context_inst0:
    # emulate movq SGX_CPU_CONTEXT_R15 - SGX_CPU_CONTEXT_RIP(%rsp), %r15
    movq SGX_GPR_RSP(%rbx), %rax
    movq SGX_CPU_CONTEXT_R15 - SGX_CPU_CONTEXT_RIP(%rax), %rax
    movq %rax, SGX_GPR_R15(%rbx)

.Lcssa1_exception_emulate_restore_sgx_context_inst1:
    # emulate movq SGX_CPU_CONTEXT_RSP - SGX_CPU_CONTEXT_RIP(%rsp), %rsp
    movq SGX_GPR_RSP(%rbx), %rax
    movq SGX_CPU_CONTEXT_RSP - SGX_CPU_CONTEXT_RIP(%rax), %rax
    movq %rax, SGX_GPR_RSP(%rbx)

.Lcssa1_exception_emulate_restore_sgx_context_inst2:
    # emulate `jmp *%gs:SGX_TMP_RIP`
    movq %gs:SGX_TMP_RIP, %rax
    movq %rax, SGX_GPR_RIP(%rbx)

.Lcssa1_exception_rewire_ssa0_to_handler:
    movq SGX_GPR_RSP(%rbx), %rsi

    cmpq $0, %gs:SGX_READY_FOR_AEX_NOTIFY
    je 1f
    # Mitigation handler uses the sig_stack. If an interrupt happens in
    # the mitigation handler before the stack switch to the previous stack, we 
    # need to use the sp from previous interrupt to determine how to allocate
    # on sig_stack
    movq  SGX_GPR_RIP(%rbx), %rax  
    cmpb  $0xc3, (%rax)    # ZF=1 if interrupted c3 (ret)
    jnz .Lcheck_aex_in_mitigation

    # If interrupts on c3, check whether sp is on the sig_stack. If yes, it means the mitigation may 
    # occur during the call instruction in mitigation handler. In this case, retrieve the IP from stack.
    # SSA0.rsp may not be accessable in some case. So we add the check before access it.
    CHECK_IF_SIGNAL_STACK_IS_USED %rsi, .Lretrieve_ip, .Lcheck_aex_in_mitigation
.Lretrieve_ip:
    movq (%rsi), %rax

.Lcheck_aex_in_mitigation:
    lea .Lct_restore_sgx_context_inst0(%rip), %rsi
    subq %rax, %rsi
    cmpq $(.Lct_restore_sgx_context_inst0 - __ct_mitigation_begin + 1), %rsi
    movq SGX_GPR_RSP(%rbx), %rsi
    jae 1f
    # interrupt happens in AEX mitigation handler.
    # retrive the SP from reserved cpu context.
    movq SGX_GPR_R15(%rbx), %rax
    movq SGX_CPU_CONTEXT_RSP(%rax), %rsi
1:
    CHECK_IF_SIGNAL_STACK_IS_USED %rsi, .Lon_signal_stack, .Lout_of_signal_stack

.Lout_of_signal_stack:
    movq %gs:SGX_SIG_STACK_HIGH, %rsi

    # When switching to the not yet used signal stack we don't need to reserve a redzone. So move
    # the stack pointer up here to undo the move down below.
    addq $RED_ZONE_SIZE, %rsi

    # Setup stack for stage-2 handler _PalExceptionHandler().
    #
    # Stack layout:
    #     8-bytes padding:    (8 mod 16) bytes aligned for x86 ABI
    #     EXINFO:             16 bytes
    #     sgx_cpu_context_t:  144 bytes
    #     XSAVE area:         PAL_XSTATE_ALIGN=64 bytes aligned
    #     xstate magic:       For PAL_FP_XSTATE_MAGIC2
    #     sgx_cpu_context_t:  144 bytes (reserved for AEX mitigation)
    #     8 bytes :           For AEX handler usage
    #     padding:            (if necessary)    
    #     RED_ZONE:           (unless newly switching to signal stack)
    #
    # NOTE: there is no saved RIP on the stack (to return) because _PalExceptionHandler() calls
    #       _restore_sgx_context().

#define STACK_PADDING_SIZE (PAL_FP_XSTATE_MAGIC2_SIZE + 8 + 8*2)
#define STACK_FRAME_SUB \
    (SGX_CPU_CONTEXT_SIZE * 2 + RED_ZONE_SIZE + STACK_PADDING_SIZE)

.Lon_signal_stack:
    movl g_xsave_size(%rip), %eax
    addq $STACK_FRAME_SUB, %rax
    subq %rax, %rsi

    # Disallow too many nested exceptions. In normal Gramine flow, this should never happen. Since
    # addresses need to be canonical, this addition does not overflow.
    movq %gs:SGX_SIG_STACK_HIGH, %rax
    addq %gs:SGX_SIG_STACK_LOW, %rax
    shrq $1, %rax
    cmp %rax, %rsi        # rsi - sp on sig_stack
    jae 1f
    FAIL_LOOP
1:

    # Align XSAVE area to 64 bytes after sgx_cpu_context_t
    andq $~(PAL_XSTATE_ALIGN - 1), %rsi
    subq $SGX_CPU_CONTEXT_XSTATE_ALIGN_SUB, %rsi

    # Rewire SSA0: pass 1st arg to _PalExceptionHandler():
    #    - exit info (in RDI, either trusted SSA[0].GPRSGX.EXITINFO or possibly-malicious
    #                 "external event")
    #
    # Also copy SSA[0].GPRSGX.RDI to the CPU context on the stack
    xchgq %rdi, SGX_GPR_RDI(%rbx)
    movq %rdi, SGX_CPU_CONTEXT_RDI(%rsi)

    # sgx_cpu_context = sgx_gpr
    # Copy the rest of SSA[0].GPRSGX to the CPU context on the stack
    movq SGX_GPR_RAX(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_RAX(%rsi)
    movq SGX_GPR_RCX(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_RCX(%rsi)
    movq SGX_GPR_RDX(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_RDX(%rsi)
    movq SGX_GPR_RBX(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_RBX(%rsi)
    movq SGX_GPR_RSP(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_RSP(%rsi)
    movq SGX_GPR_RBP(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_RBP(%rsi)
    movq SGX_GPR_RSI(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_RSI(%rsi)
    /* RDI was saved above */
    movq SGX_GPR_R8(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_R8(%rsi)
    movq SGX_GPR_R9(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_R9(%rsi)
    movq SGX_GPR_R10(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_R10(%rsi)
    movq SGX_GPR_R11(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_R11(%rsi)
    movq SGX_GPR_R12(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_R12(%rsi)
    movq SGX_GPR_R13(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_R13(%rsi)
    movq SGX_GPR_R14(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_R14(%rsi)
    movq SGX_GPR_R15(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_R15(%rsi)
    movq SGX_GPR_RFLAGS(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_RFLAGS(%rsi)
    movq SGX_GPR_RIP(%rbx), %rdi
    movq %rdi, SGX_CPU_CONTEXT_RIP(%rsi)

    # Rewire SSA0: pass more args to _PalExceptionHandler():
    #    - pointer to sgx_cpu_context_t (SSA[0].GPRSGX.RSI, 2nd arg)
    #    - pointer to PAL_XREGS_STATE   (SSA[0].GPRSGX.RDX, 3rd arg)
    movq %rsi, SGX_GPR_RSI(%rbx)
    movq %rsi, SGX_GPR_RDX(%rbx)
    addq $SGX_CPU_CONTEXT_SIZE, SGX_GPR_RDX(%rbx)

    # Rewire SSA0 (args to _PalExceptionHandler()):
    #    - pointer to EXINFO            (SSA[0].GPRSGX.RCX, 4rd arg)
    sub $SSA_MISC_EXINFO_SIZE, %rsi
    mov %rsi, SGX_GPR_RCX(%rbx)

    # Save EXINFO - it's always immediately before GPR in SSA.
    # If EXINFO MISC component is not enabled, it will contain padding with all 0.
    mov %gs:SGX_GPR, %rdi
    sub $SSA_MISC_EXINFO_SIZE, %rdi
    # SSA_MISC_EXINFO_SIZE=16, so we can inline this copy.
    mov 0(%rdi), %rax
    mov %rax, 0(%rsi)
    mov 8(%rdi), %rax
    mov %rax, 8(%rsi)

    # Rewire SSA0: SSA[0].GPRSGX.RSP points to SGX PAL signal stack
    #
    # x86-64 SysV ABI requires 16B alignment of stack before call instruction which implies a (8 mod
    # 16)B alignment on function entry (due to implicit push of RIP). Since we already aligned XSAVE
    # area above, this requirement is satisfied.
    subq $8, %rsi
    movq %rsi, SGX_GPR_RSP(%rbx)   # GPR0.RSP points to the sig_stack sp for cssa1 exception handling

    # clear SSA.GPRSGX.EXITINFO; we used it to identify HW exception (if any), and a scenario is
    # possible where the same SSA is re-used to handle more signals that arrive right after this
    # exception, so we must clear state
    movq $0, SGX_GPR_EXITINFO(%rbx)

    # Rewire SSA0: modify SSA[0].GPRSGX.RFLAGS:
    #   - clear RFLAGS.DF to conform to the SysV ABI,
    #   - clear RFLAGS.AC to prevent the #AC-fault side channel
    andq $(~(RFLAGS_DF | RFLAGS_AC)), SGX_GPR_RFLAGS(%rbx)

    # Rewire SSA0: SSA[0].GPRSGX.RIP points to _PalExceptionHandler()
    leaq _PalExceptionHandler(%rip), %rdi
    movq %rdi, SGX_GPR_RIP(%rbx)

    # copy the whole SSA[0].XSAVE region to the CPU context's XSAVE on stack;
    # __restore_xregs / __save_xregs clobber RDX so need to stash it in R10
    movq %rdx, %r10
    movq %gs:SGX_SSA, %rdi
    leaq 1f(%rip), %r11
    jmp __restore_xregs
1:
    leaq SGX_CPU_CONTEXT_SIZE + SSA_MISC_EXINFO_SIZE + 8(%rsi), %rdi
    leaq 2f(%rip), %r11
    jmp __save_xregs
2:
    movq %r10, %rdx

.Lcssa1_exception_eexit:
    cmpb $1, g_aex_notify_enabled(%rip)
    je 1f

    # AEX Notify is not set, stage-1 exception handler follows the normal EEXIT flow.

    # .Lcssa0_ocall_or_cssa1_exception_eexit has an ABI that uses RSI, RDI, RSP; clear the relevant
    # regs (note that stage-1 handler didn't clobber RSP -- which contains an untrusted pointer to
    # untrusted-runtime stack -- but this flow doesn't read/write RSP at all so there is no need to
    # sanitize/zero RSP)
    xorq %rdi, %rdi
    xorq %rsi, %rsi

    # upon EENTER the exit address was in RDX, mov it to RBX for EEXIT
    movq %rdx, %rbx
    jmp .Lcssa0_ocall_or_cssa1_exception_eexit

1:
    # AEX Notify is set, stage-1 exception handler doesn't invoke EEXIT but instead the new EDECCSSA
    # instruction.

    # after restoring SSA[0] context into GPRs, we'll need to jump to the stage-2 handler, so
    # memorize SSA[0].GPRSGX.RIP in an otherwise-unused R11
    movq SGX_GPR_RIP(%rbx), %r11

    # clear bit 0 within SSA[0].GPRSGX.AEXNOTIFY (so that ERESUME actually resumes stage-2 handler)
    movb $0, SGX_GPR_AEXNOTIFY(%rbx)

    # restore context from SSA[0] (which was already modified above to jump to stage-2 C handler);
    # note that XSAVE area (xregs) was already restored above, so only need to restore GPRs;
    # note that we only restore those GPRs of SSA[0] that were used/modified by stage-1 handler;
    # note that we don't care about SSA[0].GPRSGX.{URSP,URBP,EXITINFO,RESERVED,GSBASE}

    leaq SGX_GPR_RFLAGS(%rbx), %rsp     # trick to restore RFLAGS directly from SSA[0].GPRSGX.RFLAGS
    popfq

    movq SGX_GPR_FSBASE(%rbx), %rdi
    .byte 0xf3, 0x48, 0x0f, 0xae, 0xd7  # WRFSBASE %RDI

    movq SGX_GPR_RDI(%rbx), %rdi
    movq SGX_GPR_RSI(%rbx), %rsi
    movq SGX_GPR_RDX(%rbx), %rdx
    movq SGX_GPR_RCX(%rbx), %rcx     # not strictly needed
    movq SGX_GPR_R8(%rbx),  %r8      # not strictly needed
    movq SGX_GPR_R9(%rbx),  %r9      # not strictly needed
    movq SGX_GPR_R10(%rbx), %r10     # not strictly needed
    movq SGX_GPR_R12(%rbx), %r12     # not strictly needed
    movq SGX_GPR_R13(%rbx), %r13     # not strictly needed
    movq SGX_GPR_R14(%rbx), %r14     # not strictly needed
    movq SGX_GPR_R15(%rbx), %r15     # not strictly needed
    movq SGX_GPR_RBP(%rbx), %rbp     # not strictly needed
    movq SGX_GPR_RSP(%rbx), %rsp
    xorq %rbx, %rbx                  # for sanity

    # go from SSA[1] to SSA[0] (more specifically, simply decrement CSSA from 1 to 0);
    # must be careful after this ENCLU instruction because may be interrupted by new exceptions
    movq $EDECCSSA, %rax
    enclu

    # finally jump to the stage-2 C exception handler; beware of data races!
.Lfinalize_context_after_deccssa_inst0:
    jmp *%r11

    .cfi_endproc


    .global sgx_ocall
    .type sgx_ocall, @function
sgx_ocall:
.Lcssa0_ocall:
    # Arguments:
    #   RDI: OCALL number (code)
    #   RSI: OCALL args on untrusted stack (ms)
    #
    # Function prepares the enclave stack (to return after OCALL) as follows:
    #   sgx_cpu_context_t:
    #      RAX = 0: place holder
    #      RCX
    #      ...
    #      RFLAGS
    #      RIP
    #   XSAVE area:
    #     xregs
    #   (padding)
    #   sgx_cpu_context_t: for backup - to align with the stack layout of cssa1_exception
    #   8 bytes :  for AEX handler usage - to align with the stack layout of cssa1_exception
    # --- stack may be non-contiguous as we may switch the stack to signal stack
    #   previous RBX
    #   previous RBP
    #   previous RIP: pushed by callq

    .cfi_startproc
    pushq %rbp
    .cfi_adjust_cfa_offset 8
    movq %rsp, %rbp
    .cfi_offset %rbp, -16
    .cfi_def_cfa_register %rbp
    pushq %rbx
    .cfi_offset %rbx, -24

    # Disable aex-notify before stack switch
    cmpq $0, %gs:SGX_READY_FOR_AEX_NOTIFY
    je 1f
    movq %gs:SGX_GPR, %rax
    cmpb $0, SGX_GPR_AEXNOTIFY(%rax)
    je 1f
    movb $0, SGX_GPR_AEXNOTIFY(%rax)
    movq $0x1, %gs:SGX_AEX_NOTIFY_FLAG  # set aexnotify_flag
1:
    CHECK_IF_SIGNAL_STACK_IS_USED %rsp, .Lon_signal_stack_ocall, .Lout_of_signal_stack_ocall

.Lout_of_signal_stack_ocall:
    movq %gs:SGX_SIG_STACK_HIGH, %rsp

.Lon_signal_stack_ocall:
    movl g_xsave_size(%rip), %eax
    # The reason we add the other SGX_CPU_CONTEXT_SIZE on the signal stack is to align with 
    # cssa1 exception layout. Consider the case that an interrupt happens during 
    # sgx_ocall/Lcssa0_ocall_return assembly code. It will trigger Lcssa1_exception_during_ocall_flows.
    # If AEX Notify is enabled, it requires a reserved cpu context in the mitigion code.
    addq $STACK_PADDING_SIZE + SGX_CPU_CONTEXT_SIZE, %rax
    subq %rax, %rsp
    andq $~(PAL_XSTATE_ALIGN - 1), %rsp

    pushq %rdx
    pushq %rdi
    movq %rsp, %rdi
    addq $2 * 8, %rdi      # adjust `pushq %rdx; pushq %rdi` above
    callq save_xregs
    popq %rdi
    popq %rdx

    movq 8(%rbp), %rax
    pushq %rax             # previous RIP
    pushfq

    # Under GDB, single-stepping sets Trap Flag (TP) of EFLAGS, thus TP=1 is stored on pushfq above.
    # Upon consequent popfq, TP is 1, resulting in spurious trap. Reset TP here.
    andq $~0x100, (%rsp)

    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rdi
    pushq %rsi
    movq (%rbp), %rax
    pushq %rax             # previous RBP
    leaq 16(%rbp), %rax
    pushq %rax             # previous RSP
    pushq %rbx
    pushq %rdx
    pushq %rcx
    pushq $0               # placeholder for RAX

    # OCALL_EXIT should never return (see sgx_ocall_exit(): it always exits the thread). Skip
    # setting SGX_PRE_OCALL_STACK to land in special-case of ECALL_THREAD_RESET (issued in
    # sgx_ocall_exit()) later. Note that if there is an interrupt (which usually would result in a
    # simulated return of -EINTR), it will be silently ignored via .Lcssa1_exception_eexit.
    cmpq $OCALL_EXIT, %rdi
    jne 1f
    movq $1, %gs:SGX_OCALL_EXIT_CALLED
    jmp .Lcssa0_ocall_eexit_prepare
1:

    movq %rsp, %gs:SGX_PRE_OCALL_STACK

.Lcssa0_ocall_eexit_prepare:
    # From here .Lcssa1_exception_determine_when can mess with our state (RIP and RSP).
    # We need to be extremely careful when making changes here.
    #
    # It's ok to use the untrusted stack and exit target below without checks since the processor
    # will ensure that after exiting enclave mode in-enclave memory can't be accessed.
1:
    movq %gs:SGX_USTACK, %rsp

#ifdef DEBUG
    # Push RIP of some code inside __morestack() on untrusted stack.
    leaq .Lfor_cfa_debug_info(%rip), %r8
    pushq %r8
#endif

    movq %gs:SGX_EXIT_TARGET, %rbx
    # fallthrough
    .cfi_endproc


    # Clear GPRs (other than below args), reset XSAVE area and call EEXIT
    #
    # Arguments for EEXIT/untrusted code (not cleared):
    #     RAX:       contains `EEXIT` code
    #     RBX:       exit target
    #     RSP:       untrusted stack
    #     RDI, RSI:  (optional) arguments to untrusted code
.Lcssa0_ocall_or_cssa1_exception_eexit:
    .cfi_startproc

    # Clear "extended" state (FPU aka x87, SSE, AVX, ...).
    #
    # g_pal_linuxsgx_state.enclave_info.attributes.xfrm will always be zero before init_enclave has
    # been called by pal_linux_main. So during early init nothing should use features not covered by
    # fxrstor, like AVX.
    cmpl $0, g_xsave_enabled(%rip)
    jne 1f
    fxrstor64 g_xsave_reset_state(%rip)
    jmp 2f
1:
    mov $0xffffffff, %eax
    mov %eax, %edx
    xrstor64 g_xsave_reset_state(%rip)
2:

#ifdef DEBUG
    # Store pointer to context in RDX, for the SGX profiler.
    movq %gs:SGX_PRE_OCALL_STACK, %rdx

    # Keep callee-saved registers in order to recover stack later (see
    # __morestack() below).
#else
    # In non-debug mode, clear these registers to prevent information leaks.
    xorq %rdx, %rdx
    xorq %rbp, %rbp
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15
#endif

    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    subq %r11, %r11  # use sub to set flags to a fixed value

    movq $EEXIT, %rax
    enclu
.Lcssa0_ocall_eexit_done:
    .cfi_endproc


.Lcssa0_ocall_return:
    # PAL convention:
    #   RDI - return value
    #   RSI - external event (if there is any)

    # restore the enclave (OCALL) stack
    movq %gs:SGX_PRE_OCALL_STACK, %rsp
    movq $0, %gs:SGX_PRE_OCALL_STACK
.Lcssa0_ocall_return_after_stack_restore:

    movq %rdi, SGX_CPU_CONTEXT_RAX(%rsp)     # return value of OCALL

    # restore FSBASE if necessary
    movq %gs:SGX_FSBASE, %rbx
    cmpq $0, %rbx
    je 1f
    .byte 0xf3, 0x48, 0x0f, 0xae, 0xd3       # WRFSBASE %RBX
1:
    # check if there was an event (async signal from host) during this OCALL
    cmpq $PAL_EVENT_NO_EVENT, %rsi
    je 1f
    cmpq $PAL_EVENT_NUM_BOUND, %rsi
    jb 2f

1:
    # check if it is ready to enable AEX-Notify
    cmpq $0, %gs:SGX_READY_FOR_AEX_NOTIFY
    je 1f
    # check if aexnotify is disabled during ocall-exit
    cmpq $0, %gs:SGX_AEX_NOTIFY_FLAG
    je 1f
    movq $0, %gs:SGX_AEX_NOTIFY_FLAG
    movq %gs:SGX_GPR, %rdi
    movb $0x1, SGX_GPR_AEXNOTIFY(%rdi)
1:
    # there was no event, simply call _restore_sgx_context(uc, xsave_area)
    movq %rsp, %rdi

    movq %rsp, %rsi
    addq $SGX_CPU_CONTEXT_SIZE, %rsi

    jmp _restore_sgx_context

2:
    # there was some event, call _PalHandleExternalEvent(event, uc, xregs_state)
    # Note we don't check AEX-Notify here. If we disable it during ocall-exit and 
    # the execution comes below code, the aex-notify will be enabled after event handling

    # clear the Alignment Check flag to prevent #AC-fault side channel
    pushfq
    andq $(~RFLAGS_AC), (%rsp)
    popfq

    # restore default in-enclave XSAVE area
    leaq g_xsave_reset_state(%rip), %rdi
    callq restore_xregs

    movq %rsi, %rdi                         # external event (1st arg)
    movq %rsp, %rsi                         # SGX context    (2nd arg)
    leaq SGX_CPU_CONTEXT_SIZE(%rsp), %rdx   # xregs_state    (3rd arg)
    callq _PalHandleExternalEvent
    FAIL_LOOP                               # cannot be reached


    # noreturn void _restore_sgx_context(sgx_cpu_context_t* uc, PAL_XREGS_STATE* xsave_area)
    #
    # Restore SGX context as generated by .Lcssa1_exception_determine_when.
    # Execution will continue as specified by RIP in the context.
    #
    # If RDI (uc) points into the signal stack we need to ensure that until the last read from
    # there RSP points there, or code in .Lcssa1_exception_during_enclave_run might mess with it
    # because it would think that the signal stack is not in use. In this case we assume that RSP
    # points into the signal stack when we get called.
    #
    # Also keep the redzone in mind, see asserts for sgx_cpu_context_t in sgx_arch.h.

    .global _restore_sgx_context
    .type _restore_sgx_context, @function
_restore_sgx_context:
    .cfi_startproc
    xchgq %rdi, %rsi
    callq restore_xregs

    movq %rsi, %r15

    movq SGX_CPU_CONTEXT_RAX(%r15), %rax
    movq SGX_CPU_CONTEXT_RCX(%r15), %rcx
    movq SGX_CPU_CONTEXT_RDX(%r15), %rdx
    movq SGX_CPU_CONTEXT_RBX(%r15), %rbx
    # For RSP see below
    movq SGX_CPU_CONTEXT_RBP(%r15), %rbp
    movq SGX_CPU_CONTEXT_RSI(%r15), %rsi
    movq SGX_CPU_CONTEXT_RDI(%r15), %rdi
    movq SGX_CPU_CONTEXT_R8(%r15), %r8
    movq SGX_CPU_CONTEXT_R9(%r15), %r9
    movq SGX_CPU_CONTEXT_R10(%r15), %r10
    movq SGX_CPU_CONTEXT_R11(%r15), %r11
    movq SGX_CPU_CONTEXT_R12(%r15), %r12
    movq SGX_CPU_CONTEXT_R13(%r15), %r13
    movq SGX_CPU_CONTEXT_R14(%r15), %r14
    # R15 will be restored below

    leaq SGX_CPU_CONTEXT_RFLAGS(%r15), %rsp
    popfq

    # See the comment at .Lcssa1_exception_during_enclave_run.
    #
    # The use of SGX_TMP_RIP (pal_enclave_tcb::tmp_rip per-enclave-thread field) must be atomic.
    # Consider a data race:
    #
    # (1) thread handles a previous exception in SSA=0,
    # (2) thread is done and returns from exception handler via restore_sgx_context(),
    # (3) in the middle of _restore_sgx_context() a new exception arrives,
    # (4) the exception handler for this new exception is prepared in SSA=1,
    # (5) thread returns back to SSA=0 and handles this new exception,
    # (6) thread is done and returns from exception handler via _restore_sgx_context() and updates
    #     SGX_TMP_RIP (overwrites pal_enclave_tcb::tmp_rip). Now the thread returned in the middle
    #     of _restore_sgx_context() and will try to `jmp *%gs:SGX_TMP_RIP` but this value is lost,
    #     and SIGILL/SEGFAULT follows.
    #
    # The last 4 instructions that restore RIP, RSP and R15 (needed as tmp reg) need to be atomic
    # wrt .Lcssa1_exception_during_enclave_run.
    #
    # The reason is that .Lcssa1_exception_during_enclave_run can interrupt us in the middle and the
    # nested exception handler that it injects would mess with GS:SGX_TMP_RIP when it calls us to
    # return (GS:SGX_TMP_RIP is a single memory location per thread, so not re-entry save).
    #
    # Since they are not atomic, .Lcssa1_exception_during_enclave_run will emulate this behavior if
    # it gets called while executing them (see there).

    # RSP points to RIP so need relative addressing to restore RIP, R15, and RSP
    movq SGX_CPU_CONTEXT_RIP - SGX_CPU_CONTEXT_RIP(%rsp), %r15
    movq %r15, %gs:SGX_TMP_RIP
.Lrestore_sgx_context_inst0:
    movq SGX_CPU_CONTEXT_R15 - SGX_CPU_CONTEXT_RIP(%rsp), %r15
.Lrestore_sgx_context_inst1:
    movq SGX_CPU_CONTEXT_RSP - SGX_CPU_CONTEXT_RIP(%rsp), %rsp
.Lrestore_sgx_context_inst2:
    jmp *%gs:SGX_TMP_RIP
    .cfi_endproc


    # void __save_xregs(PAL_XREGS_STATE* xsave_area)
    #
    #   RDI: argument: pointer to xsave_area
    #   R11: return address: in order to not touch stack (sometimes stack is not available)
    #   RAX, RDX: clobbered

    .global __save_xregs
    .type __save_xregs, @function
__save_xregs:
    .cfi_startproc
    movl g_xsave_enabled(%rip), %eax
    cmpl $0, %eax
    jz 1f

    # clear XSAVE area header
    movq $0, XSAVE_HEADER_OFFSET + 0 * 8(%rdi)
    movq $0, XSAVE_HEADER_OFFSET + 1 * 8(%rdi)
    movq $0, XSAVE_HEADER_OFFSET + 2 * 8(%rdi)
    movq $0, XSAVE_HEADER_OFFSET + 3 * 8(%rdi)
    movq $0, XSAVE_HEADER_OFFSET + 4 * 8(%rdi)
    movq $0, XSAVE_HEADER_OFFSET + 5 * 8(%rdi)
    movq $0, XSAVE_HEADER_OFFSET + 6 * 8(%rdi)
    movq $0, XSAVE_HEADER_OFFSET + 7 * 8(%rdi)

    movl $0xffffffff, %eax
    movl $0xffffffff, %edx
    xsave64 (%rdi)
    jmp *%r11
1:
    fxsave64 (%rdi)
    jmp *%r11
    .cfi_endproc


    # void save_xregs(PAL_XREGS_STATE* xsave_area)

    .global save_xregs
    .type save_xregs, @function
save_xregs:
    .cfi_startproc
    popq %r11
    jmp __save_xregs
    .cfi_endproc


    # void __restore_xregs(const PAL_XREGS_STATE* xsave_area)
    #
    #   RDI: argument: pointer to xsave_area
    #   R11: return address: in order to not touch stack (sometimes stack is not available)
    #   RAX, RDX: clobbered

    .global __restore_xregs
    .type __restore_xregs, @function
__restore_xregs:
    .cfi_startproc
    movl g_xsave_enabled(%rip), %eax
    cmpl $0, %eax
    jz 1f

    movl $0xffffffff, %eax
    movl $0xffffffff, %edx
    xrstor64 (%rdi)
    jmp *%r11
1:
    fxrstor64 (%rdi)
    jmp *%r11
    .cfi_endproc


    # void restore_xregs(const PAL_XREGS_STATE* xsave_area)

    .global restore_xregs
    .type restore_xregs, @function
restore_xregs:
    .cfi_startproc
    popq %r11
    jmp __restore_xregs
    .cfi_endproc


#ifdef DEBUG
    # CFI "trampoline" to make GDB happy. GDB normally does not handle switching stack in the middle
    # of backtrace (which is what happens when we exit the enclave), unless the function doing it is
    # called __morestack.
    #
    # To make GDB backtrace work, we make sure that the first function outside of enclave
    # (sgx_entry) has a return address on stack, pointing inside __morestack. We will not actually
    # return to this function (sgx_entry performs EENTER to go back to enclave), but GDB will make a
    # stack frame for it.
    #
    # The function contains CFI directives to make sure that all callee-saved registers can be
    # recovered. They should reflect the situation during EEXIT in code above.

    .global __morestack
    .type __morestack, @function
__morestack:
    .cfi_startproc

    # Callee-saved registers:

    # RIP, RSP: deduced from current RBP (which was not cleared in debug mode)
    .cfi_def_cfa %rbp, 16

    # RBP, RBX: saved on stack (at the beginning of sgx_ocall)
    .cfi_offset %rbp, -16
    .cfi_offset %rbx, -24

    # R12, R13, R14, R15: not changed (not cleared in debug mode)

    nop
.Lfor_cfa_debug_info:
    nop

    .cfi_endproc
#endif

    # noreturn void _apply_mitigation_and_restore_sgx_context(sgx_cpu_context_t* uc, PAL_XREGS_STATE* xsave_area, 
    #                                                         uintptr_t stp, uintptr_t dtp, uintptr_t ctp, uintptr_t c3_byte_address);
    # Inputs:
    #     rdi - uc
    #     rsi - xsave_area
    #     rdx - stack_tickle_pages
    #     rcx - data_tickle_pages
    #     r8 -  code_tickle_page
    #     r9 -  c3 byte address
    #
    # This function will  apply the AEX mitigation, restore the cpu context and continue execution.
    .global _apply_mitigation_and_restore_sgx_context
    .type _apply_mitigation_and_restore_sgx_context, @function
_apply_mitigation_and_restore_sgx_context:
    .cfi_startproc

    movq %rdx, %rbx
    # restore xregs firstly
    xchgq %rdi, %rsi   # rsi - uc, rdi - xsave_area
    callq restore_xregs    
    movq %rbx, %rdx

    movq %rsi, %r15
    addq g_xsave_size(%rip), %r15
    addq $PAL_FP_XSTATE_MAGIC2_SIZE + SGX_CPU_CONTEXT_SIZE, %r15 # rsi - uc, r15 - reserved uc

    movq %r15, %rax
    addq $SGX_CPU_CONTEXT_SIZE + 8, %rax
    movq %rax, %rsp

    # increase aexcounter
    lock incq %gs:SGX_AEX_COUNTER

    movq SGX_CPU_CONTEXT_RIP(%rsi), %rax

    movq SGX_CPU_CONTEXT_RSP(%rsi), %r10   # r10 - uc.rsp

    # Check whether the last AEX occurred during the mitigation
    cmpb $0xc3, (%rax)             # ZF=1 if interrupted c3 (ret)
    jnz .Lct_check_aex_in_mitigation

    # If ip = ret, check whether sp is on the sig_stack. If yes, it means the mitigation may 
    # occur during the call instruction in mitigation handler. In this case, retrieve the IP from stack.
    # uc.rsp may not be accessable in some case. So we add the check before access it.
    CHECK_IF_SIGNAL_STACK_IS_USED %r10, .Lct_retrieve_ip, .Lct_check_aex_in_mitigation
.Lct_retrieve_ip:
    movq (%r10), %rax   # rax: irq c3? caller rip : pre-irq rip
    
.Lct_check_aex_in_mitigation:
    lea __ct_mitigation_end(%rip), %rbx
    subq %rax, %rbx
    cmpq $(__ct_mitigation_end - __ct_mitigation_begin + 1), %rbx
    # CMP will set CF=1 (B) if the mitigation was interrupted, CF=0 (NB) otherwise
    # If the mitigation was interrupt, restore the SP from reserved cpu context. Reason is we 
    # change the SP to save the return IP in the mitigation process. So we need to correct the
    # SP if the mitigation was interrupt
    cmovb SGX_CPU_CONTEXT_RSP(%r15), %r10
  
    movq %r10, SGX_CPU_CONTEXT_RSP(%r15)

    # If the mitigation was interrupted, restore the interrupted IP from the reserved cpu context
    movq SGX_CPU_CONTEXT_RIP(%rsi), %rbx
    cmovb SGX_CPU_CONTEXT_RIP(%r15), %rbx
    movq %rbx, SGX_CPU_CONTEXT_RIP(%r15)  # save the IP to reserved_uc->ip

    # Copy RFLAGS onto the reserved stack area
    movq SGX_CPU_CONTEXT_RFLAGS(%rsi), %rax
    movq %rax, SGX_CPU_CONTEXT_RFLAGS(%r15)

    # If the mitigation was interrupted, restore tickle parameters (rdx, rcx, r8, r9) from the the reserved cpu context.
    cmovb SGX_CPU_CONTEXT_R10(%r15), %rdx
    cmovb SGX_CPU_CONTEXT_R11(%r15), %rcx
    cmovb SGX_CPU_CONTEXT_R8(%r15), %r8
    cmovb SGX_CPU_CONTEXT_R9(%r15), %r9

    movq %rdx, SGX_CPU_CONTEXT_R10(%r15) # save rdx to reserved_uc->r10 (stack tickle pages)
    movq %rcx, SGX_CPU_CONTEXT_R11(%r15) # save rcx to reserved_uc->r11 (data tickle page)
    movq %r8, SGX_CPU_CONTEXT_R8(%r15)   # code tickle page
    movq %r9, SGX_CPU_CONTEXT_R9(%r15)   # c3 byte address

    # If the mitigation was not interrupted (the interrupt occured in the main flow),
    # then restore the registers from cpu context
    movq SGX_CPU_CONTEXT_RAX(%rsi), %rax
    cmovb SGX_CPU_CONTEXT_RAX(%r15), %rax
    movq %rax, SGX_CPU_CONTEXT_RAX(%r15) 

    movq SGX_CPU_CONTEXT_RCX(%rsi), %rcx
    movq SGX_CPU_CONTEXT_RDX(%rsi), %rdx
    movq SGX_CPU_CONTEXT_RBX(%rsi), %rbx
    movq SGX_CPU_CONTEXT_RBP(%rsi), %rbp
    movq SGX_CPU_CONTEXT_RDI(%rsi), %rdi
    movq SGX_CPU_CONTEXT_R8(%rsi), %r8
    movq SGX_CPU_CONTEXT_R9(%rsi), %r9
    movq SGX_CPU_CONTEXT_R10(%rsi), %r10    
    movq SGX_CPU_CONTEXT_R11(%rsi), %r11
    movq SGX_CPU_CONTEXT_R12(%rsi), %r12
    movq SGX_CPU_CONTEXT_R13(%rsi), %r13
    movq SGX_CPU_CONTEXT_R14(%rsi), %r14 
    # use rax to save r15  
    movq SGX_CPU_CONTEXT_R15(%rsi), %rax

    movq SGX_CPU_CONTEXT_RSI(%rsi), %rsi
    # If the mitigation was interrupted, restore registers from reserved cpu context
    # rax has been handled above
    cmovb SGX_CPU_CONTEXT_RCX(%r15), %rcx
    cmovb SGX_CPU_CONTEXT_RDX(%r15), %rdx
    cmovb SGX_CPU_CONTEXT_RBX(%r15), %rbx
    cmovb SGX_CPU_CONTEXT_RBP(%r15), %rbp
    cmovb SGX_CPU_CONTEXT_RSI(%r15), %rsi
    cmovb SGX_CPU_CONTEXT_RDI(%r15), %rdi
    cmovb SGX_CPU_CONTEXT_R15(%r15), %rax

    movq %rcx, SGX_CPU_CONTEXT_RCX(%r15)
    movq %rdx, SGX_CPU_CONTEXT_RDX(%r15)
    movq %rbx, SGX_CPU_CONTEXT_RBX(%r15)
    movq %rbp, SGX_CPU_CONTEXT_RBP(%r15)
    movq %rdi, SGX_CPU_CONTEXT_RDI(%r15)
    movq %rsi, SGX_CPU_CONTEXT_RSI(%r15)
    movq %rax, SGX_CPU_CONTEXT_R15(%r15)   
  
    # Restore tickle addresses
    movq SGX_CPU_CONTEXT_R8(%r15), %rsi  # code tickle page
    movq SGX_CPU_CONTEXT_R9(%r15), %rdi  # c3 byte address
    movq SGX_CPU_CONTEXT_R10(%r15), %rbp # stack tickle pages
    movq SGX_CPU_CONTEXT_R11(%r15), %rdx # data tickle page

    # Setup the stack tickles
    shrb $1, %bpl # Bit 0 in %rbp indicates whether a second stack page can be tickled
    movq %rbp, %rbx
    jnc 1f
    subq $0x1000, %rbx

1:
    # Restore rflags
    leaq SGX_CPU_CONTEXT_RFLAGS(%r15), %rax   # these are stored in the sig_stack as the cpu_context
    xchg %rax, %rsp
    popfq
    xchg %rax, %rsp
    # NOTHING AFTER THIS POINT CAN MODIFY EFLAGS/RFLAGS

################################################################################
# BEGIN MITIGATION CODE
################################################################################

#define MITIGATION_CODE_ALIGNMENT 0x200
.align MITIGATION_CODE_ALIGNMENT

# Enable AEX Notify
.ct_enable_aexnotify:
    # Before apply mitigation, enable aex_notify first
    movq %gs:SGX_GPR, %rax
    movb $0x1, SGX_GPR_AEXNOTIFY(%rax)

    .global __ct_mitigation_begin
__ct_mitigation_begin:
    lfence

.ct_check_write:
    movl    $63, %ecx
    shlx    %rcx, %rsi, %rcx # Bit 0 in %rsi indicates whether data_tickle_address can be written
    jrcxz   .ct_clear_low_bits_of_rdx
    lea     -1(%rsi), %rsi   # Clear bit 0 in %rsi
    movb    (%rdx), %al
    movb    %al, (%rdx)      # Will fault if the data page is not writable

.ct_clear_low_bits_of_rdx:
    movl    $12, %ecx
    shrx    %rcx, %rdx, %rdx
    shlx    %rcx, %rdx, %rdx

.ct_check_execute:
    call    *%rdi

# Load all working set cache lines and warm the TLB entries
    mov     $0x1000, %ecx
.align 0x10
.ct_warm_caches_and_tlbs:
    lea     -0x40(%ecx), %ecx
    mov     (%rsi, %rcx), %eax
    mov     (%rbp, %rcx), %eax
    mov     (%rbx, %rcx), %eax
    mov     (%rdx, %rcx), %eax
    jrcxz   .ct_restore_state
    jmp     .ct_warm_caches_and_tlbs # loops 64 times

.ct_restore_state:
    # Bit 4 of %sil indicates whether cycles should be added
    movzx   %sil, %ecx
    movq SGX_CPU_CONTEXT_RDI(%r15), %rdi
    movq SGX_CPU_CONTEXT_RSI(%r15), %rsi
    movq SGX_CPU_CONTEXT_RBP(%r15), %rbp
    movq SGX_CPU_CONTEXT_RBX(%r15), %rbx
    movq SGX_CPU_CONTEXT_RDX(%r15), %rdx
    movq SGX_CPU_CONTEXT_RAX(%r15), %rax

# Inject random cycle noise
    jrcxz  .ct_restore_rcx
    CYCLE_DELAY 20, %rsp

.ct_restore_rcx:
    movq SGX_CPU_CONTEXT_RCX(%r15), %rcx

    movq SGX_CPU_CONTEXT_RIP(%r15), %rsp
    movq %rsp, %gs:SGX_TMP_RIP
 .Lct_restore_sgx_context_inst0:
    movq SGX_CPU_CONTEXT_RSP(%r15), %rsp
    movq SGX_CPU_CONTEXT_R15(%r15), %r15
  __ct_mitigation_end:
    jmp *%gs:SGX_TMP_RIP

   .cfi_endproc


.global __ct_mitigation_ret
__ct_mitigation_ret:
    ret

.ct_aexnotify_end:

.sect   _to_be_discarded, "e", @nobits
.space MITIGATION_CODE_ALIGNMENT - (.ct_aexnotify_end - .ct_enable_aexnotify)
.previous
