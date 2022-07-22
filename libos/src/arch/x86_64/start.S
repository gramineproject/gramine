/* Our PAL loader invokes this entrypoint with all registers unspecified, except %rsp.
 * For detailed description of the stack layout see pal/src/pal_rtld.c:start_execution().
 */

    .text
    .globl libos_start
    .type libos_start,@function
libos_start:
    .cfi_startproc

    # Clear the frame pointer. The ABI suggests this be done, to mark
    # the outermost frame obviously.
    xorq %rbp, %rbp

    # Arguments for libos_init:
    movq 0(%rsp), %r8          # argc, unused by libos_init, used to calculate location of envp
    leaq 8(%rsp), %rdi         # argv
    leaq 8(%rdi,%r8,8), %rsi   # envp, after all args (including argv[argc] = NULL)

    # Required by System V AMD64 ABI.
    andq  $~0xF, %rsp

    callq *libos_init@GOTPCREL(%rip)

    .cfi_endproc
