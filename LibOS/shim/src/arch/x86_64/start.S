/* Our PAL loader invokes this entrypoint with all registers unspecified, except %rsp:
 *
 *   %rsp                  The stack contains the arguments and environment:
 *   0(%rsp)               argc
 *   8(%rsp)               argv[0]
 *   16(%rsp)              argv[1]
 *   ...
 *   (8*(argc+1))(%rsp)    argv[argc] = NULL
 *   (8*(argc+2))(%rsp)    envp[0]
 *   (8*(argc+3))(%rsp)    envp[1]
 *   ...
 *   (8*(argc+n+2))(%rsp)  envp[n] = NULL
 *   (8*(argc+n+3))(%rsp)  auxv[0] = AT_NULL
 *
 * For details on the PAL loader, see Pal/src/db_rtld.c: start_execution()
 */

    .text
    .globl shim_start
    .type shim_start,@function
shim_start:
    .cfi_startproc

    # Clear the frame pointer. The ABI suggests this be done, to mark
    # the outermost frame obviously.
    xorq %rbp, %rbp

    # Arguments for shim_init:
    movq 0(%rsp), %rdi         # argc
    leaq 8(%rsp), %rsi         # argv
    leaq 8(%rsi,%rdi,8), %rdx  # envp, after all args (including argv[argc] = NULL)

    # Required by System V AMD64 ABI.
    andq  $~0xF, %rsp

    callq *shim_init@GOTPCREL(%rip)

    .cfi_endproc
