/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation */

.global ct_memcmp
.type ct_memcmp, @function
.align 0x10
ct_memcmp:
    .cfi_startproc

    # Arguments:
    #   RDI: Pointer to the first buffer (lhs)
    #   RSI: Pointer to the second buffer (rhs)
    #   RDX: The number of bytes to compare in the buffer (count)

    movb   $0x0, -0x1(%rsp)
    test   %rdx, %rdx
    je     .L2
    add    %rdi, %rdx
.L1:
    movzbl (%rdi), %eax
    movzbl (%rsi), %r8d
    add    $0x1, %rdi
    add    $0x1, %rsi
    movzbl -0x1(%rsp), %ecx
    xor    %r8d, %eax
    or     %ecx, %eax
    mov    %al, -0x1(%rsp)
    cmp    %rdx, %rdi
    jne    .L1
.L2:
    movzbl -0x1(%rsp), %eax
    ret
    .cfi_endproc
