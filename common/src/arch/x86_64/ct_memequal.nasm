; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation

; Constant-time buffer comparison

global ct_memequal

section .text

; bool ct_memequal(const void* lhs, const void* rhs, size_t count)
; Arguments:
; - RDI: Pointer to the first buffer (lhs)
; - RSI: Pointer to the second buffer (rhs)
; - RDX: The number of bytes to compare in the buffer (count)
ct_memequal:
    mov     ecx, 0
    test    rdx, rdx
    jz      .return
    add     rdx, rdi
.loop:
    movzx   eax, byte [rdi]
    movzx   r8d, byte [rsi]
    add     rdi, 1
    add     rsi, 1
    xor     eax, r8d        ; using bitwise operation rather than a branch
    or      ecx, eax
    cmp     rdi, rdx
    jnz     .loop
.return:
    mov     eax, ecx
    test    al, al
    sete    al
    ret
