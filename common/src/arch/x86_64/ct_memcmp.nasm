; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation

; Constant-time buffer comparison without branches

global ct_memcmp

; int ct_memcmp(const void* lhs, const void* rhs, size_t count)
; Arguments:
; - RDI: Pointer to the first buffer (lhs)
; - RSI: Pointer to the second buffer (rhs)
; - RDX: The number of bytes to compare in the buffer (count)
ct_memcmp:
        mov     ecx, 0
        test    rdx, rdx
        jz      .L2
        add     rdx, rdi
.L1:    movzx   eax, byte [rdi]
        movzx   r8d, byte [rsi]
        add     rdi, 1
        add     rsi, 1
        xor     eax, r8d
        or      ecx, eax
        cmp     rdi, rdx
        jnz     .L1
.L2:    mov     eax, ecx
        ret
