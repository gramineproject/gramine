; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2023 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
;

extern  test_exit

global  _start

section .text

%define NEW_RSP_VALUE   0x8811223344556677

; Turn on all EFLAGS.
; x86_64 ABI defines which flags are set and which are not on
; process startup. Please refer to x86_64 ABI test for more details.
; In this test we set all of them, besides TF (trap flag),
; which would cause an exception later.
%define NEW_RFLAGS      0xED7

check_rflags:
    pushfq
    pop     rdi
    xor     rdi, NEW_RFLAGS
    jnz     test_exit
    ret

test_rflags:
    mov     rax, rsp
    mov     rdx, ss            ; this test doesn't change ss, because
    push    rdx                ; Gramine doesn't support doing this through iret
    push    rax                ; new rsp
    push    NEW_RFLAGS         ; new rflags
    mov     rdx, cs            ; this test doesn't change cs, because
    push    rdx                ; Gramine doesn't support doing this through iret
    push    check_rflags       ; new rip
    iretq

check_rsp:
    ; We can't use stack until restored.
    mov     rdi, rsp
    mov     rsp, rax            ; restore stack value from rax,
                                ; it was assigned in `test_rsp` first instruction
    mov     rax, NEW_RSP_VALUE
    xor     rdi, rax
    jnz     test_exit
    ret

test_rsp:
    mov     rax, rsp           ; store current rsp in rax,
                               ; this test sets rsp to garbage value
    mov     rdx, ss            ; this test doesn't change ss, because
    push    rdx                ; Gramine doesn't support doing this through iret
    mov     rdx, NEW_RSP_VALUE ; new rsp
    push    rdx
    push    0x00               ; new rflags
    mov     rdx, cs            ; this test doesn't change cs, because
    push    rdx                ; Gramine doesn't support doing this through iret
    push    check_rsp          ; new rip
    iretq

_start:
    call    test_rflags
    call    test_rsp
    xor     rdi, rdi
    jmp     test_exit
