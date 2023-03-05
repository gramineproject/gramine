; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2023 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
;

extern  test_exit

global  _start

section .text

%define NEW_RSP_VALUE   0x8811223344556677

; Turn on all EFLAGS.
; ABI x86_64 defines which are set and which are not.
; Please refer to x86_64 abi test for more details.
; In this test we set all of them.
%define NEW_RFLAGS      0xFDF

check_rflags:
    pushfq
    pop     rdi
    xor     rdi, NEW_RFLAGS
    jnz     test_exit
    ret

test_rflags:
    mov     rax, rsp
    mov     rdx, ss            ; ss register can't change
    push    rdx
    push    rax                ; new rsp
    push    NEW_RFLAGS         ; new rflags
    mov     rdx, cs            ; cs register can't change
    push    rdx
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
                               ; this tests sets rsp to garbage value
    mov     rdx, ss
    push    rdx                ; ss register can't change
    mov     rdx, NEW_RSP_VALUE ; new rsp
    push    rdx
    push    0x00               ; new rflags
    mov     rdx, cs            ; cs register can't change
    push    rdx
    push    check_rsp          ; new rip
    iretq

_start:
    call    test_rflags
    call    test_rsp
    xor     rdi, rdi
    jmp     test_exit
