; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2023 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
;

extern  test_exit

global  _start

section .text

%define NEW_RSP_VALUE   0x8811223344556677
%define NEW_RFLAGS      0xED7

check_rflags:
    pushfq
    pop     rdi
    xor     rdi, NEW_RFLAGS
    jnz     test_exit
    ret

test_rflags:
    mov     rax, rsp
    mov     rdx, ss            ; new ss, can't change
    push    rdx
    push    rax                ; new rsp
    push    NEW_RFLAGS         ; new rflags
    mov     rdx, cs            ; new cs, can't change
    push    rdx
    push    check_rflags       ; new rip
    iretq

check_rsp:
    mov     rdi, rsp
    mov     rsp, rax
    mov     rax, NEW_RSP_VALUE
    xor     rdi, rax
    jnz     test_exit
    ret

test_rsp:
    mov     rax, rsp
    mov     rdx, ss
    push    rdx                ; new ss, can't change
    mov     rdx, NEW_RSP_VALUE ; new rsp
    push    rdx
    push    0x00               ; new rflags
    mov     rdx, cs            ; new cs, can't change
    push    rdx
    push    check_rsp          ; new rip
    iretq

_start:
    call    test_rflags
    call    test_rsp
    xor     rdi, rdi
    jmp     test_exit
