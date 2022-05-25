; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

; This test verifies that the system call layer doesn't change the value
; of R12-R15, RBX, and RBP. It also indirectly confirms that
; the RSP register has not changed. AMD64 ABI document defines this behavior.
; This test uses the getpid(2) syscall, as this syscall is very simple and
; shouldn't introduce significant overhead and overcomplication.
; This function uses stack above rsp so this test can never use signal handlers.

extern    test_exit
global    _start

%define   __NR_getpid   39

section   .text

; bool check_registers_after_getpid(uint64_t val)
; 1/true - test passed
; 0/false - something is wrong with registers
check_registers_after_getpid:
    push  rbp
    mov   rbp, rdi
    mov   rbx, rdi
    mov   r12, rdi
    mov   r13, rdi
    mov   r14, rdi
    mov   r15, rdi

    push  rdi
    mov   rax, __NR_getpid
    syscall
    pop   rdi
    mov   rax, 1
    xor   rsi, rsi

    cmp   rbp, rdi
    sete  sil
    and   rax, rsi

    cmp   rbx, rdi
    sete  sil
    and   rax, rsi

    cmp   r12, rdi
    sete  sil
    and   rax, rsi

    cmp   r13, rdi
    sete  sil
    and   rax, rsi

    cmp   r14, rdi
    sete  sil
    and   rax, rsi

    cmp   r15, rdi
    sete  sil
    and   rax, rsi

    pop   rbp
    ret

_start:
    mov  rdi, 0x0A
    call check_registers_after_getpid
    mov  rdi, 1
    cmp  rax, 0
    je   test_exit

    ; Verify that it's not set to 10 by syscall.
    mov  rdi, 0x9987654321ABCDEF
    call check_registers_after_getpid
    mov  rdi, rax
    xor  rdi, 1
    jmp  test_exit
