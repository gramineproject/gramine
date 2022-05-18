; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

; This test verifies that the system call layer doesn't change the value
; of R12-R15, RBX, and RBP. It also indirectly confirms that
; the RSP register has not changed. AMD64 ABI document defines this behavior.
; Additionally, this test verifies the persistence of these registers: RDX, RDI,
; R8-R10 and RSI. This test uses the getpid(2) syscall, as this syscall is very
; simple and shouldn't introduce significant overhead and overcomplication.

extern    test_exit
global    _start

%define   __NR_getpid   39

section   .text

; bool check_registers_after_getpid(uint64_t val)
; 1/true - test passed
; 0/false - something is wrong with registers
check_registers_after_getpid:
    mov   rbp, rdi
    mov   rbx, rdi
    mov   rdx, rdi
    mov   rsi, rdi
    mov   r8, rdi
    mov   r9, rdi
    mov   r10, rdi
    mov   r12, rdi
    mov   r13, rdi
    mov   r14, rdi
    mov   r15, rdi

    push  rdi
    mov   rax, __NR_getpid
    syscall
    pop   rcx
    xor   rax, rax

    cmp   rsi, rcx
    sete  al
    xor   rsi, rsi

    cmp   rbp, rcx
    sete  sil
    and   rax, rsi

    cmp   rbx, rcx
    sete  sil
    and   rax, rsi

    cmp   rdx, rcx
    sete  sil
    and   rax, rsi

    cmp   r8, rcx
    sete  sil
    and   rax, rsi

    cmp   r9, rcx
    sete  sil
    and   rax, rsi

    cmp   r10, rcx
    sete  sil
    and   rax, rsi

    cmp   r12, rcx
    sete  sil
    and   rax, rsi

    cmp   r13, rcx
    sete  sil
    and   rax, rsi

    cmp   r14, rcx
    sete  sil
    and   rax, rsi

    cmp   r15, rcx
    sete  sil
    and   rax, rsi

    ret

_start:
    mov  rdi, 0x0A
    call check_registers_after_getpid
    mov  rdi, 1
    cmp  rax, 0
    je   test_exit

    ; Verify that it's not set to 10 by syscall.
    mov  rdi, 0x1987654321ABCDEF
    call check_registers_after_getpid
    mov  rdi, rax
    xor  rdi, 1
    jmp  test_exit
