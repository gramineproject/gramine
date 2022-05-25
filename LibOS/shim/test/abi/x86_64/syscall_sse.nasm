; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

; This test verifies that the system call layer doesn't change SSE values.
; AMD64 ABI document defines this behavior. The goal is to test the common part
; of the syscall layer. This test uses the getpid(2) syscall, as this syscall is
; very simple and shouldn't introduce significant overhead and overcomplication.
; The test uses the FXSAVE operand to get the current state of XMM registers.
; The XMM registers are saved on bytes from 160 to 415. It also verifies
; the MXCSR register. Thie check function uses stack above rsp so this
; test can never use signal handlers.

default   rel

extern    test_exit
global    _start

%define   __NR_getpid   39

section   .text

; bool check_sse_after_getpid()
; 1/true - test passed
; 0/false - something is wrong with SSE
check_sse_after_getpid:
    push      rbp
    mov       rbp, rsp

    fxsave64  [rbp - 0x200]
    stmxcsr   [rbp - 0x400]

    mov       rax, __NR_getpid
    syscall
    xor       rax, rax

    fxsave64  [rbp - 0x400]
    lea       rsi, [rbp - 0x100 + 0xA0]
    lea       rdi, [rbp - 0x200 + 0xA0]
    mov       rcx, 256
    repe      cmpsb
    ; The ZF will be cleared if there is a mismatch.
    setz      al

    stmxcsr   [rbp - 1032]
    mov       esi, [rbp - 1028]
    cmp       esi, [rbp - 1032]
    setz      dil

    and       al, dil

    pop       rbp
    ret

_start:
    call check_sse_after_getpid
    mov  rdi, 1
    cmp  rax, 0
    je   test_exit

    ; Verify that it's not initialized to default values.
    mov  rax, 0x9987654321ABCDEF
    movq xmm0, rax
    movq xmm1, rax
    movq xmm2, rax
    movq xmm3, rax
    movq xmm4, rax
    movq xmm5, rax
    movq xmm6, rax
    movq xmm7, rax
    movq xmm8, rax
    movq xmm9, rax
    movq xmm10, rax
    movq xmm11, rax
    movq xmm12, rax
    movq xmm13, rax
    movq xmm14, rax
    movq xmm15, rax
    ldmxcsr [mxcsr_test_val]

    call check_sse_after_getpid
    mov  rdi, rax
    xor  rdi, 1
    jmp  test_exit

section   .data

; The mxcsr it not 0 at the entry of the binary, so we can us 0 as
; 0 as test data here (the mxcsr.nasm test verifies that).
mxcsr_test_val      db    0x00
