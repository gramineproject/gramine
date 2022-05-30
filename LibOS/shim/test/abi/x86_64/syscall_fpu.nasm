; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

; This test verifies that the system call layer doesn't change x87 unit flags.
; AMD64 ABI document defines this behavior. This test uses the getpid(2)
; syscall, as this syscall is very simple and shouldn't introduce significant
; overhead and overcomplication. The goal is to test the common part of the
; syscall layer.
; The x87 FPU Control Word register:
; +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
; | R| R| R| X|   RC|   PC| R| R|PM|UM|OM|ZM|DM|IM|
; +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
; 5 bits in x87 FPU flags are reserved.
; The reserved bits are marked with the letter 'R'.
; This check function uses stack above rsp so this test can never use
; signal handlers.

extern    test_exit
global    _start

%define   __NR_getpid   39

section   .text

; bool check_fpu_after_getpid(uint64_t fpuvalue)
; 1/true - test passed
; 0/false - something is wrong with FPU word
check_fpu_after_getpid:
    push  rbp
    mov   rbp, rsp

    mov   [rbp - 0x8], rdi
    fldcw [rbp - 0x8]

    mov   rax, __NR_getpid
    syscall
    xor   rax, rax

    fstcw [rbp - 0x10]
    mov   rdi, [rbp - 0x10]
    cmp   rdi, [rbp - 0x8]
    sete  al

    pop   rbp
    ret

_start:
    mov  rdi, 0xF
    call check_fpu_after_getpid
    mov  rdi, 1
    cmp  rax, 0
    je   test_exit

    ; Make sure syscall has not set the FPU unit to the value from the previous
    ; test.
    mov  rdi, 0x0
    call check_fpu_after_getpid
    mov  rdi, rax
    xor  rdi, 1
    jmp  test_exit
