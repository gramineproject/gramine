; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

; Verify argv which should be in rsp + 8.

default   rel

extern    gramine_exit
extern    gramine_strcmp

global    _start

section   .text

_start:
    mov   rbp, rsp
    sub   rsp, 0x20         ; Try to not override argv and argc.
                            ; It may be overrided by calling gramine_strcmp.

    mov   rdi, [rsp]        ; Verify argc
    cmp   rdi, 3
    jne   gramine_exit

    lea   rdi, [argv0]      ; Verify argv[0]
    mov   rsi, [rbp + 8 * 1]
    call  gramine_strcmp
    mov   rdi, rax
    cmp   rdi, 1
    je    gramine_exit

    lea   rdi, [argv1]      ; Verify argv[1]
    mov   rsi, [rbp + 8 * 2]
    call  gramine_strcmp
    mov   rdi, rax
    cmp   rdi, 1
    je    gramine_exit

    lea   rdi, [argv2]      ; Verify argv[2]
    mov   rsi, [rbp + 8 * 3]
    call  gramine_strcmp
    mov   rdi, rax
    cmp   rdi, 1
    je    gramine_exit

    lea   rdi, [argv3]      ; Verify argv[3]
    mov   rsi, [rbp + 8 * 4]
    call  gramine_strcmp
    mov   rdi, rax
    jmp   gramine_exit

section   .data

argv0    db    "stack_arg", 0x00
argv1    db    "foo", 0x00
argv2    db    "bar", 0x00
argv3    db    0x00
