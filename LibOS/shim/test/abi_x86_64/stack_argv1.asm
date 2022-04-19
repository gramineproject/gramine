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
    lea   rdi, [argv0]
    mov   rsi, [rsp + 8 * 1]
    call  gramine_strcmp
    mov   rdi, rax
    jmp   gramine_exit

section   .data

argv0    db    "stack_argv1", 0x00
