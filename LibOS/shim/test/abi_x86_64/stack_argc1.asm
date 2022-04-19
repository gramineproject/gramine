; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

; First value on stack should point to argument count.

extern    gramine_exit

global    _start

section   .text

_start:
    mov   rdi, [rsp]
    xor   rdi, 1

    jmp   gramine_exit
