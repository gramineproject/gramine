; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation
;                    Borys Popławski <borysp@invisiblethingslab.com>

global probe_stack
section .text

; void probe_stack(size_t pages_count)
probe_stack:
    mov rcx, rdi
    mov rdi, rsp

.Lrep:
    sub rsp, 0x1000
    or QWORD [rsp], 0
    loop .Lrep

    mov rsp, rdi
    ret
