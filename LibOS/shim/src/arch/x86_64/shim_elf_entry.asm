; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

; The System V ABI (see section 3.4.1) expects us to set the following before jumping to the entry
; point:
;
; - RDX: function pointer to be registered with `atexit` (we pass 0)
; - RSP: the initial stack, contains program arguments and environment
; - FLAGS: should be zeroed out

global    call_elf_entry

call_elf_entry:
    xor     rdx, rdx ; set RDX to 0
    push    0
    popf             ; set lower part of rFLAGS to 0
    mov     rsp, rsi ; set stack pointer to secend arg
    mov     rax, rdi ; jmp to entry point (first arg)
    jmp     rax
