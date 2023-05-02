; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation
;                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

; The System V ABI (see section 3.4.1) expects us to set the following before jumping to the entry
; point:
;
; - RDX: function pointer to be registered with `atexit` (we pass 0)
; - RSP: the initial stack, contains program arguments and environment
; - FLAGS: should be zeroed out
; - MXCSR: should be set to 0x1F80, this sets flags as follows:
;   +--+--+--+--+--+--+--+--+--+---+--+--+--+--+--+--+
;   |FZ|   RC|PM|UM|OM|ZM|DM|IM|DAZ|PE|UE|OE|ZE|DE|IE|
;   +--+--+--+--+--+--+--+--+--+---+--+--+--+--+--+--+
;   | 0| 0  0| 1| 1| 1| 1| 1| 1|  0| 0| 0| 0| 0| 0| 0|
;   +--+--+--+--+--+--+--+--+--+---+--+--+--+--+--+--+

global call_elf_entry
section .text

; noreturn void call_elf_entry(elf_addr_t entry, void* argp)
call_elf_entry:
    xor     rdx, rdx ; set RDX to 0
    push    0x1F80
    ldmxcsr [rsp]    ; set MXCSR to 0x1F80
    add     rsp, 8   ; let's clean stack, it shouldn't matter, but let's keep it clean
                     ; for further uses
    push    0x202
    popf             ; set lower part of rFLAGS to 0
    mov     rsp, rsi ; set stack pointer to second arg
    jmp     rdi      ; jmp to entry point (first arg)
