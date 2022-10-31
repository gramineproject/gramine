; Copyright (C) 2022 Intel Corporation
;                    Borys Popławski <borysp@invisiblethingslab.com>

; Our PAL loader invokes this entrypoint with all registers unspecified, except %rsp.
; For detailed description of the stack layout see pal/src/pal_rtld.c:start_execution().

default rel

extern main
extern pal_regression_start_main
extern PalProcessExit

global _start
section .text

_start:
    ; Clear the frame pointer. The ABI suggests this be done, to mark the outermost frame.
    xor rbp, rbp

    ; Arguments for `pal_regression_start_main`:
    mov rdi, [rsp]              ; argc
    lea rsi, [rsp+8]            ; argv
    lea rdx, [rsi + 8*rdi + 8]  ; envp, after all args (including argv[argc] = NULL)
    lea rcx, [main]             ; `main` function

    ; Required by System V AMD64 ABI.
    and rsp, ~0xF

    call pal_regression_start_main

    mov rdi, rax
    call PalProcessExit wrt ..plt
