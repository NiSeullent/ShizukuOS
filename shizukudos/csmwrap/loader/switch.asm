; SPDX-License-Identifier: GPL-2.0-only
; After ExitBootServices, drop to the real-mode stub at 07E0:0000.
; The transition never calls a UEFI boot service.
bits 64
default rel

global csmwrap_jump_real

section .text
csmwrap_jump_real:
    cli
    lea rax, [rel gdt]
    mov [rel gdtr + 2], rax
    lgdt [rel gdtr]
    push qword 0x08
    lea rax, [rel compat32]
    push rax
    retfq

compat32:
    ; Compatibility mode (32-bit code, paging still on). Encoded explicitly so
    ; this file can stay in a 64-bit object.
    db 0xB8, 0x10, 0x00, 0x00, 0x00
    db 0x8E, 0xD8
    db 0x8E, 0xC0
    db 0x8E, 0xD0
    db 0x0F, 0x20, 0xC0
    db 0x25, 0xFF, 0xFF, 0xFF, 0x7F
    db 0x0F, 0x22, 0xC0
    db 0xB9, 0x80, 0x00, 0x00, 0xC0
    db 0x0F, 0x32
    db 0x25, 0xFF, 0xFE, 0xFF, 0xFF
    db 0x0F, 0x30
    db 0x0F, 0x20, 0xC0
    db 0x25, 0xFE, 0xFF, 0xFF, 0xFF
    db 0x0F, 0x22, 0xC0
    db 0x66, 0xEA
    dw 0x0000
    dw 0x07E0

section .data
align 8
gdt:
    dq 0
    dq 0x00cf9a000000ffff
    dq 0x00cf92000000ffff
    dq 0x00009a000000ffff
    dq 0x000092000000ffff
gdt_end:
gdtr:
    dw gdt_end - gdt - 1
    dq 0
