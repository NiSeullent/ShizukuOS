; SPDX-License-Identifier: GPL-2.0-only
; T_MODE: proves the program runs in genuine real mode, not V86.
; `mov eax, cr0` and pushfd/EFLAGS.VM are only meaningful at CPL0 real mode;
; a V86 monitor would fault on the CR read or report VM=1.
%include "common.inc"
start:
    smsw ax
    test al, 1
    jnz fail_pe
    mov eax, cr0
    mov [cr0v], eax
    test al, 1
    jnz fail_pe
    mov eax, cr4
    mov [cr4v], eax
    pushfd
    pop eax
    mov [efl], eax
    test eax, 0x20000            ; EFLAGS.VM
    jnz fail_vm
    mov di, line + 16
    mov eax, [cr0v]
    call print_hex32
    mov di, line + 29
    mov eax, [cr4v]
    call print_hex32
    mov di, line + 42
    mov eax, [efl]
    call print_hex32
    mov si, line
    mov cx, line_end - line
    call append_result
    PRINT ok_msg
    mov ax, 0x4c00
    int 0x21
fail_pe:
    mov si, fail_pe_line
    mov cx, fail_pe_end - fail_pe_line
    call append_result
    PRINT bad_msg
    mov ax, 0x4c01
    int 0x21
fail_vm:
    mov si, fail_vm_line
    mov cx, fail_vm_end - fail_vm_line
    call append_result
    PRINT bad_msg
    mov ax, 0x4c02
    int 0x21
line:        db 'T_MODE PASS CR0=00000000 CR4=00000000 EFL=00000000', 13, 10
line_end:
fail_pe_line: db 'T_MODE FAIL CR0.PE set', 13, 10
fail_pe_end:
fail_vm_line: db 'T_MODE FAIL EFLAGS.VM set', 13, 10
fail_vm_end:
cr0v: dd 0
cr4v: dd 0
efl:  dd 0
ok_msg: db 'T_MODE: real mode confirmed', 13, 10, '$'
bad_msg: db 'T_MODE: FAILED', 13, 10, '$'
