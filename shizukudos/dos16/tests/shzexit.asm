; SPDX-License-Identifier: GPL-2.0-only
; SHZEXIT n: writes "SHZ-EXIT:<n>" to COM1 (0x3F8) then halts with interrupts
; enabled. A harness on the host (QEMU serial, or the Supervisor's virtual UART)
; treats that line as the guest-requested end of the session.
bits 16
cpu 386
org 0x100
start:
    mov si, 0x81
.skip:
    lodsb
    cmp al, ' '
    je .skip
    sub al, '0'
    cmp al, 9
    jbe .digit
    xor al, al
.digit:
    add al, '0'
    mov [digit], al
    mov si, msg
.out:
    lodsb
    or al, al
    jz .halt
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    mov dx, 0x3f8
    mov al, [si - 1]
    out dx, al
    jmp .out
.halt:
    sti
    hlt
    jmp .halt
msg: db 13, 10, 'SHZ-EXIT:'
digit: db '0', 13, 10, 0
