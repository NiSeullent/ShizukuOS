; SPDX-License-Identifier: GPL-2.0-only
; Bounded COM1 diagnostic marker; return to DOS, never signal SHZ-EXIT or HLT.
bits 16
cpu 386
org 0x100
start:
    push cs
    pop ds
    mov si, 0x81
.argument:
    lodsb
    cmp al, ' '
    je .argument
    or al, 0x20
    mov si, normal
    cmp al, 'r'
    jne .startup
    mov si, recovery
    jmp .uart
.startup:
    cmp al, 's'
    jne .probe
    mov si, startup
    jmp .uart
.probe:
    cmp al, 'p'
    jne .uart
    mov si, probe
.uart:
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 1
    out dx, al
    inc dx
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 3
    out dx, al
    mov dx, 0x3fa
    mov al, 7
    out dx, al
    mov dx, 0x3fc
    mov al, 3
    out dx, al
.next:
    lodsb
    test al, al
    jz .return
    mov bl, al
    mov cx, 0xffff
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jnz .send
    loop .wait
    jmp .return
.send:
    mov dx, 0x3f8
    mov al, bl
    out dx, al
    jmp .next
.return:
    mov ax, 0x4c00
    int 0x21
normal: db 13, 10, 'SHZ-DOS10: READY NORMAL', 13, 10, 0
recovery: db 13, 10, 'SHZ-DOS10: READY RECOVERY', 13, 10, 0
startup: db 13, 10, 'SHZ-DOS10: STARTUP', 13, 10, 0
probe: db 13, 10, 'SHZ-DOS10: USER PROBE', 13, 10, 0
