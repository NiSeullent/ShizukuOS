; SPDX-License-Identifier: GPL-2.0-only
; Shared helpers for the ShizukuDOS DOS16 conformance programs (.COM, NASM).
; Each program appends one result line to A:\RESULT.TXT so the host can verify
; guest-generated data from the disk image rather than trusting screen text.
bits 16
cpu 386
org 0x100
    jmp near start              ; helpers below must not sit at the .COM entry point

%macro PRINT 1
    mov dx, %1
    mov ah, 9
    int 0x21
%endmacro

; print_hex32: EAX -> 8 hex digits into [di], DI advanced.
print_hex32:
    push ecx
    push edx
    mov ecx, 8
.next:
    rol eax, 4
    mov dl, al
    and dl, 0x0f
    add dl, '0'
    cmp dl, '9'
    jbe .store
    add dl, 7
.store:
    mov [di], dl
    inc di
    loop .next
    pop edx
    pop ecx
    ret

; append_result: DS:SI = line, CX = length. Returns CF=1 on failure.
append_result:
    mov [ar_si], si
    mov [ar_cx], cx
    pusha
    mov dx, result_name
    mov ax, 0x3d01              ; open for writing
    int 0x21
    jnc .have
    mov dx, result_name
    xor cx, cx
    mov ah, 0x3c                ; create
    int 0x21
    jc .fail
.have:
    mov bx, ax
    mov ax, 0x4202              ; seek to end
    xor cx, cx
    xor dx, dx
    int 0x21
    jc .close_fail
    mov dx, [ar_si]
    mov cx, [ar_cx]
    mov ah, 0x40
    int 0x21
    jc .close_fail
    cmp ax, [ar_cx]
    jne .close_fail
    mov ah, 0x3e
    int 0x21
    popa
    clc
    ret
.close_fail:
    mov ah, 0x3e
    int 0x21
.fail:
    popa
    stc
    ret

ar_si: dw 0
ar_cx: dw 0
result_name: db 'RESULT.TXT', 0
