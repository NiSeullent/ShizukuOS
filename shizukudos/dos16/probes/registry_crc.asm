; SPDX-License-Identifier: GPL-2.0-only
; Read-only DOS registry-file diagnostic for the observed C:\WINDOWS source.
; Creates C:\REGCRC.TXT exclusively; never opens a Windows file for writing.
; CRC32/seek-size/read-size agreement is file-I/O evidence, not Windows success.
bits 16
cpu 386
org 0x100

start:
    push cs
    pop ds
    push cs
    pop es
    cld
    mov dx, report_path
    xor cx, cx
    mov ax, 0x5b00
    int 0x21
    jc refuse
    mov [report], ax
    mov word [cursor], paths
.next:
    mov si, [cursor]
    lodsw
    mov [cursor], si
    test ax, ax
    jz finish
    mov [current], ax
    mov si, ax
    call write_string
    mov si, space
    call write_string
    mov dx, [current]
    mov ax, 0x3d00
    int 0x21
    jc input_error
    mov [input], ax
    mov bx, ax
    xor cx, cx
    xor dx, dx
    mov ax, 0x4202
    int 0x21
    jc input_error
    movzx eax, ax
    movzx edx, dx
    shl edx, 16
    or eax, edx
    mov [seek_size], eax
    mov bx, [input]
    xor cx, cx
    xor dx, dx
    mov ax, 0x4200
    int 0x21
    jc input_error
    test ax, ax
    jnz refuse
    test dx, dx
    jnz refuse
    mov dword [count], 0
    mov dword [crc], 0xffffffff
.read:
    mov bx, [input]
    mov dx, buffer
    mov cx, 1024
    mov ah, 0x3f
    int 0x21
    jc input_error
    test ax, ax
    jz .complete
    cmp ax, 1024
    ja refuse
    movzx eax, ax
    add [count], eax
    jc refuse
    cmp dword [count], 0x01000000
    ja refuse
    mov cx, ax
    mov si, buffer
    mov edx, [crc]
.byte:
    lodsb
    xor dl, al
    mov bl, 8
.bit:
    shr edx, 1
    jnc .unchanged
    xor edx, 0xedb88320
.unchanged:
    dec bl
    jnz .bit
    loop .byte
    mov [crc], edx
    jmp .read
.complete:
    mov bx, [input]
    mov ah, 0x3e
    int 0x21
    jc refuse
    mov word [input], 0xffff
    mov si, size_text
    call write_string
    mov eax, [seek_size]
    call write_hex
    mov si, read_text
    call write_string
    mov eax, [count]
    call write_hex
    mov si, crc_text
    call write_string
    mov eax, [crc]
    not eax
    call write_hex
    mov si, newline
    call write_string
    mov eax, [count]
    cmp eax, [seek_size]
    jne refuse
    jmp start.next

input_error:
    mov [error], ax
    mov byte [failed], 1
    cmp word [input], 0xffff
    je .closed
    mov bx, [input]
    mov ah, 0x3e
    int 0x21
    jc refuse
    mov word [input], 0xffff
.closed:
    mov si, error_text
    call write_string
    movzx eax, word [error]
    call write_hex
    mov si, newline
    call write_string
    jmp start.next

write_hex:
    mov di, hex_buffer
    mov cx, 8
.digit:
    rol eax, 4
    mov edx, eax
    and dx, 15
    mov bx, digits
    add bx, dx
    mov dl, [bx]
    mov [di], dl
    inc di
    loop .digit
    mov si, hex_buffer
    ; Fall through: preserves no DOS parameter registers across interrupts.
write_string:
    mov dx, si
    xor cx, cx
.length:
    cmp byte [si], 0
    je .write
    inc si
    inc cx
    jmp .length
.write:
    mov [write_size], cx
    mov bx, [report]
    mov ah, 0x40
    int 0x21
    jc refuse
    cmp ax, [write_size]
    jne refuse
    ret

finish:
    mov bx, [report]
    mov ah, 0x68
    int 0x21
    jc refuse
    mov bx, [report]
    mov ah, 0x3e
    int 0x21
    jc refuse
    mov al, [failed]
    mov ah, 0x4c
    int 0x21

refuse:
    ; Close owned handles where possible; partial report never has success scope.
    cmp word [input], 0xffff
    je .report
    mov bx, [input]
    mov ah, 0x3e
    int 0x21
.report:
    cmp word [report], 0xffff
    je .exit
    mov bx, [report]
    mov ah, 0x3e
    int 0x21
.exit:
    mov ax, 0x4c02
    int 0x21

paths: dw system_dat, user_dat, 0
system_dat: db 'C:\WINDOWS\SYSTEM.DAT', 0
user_dat: db 'C:\WINDOWS\USER.DAT', 0
report_path: db 'C:\REGCRC.TXT', 0
space: db ' ', 0
size_text: db 'seek_bytes=', 0
read_text: db ' read_bytes=', 0
crc_text: db ' crc32=', 0
error_text: db 'DOS_ERROR=', 0
newline: db 13, 10, 0
digits: db '0123456789ABCDEF'
hex_buffer: times 8 db 0
            db 0
report: dw 0xffff
input: dw 0xffff
cursor: dw 0
current: dw 0
write_size: dw 0
error: dw 0
failed: db 0
seek_size: dd 0
count: dd 0
crc: dd 0
buffer: times 1024 db 0
