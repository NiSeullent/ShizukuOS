; SPDX-License-Identifier: GPL-2.0-only
; Ring-3 test program: syscalls, computation in user mode, exit code 42.
bits 32
org 0x40000000
SYS_WRITE equ 1
SYS_EXIT equ 2
SYS_GETPID equ 3
SYS_YIELD equ 4
SYS_EVIDENCE equ 5
SYS_TICKS equ 7
start:
    mov eax, SYS_GETPID
    int 0x80
    mov [pid], eax
    mov eax, SYS_WRITE
    mov ebx, msg
    mov ecx, msg_end - msg
    int 0x80
    mov edi, 5
.yield:
    mov eax, SYS_YIELD
    int 0x80
    dec edi
    jnz .yield
    xor eax, eax                ; sum 1..1000 in user mode
    mov ecx, 1000
.sum:
    add eax, ecx
    loop .sum
    mov ecx, eax                ; 500500
    mov eax, SYS_EVIDENCE
    mov ebx, 17
    int 0x80
    mov eax, SYS_EVIDENCE
    mov ebx, 16
    mov ecx, [pid]
    int 0x80
    mov eax, SYS_EXIT
    mov ebx, 42
    int 0x80
.hang:
    jmp .hang
msg: db 'hello from ring 3', 10
msg_end:
pid: dd 0
