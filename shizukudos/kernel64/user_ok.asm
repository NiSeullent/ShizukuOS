; SPDX-License-Identifier: GPL-2.0-only
; Ring-3 Long Mode test program: NT-style syscalls (EAX = number, R10/RDX/R8/R9 args),
; SSE arithmetic that must survive preemption, and exit code 42.
bits 64
default abs
org 0x400000
NtTerminateProcess equ 0x01
NtYieldExecution equ 0x18
NtShzDebugPrint equ 0x30
NtShzEvidence equ 0x31
start:
    mov r10, msg
    mov edx, msg_end - msg
    mov eax, NtShzDebugPrint
    syscall
    ; xmm7 holds a value that only survives if the kernel saves/restores SSE state
    mov rax, 0x4008000000000000        ; 3.0
    movq xmm7, rax
    mov ebx, 300
.loop:
    mov eax, NtYieldExecution
    syscall
    movq rax, xmm7
    mov rcx, 0x4008000000000000
    cmp rax, rcx
    jne .corrupt
    dec ebx
    jnz .loop
    movsd xmm0, [a]
    mulsd xmm0, [b]                     ; 1.5 * 2.0
    cvttsd2si rcx, xmm0                 ; 3
    mov r10d, 17
    mov rdx, rcx
    mov eax, NtShzEvidence
    syscall
    mov r10d, 16
    mov edx, 0x600d
    mov eax, NtShzEvidence
    syscall
    xor r10d, r10d
    mov edx, 42
    mov eax, NtTerminateProcess
    syscall
.corrupt:
    xor r10d, r10d
    mov edx, 0xbad
    mov eax, NtTerminateProcess
    syscall
a: dq 0x3ff8000000000000               ; 1.5
b: dq 0x4000000000000000               ; 2.0
msg: db 'hello from Long Mode ring 3', 10
msg_end:
