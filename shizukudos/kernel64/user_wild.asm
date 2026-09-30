; SPDX-License-Identifier: GPL-2.0-only
; Long Mode ring-3 program writing to a kernel address: must take #PF and be killed.
bits 64
default abs
org 0x400000
start:
    mov rax, 0xffff800000100000        ; direct-map alias of kernel memory
    mov qword [rax], 1
    mov r10, -1                         ; NtTerminateProcess(NtCurrentProcess(), 0) if it survived
    xor edx, edx
    mov eax, 1
    syscall
