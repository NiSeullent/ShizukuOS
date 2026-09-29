; SPDX-License-Identifier: GPL-2.0-only
; Ring-3 program that writes to kernel memory: must be killed with #PF, kernel intact.
bits 32
org 0x40000000
start:
    mov dword [0x00100000], 0xdeadbeef     ; supervisor-only page
    mov eax, 2
    xor ebx, ebx
    int 0x80
