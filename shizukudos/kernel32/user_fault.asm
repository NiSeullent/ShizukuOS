; SPDX-License-Identifier: GPL-2.0-only
; Ring-3 program that executes a privileged instruction: must be killed with #GP.
bits 32
org 0x40000000
start:
    mov eax, 1
    mov ebx, msg
    mov ecx, msg_end - msg
    int 0x80
    cli                         ; #GP(0) in ring 3
    mov eax, 2
    xor ebx, ebx
    int 0x80
msg: db 'about to execute cli', 10
msg_end:
