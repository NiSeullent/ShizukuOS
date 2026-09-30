; SPDX-License-Identifier: GPL-2.0-only
; Long Mode ring-3 program executing a privileged instruction: killed, kernel intact.
bits 64
default abs
org 0x400000
start:
    mov r10, msg
    mov edx, msg_end - msg
    mov eax, 0x30
    syscall
    cli
    mov r10, -1                         ; NtTerminateProcess(NtCurrentProcess(), 0) if it survived
    xor edx, edx
    mov eax, 1
    syscall
msg: db 'about to execute cli', 10
msg_end:
