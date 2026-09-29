; SPDX-License-Identifier: GPL-2.0-only
; Long Mode ring-3 program using virtual addresses far above 4 GiB:
;  phase A reserves+commits 64 KiB at 8 GiB, writes and verifies a pattern, also at the last page;
;  phase B releases the region; phase C touches it again and must be killed (STATUS_ACCESS_VIOLATION).
bits 64
default abs
org 0x400000
NtTerminateProcess equ 0x01
NtAllocateVirtualMemory equ 0x07
NtFreeVirtualMemory equ 0x08
NtShzEvidence equ 0x31
start:
    sub rsp, 0x58
    mov rax, 0x200000000                ; 8 GiB
    mov [base], rax
    mov qword [size], 0x10000
    mov r10, -1
    lea rdx, [base]
    xor r8d, r8d
    lea r9, [size]
    mov qword [rsp + 0x28], 0x3000      ; MEM_COMMIT | MEM_RESERVE
    mov qword [rsp + 0x30], 4           ; PAGE_READWRITE
    mov eax, NtAllocateVirtualMemory
    syscall
    test eax, eax
    jnz .fail
    mov rdi, [base]
    mov rax, 0x1122334455667788
    mov [rdi], rax
    mov [rdi + 0xf000], rax             ; last page: demand-zero populated on first touch
    mov rbx, [rdi + 0xf000]
    cmp rbx, [rdi]
    jne .fail
    mov r10d, 16                        ; evidence: the address used (must exceed 4 GiB)
    mov rdx, rdi
    mov eax, 0x31
    syscall
    mov r10d, 17                        ; evidence: value read back at the far page
    mov rdx, rbx
    mov eax, 0x31
    syscall
    ; phase B: release
    mov qword [size], 0
    mov r10, -1
    lea rdx, [base]
    lea r8, [size]
    mov r9d, 0x8000                     ; MEM_RELEASE
    mov eax, NtFreeVirtualMemory
    syscall
    mov r10d, 18                        ; evidence: status of the free (0 = success)
    mov edx, eax
    mov eax, 0x31
    syscall
    ; phase C: touching released memory must fault
    mov rdi, [base]
    mov rax, [rdi]
    mov r10d, 19                        ; only reached if the access wrongly succeeded
    mov edx, 0xbad
    mov eax, 0x31
    syscall
.fail:
    mov r10, -1
    mov edx, 0xfa11
    mov eax, NtTerminateProcess
    syscall
base: dq 0
size: dq 0
