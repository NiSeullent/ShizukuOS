; SPDX-License-Identifier: GPL-2.0-only
; VM entry / exit trampolines for the Intel VMX backend (System V AMD64 ABI).
;
; struct vcpu layout (see vmx.h): gpr[16] @0 (rax,rcx,rdx,rbx,-,rbp,rsi,rdi,r8..r15),
; launched @128, host_rsp_saved @136. VMCS HOST_RSP points at a slot holding the
; vcpu pointer, so the exit path can find the guest register area without any
; guest-controlled register.
bits 64
default rel
section .text

global vmx_enter
global vmx_exit_entry

; int vmx_enter(struct vcpu *vc)  -- rdi = vc
vmx_enter:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi                        ; [rsp] = vc, popped on both exit paths
    mov [rdi + 136], rsp
    cmp qword [rdi + 128], 0        ; flags survive the mov's below: ZF => VMLAUNCH
    mov rcx, [rdi + 8]
    mov rdx, [rdi + 16]
    mov rbx, [rdi + 24]
    mov rbp, [rdi + 40]
    mov rsi, [rdi + 48]
    mov r8,  [rdi + 64]
    mov r9,  [rdi + 72]
    mov r10, [rdi + 80]
    mov r11, [rdi + 88]
    mov r12, [rdi + 96]
    mov r13, [rdi + 104]
    mov r14, [rdi + 112]
    mov r15, [rdi + 120]
    mov rax, [rdi + 0]
    mov rdi, [rdi + 56]
    jne .resume
    vmlaunch
    jmp .failed
.resume:
    vmresume
.failed:
    ; VMfailInvalid sets CF, VMfailValid sets ZF. Host registers are still the
    ; guest values, but RSP is untouched, so unwind from the stack alone.
    mov eax, 1
    jc .unwind
    mov eax, 2
.unwind:
    add rsp, 8                      ; drop vc slot
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; Reached through VMCS HOST_RIP with RSP = slot holding the vcpu pointer.
vmx_exit_entry:
    push rax
    mov rax, [rsp + 8]              ; vcpu pointer
    mov [rax + 8], rcx
    mov [rax + 16], rdx
    mov [rax + 24], rbx
    mov [rax + 40], rbp
    mov [rax + 48], rsi
    mov [rax + 56], rdi
    mov [rax + 64], r8
    mov [rax + 72], r9
    mov [rax + 80], r10
    mov [rax + 88], r11
    mov [rax + 96], r12
    mov [rax + 104], r13
    mov [rax + 112], r14
    mov [rax + 120], r15
    pop rcx
    mov [rax + 0], rcx              ; guest rax
    mov rsp, [rax + 136]
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    xor eax, eax
    ret
