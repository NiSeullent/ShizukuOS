; SPDX-License-Identifier: GPL-2.0-only
; Supervisor payload entry, descriptor-table reload and exception stubs.
; The UEFI loader jumps here after ExitBootServices in 64-bit ring 0 with
; RDI = shz_info_t* (System V ABI). Interrupts are off, firmware page tables active.
bits 64
default rel
section .text.entry

extern sup_main
extern sup_exception
extern sup_stack_top
extern __bss_start
extern __bss_end

global _start
_start:
    cli
    cld
    mov rbx, rdi                    ; shz_info_t* from the loader
    lea rdi, [rel __bss_start]      ; the loader copied only the file-backed image
    lea rcx, [rel __bss_end]
    sub rcx, rdi
    xor eax, eax
    rep stosb
    mov rdi, rbx
    lea rsp, [rel sup_stack_top]
    xor ebp, ebp
    call sup_main
.halt:
    cli
    hlt
    jmp .halt

section .text
global load_descriptor_tables
; void load_descriptor_tables(struct dtr *gdt, struct dtr *idt, uint16_t tr)
load_descriptor_tables:
    lgdt [rdi]
    lidt [rsi]
    push qword 0x08
    lea rax, [rel .reload]
    push rax
    o64 retf
.reload:
    mov eax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    ltr dx
    ret

; Exception stubs: push a uniform frame and call sup_exception(frame*).
%macro ISR_NOERR 1
isr_%1:
    push qword 0
    push qword %1
    jmp isr_common
%endmacro
%macro ISR_ERR 1
isr_%1:
    push qword %1
    jmp isr_common
%endmacro

%assign v 0
%rep 256
    %if v == 8 || (v >= 10 && v <= 14) || v == 17 || v == 21 || v == 29 || v == 30
        ISR_ERR v
    %else
        ISR_NOERR v
    %endif
    %assign v v+1
%endrep

isr_common:
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    cld
    call sup_exception
.hang:
    cli
    hlt
    jmp .hang

section .rodata
global isr_table
align 8
isr_table:
%assign v 0
%rep 256
    dq isr_ %+ v
    %assign v v+1
%endrep
