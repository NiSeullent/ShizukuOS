; SPDX-License-Identifier: GPL-2.0-only
; Standalone Kernel64 boot stub: a Multiboot 1 ELF32 image for `qemu -kernel`, so Kernel64 and its Win64
; processes can run under QEMU TCG where Intel VMX (the Supervisor) is unavailable. It does what the
; Supervisor's kernel_domain_create() does for a Long Mode guest: kernel and initrd copied into place, a
; bootinfo block at 0x7000, boot page tables (identity + higher half), then Long Mode with RDI = bootinfo.
bits 32

section .multiboot
align 4
    dd 0x1BADB002                       ; magic
    dd 0x00000003                       ; page-align modules, provide memory info
    dd -(0x1BADB002 + 3)

section .text
global _start
extern stub_prepare
_start:
    cli
    cld
    mov esp, stack_top
    push ebx                            ; multiboot info
    push eax                            ; magic
    call stub_prepare                   ; never returns on error
    lgdt [gdtr]
    mov eax, cr4
    or eax, 0x20                        ; PAE
    mov cr4, eax
    mov eax, 0x1000                     ; PML4 built by stub_prepare
    mov cr3, eax
    mov ecx, 0xC0000080                 ; EFER
    rdmsr
    or eax, 0x100                       ; LME
    wrmsr
    mov eax, cr0
    or eax, 0x80000000                  ; PG
    mov cr0, eax
    jmp 0x08:long_entry

bits 64
long_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    mov edi, 0x7000                     ; bootinfo (physical)
    mov rax, 0xFFFFFFFF80100000         ; Kernel64 entry
    jmp rax

section .rodata
align 8
gdt:
    dq 0
    dq 0x00af9b000000ffff               ; 0x08 code, L=1
    dq 0x00cf93000000ffff               ; 0x10 data
gdt_end:
gdtr:
    dw gdt_end - gdt - 1
    dd gdt

section .bss
align 16
    resb 16384
stack_top:
