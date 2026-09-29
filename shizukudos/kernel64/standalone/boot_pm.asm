; SPDX-License-Identifier: GPL-2.0-only
; Standalone Kernel32 boot stub (Multiboot 1 ELF32 for `qemu -kernel`): stub_prepare() (boot32.c, -DSTUB_K32) copies the
; kernel to 1 MiB and writes the bootinfo at 0x7000; the kernel is then entered as the Supervisor enters it:
; 32-bit Protected Mode, paging off, flat segments, EAX = bootinfo magic, EBX = bootinfo, interrupts off.
bits 32

section .multiboot
align 4
    dd 0x1BADB002
    dd 0x00000003
    dd -(0x1BADB002 + 3)

section .text
global _start
extern stub_prepare
_start:
    cli
    cld
    mov esp, stack_top
    push ebx
    push eax
    call stub_prepare
    lgdt [gdtr]
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov eax, 0x544f4f42                 ; SHZ_BOOTINFO_MAGIC
    mov ebx, 0x7000                     ; SHZ_BOOTINFO_GPA
    mov ecx, 0x100000                   ; kernel entry
    jmp 0x08:reload
reload:
    jmp ecx

section .rodata
align 8
gdt:
    dq 0
    dq 0x00cf9b000000ffff               ; 0x08 code32 flat (the Supervisor's boot GDT layout)
    dq 0x00cf93000000ffff               ; 0x10 data flat
gdt_end:
gdtr:
    dw gdt_end - gdt - 1
    dd gdt

section .bss
align 16
    resb 16384
stack_top:
