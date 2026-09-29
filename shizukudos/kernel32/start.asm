; SPDX-License-Identifier: GPL-2.0-only
; Kernel32 entry, interrupt stubs, context switch and ring-3 entry.
; The Supervisor starts the vCPU at _start in 32-bit Protected Mode, paging off, flat
; segments (CS=0x08, DS=SS=0x10 of the boot GDT), EAX = bootinfo magic, EBX = bootinfo,
; interrupts disabled.
bits 32
section .text.entry
global _start
extern kmain
_start:
    cli
    cld
    mov esp, kstack_top
    xor ebp, ebp
    push ebx
    call kmain
.halt:
    cli
    hlt
    jmp .halt

section .text
extern isr_dispatch

; ---- interrupt stubs ------------------------------------------------------
%macro STUB_NOERR 1
stub_%1:
    push dword 0
    push dword %1
    jmp isr_common
%endmacro
%macro STUB_ERR 1
stub_%1:
    push dword %1
    jmp isr_common
%endmacro

%assign v 0
%rep 256
  %if v == 8 || (v >= 10 && v <= 14) || v == 17 || v == 21 || v == 29 || v == 30
    STUB_ERR v
  %else
    STUB_NOERR v
  %endif
  %assign v v+1
%endrep

isr_common:
    pusha
    push ds
    push es
    push fs
    push gs
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    cld
    push esp
    call isr_dispatch
    add esp, 4
    pop gs
    pop fs
    pop es
    pop ds
    popa
    add esp, 8
    iretd

; void switch_stacks(uint32_t *save_esp, uint32_t new_esp)
global switch_stacks
switch_stacks:
    mov eax, [esp + 4]
    mov edx, [esp + 8]
    pushfd
    push ebp
    push ebx
    push esi
    push edi
    mov [eax], esp
    mov esp, edx
    pop edi
    pop esi
    pop ebx
    pop ebp
    popfd
    ret

; void enter_user(uint32_t entry, uint32_t user_esp): drop to ring 3 via iretd.
global enter_user
enter_user:
    mov ecx, [esp + 4]
    mov edx, [esp + 8]
    mov ax, 0x23
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    push dword 0x23             ; user SS
    push edx                    ; user ESP
    push dword 0x202            ; EFLAGS: IF=1
    push dword 0x1b             ; user CS
    push ecx                    ; EIP
    iretd

global gdt_flush
; void gdt_flush(void *gdtr, uint16_t tss_sel)
gdt_flush:
    mov eax, [esp + 4]
    lgdt [eax]
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    jmp 0x08:.reload
.reload:
    mov ax, [esp + 8]
    ltr ax
    ret

global idt_load
idt_load:
    mov eax, [esp + 4]
    lidt [eax]
    ret

section .rodata
align 4
global isr_stub_table
isr_stub_table:
%assign v 0
%rep 256
    dd stub_ %+ v
    %assign v v+1
%endrep

; embedded ring-3 programs (assembled by kbuild.py into the object directory)
global user_ok_start, user_ok_end, user_fault_start, user_fault_end, user_wild_start, user_wild_end
user_ok_start:    incbin "user_ok.bin"
user_ok_end:
user_fault_start: incbin "user_fault.bin"
user_fault_end:
user_wild_start:  incbin "user_wild.bin"
user_wild_end:

section .bss
align 16
kstack: resb 16384
global kstack_top
kstack_top:
