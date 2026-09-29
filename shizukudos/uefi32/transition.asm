; SPDX-License-Identifier: GPL-2.0-only
; Original x64 -> compatibility mode -> legacy 32-bit protected-mode handoff.
; All instructions/GDT/IDTs live in EFI-allocated identity-mapped low memory.
%include "layout.inc"
ORG SD32_BASE
BITS 64

transition_entry:
    cli
    cld
    mov rsp, SD32_STACK_TOP
    lgdt [rel gdt_pointer]
    lidt [rel idt64_pointer]
    mov dword [abs SD32_HANDOFF + 12], 3
    push qword 0x10
    lea rax, [rel compatibility32]
    push rax
    retfq

BITS 32
compatibility32:
    mov ax, 0x18
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov esp, SD32_STACK_TOP
    ; PCIDE must be clear before CR0.PG is cleared.
    mov eax, cr4
    and eax, ~0x00020000
    mov cr4, eax
    ; Current code and following instructions are identity mapped below 4 GiB.
    mov eax, cr0
    and eax, 0x7fffffff
    mov cr0, eax
    ; IDT gates are now legacy 8-byte gates. No firmware descriptors survive.
    lidt [idt32_pointer]
    mov ecx, 0xc0000080
    rdmsr
    and eax, ~0x00000100
    wrmsr
    mov eax, cr4
    and eax, ~0x00021020 ; PCIDE, LA57, PAE off after IA-32e has been deactivated
    mov cr4, eax
    xor ebp, ebp
    push dword SD32_HANDOFF
    mov eax, SD32_PAYLOAD
    call eax
halt32:
    cli
    hlt
    jmp halt32

fault32:
    cli
    mov dword [SD32_HANDOFF + 12], 0xdead2000
    jmp halt32

BITS 64
fault64:
    cli
    mov dword [abs SD32_HANDOFF + 12], 0xdead1000
halt64:
    hlt
    jmp halt64

ALIGN 16
gdt:
    dq 0
    dq 0x00af9a000000ffff ; selector 08: 64-bit code, L=1, D=0
    dq 0x00cf9a000000ffff ; selector 10: flat 32-bit code, L=0, D=1
    dq 0x00cf92000000ffff ; selector 18: flat 32-bit data/stack
gdt_end:
gdt_pointer:
    dw gdt_end - gdt - 1
    dq gdt
idt64_pointer:
    dw 4095
    dq SD32_BASE + 0x1000
idt32_pointer:
    dw 2047
    dd SD32_BASE + 0x2000

times 0x1000 - ($ - $$) db 0
%assign HANDLER64 (fault64 - $$ + SD32_BASE)
%rep 256
    dw HANDLER64 & 0xffff
    dw 0x08
    db 0, 0x8e
    dw (HANDLER64 >> 16) & 0xffff
    dd 0, 0
%endrep
%assign HANDLER32 (fault32 - $$ + SD32_BASE)
%rep 256
    dw HANDLER32 & 0xffff
    dw 0x10
    db 0, 0x8e
    dw (HANDLER32 >> 16) & 0xffff
%endrep
