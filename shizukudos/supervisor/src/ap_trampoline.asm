; SPDX-License-Identifier: GPL-2.0-only
; Each AP owns one LoaderData page below 1 MiB. Fixed offsets are verified by
; build.py; loader patches only GDTR/far targets, BSP fills its private params.
bits 16
org 0
    jmp short real_start
times 16-($-$$) db 0
gdtr: dw 31
      dd 384                     ; +18: loader adds page physical base
times 24-($-$$) db 0
ptr32: dd 128                    ; +24: loader adds base
       dw 8
times 32-($-$$) db 0
ptr64: dd 256                    ; +32: loader adds base
       dw 24
times 64-($-$$) db 0
real_start:
    cli
    cld
    xor ebp, ebp
    mov bp, cs
    shl ebp, 4
    lgdt [cs:gdtr]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp dword far [cs:ptr32]
times 128-($-$$) db 0
bits 32
pm32:
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, 1
    cpuid
    shr ebx, 24
    cmp ebx, [ebp+0x808]
    jne park32
    xor eax, eax
    mov edx, 1
    lock cmpxchg [ebp+0x80c], edx
    jne park32
    mov eax, 0x20                ; PAE; PGE and PCIDE stay off
    mov cr4, eax
    mov eax, [ebp+0x800]
    mov cr3, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x100               ; LME; do not require optional NX
    wrmsr
    mov eax, cr0
    and eax, 0xdffffffb         ; NW/EM off; keep caching disabled until checked
    or eax, 0xc0010003          ; PG|CD|WP|MP|PE
    mov cr0, eax
    jmp far [ebp+ptr64]
park32:
    cli
    hlt
    jmp park32
times 256-($-$$) db 0
bits 64
long64:
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    mov rsp, [rbp+0x810]
    xor ebx, ebx
    mov edi, [rbp+0x804]
    call [rbp+0x818]
park64:
    cli
    hlt
    jmp park64
times 384-($-$$) db 0
gdt:
    dq 0
    dq 0x00cf9b000000ffff        ; bootstrap PM code
    dq 0x00cf93000000ffff        ; flat data
    dq 0x00af9b000000ffff        ; bootstrap LM code
times 0x800-($-$$) db 0
    times 32 db 0               ; shz_ap_params_t
times 4096-($-$$) db 0
