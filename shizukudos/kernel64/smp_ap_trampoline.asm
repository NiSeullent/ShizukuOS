; SPDX-License-Identifier: GPL-2.0-only
; Copied verbatim to the proven retired native boot PML4 page0x1000. All low addresses are
; fixed constants relative to this copied blob, never high-half ELF relocations.
; Trampoline parameters at0x1800 are published for one target at a time.
section .rodata.smp_trampoline align=16
global shz_smp_trampoline_start,shz_smp_trampoline_end
%define LOW 0x1000
%define PARAM (LOW+0x800)
bits 16
shz_smp_trampoline_start:
    cli
    cld
    xor ax,ax
    mov ds,ax
    mov es,ax
    mov ss,ax
    ; No shared stack is used before each AP loads its private64-bit stack.
    lgdt [cs:gdtr-shz_smp_trampoline_start]
    mov eax,cr0
    or eax,1
    mov cr0,eax
    jmp dword 0x08:(LOW+pm32-shz_smp_trampoline_start)
bits 32
pm32:
    mov ax,0x10
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov eax,1
    cpuid
    shr ebx,24
    cmp ebx,[PARAM+8]
    jne park32
    xor eax,eax
    mov edx,1
    lock cmpxchg [PARAM+12],edx
    jne park32
    mov eax,0x620                  ; PAE, OSFXSR, OSXMMEXCPT
    mov cr4,eax
    mov eax,[PARAM]
    mov cr3,eax
    mov ecx,0xc0000080
    rdmsr
    or eax,0x900                   ; EFER.LME|NXE
    wrmsr
    mov eax,cr0
    and eax,0xfffffffb             ; clear EM
    or eax,0x80010003              ; paging, WP, MP, PE
    mov cr0,eax
    jmp 0x18:(LOW+long64-shz_smp_trampoline_start)
park32:
    cli
    hlt
    jmp park32
bits 64
long64:
    mov ax,0x10
    mov ds,ax
    mov es,ax
    mov ss,ax
    xor eax,eax
    mov fs,ax
    mov gs,ax
    mov rsp,[abs PARAM+16]
    xor ebp,ebp
    mov edi,[abs PARAM+4]
    mov rax,[abs PARAM+24]
    call rax
park64:
    cli
    hlt
    jmp park64
align 8
gdt:
    dq 0
    dq 0x00cf9b000000ffff          ;0x08 protected-mode code
    dq 0x00cf93000000ffff          ;0x10 data
    dq 0x00af9b000000ffff          ;0x18 LongMode code
gdt_end:
gdtr:
    dw gdt_end-gdt-1
    dd LOW+gdt-shz_smp_trampoline_start
times 0x800-($-shz_smp_trampoline_start) db 0
times 32 db 0                     ; patched struct trampoline_params
shz_smp_trampoline_end:
