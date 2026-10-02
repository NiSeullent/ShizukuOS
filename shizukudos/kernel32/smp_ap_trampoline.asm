; SPDX-License-Identifier: GPL-2.0-only
; Distinct 16 -> non-PAE protected-mode blob copied to 0x1000. No stack
; access, EFER write, PAE or 64-bit instruction before private ESP admission.
BITS 32
SECTION .rodata align=16
GLOBAL k32_ap_blob_start,k32_ap_blob_end
k32_ap_blob_start:
BITS 16
    cli
    cld
    xor ax,ax
    mov ds,ax
    lgdt [0x1000 + (low_gdtr-k32_ap_blob_start)]
    mov eax,cr0
    or eax,1
    mov cr0,eax
    jmp dword 0x08:0x1000+(protected-k32_ap_blob_start)
BITS 32
protected:
    mov ax,0x10
    mov ds,ax
    mov es,ax
    mov fs,ax
    mov gs,ax
    mov ss,ax
    mov eax,1
    cpuid
    shr ebx,24
    mov ecx,[0x17fc]            ; immutable record count, published pre-INIT
    test ecx,ecx
    jz park
    cmp ecx,3
    ja park
    mov ebp,0x1800
find_record:
    cmp ebx,[ebp+8]             ; actual physical id chooses immutable slot
    je claim
    add ebp,24
    loop find_record
    jmp park
claim:
    xor eax,eax
    mov edx,1
    lock cmpxchg [ebp+12],edx    ; single-use claim before ANY stack use
    jne park
    mov esi,[ebp+4]
    mov edi,[ebp+20]
    mov esp,[ebp+16]
    mov eax,cr4
    and eax,~0x20               ; explicitly non-PAE
    mov cr4,eax
    mov eax,[ebp]
    mov cr3,eax
    mov eax,cr0
    or eax,0x80010001           ; PG, WP, PE; cache policy is checked by C
    mov cr0,eax
    push esi
    call edi
park:
    cli
    hlt
    jmp park
align 8
low_gdt:
    dq 0,0x00cf9a000000ffff,0x00cf92000000ffff
low_gdtr:
    dw low_gdtr-low_gdt-1
    dd 0x1000+(low_gdt-k32_ap_blob_start)
k32_ap_blob_end:
%if k32_ap_blob_end-k32_ap_blob_start > 0x7fc
%error trampoline_overlaps_parameters
%endif

SECTION .text
BITS 32
GLOBAL k32_ap_stack_enter,k32_ap_stack_leave
EXTERN k32_ap_idle_main,k32_ap_stack_leave_complete
k32_ap_stack_enter:
    pushfd
    push ebp
    push ebx
    push esi
    push edi
    mov eax,[esp+24]            ; &saved bootstrap ESP
    mov edx,[esp+28]            ; idle stack top
    mov ecx,[esp+32]            ; owning logical cpu
    mov [eax],esp
    mov esp,edx
    sub esp,12
    push ecx
    call k32_ap_idle_main       ; admission occurs on actual destination ESP
    ud2
k32_ap_stack_leave:
    mov eax,[esp+4]
    mov ecx,[esp+8]
    mov esp,eax                ; destination is retained bootstrap stack
    sub esp,12
    push ecx
    call k32_ap_stack_leave_complete
    add esp,16
    pop edi
    pop esi
    pop ebx
    pop ebp
    popfd                      ; only after online ownership withdrawal
    ret
SECTION .note.GNU-stack noalloc noexec nowrite progbits
