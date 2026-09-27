; SPDX-License-Identifier: GPL-2.0-only
; Original NASM ABI bridge. Factual constants: REFERENCES.md.
BITS 32
GLOBAL ntwv_ddb, ntwv_control, ntwv_irq_enter, ntwv_irq_leave
GLOBAL ntwv_vmm_check, ntwv_vmm_lock, ntwv_vmm_unlock, ntwv_vmm_ptes
EXTERN ntwv_native_init, ntwv_native_exit, ntwv_native_dioc

SECTION .ddb progbits alloc noexec write align=4
ntwv_ddb:
    dd 0                       ; next (owned by VMM)
    dw 0x040a, 0               ; Win98 DDK ABI, unassigned device ID
    db 1, 0                    ; component major/minor
    dw 0                       ; flags owned by VMM
    db 'NTWRAP9X'              ; exact 8-byte module name
    dd 0x80000000              ; undefined initialization order
    dd ntwv_control            ; must receive LE internal relocation
    times 8 dd 0               ; V86/PM API, CSIP, reference, services, Win32
    dd 0x50726576              ; DDB_Prev initial sentinel ('Prev')
    dd 80                      ; Windows4.x DDB size
    dd 0x52737631, 0x52737632, 0x52737633

SECTION .text progbits alloc exec nowrite align=16
ntwv_control:
    pushfd
    pushad
    cld
    cmp eax, 0x1b              ; SYS_DYNAMIC_DEVICE_INIT
    je .initialize
    cmp eax, 0x1c              ; SYS_DYNAMIC_DEVICE_EXIT
    je .shutdown
    cmp eax, 0x23              ; W32_DEVICEIOCONTROL; ESI = VWIN32 DIOC
    je .dioc
    mov eax, 1                 ; ignore other broadcast notifications
    jmp .success
.initialize:
    call ntwv_native_init
    jmp .boolean
.shutdown:
    call ntwv_native_exit
.boolean:
    test eax, eax
    jnz .success
    or dword [esp + 32], 1     ; failure CF in caller's saved EFLAGS
    jmp .restore
.dioc:
    push esi
    call ntwv_native_dioc
    add esp, 4
.success:
    and dword [esp + 32], ~1   ; DIOC uses EAX error + clear carry
.restore:
    mov [esp + 28], eax
    popad
    popfd                      ; preserve caller IF/DF and non-result flags
    ret

; cdecl lock callbacks. Suitable only for UP synchronous, non-reentrant use.
ntwv_irq_enter:
    pushfd
    pop eax
    cli
    ret
ntwv_irq_leave:
    push dword [esp + 8]
    popfd
    ret

; VMM C services expect arguments immediately above the INT20 return context;
; repush cdecl arguments so our own near return address is not seen as arg1.
%macro VMM_THREE 2
%1:
    push ebp
    mov ebp, esp
    push dword [ebp + 16]
    push dword [ebp + 12]
    push dword [ebp + 8]
    int 0x20
    dd %2
    add esp, 12
    pop ebp
    ret
%endmacro
VMM_THREE ntwv_vmm_check,  0x00010067
VMM_THREE ntwv_vmm_lock,   0x00010063
VMM_THREE ntwv_vmm_unlock, 0x00010064
ntwv_vmm_ptes:
    push ebp
    mov ebp, esp
    push dword [ebp + 20]
    push dword [ebp + 16]
    push dword [ebp + 12]
    push dword [ebp + 8]
    int 0x20
    dd 0x00010061
    add esp, 16
    pop ebp
    ret

SECTION .note.GNU-stack noalloc noexec nowrite progbits
