; SPDX-License-Identifier: GPL-2.0-only -- original thunks; pinned Win98 DDK
; declaration order and service topic contracts are recorded in REFERENCES.md.
BITS 32
GLOBAL ntwv_vmm_system_vm, ntwv_vmm_current_vm, ntwv_vmm_current_thread, ntwv_vmm_now_ms
GLOBAL ntwv_vmm_open_event, ntwv_vmm_set_event, ntwv_vmm_close_event
GLOBAL ntwv_vmm_schedule_event, ntwv_vmm_cancel_event
GLOBAL ntwv_vmm_schedule_timeout, ntwv_vmm_cancel_timeout
GLOBAL ntwv_pma_event_thunk, ntwv_pma_timeout_thunk
EXTERN ntwv_pma_event, ntwv_pma_timeout
SECTION .text progbits alloc exec nowrite align=16
ntwv_vmm_system_vm:
    push ebx
    int 0x20
    dd 0x00010003
    mov eax, ebx
    pop ebx
    ret
ntwv_vmm_current_vm:
    push ebx
    int 0x20
    dd 0x00010001
    mov eax, ebx
    pop ebx
    ret
ntwv_vmm_current_thread:
    push edi
    int 0x20
    dd 0x00010108
    mov eax, edi
    pop edi
    ret
ntwv_vmm_now_ms:
    int 0x20
    dd 0x0001003f
    ret
; _VWIN32_OpenVxDHandle(Win32Handle, OPENVXD_TYPE_EVENT): original VWIN32.H
; explicitly pushes both cdecl arguments and performs caller cleanup.
ntwv_vmm_open_event:
    push dword 1
    push dword [esp + 8]
    int 0x20
    dd 0x002a0025
    add esp, 8
    ret
; The original help specifies the owned ring0 handle in EAX and success in EAX.
ntwv_vmm_set_event:
    mov eax, [esp + 4]
    int 0x20
    dd 0x002a000e
    ret
ntwv_vmm_close_event:
    mov eax, [esp + 4]
    int 0x20
    dd 0x002a0014
    ret
ntwv_vmm_schedule_event:
    push ebx
    push esi
    push edi
    int 0x20
    dd 0x00010003
    xor eax, eax                ; no Windows priority policy change
    mov ecx, 0x4b               ; STI | NOT_CRIT | ALWAYS_SCHED | NOT_NESTED_EXEC
    mov edx, [esp + 16]
    mov esi, ntwv_pma_event_thunk
    xor edi, edi                ; no timeout bypass of VM/context restrictions
    int 0x20
    dd 0x0001015a
    mov eax, esi
    pop edi
    pop esi
    pop ebx
    ret
ntwv_vmm_cancel_event:
    push esi
    mov esi, [esp + 8]
    int 0x20
    dd 0x0001015b
    pop esi
    ret
ntwv_vmm_schedule_timeout:
    push esi
    mov eax, [esp + 8]
    mov edx, [esp + 12]
    mov esi, ntwv_pma_timeout_thunk
    int 0x20
    dd 0x0001003c
    mov eax, esi
    pop esi
    ret
ntwv_vmm_cancel_timeout:
    push esi
    mov esi, [esp + 8]
    int 0x20
    dd 0x0001003e
    pop esi
    ret
ntwv_pma_event_thunk:
    pushad
    cld
    push edx                    ; DDK RefData
    push edi                    ; actual current VMM thread
    push ebx                    ; actual current VM
    call ntwv_pma_event
    add esp, 12
    popad
    cld
    sti                         ; callback contract requires enabled IF/clear DF
    ret
ntwv_pma_timeout_thunk:
    pushad
    cld
    push edx
    call ntwv_pma_timeout
    add esp, 4
    popad
    cld
    sti
    ret
SECTION .note.GNU-stack noalloc noexec nowrite progbits
