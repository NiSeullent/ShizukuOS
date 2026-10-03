; SPDX-License-Identifier: GPL-2.0-only
; Original readonly bootstrap, derived from public ntwrapper ABI thunks.
BITS 32
GLOBAL ntwv_ddb, ntwv_control, ntwv_irq_enter, ntwv_irq_leave
GLOBAL ntwv_vmm_check, ntwv_vmm_lock, ntwv_vmm_unlock, ntwv_vmm_ptes, ntwv_vmm_map_phys
GLOBAL ntwv_vmcall, ntwv_cpuid
EXTERN ntwv_native_init, ntwv_native_exit, ntwv_native_dioc, ntwv_native_lifecycle

SECTION .ddb progbits alloc noexec write align=4
ntwv_ddb:
    dd 0                       ; next (owned by VMM)
    dw 0x040a, 0               ; Win98 DDK ABI, unassigned device ID
    db 1, 0                    ; component major/minor
    dw 0                       ; flags owned by VMM
    db 'SHZGUARD'              ; exact 8-byte module name
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
    cmp eax, 0x20              ; THREAD_NOT_EXECUTEABLE; EDI = thread
    je .lifecycle
    cmp eax, 0x21              ; DESTROY_THREAD
    je .lifecycle
    cmp eax, 0x0b              ; VM_NOT_EXECUTEABLE; EBX = VM
    je .lifecycle
    cmp eax, 0x0c              ; DESTROY_VM
    je .lifecycle
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
    jmp .success
.lifecycle:
    push edi
    push ebx
    push eax
    call ntwv_native_lifecycle
    add esp, 12
    mov eax, 1                 ; lifecycle broadcast cannot be failed
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
VMM_THREE ntwv_vmm_map_phys, 0x0001006C   ; _MapPhysToLinear(PhysAddr, nBytes, Flags): linear alias in EAX
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

; ShizukuDOS Supervisor hypercall (shz_abi.h): int32_t ntwv_vmcall(op, a, b, uint32_t *ebx_out, uint32_t *ecx_out).
; EAX = opcode, EBX/ECX = arguments; the Supervisor returns the status in EAX and results in EBX/ECX. Only
; executed after ntwv_cpuid confirmed the hypervisor signature: VMCALL outside a VMX guest raises #UD.
ntwv_vmcall:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    mov eax, [ebp + 8]
    mov ebx, [ebp + 12]
    mov ecx, [ebp + 16]
    vmcall
    mov esi, [ebp + 20]
    test esi, esi
    jz .no_ebx
    mov [esi], ebx
.no_ebx:
    mov esi, [ebp + 24]
    test esi, esi
    jz .no_ecx
    mov [esi], ecx
.no_ecx:
    pop esi
    pop ebx
    pop ebp
    ret

; void ntwv_cpuid(uint32_t leaf, uint32_t regs[4])
ntwv_cpuid:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    mov eax, [ebp + 8]
    xor ecx, ecx
    cpuid
    mov esi, [ebp + 12]
    mov [esi], eax
    mov [esi + 4], ebx
    mov [esi + 8], ecx
    mov [esi + 12], edx
    pop esi
    pop ebx
    pop ebp
    ret

SECTION .note.GNU-stack noalloc noexec nowrite progbits
