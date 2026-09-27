; SPDX-License-Identifier: GPL-2.0-only
; Linux32 user-mode harness for actual control.o. IRQ/VMM thunks are not called.
BITS 32
GLOBAL _start, ntwv_native_init, ntwv_native_exit, ntwv_native_dioc
EXTERN ntwv_control
SECTION .data
result: dd 1
saved_stack: dd 0
saved_flags: dd 0
expected_eax: dd 1
expected_carry: dd 0
SECTION .text
ntwv_native_init:
ntwv_native_exit:
    pushfd
    pop ecx
    test ecx, 0x400
    jnz fail                     ; C entry must have DF clear
    mov eax, [result]
    mov ecx, 0xbad
    mov edx, 0xbad
    ret
ntwv_native_dioc:
    cmp dword [esp+4], 0x44444444
    jne fail                     ; correct ESI -> cdecl marshalling
    jmp ntwv_native_init
_start:
    mov eax, 0x1b
    call exercise
    mov dword [result], 0
    mov dword [expected_eax], 0
    mov dword [expected_carry], 1
    mov eax, 0x1b
    call exercise
    mov dword [result], 1
    mov dword [expected_eax], 1
    mov dword [expected_carry], 0
    mov eax, 0x1c
    call exercise
    mov dword [result], 998
    mov dword [expected_eax], 998
    mov eax, 0x23
    call exercise
    mov dword [expected_eax], 1
    mov eax, 0x76543210
    call exercise
    cld
    mov eax, 1
    xor ebx, ebx
    int 0x80
exercise:
    mov ebx, 0x11111111
    mov ecx, 0x22222222
    mov edx, 0x33333333
    mov esi, 0x44444444
    mov edi, 0x55555555
    mov ebp, 0x66666666
    mov [saved_stack], esp
    std
    call ntwv_control
    pushfd
    pop dword [saved_flags]
    cmp eax, [expected_eax]
    jne fail
    cmp esp, [saved_stack]
    jne fail
    cmp ebx, 0x11111111
    jne fail
    cmp ecx, 0x22222222
    jne fail
    cmp edx, 0x33333333
    jne fail
    cmp esi, 0x44444444
    jne fail
    cmp edi, 0x55555555
    jne fail
    cmp ebp, 0x66666666
    jne fail
    mov eax, [saved_flags]
    test eax, 0x400
    jz fail                      ; caller DF must be restored
    and eax, 1
    cmp eax, [expected_carry]
    jne fail
    cld
    ret
fail:
    cld
    mov eax, 1
    mov ebx, 1
    int 0x80
SECTION .note.GNU-stack noalloc noexec nowrite progbits
