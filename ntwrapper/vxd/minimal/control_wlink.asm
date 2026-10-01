; SPDX-License-Identifier: GPL-2.0-only
; Separate original OMF fixture for the toolchain's native VxD writer.
BITS 32
segment _TEXT public class=DATA use32
global VXD_DDB
VXD_DDB:
    dd 0
    dw 0x030a, 0
    db 1, 0
    dw 0
    db 'NTWMIN9X'
    dd 0x80000000
    dd control
    times 8 dd 0
    dd 0x50726576, 80, 0x52737631, 0x52737632, 0x52737633
control:
    pushfd
    cmp eax, 0x23
    je .unsupported
    mov eax, 1
    jmp .finish
.unsupported:
    mov eax, 50
.finish:
    and dword [esp], 0xfffffffe
    popfd
    ret
times 8192-($-$$) db 0
