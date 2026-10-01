; SPDX-License-Identifier: GPL-2.0-only
; Original flat, control-only fixture. Interface facts: ../REFERENCES.md.
BITS 32
ORG 0

control:
    pushfd
    cmp eax, 0x23              ; W32_DEVICEIOCONTROL: deliberately no Win32 interface
    je .unsupported
    mov eax, 1                 ; VXD_SUCCESS for lifecycle notifications
    jmp .finish
.unsupported:
    mov eax, 50                ; ERROR_NOT_SUPPORTED
.finish:
    and dword [esp], 0xfffffffe
    popfd                      ; change only CF; no VMM calls or global writes
    ret

times 4096 - ($ - $$) db 0      ; separate code and writable DDB objects
ddb:
    dd 0
    dw 0x040a, 0               ; Win98 DDK version; no allocated device ID
    db 1, 0
    dw 0
    db 'NTWMIN9X'
    dd 0x80000000
    dd control                 ; object-relative zero, replaced by one internal LE fixup
    times 8 dd 0
    dd 0x50726576              ; packed 'Prev' sentinel, not an ASCII string
    dd 80
    dd 0x52737631, 0x52737632, 0x52737633
%if ($ - ddb) != 80
    %error "unexpected DDB size"
%endif
