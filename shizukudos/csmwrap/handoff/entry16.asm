; SPDX-License-Identifier: GPL-2.0-only
; 16-bit entry copied to physical 0x7E00 before ExitBootServices.
; It checks the CSMWRAP handoff and only then enters ShizukuDOS at 0x1000:0000.
; It does not call UEFI and it does not jump to a hard-disk boot sector.
bits 16
org 0x7e00

    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    cmp dword [0x7000], 0x574D5343
    jne hang
    cmp dword [0x7004], 0x00504152
    jne hang
    mov al, [0x707c]
    and al, 0x03
    cmp al, 0x03
    jne hang
    jmp 0x1000:0x0000

hang:
    cli
    hlt
    jmp hang
