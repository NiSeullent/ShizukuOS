; SPDX-License-Identifier: GPL-2.0-only
; Original minimal DOS-style MBR for ShizukuDOS test disks.
; BIOS loads this to 0000:7C00 with DL = boot drive. It relocates itself, picks the
; first partition entry flagged active (0x80), reads that partition's boot sector by
; CHS from the entry, verifies the 0xAA55 signature and jumps to it with DL preserved
; and DS:SI -> the partition entry (the convention DOS boot sectors expect).
bits 16
org 0x600

start:
    cli
    xor ax, ax
    mov ss, ax
    mov sp, 0x7c00
    mov ds, ax
    mov es, ax
    mov si, sp
    mov di, 0x600
    mov cx, 256
    cld
    rep movsw
    jmp 0:relocated
relocated:
    sti
    mov [boot_drive], dl
    mov si, 0x600 + 446
    mov cx, 4
.scan:
    test byte [si], 0x80
    jnz .found
    add si, 16
    loop .scan
    mov si, msg_noactive
    jmp fail
.found:
    mov bp, si                    ; keep the entry pointer across the BIOS call
    mov dl, [boot_drive]
    mov dh, [si + 1]              ; head
    mov cx, [si + 2]              ; cylinder/sector packed as INT 13h expects
    mov bx, 0x7c00
    mov ax, 0x0201
    int 0x13
    jc .diskerr
    cmp word [0x7c00 + 510], 0xaa55
    jne .badsig
    mov si, bp
    mov dl, [boot_drive]
    jmp 0:0x7c00
.diskerr:
    mov si, msg_disk
    jmp fail
.badsig:
    mov si, msg_sig
fail:
    lodsb
    or al, al
    jz .hang
    mov ah, 0x0e
    mov bx, 7
    int 0x10
    jmp fail
.hang:
    cli
    hlt
    jmp .hang

boot_drive: db 0
msg_noactive: db 'No active partition', 0
msg_disk: db 'Disk read error', 0
msg_sig: db 'Bad boot signature', 0

times 446 - ($ - $$) db 0
times 64 db 0
dw 0xaa55
