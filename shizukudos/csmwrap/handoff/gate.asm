; SPDX-License-Identifier: GPL-2.0-only
; Real-mode gate used by ShizukuDOS stage2. Native BIOS builds a handoff here.
; Windows 98 is reached only when KERNEL64 and this gate have both been recorded.

csmwrap_real_enter:
    push ds
    push es
    push si
    push di
    push cx
    push ax
    xor ax, ax
    mov ds, ax
    mov es, ax
    cmp dword [0x7000], 0x574D5343
    jne .build
    cmp dword [0x7004], 0x00504152
    jne .build
    or byte [0x707c], 0x02
    call csmwrap_seal_handoff
    jmp .done
.build:
    mov di, 0x7000
    mov cx, 132
    xor al, al
    cld
    rep stosb
    mov di, 0x7000
    mov ax, 'CS'
    stosw
    mov ax, 'MW'
    stosw
    mov ax, 'RA'
    stosw
    mov ax, 0x0050
    stosw
    mov ax, 1
    mov [0x7008], ax
    mov word [0x700a], 0
    mov dword [0x700c], 132
    mov dword [0x7010], 1
    mov dword [0x7014], 1
    int 0x12
    movzx eax, ax
    mov [0x7040], eax
    mov byte [0x707c], 0x02
    call csmwrap_seal_handoff
.done:
    pop ax
    pop cx
    pop di
    pop si
    pop es
    pop ds
    ret

; DS must be 0. Checksum low byte makes the 132-byte sum congruent to 0 mod 256.
csmwrap_seal_handoff:
    push si
    push cx
    push ax
    push bx
    mov dword [0x7080], 0
    xor bx, bx
    mov si, 0x7000
    mov cx, 132
.sum:
    lodsb
    add bl, al
    loop .sum
    neg bl
    mov [0x7080], bl
    pop bx
    pop ax
    pop cx
    pop si
    ret

; Returns CF=1 when KERNEL64 or CSMWrap was skipped. Does not chain by itself.
csmwrap_allow_win98:
    push ds
    push ax
    xor ax, ax
    mov ds, ax
    cmp dword [0x7000], 0x574D5343
    jne .no
    cmp dword [0x7004], 0x00504152
    jne .no
    mov al, [0x707c]
    and al, 0x03
    cmp al, 0x03
    jne .no
    pop ax
    pop ds
    clc
    ret
.no:
    pop ax
    pop ds
    stc
    ret

csmwrap_blocked_text:
    db 'CSMWrap and KERNEL64 are required before Windows 98.', 13, 10, 0
