; SPDX-License-Identifier: GPL-2.0-only
; T_BIOS: BIOS-visible platform contract used by FreeDOS/Windows 98 boot code:
; INT 11h/12h/15h/1Ah/10h/16h, BDA fields, PIT-driven tick advance, A20 wrap.
%include "common.inc"
start:
    int 0x12                       ; conventional memory in KiB
    cmp ax, 480
    jb f_mem
    cmp ax, 640
    ja f_mem
    mov [convk], ax
    int 0x11                       ; equipment word
    mov [equip], ax
    mov ah, 0x88                   ; extended memory above 1 MiB
    clc
    int 0x15
    jc f_ext
    mov [extk], ax
    mov ah, 0x0f                   ; current video mode
    int 0x10
    cmp al, 3
    jne f_video
    mov ah, 0x01                   ; keyboard status: must not block
    int 0x16
    ; BDA: memory size at 0040:0013 must equal INT 12h
    push es
    mov ax, 0x40
    mov es, ax
    mov ax, [es:0x13]
    pop es
    cmp ax, [convk]
    jne f_bda
    ; RTC date: BCD century/year sanity
    mov ah, 0x04
    int 0x1a
    jc f_rtc
    cmp cl, 0x99
    ja f_rtc
    ; tick counter must advance (PIT/IRQ0 -> INT 08h -> BDA) within ~3 s
    mov ah, 0
    int 0x1a
    mov [t0], dx
    mov [t0 + 2], cx
    mov ecx, 0x02000000
.wait:
    push ecx
    mov ah, 0
    int 0x1a
    pop ecx
    cmp dx, [t0]
    jne .ticked
    dec ecx
    jnz .wait
    jmp f_tick
.ticked:
    ; A20: 0000:0500 and FFFF:0510 must be different bytes once A20 is enabled
    push ds
    push es
    xor ax, ax
    mov ds, ax
    mov ax, 0xffff
    mov es, ax
    mov byte [0x500], 0x5a
    mov byte [es:0x510], 0xa5
    mov al, [0x500]
    pop es
    pop ds
    cmp al, 0x5a
    jne f_a20
    mov di, line + 17
    movzx eax, word [convk]
    call print_hex32
    mov di, line + 30
    movzx eax, word [extk]
    call print_hex32
    mov di, line + 45
    movzx eax, word [equip]
    call print_hex32
    mov si, line
    mov cx, line_end - line
    call append_result
    PRINT ok_msg
    mov ax, 0x4c00
    int 0x21
%macro FAIL 2
%1:
    mov si, %2
    mov cx, %2 %+ _end - %2
    call append_result
    PRINT bad_msg
    mov ax, 0x4c01
    int 0x21
%endmacro
    FAIL f_mem, l_mem
    FAIL f_ext, l_ext
    FAIL f_video, l_video
    FAIL f_bda, l_bda
    FAIL f_rtc, l_rtc
    FAIL f_tick, l_tick
    FAIL f_a20, l_a20
line: db 'T_BIOS PASS CONV=00000000 EXT=00000000 EQUIP=00000000', 13, 10
line_end:
l_mem: db 'T_BIOS FAIL int12', 13, 10
l_mem_end:
l_ext: db 'T_BIOS FAIL int15-88', 13, 10
l_ext_end:
l_video: db 'T_BIOS FAIL video-mode', 13, 10
l_video_end:
l_bda: db 'T_BIOS FAIL bda-memsize', 13, 10
l_bda_end:
l_rtc: db 'T_BIOS FAIL rtc', 13, 10
l_rtc_end:
l_tick: db 'T_BIOS FAIL tick-not-advancing', 13, 10
l_tick_end:
l_a20: db 'T_BIOS FAIL a20', 13, 10
l_a20_end:
ok_msg: db 'T_BIOS: platform contract OK', 13, 10, '$'
bad_msg: db 'T_BIOS: FAILED', 13, 10, '$'
convk: dw 0
extk: dw 0
equip: dw 0
t0: dd 0
