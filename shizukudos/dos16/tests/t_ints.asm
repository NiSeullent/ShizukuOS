; SPDX-License-Identifier: GPL-2.0-only
; T_INTS: PC BIOS interrupt coverage for a DOS IO.SYS-class kernel.
;
; Exercises, from DOS in real mode, the firmware services a DOS kernel relies on
; at boot and at run time, and writes every raw result to C:\INTS.TXT in a
; line-oriented "KEY name=value ..." format that the host parses
; (shizukudos/dos16/ints.py). One summary line goes to RESULT.TXT.
;
; All BIOS calls run first and results are kept in memory; DOS (INT 21h) is used
; only at the end, so DOS's own Ctrl-C/keyboard polling cannot consume the
; keystrokes the INT 16h checks stuff into the BIOS buffer.
;
; References (expected semantics):
;   INT 10h/11h/12h/13h/15h/16h/1Ah  Ralf Brown's Interrupt List (RBIL) r61;
;                                    IBM PC/AT Technical Reference (BIOS listing)
;   INT 13h AH=41h..48h (EDD)        Phoenix "BIOS Enhanced Disk Drive Specification"
;                                    v1.1 and v3.0 (T13/D1386), device path in 48h
;   INT 15h E820h                    ACPI 6.x sec. 15 "System Address Map Interfaces"
;                                    (INT 15H E820H), 20- and 24-byte entries
;   INT 15h 2400h-2403h              IBM PS/2 BIOS A20 gate services (RBIL)
;   INT 15h C0h                      IBM PS/2 & PC BIOS Interface Tech. Ref., system
;                                    configuration parameters
;   INT 10h 4F00h/4F01h              VESA BIOS Extension (VBE) Core 3.0
;
; Disk writes go only to LBA 2 and LBA 3 of the boot disk: the unused gap between
; the MBR (LBA 0) and the first partition (LBA 63) of the ShizukuDOS test disk.
%include "common.inc"

%macro E 1+                     ; emit literal text
    jmp %%skip
%%t: db %1
%%skip:
    push si
    push cx
    mov si, %%t
    mov cx, %%skip - %%t
    call emit_mem
    pop cx
    pop si
%endmacro

%macro HX 2                     ; emit %1 hex digits of a 32-bit source
    push eax
    mov eax, %2
    push cx
    mov cl, %1
    call emit_hex
    pop cx
    pop eax
%endmacro

%macro HXW 1                    ; emit a 16-bit source as 4 hex digits
    push eax
    movzx eax, %1
    push cx
    mov cl, 4
    call emit_hex
    pop cx
    pop eax
%endmacro

%macro HXB 1                    ; emit an 8-bit source as 2 hex digits
    push eax
    movzx eax, %1
    push cx
    mov cl, 2
    call emit_hex
    pop cx
    pop eax
%endmacro

%macro FAILIF 2                 ; FAILIF cc, bit: record mandatory failure when cc holds
    j%-1 %%ok
    or dword [failmask], 1 << %2
%%ok:
%endmacro

start:
    cld
    mov word [optr], outbuf
    E "INTS 1"
    call nl

; ------------------------------------------------------------- INT 11h / 12h
    int 0x11
    call save
    E "I11 AX="
    HXW word [r_eax]
    push ds
    mov ax, 0x40
    mov ds, ax
    mov ax, [0x10]
    mov bx, [0x13]
    mov cx, [0x0e]
    mov dl, [0x75]
    mov dh, [0x96]
    pop ds
    mov [bda_equip], ax
    mov [bda_mem], bx
    mov [bda_ebda], cx
    mov [bda_hd], dl
    mov [bda_kbd], dh
    E " BDA410="
    HXW word [bda_equip]
    call nl
    mov ax, [r_eax]
    cmp ax, [bda_equip]
    FAILIF ne, 30

    int 0x12
    call save
    E "I12 AX="
    HXW word [r_eax]
    E " BDA413="
    HXW word [bda_mem]
    E " EBDA="
    HXW word [bda_ebda]
    call nl
    mov ax, [r_eax]
    cmp ax, [bda_mem]
    FAILIF ne, 29

; ------------------------------------------------------------- INT 13h
    mov ah, 0x00                    ; reset
    mov dl, 0x80
    int 0x13
    call save
    E "I13_00"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 0

    push es
    xor di, di                      ; RBIL: ES:DI=0000:0000 guards against BIOS bugs
    mov es, di
    mov ah, 0x08
    mov dl, 0x80
    int 0x13
    call save                       ; restores ES=CS
    pop es
    mov al, [r_ecx]                 ; CL: sectors (bits 0-5), cyl bits 8-9 (6-7)
    and al, 0x3f
    mov [geo_spt], al
    mov al, [r_edx + 1]
    inc al
    mov [geo_heads], al
    movzx ax, byte [r_ecx]
    shl ax, 2
    and ax, 0x300
    mov al, [r_ecx + 1]
    inc ax
    mov [geo_cyls], ax
    E "I13_08"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    E " CX="
    HXW word [r_ecx]
    E " DX="
    HXW word [r_edx]
    E " CYLS="
    HXW word [geo_cyls]
    E " HEADS="
    HXB byte [geo_heads]
    E " SPT="
    HXB byte [geo_spt]
    E " BDA475="
    HXB byte [bda_hd]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 1
    cmp byte [r_edx], 0
    FAILIF e, 1
    cmp byte [geo_spt], 0
    FAILIF e, 1

    mov ah, 0x15                    ; read DASD type
    mov dl, 0x80
    int 0x13
    call save
    E "I13_15"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    E " CX="
    HXW word [r_ecx]
    E " DX="
    HXW word [r_edx]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 2
    cmp byte [r_eax + 1], 3
    FAILIF ne, 2

    mov ah, 0x41                    ; EDD installation check
    mov bx, 0x55aa
    mov dl, 0x80
    stc
    int 0x13
    call save
    E "I13_41"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    E " BX="
    HXW word [r_ebx]
    E " CX="
    HXW word [r_ecx]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 3
    cmp word [r_ebx], 0xaa55
    FAILIF ne, 3
    test byte [r_ecx], 1            ; bit 0: fixed disk access subset (42h-44h,47h,48h)
    FAILIF z, 3

    mov di, edd
    mov cx, 0x42
    xor al, al
    rep stosb
    mov word [edd], 0x42            ; EDD 3.0 buffer size
    mov ah, 0x48
    mov dl, 0x80
    mov si, edd
    int 0x13
    call save
    E "I13_48"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    E " SIZE="
    HXW word [edd]
    E " FLAGS="
    HXW word [edd + 0x02]
    E " CYLS="
    HX 8, dword [edd + 0x04]
    E " HEADS="
    HX 8, dword [edd + 0x08]
    E " SPT="
    HX 8, dword [edd + 0x0c]
    E " SECTORS="
    HX 8, dword [edd + 0x14]
    HX 8, dword [edd + 0x10]
    E " BPS="
    HXW word [edd + 0x18]
    cmp word [edd], 0x1e
    jb .edd_done
    E " DPTE="
    HX 8, dword [edd + 0x1a]
    cmp word [edd], 0x42
    jb .edd_done
    E " KEY="
    HXW word [edd + 0x1e]
    E " DPLEN="
    HXB byte [edd + 0x20]
    E " HOSTBUS="
    mov si, edd + 0x24
    mov cx, 4
    call emit_token
    E " IFACE="
    mov si, edd + 0x28
    mov cx, 8
    call emit_token
    E " IPATH="
    HX 8, dword [edd + 0x34]
    HX 8, dword [edd + 0x30]
    E " DPATH="
    HX 8, dword [edd + 0x3c]
    HX 8, dword [edd + 0x38]
.edd_done:
    call nl
    test byte [r_flags], 1
    FAILIF nz, 4

    ; MBR by CHS (0/0/1) and by LBA 0: must be the same known sector
    mov ax, 0x0201
    mov cx, 0x0001
    xor dh, dh
    mov bx, sec1
    call chs_io
    E "I13_02 LBA=00000000"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    E " AL="
    HXB byte [r_eax]
    mov si, sec1
    call fnv
    E " FNV="
    HX 8, eax
    call nl
    test byte [r_flags], 1
    FAILIF nz, 5
    cmp word [sec1 + 510], 0xaa55
    FAILIF ne, 5

    xor eax, eax
    mov bx, sec2
    mov dx, 0x4200
    call lba_io
    E "I13_42 LBA=00000000"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    mov si, sec2
    call fnv
    E " FNV="
    HX 8, eax
    call cmp_sec12
    E " SAME="
    call emit_bool
    call nl
    test byte [r_flags], 1
    FAILIF nz, 6
    test al, al
    FAILIF z, 6

    ; first partition boot sector (LBA 63) by CHS derived from AH=08h geometry and by LBA
    mov ax, 63
    xor dx, dx
    movzx cx, byte [geo_spt]
    div cx                          ; ax = track, dx = sector - 1
    inc dx
    mov [chs_s], dl
    xor dx, dx
    movzx cx, byte [geo_heads]
    div cx                          ; ax = cylinder, dx = head
    mov [chs_h], dl
    mov [chs_c], ax
    mov cl, [chs_s]
    mov ch, al
    shl ah, 6
    or cl, ah
    mov dh, [chs_h]
    mov ax, 0x0201
    mov bx, sec1
    call chs_io
    E "I13_02 LBA=0000003F C="
    HXW word [chs_c]
    E " H="
    HXB byte [chs_h]
    E " S="
    HXB byte [chs_s]
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    mov si, sec1
    call fnv
    E " FNV="
    HX 8, eax
    call nl
    test byte [r_flags], 1
    FAILIF nz, 7
    mov eax, 63
    mov bx, sec2
    mov dx, 0x4200
    call lba_io
    E "I13_42 LBA=0000003F"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    mov si, sec2
    call fnv
    E " FNV="
    HX 8, eax
    call cmp_sec12
    E " SAME="
    call emit_bool
    call nl
    test byte [r_flags], 1
    FAILIF nz, 7
    test al, al
    FAILIF z, 7

    ; write a known pattern to LBA 2 by CHS (0/0/3) and another to LBA 3 by LBA
    mov di, wbuf
    mov si, tag_chs
    mov bl, 0xa5
    call fill_pattern
    mov ax, 0x0301
    mov cx, 0x0003
    xor dh, dh
    mov bx, wbuf
    call chs_io
    E "I13_03 LBA=00000002"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    E " AL="
    HXB byte [r_eax]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 8

    mov di, wbuf
    mov si, tag_lba
    mov bl, 0x5a
    call fill_pattern
    mov eax, 3
    mov bx, wbuf
    mov dx, 0x4300                  ; AL=0: write without verify
    call lba_io
    E "I13_43 LBA=00000003"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 9

    ; read both back the *other* way round
    mov eax, 2
    mov bx, sec1
    mov dx, 0x4200
    call lba_io
    mov di, wbuf
    mov si, tag_chs
    mov bl, 0xa5
    call fill_pattern
    mov si, sec1
    mov di, wbuf
    mov cx, 512
    repe cmpsb
    sete al
    mov [tmp8], al
    E "I13_RB LBA=00000002 VIA=42"
    call emit_cf
    E " MATCH="
    mov al, [tmp8]
    call emit_bool
    call nl
    test byte [r_flags], 1
    FAILIF nz, 10
    cmp byte [tmp8], 1
    FAILIF ne, 10

    mov ax, 0x0201
    mov cx, 0x0004
    xor dh, dh
    mov bx, sec1
    call chs_io
    mov di, wbuf
    mov si, tag_lba
    mov bl, 0x5a
    call fill_pattern
    mov si, sec1
    mov di, wbuf
    mov cx, 512
    repe cmpsb
    sete al
    mov [tmp8], al
    E "I13_RB LBA=00000003 VIA=02"
    call emit_cf
    E " MATCH="
    mov al, [tmp8]
    call emit_bool
    call nl
    test byte [r_flags], 1
    FAILIF nz, 11
    cmp byte [tmp8], 1
    FAILIF ne, 11

; ------------------------------------------------------------- INT 15h E820h
    ; walk 1: 24-byte (ACPI 3.0 extended attributes) requests
    mov byte [e820n], 0
    mov byte [e820end], 'X'
    mov byte [e820size_min], 0xff
    mov byte [e820size_max], 0
    xor ebx, ebx
.e820_next:
    mov di, ent
    mov cx, 24
    xor al, al
    rep stosb
    mov dword [ent + 20], 1         ; ACPI: set bit 0 so a 20-byte BIOS leaves a valid value
    mov eax, 0xe820
    mov edx, 0x534d4150             ; 'SMAP'
    mov ecx, 24
    mov di, ent
    int 0x15
    call save
    test byte [r_flags], 1
    jz .e820_ok
    mov byte [e820end], 'C'         ; CF=1: end of list (allowed after >= 1 entry)
    jmp .e820_done
.e820_ok:
    cmp dword [r_eax], 0x534d4150
    je .e820_sig
    mov byte [e820end], 'S'
    jmp .e820_done
.e820_sig:
    mov al, [r_ecx]
    cmp al, [e820size_min]
    jae .e820_s1
    mov [e820size_min], al
.e820_s1:
    cmp al, [e820size_max]
    jbe .e820_s2
    mov [e820size_max], al
.e820_s2:
    movzx di, byte [e820n]          ; keep the 20 architectural bytes for walk 2
    imul di, di, 20
    add di, e820tab
    mov si, ent
    mov cx, 20
    rep movsb
    E "E820 "
    HXB byte [e820n]
    E " BASE="
    HX 8, dword [ent + 4]
    HX 8, dword [ent]
    E " LEN="
    HX 8, dword [ent + 12]
    HX 8, dword [ent + 8]
    E " TYPE="
    HX 8, dword [ent + 16]
    E " ECX="
    HXB byte [r_ecx]
    E " EXT="
    HX 8, dword [ent + 20]
    E " EBX="
    HX 8, dword [r_ebx]
    call nl
    inc byte [e820n]
    mov ebx, [r_ebx]
    test ebx, ebx
    jnz .e820_more
    mov byte [e820end], 'Z'         ; EBX=0: this was the last entry
    jmp .e820_done
.e820_more:
    cmp byte [e820n], E820MAX
    jb .e820_next
    mov byte [e820end], 'O'         ; overflow of our table: reported, fails on the host
.e820_done:
    E "I15_E820 N="
    HXB byte [e820n]
    E " END="
    mov al, [e820end]
    call emit_char
    E " AH="
    HXB byte [r_eax + 1]
    E " ECXMIN="
    HXB byte [e820size_min]
    E " ECXMAX="
    HXB byte [e820size_max]
    call nl
    cmp byte [e820n], 0
    FAILIF e, 12
    cmp byte [e820end], 'S'
    FAILIF e, 12
    cmp byte [e820end], 'O'
    FAILIF e, 12

    ; walk 2: 20-byte requests must return the same entries, ECX=20 each time
    mov byte [e820n2], 0
    mov byte [tmp8], 1              ; same so far
    xor ebx, ebx
.w2_next:
    mov eax, 0xe820
    mov edx, 0x534d4150
    mov ecx, 20
    mov di, ent
    int 0x15
    call save
    test byte [r_flags], 1
    jnz .w2_done
    cmp dword [r_eax], 0x534d4150
    jne .w2_bad
    cmp byte [r_ecx], 20
    jne .w2_bad
    movzx si, byte [e820n2]
    imul si, si, 20
    add si, e820tab
    mov di, ent
    mov cx, 20
    repe cmpsb
    jne .w2_bad
    jmp .w2_counted
.w2_bad:
    mov byte [tmp8], 0
.w2_counted:
    inc byte [e820n2]
    mov ebx, [r_ebx]
    test ebx, ebx
    jz .w2_done
    cmp byte [e820n2], E820MAX
    jb .w2_next
.w2_done:
    mov al, [e820n2]
    cmp al, [e820n]
    je .w2_count_ok
    mov byte [tmp8], 0
.w2_count_ok:
    E "I15_E820_20 N="
    HXB byte [e820n2]
    E " SAME="
    mov al, [tmp8]
    call emit_bool
    call nl
    cmp byte [tmp8], 1
    FAILIF ne, 13

; ------------------------------------------------------------- INT 15h E801h / 88h / C0h
    mov ax, 0xe801
    xor bx, bx
    xor cx, cx
    xor dx, dx
    clc
    int 0x15
    call save
    E "I15_E801"
    call emit_cf
    E " AX="
    HXW word [r_eax]
    E " BX="
    HXW word [r_ebx]
    E " CX="
    HXW word [r_ecx]
    E " DX="
    HXW word [r_edx]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 14

    mov ah, 0x88
    clc
    int 0x15
    call save
    E "I15_88"
    call emit_cf
    E " AX="
    HXW word [r_eax]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 15

    mov ah, 0xc0
    stc
    int 0x15
    call save
    E "I15_C0"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    E " PTR="
    HXW word [r_es]
    E ":"
    HXW word [r_ebx]
    test byte [r_flags], 1
    jnz .c0_done
    mov fs, [r_es]
    mov bx, [r_ebx]
    E " LEN="
    HXW word [fs:bx]
    E " MODEL="
    HXB byte [fs:bx + 2]
    E " SUB="
    HXB byte [fs:bx + 3]
    E " REV="
    HXB byte [fs:bx + 4]
    E " FEAT="
    HXB byte [fs:bx + 5]
    HXB byte [fs:bx + 6]
    HXB byte [fs:bx + 7]
    HXB byte [fs:bx + 8]
    HXB byte [fs:bx + 9]
.c0_done:
    call nl
    test byte [r_flags], 1
    FAILIF nz, 16

; ------------------------------------------------------------- INT 15h 2400h-2403h (A20)
    mov ax, 0x2403
    int 0x15
    call save
    E "I15_2403"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    E " BX="
    HXW word [r_ebx]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 17

    call a20_status_line            ; "I15_2402 ..." initial state
    mov al, [a20_state]
    mov [a20_initial], al

    mov ax, 0x2400                  ; disable
    int 0x15
    call save
    E "I15_2400"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    call nl
    mov al, [r_flags]
    mov [a20_fl_off], al
    call a20_status_line
    test byte [a20_fl_off], 1
    jnz .a20_skip_off
    cmp byte [a20_wrapv], 1          ; disabled A20 must make FFFF:0500 alias 0000:04F0
    FAILIF ne, 18
.a20_skip_off:

    mov ax, 0x2401                  ; enable
    int 0x15
    call save
    E "I15_2401"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    call nl
    mov al, [r_flags]
    mov [a20_fl_on], al
    call a20_status_line
    test byte [a20_fl_on], 1
    FAILIF nz, 18
    cmp byte [a20_wrapv], 0
    FAILIF ne, 18
    cmp byte [a20_initial], 0       ; leave A20 as DOS had it
    jne .a20_restored
    mov ax, 0x2400
    int 0x15
.a20_restored:

; ------------------------------------------------------------- INT 16h (non-blocking only)
    mov byte [tmp8], 0
.kflush:                            ; drain anything typed so far
    mov ah, 0x01
    int 0x16
    jz .kflushed
    mov ah, 0x00
    int 0x16
    inc byte [tmp8]
    cmp byte [tmp8], 64
    jb .kflush
.kflushed:
    push ds
    mov ax, 0x40
    mov ds, ax
    mov al, [0x17]
    pop ds
    mov [bda_shift], al
    mov ah, 0x02
    int 0x16
    call save
    E "I16_02 AL="
    HXB byte [r_eax]
    E " BDA417="
    HXB byte [bda_shift]
    E " BDA496="
    HXB byte [bda_kbd]
    E " FLUSHED="
    HXB byte [tmp8]
    call nl
    mov ah, 0x12
    int 0x16
    call save
    E "I16_12 AX="
    HXW word [r_eax]
    call nl

    mov ah, 0x01                    ; empty buffer: ZF=1
    int 0x16
    call save
    E "I16_01 STATE=EMPTY"
    call emit_zf
    call nl
    test byte [r_flags], 0x40
    FAILIF z, 19

    mov ah, 0x05                    ; store 'a' (scan 1Eh)
    mov cx, 0x1e61
    int 0x16
    call save
    E "I16_05 CX=1E61"
    call emit_cf
    E " AL="
    HXB byte [r_eax]
    call nl
    mov ah, 0x01
    int 0x16
    call save
    E "I16_01 STATE=QUEUED"
    call emit_zf
    E " AX="
    HXW word [r_eax]
    call nl
    test byte [r_flags], 0x40
    FAILIF nz, 20
    cmp word [r_eax], 0x1e61
    FAILIF ne, 20
    mov ah, 0x00                    ; key is queued: returns immediately
    int 0x16
    call save
    E "I16_00 AX="
    HXW word [r_eax]
    call nl
    cmp word [r_eax], 0x1e61
    FAILIF ne, 20

    mov ah, 0x05                    ; store 'b' (scan 30h)
    mov cx, 0x3062
    int 0x16
    call save
    mov ah, 0x11
    int 0x16
    call save
    E "I16_11 STATE=QUEUED"
    call emit_zf
    E " AX="
    HXW word [r_eax]
    call nl
    test byte [r_flags], 0x40
    FAILIF nz, 21
    cmp word [r_eax], 0x3062
    FAILIF ne, 21
    mov ah, 0x10
    int 0x16
    call save
    E "I16_10 AX="
    HXW word [r_eax]
    call nl
    cmp word [r_eax], 0x3062
    FAILIF ne, 21
    mov ah, 0x11
    int 0x16
    call save
    E "I16_11 STATE=EMPTY"
    call emit_zf
    call nl
    test byte [r_flags], 0x40
    FAILIF z, 21

; ------------------------------------------------------------- INT 1Ah
    mov ah, 0x02                    ; RTC time
    clc
    int 0x1a
    call save
    E "I1A_02"
    call emit_cf
    E " CX="
    HXW word [r_ecx]
    E " DX="
    HXW word [r_edx]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 22
    mov al, [r_ecx + 1]
    mov ah, 0x23
    call bcd_check
    FAILIF c, 22
    mov al, [r_ecx]
    mov ah, 0x59
    call bcd_check
    FAILIF c, 22
    mov al, [r_edx + 1]
    mov ah, 0x59
    call bcd_check
    FAILIF c, 22

    mov ah, 0x00                    ; tick count right after the RTC read
    int 0x1a
    call save
    E "I1A_00 CX="
    HXW word [r_ecx]
    E " DX="
    HXW word [r_edx]
    E " AL="
    HXB byte [r_eax]
    call nl

    mov ah, 0x04                    ; RTC date
    clc
    int 0x1a
    call save
    E "I1A_04"
    call emit_cf
    E " CX="
    HXW word [r_ecx]
    E " DX="
    HXW word [r_edx]
    call nl
    test byte [r_flags], 1
    FAILIF nz, 23
    mov al, [r_ecx + 1]
    mov ah, 0x99
    call bcd_check
    FAILIF c, 23
    mov al, [r_ecx]
    mov ah, 0x99
    call bcd_check
    FAILIF c, 23
    mov al, [r_edx + 1]
    mov ah, 0x12
    call bcd_check
    FAILIF c, 23
    mov al, [r_edx]
    mov ah, 0x31
    call bcd_check
    FAILIF c, 23

; ------------------------------------------------------------- INT 10h
    mov ah, 0x0f
    int 0x10
    call save
    mov al, [r_ebx + 1]
    mov [vpage], al
    push ds
    mov ax, 0x40
    mov ds, ax
    mov al, [0x49]
    mov bx, [0x4a]
    mov cl, [0x84]
    mov dx, [0x63]
    pop ds
    mov [bda_vmode], al
    mov [bda_cols], bx
    mov [bda_rows], cl
    mov [bda_crtc], dx
    E "I10_0F AL="
    HXB byte [r_eax]
    E " AH="
    HXB byte [r_eax + 1]
    E " BH="
    HXB byte [vpage]
    E " BDA449="
    HXB byte [bda_vmode]
    E " BDA44A="
    HXW word [bda_cols]
    E " BDA484="
    HXB byte [bda_rows]
    E " BDA463="
    HXW word [bda_crtc]
    call nl
    cmp byte [r_eax], 3
    FAILIF ne, 24
    cmp byte [r_eax + 1], 80
    FAILIF ne, 24

    mov ah, 0x03
    mov bh, [vpage]
    int 0x10
    call save
    E "I10_03 DX="
    HXW word [r_edx]
    E " CX="
    HXW word [r_ecx]
    call nl

    ; teletype: CR must return to column 0, 6 characters must advance 6 columns
    mov al, 13
    call tty
    mov ah, 0x03
    mov bh, [vpage]
    int 0x10
    mov [cur0], dx
    mov si, tty_text
.tty_loop:
    lodsb
    test al, al
    jz .tty_done
    call tty
    jmp .tty_loop
.tty_done:
    mov ah, 0x03
    mov bh, [vpage]
    int 0x10
    mov [cur1], dx
    ; the characters must be in text memory at B800:(row*80+0)*2 (page 0, mode 3)
    push es
    mov ax, 0xb800
    mov es, ax
    movzx ax, byte [cur0 + 1]
    imul di, ax, 160
    mov si, tty_text
    mov cx, 6
    xor bl, bl
.vram:
    lodsb
    cmp al, [es:di]
    jne .vram_bad
    add di, 2
    loop .vram
    mov bl, 1
.vram_bad:
    pop es
    mov [tmp8], bl
    mov al, 13
    call tty
    mov al, 10
    call tty
    E "I10_0E ROW="
    HXB byte [cur0 + 1]
    E " COL0="
    HXB byte [cur0]
    E " COL1="
    HXB byte [cur1]
    E " VRAM="
    mov al, [tmp8]
    call emit_bool
    call nl
    cmp byte [cur0], 0
    FAILIF ne, 25
    cmp byte [cur1], 6
    FAILIF ne, 25
    mov al, [cur0 + 1]
    cmp al, [cur1 + 1]
    FAILIF ne, 25
    cmp byte [tmp8], 1
    FAILIF ne, 25

    mov ah, 0x12                    ; EGA/VGA information
    mov bl, 0x10
    int 0x10
    call save
    E "I10_12_10 BX="
    HXW word [r_ebx]
    E " CX="
    HXW word [r_ecx]
    call nl
    cmp byte [r_ebx], 0x10          ; BL unchanged = not supported
    FAILIF e, 31

    mov ax, 0x1a00                  ; display combination code
    int 0x10
    call save
    E "I10_1A AL="
    HXB byte [r_eax]
    E " BX="
    HXW word [r_ebx]
    call nl
    cmp byte [r_eax], 0x1a
    FAILIF ne, 26

    mov di, vbeinfo
    mov cx, 512
    xor al, al
    rep stosb
    mov dword [vbeinfo], 'VBE2'
    mov ax, 0x4f00
    mov di, vbeinfo
    int 0x10
    call save
    E "I10_4F00 AX="
    HXW word [r_eax]
    E " SIG="
    mov si, vbeinfo
    mov cx, 4
    call emit_token
    E " VER="
    HXW word [vbeinfo + 4]
    E " CAPS="
    HX 8, dword [vbeinfo + 10]
    E " MEM64K="
    HXW word [vbeinfo + 18]
    E " OEMREV="
    HXW word [vbeinfo + 20]
    ; mode list: count entries up to 0FFFFh, look for 0101h
    xor dx, dx
    mov byte [tmp8], 0
    cmp word [r_eax], 0x004f
    jne .modes_done
    mov fs, [vbeinfo + 16]
    mov si, [vbeinfo + 14]
.modes:
    mov ax, [fs:si]
    cmp ax, 0xffff
    je .modes_done
    cmp ax, 0x0101
    jne .modes_n
    mov byte [tmp8], 1
.modes_n:
    add si, 2
    inc dx
    cmp dx, 1024
    jb .modes
.modes_done:
    mov [nmodes], dx
    E " MODES="
    HXW word [nmodes]
    E " HAS0101="
    mov al, [tmp8]
    call emit_bool
    call nl
    cmp word [r_eax], 0x004f
    FAILIF ne, 27
    cmp dword [vbeinfo], 'VESA'
    FAILIF ne, 27
    cmp word [r_eax], 0x004f
    jne .no_strings
    E "I10_4F00_OEM "
    mov eax, [vbeinfo + 6]
    call emit_farstr
    call nl
    cmp word [vbeinfo + 4], 0x0200
    jb .no_strings
    E "I10_4F00_VENDOR "
    mov eax, [vbeinfo + 22]
    call emit_farstr
    call nl
    E "I10_4F00_PRODUCT "
    mov eax, [vbeinfo + 26]
    call emit_farstr
    call nl
.no_strings:

    mov di, modeinfo
    mov cx, 256
    xor al, al
    rep stosb
    mov ax, 0x4f01
    mov cx, 0x0101                  ; 640x480x8, a standard VESA mode number
    mov di, modeinfo
    int 0x10
    call save
    E "I10_4F01 MODE=0101 AX="
    HXW word [r_eax]
    E " ATTR="
    HXW word [modeinfo]
    E " WINA="
    HXB byte [modeinfo + 2]
    E " GRAN="
    HXW word [modeinfo + 4]
    E " WSIZE="
    HXW word [modeinfo + 6]
    E " SEGA="
    HXW word [modeinfo + 8]
    E " PITCH="
    HXW word [modeinfo + 16]
    E " XRES="
    HXW word [modeinfo + 18]
    E " YRES="
    HXW word [modeinfo + 20]
    E " BPP="
    HXB byte [modeinfo + 25]
    E " MODEL="
    HXB byte [modeinfo + 27]
    E " PHYS="
    HX 8, dword [modeinfo + 40]
    call nl
    cmp word [r_eax], 0x004f
    FAILIF ne, 28

; ------------------------------------------------------------- results
    E "FAILMASK="
    HX 8, dword [failmask]
    call nl
    E "END"
    call nl

    mov dx, ints_name               ; C:\INTS.TXT (create/truncate)
    xor cx, cx
    mov ah, 0x3c
    int 0x21
    jc write_fail
    mov bx, ax
    mov dx, outbuf
    mov cx, [optr]
    sub cx, outbuf
    mov [outlen], cx
    mov ah, 0x40
    int 0x21
    jc write_fail
    cmp ax, [outlen]
    jne write_fail
    mov ah, 0x3e
    int 0x21
    jc write_fail

    cmp dword [failmask], 0
    jne mandatory_fail
    mov si, pass_line
    mov cx, pass_line_end - pass_line
    call append_result
    PRINT ok_msg
    mov ax, 0x4c00
    int 0x21
mandatory_fail:
    mov di, fail_line + 21
    mov eax, [failmask]
    call print_hex32
    mov si, fail_line
    mov cx, fail_line_end - fail_line
    call append_result
    PRINT bad_msg
    mov ax, 0x4c01
    int 0x21
write_fail:
    mov si, wfail_line
    mov cx, wfail_line_end - wfail_line
    call append_result
    PRINT bad_msg
    mov ax, 0x4c02
    int 0x21

; ------------------------------------------------------------- helpers
; save: capture registers and FLAGS right after an INT, then ES := CS.
save:
    pushf
    mov [r_eax], eax
    mov [r_ebx], ebx
    mov [r_ecx], ecx
    mov [r_edx], edx
    mov [r_esi], esi
    mov [r_edi], edi
    mov [r_es], es
    pop word [r_flags]
    push cs
    pop es
    cld
    ret

; chs_io: AX = function/count, CX/DH = CHS, BX = buffer (ES=CS), drive 80h
chs_io:
    mov dl, 0x80
    int 0x13
    jmp save

; lba_io: EAX = LBA, BX = buffer, DX = function (4200h/4300h); one sector
lba_io:
    mov [dap_lba], eax
    mov dword [dap_lba + 4], 0
    mov word [dap_cnt], 1
    mov [dap_off], bx
    mov [dap_seg], cs
    mov ax, dx
    mov dl, 0x80
    mov si, dap
    int 0x13
    jmp save

; cmp_sec12: AL = 1 if sec1 == sec2
cmp_sec12:
    push si
    push di
    push cx
    mov si, sec1
    mov di, sec2
    mov cx, 512
    repe cmpsb
    sete al
    pop cx
    pop di
    pop si
    ret

; fnv: EAX = FNV-1a 32 of the 512 bytes at DS:SI
fnv:
    push cx
    push si
    mov eax, 0x811c9dc5
    mov cx, 512
.l:
    xor al, [si]
    inc si
    imul eax, eax, 0x01000193
    loop .l
    pop si
    pop cx
    ret

; fill_pattern: DI = 512-byte buffer, SI = 16-byte tag, BL = seed.
; bytes 16..511 = (i & 0FFh) XOR seed. The host regenerates the same bytes.
fill_pattern:
    push cx
    mov cx, 16
    rep movsb
    mov cx, 16
.l:
    mov al, cl
    xor al, bl
    stosb
    inc cx
    cmp cx, 512
    jb .l
    pop cx
    ret

; a20_status_line: INT 15h AX=2402h + independent wrap test -> one line
a20_status_line:
    mov ax, 0x2402
    int 0x15
    call save
    mov al, [r_eax]
    mov [a20_state], al
    call a20_wrap
    mov [a20_wrapv], al
    E "I15_2402"
    call emit_cf
    E " AH="
    HXB byte [r_eax + 1]
    E " AL="
    HXB byte [a20_state]
    E " WRAP="
    mov al, [a20_wrapv]
    call emit_bool
    call nl
    ret

; a20_wrap: AL = 1 if FFFF:0500 (phys 1004F0h) aliases 0000:04F0 (A20 masked).
; 0000:04F0 is the BDA inter-application area; both bytes are restored.
a20_wrap:
    push ds
    push es
    push bx
    pushf
    cli
    xor ax, ax
    mov ds, ax
    mov ax, 0xffff
    mov es, ax
    mov bl, [0x4f0]
    mov bh, [es:0x500]
    mov byte [0x4f0], 0x5a
    mov byte [es:0x500], 0xa5
    mov al, [0x4f0]
    mov [es:0x500], bh
    mov [0x4f0], bl
    popf
    pop bx
    pop es
    pop ds
    cmp al, 0xa5
    sete al
    ret

; bcd_check: AL = packed BCD byte, AH = maximum. CF=1 if invalid.
bcd_check:
    push ax
    mov ah, al
    and ah, 0x0f
    cmp ah, 9
    ja .bad
    mov ah, al
    shr ah, 4
    cmp ah, 9
    ja .bad
    pop ax
    cmp ah, al
    ret                             ; CF=1 when max < value
.bad:
    pop ax
    stc
    ret

tty:
    mov ah, 0x0e
    mov bh, [vpage]
    mov bl, 0x07
    int 0x10
    ret

emit_mem:                           ; CX bytes from DS:SI
    push di
    push si
    push cx
    mov di, [optr]
    rep movsb
    mov [optr], di
    pop cx
    pop si
    pop di
    ret

emit_char:                          ; AL
    push di
    mov di, [optr]
    stosb
    mov [optr], di
    pop di
    ret

; emit_token: CX bytes at DS:SI as one token (non-printable/space -> '_')
emit_token:
    push si
    push cx
.l:
    lodsb
    cmp al, 0x21
    jb .sub
    cmp al, 0x7e
    jbe .ok
.sub:
    mov al, '_'
.ok:
    call emit_char
    loop .l
    pop cx
    pop si
    ret

; emit_farstr: EAX = seg:off of an ASCIIZ string, at most 64 chars, printable only
emit_farstr:
    push si
    push cx
    mov si, ax
    shr eax, 16
    mov fs, ax
    mov cx, 64
.l:
    mov al, [fs:si]
    test al, al
    jz .done
    cmp al, 0x20
    jb .sub
    cmp al, 0x7e
    jbe .ok
.sub:
    mov al, '?'
.ok:
    call emit_char
    inc si
    loop .l
.done:
    pop cx
    pop si
    ret

emit_hex:                           ; EAX, CL = digits (1..8)
    push eax
    push ebx
    push cx
    push di
    mov di, [optr]
    mov ch, 8
    sub ch, cl
    shl ch, 2
    xchg cl, ch
    rol eax, cl
    mov cl, ch
    xor ch, ch
.l:
    rol eax, 4
    mov bl, al
    and bl, 0x0f
    add bl, '0'
    cmp bl, '9'
    jbe .s
    add bl, 7
.s:
    mov [di], bl
    inc di
    loop .l
    mov [optr], di
    pop di
    pop cx
    pop ebx
    pop eax
    ret

emit_bool:                          ; AL = 0/1
    push ax
    and al, 1
    add al, '0'
    call emit_char
    pop ax
    ret

emit_cf:
    push ax
    E " CF="
    mov al, [r_flags]
    call emit_bool
    pop ax
    ret

emit_zf:
    push ax
    E " ZF="
    mov al, [r_flags]
    shr al, 6
    call emit_bool
    pop ax
    ret

nl:
    push ax
    mov al, 13
    call emit_char
    mov al, 10
    call emit_char
    pop ax
    ret

E820MAX equ 64

tag_chs:     db 'SHZ-INTS-CHS-W02'
tag_lba:     db 'SHZ-INTS-LBA-W03'
tty_text:    db 'T_INTS', 0
ints_name:   db 'INTS.TXT', 0
pass_line:   db 'T_INTS PASS', 13, 10
pass_line_end:
fail_line:   db 'T_INTS FAIL FAILMASK=00000000', 13, 10
fail_line_end:
wfail_line:  db 'T_INTS FAIL write-ints-txt', 13, 10
wfail_line_end:
ok_msg:      db 'T_INTS: BIOS interrupt coverage recorded in INTS.TXT', 13, 10, '$'
bad_msg:     db 'T_INTS: FAILED', 13, 10, '$'

dap:         db 0x10, 0
dap_cnt:     dw 1
dap_off:     dw 0
dap_seg:     dw 0
dap_lba:     dq 0

failmask:    dd 0

section .bss
optr:        resw 1
outlen:      resw 1
r_eax:       resd 1
r_ebx:       resd 1
r_ecx:       resd 1
r_edx:       resd 1
r_esi:       resd 1
r_edi:       resd 1
r_es:        resw 1
r_flags:     resw 1
bda_equip:   resw 1
bda_mem:     resw 1
bda_ebda:    resw 1
bda_hd:      resb 1
bda_kbd:     resb 1
bda_shift:   resb 1
bda_vmode:   resb 1
bda_cols:    resw 1
bda_rows:    resb 1
bda_crtc:    resw 1
geo_cyls:    resw 1
geo_heads:   resb 1
geo_spt:     resb 1
chs_c:       resw 1
chs_h:       resb 1
chs_s:       resb 1
tmp8:        resb 1
e820n:       resb 1
e820n2:      resb 1
e820end:     resb 1
e820size_min: resb 1
e820size_max: resb 1
a20_state:   resb 1
a20_wrapv:   resb 1
a20_initial: resb 1
a20_fl_off:  resb 1
a20_fl_on:   resb 1
vpage:       resb 1
cur0:        resw 1
cur1:        resw 1
nmodes:      resw 1
edd:         resb 0x50
ent:         resb 24
sec1:        resb 512
sec2:        resb 512
wbuf:        resb 512
e820tab:     resb 20 * E820MAX
vbeinfo:     resb 512
modeinfo:    resb 256
outbuf:      resb 8192
