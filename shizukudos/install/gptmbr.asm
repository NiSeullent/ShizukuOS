; SPDX-License-Identifier: GPL-2.0-only
; ShizukuDOS installed-disk MBR boot code (the 440 code bytes of the protective MBR SHZSETUP writes).
;
; Original code. Legacy BIOS path of a GPT disk: find the first GPT partition whose attribute bit 2 ("legacy BIOS
; bootable", UEFI 2.10 table 5.8) is set, load its first sector to 0000:7C00 and jump there using the GPT hand-over
; convention also used by SYSLINUX's gptmbr (doc/gpt.txt):
;   EAX = 0x54504721 ("!GPT"), DL = BIOS drive, DS:SI -> { u8 0x80; u8 chs[3] = FE FF FF; u8 type = 0xED;
;   u8 chs[3] = FE FF FF; u32 start LBA (low 32 bits); u32 sectors (saturated); u32 GPT entry size; GPT entry }.
; A volume boot record can then use either the 32-bit start (classic partition entry at DS:SI) or the full 64-bit
; start in the copied GPT entry. Progress goes to the BIOS teletype and to COM1 (port 0x3F8) so an unattended
; test can see it: "SHZ-MBR" ... " ->VBR" on success, " FAIL:<c>" on error with c = E (no INT 13h extensions),
; G (no GPT header), P (no legacy-bootable partition), R (disk read error), V (partition sector not 55AA).
; Assumes 512-byte sectors (BIOS INT 13h). Needs a 386 (EAX), as every x86-64 machine has.
        bits 16
        cpu 386
        org 0x0600

HDR     equ 0x0800                      ; GPT header sector
ENT     equ 0x0a00                      ; one sector of partition entries
HAND    equ 0x0c00                      ; hand-over structure for the VBR

start:  cli
        xor ax, ax
        mov ds, ax
        mov es, ax
        mov ss, ax
        mov sp, 0x7c00
        mov si, sp
        mov di, 0x0600
        mov cx, 256
        cld
        rep movsw                       ; relocate: the VBR is loaded where we run now
        jmp 0:reloc
reloc:  sti
        mov [drive], dl
        mov si, msg_hello
        call puts
        mov ah, 0x41                    ; INT 13h extensions present?
        mov bx, 0x55aa
        int 0x13
        mov al, 'E'
        jc fail
        cmp bx, 0xaa55
        jne fail
        test cl, 1                      ; packet (AH=42h) interface
        jz fail
        xor eax, eax
        xor edx, edx
        inc ax                          ; LBA 1: primary GPT header
        mov di, HDR
        call readlba
        mov al, 'G'
        cmp dword [HDR], 'EFI '
        jne fail
        cmp dword [HDR + 4], 'PART'
        jne fail
        mov eax, [HDR + 72]             ; partition entry array LBA
        mov edx, [HDR + 76]
        mov ecx, [HDR + 80]             ; number of entries
        mov bx, [HDR + 84]              ; entry size (128 by the spec; any power of two <= 512 works here)
.sector:
        mov di, ENT
        call readlba
        mov si, ENT
.entry: test byte [si + 48], 4          ; legacy BIOS bootable
        jz .skip
        mov ebp, [si]                   ; and a used entry (type GUID not zero)
        or ebp, [si + 4]
        or ebp, [si + 8]
        or ebp, [si + 12]
        jnz found
.skip:  dec ecx
        jz .none
        add si, bx
        cmp si, ENT + 512
        jb .entry
        add eax, 1                      ; next sector of the array
        adc edx, 0
        jmp .sector
.none:  mov al, 'P'
        jmp fail

found:  mov di, HAND
        mov dword [di], 0xfffffe80      ; active, CHS FE FF FF
        mov dword [di + 4], 0xfffffeed  ; type 0xED, CHS FE FF FF
        mov eax, [si + 32]              ; first LBA
        mov [di + 8], eax
        mov eax, [si + 40]              ; last - first + 1, saturated to 32 bits
        mov edx, [si + 44]
        sub eax, [si + 32]
        sbb edx, [si + 36]
        add eax, 1
        adc edx, 0
        jz .fits
        or eax, byte -1
.fits:  mov [di + 12], eax
        movzx ecx, bx
        mov [di + 16], ecx
        add di, 20
        push si
        rep movsb                       ; copy the GPT entry
        pop si
        mov eax, [si + 32]
        mov edx, [si + 36]
        mov di, 0x7c00
        call readlba
        mov al, 'V'
        cmp word [0x7dfe], 0xaa55
        jne fail
        mov si, msg_go
        call puts
        mov eax, 0x54504721             ; "!GPT"
        mov dl, [drive]
        mov si, HAND
        jmp 0:0x7c00

; EDX:EAX = LBA, DI = buffer (segment 0). One sector. Keeps every register.
readlba:
        pushad
        mov [dap.lba], eax
        mov [dap.lba + 4], edx
        mov [dap.buf], di
        mov si, dap
        mov dl, [drive]
        mov ah, 0x42
        int 0x13
        popad
        jc .err
        ret
.err:   mov al, 'R'
fail:   push ax
        mov si, msg_fail
        call puts
        pop ax
        call putc
        int 0x18                        ; let the BIOS try the next boot device
.hang:  hlt
        jmp .hang

puts:   lodsb
        test al, al
        jz .done
        call putc
        jmp puts
.done:  ret

putc:   pusha
        mov dx, 0x3f8
        out dx, al
        mov ah, 0x0e
        mov bx, 7
        int 0x10
        popa
        ret

dap:    db 16, 0
        dw 1
.buf:   dw 0, 0
.lba:   dq 0
drive:  db 0x80
msg_hello: db "SHZ-MBR", 0
msg_go:    db " ->VBR", 13, 10, 0
msg_fail:  db " FAIL:", 0

%if ($ - $$) > 440
%error "MBR code exceeds 440 bytes"
%endif
        times 440 - ($ - $$) db 0
