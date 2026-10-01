; SPDX-License-Identifier: GPL-2.0-only
; Original diagnostic MBR; no Microsoft boot code or IO.SYS bytes included.
; NASM flat binary, assembled for physical 0000:0600 after self-relocation.
BITS 16
ORG 0x0600

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    cld
    mov si, 0x7c00
    mov di, 0x0600
    mov cx, 256
    rep movsw
    jmp 0x0000:relocated

relocated:
    mov [drive], dl
    ; 115200 baud, 8N1; every later transmit waits at most 65535 polls.
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 1
    out dx, al
    inc dx
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 3
    out dx, al
    sti
    mov al, 'S'
    call marker
    mov ax, 3
    int 0x10
    mov ah, 0x0f
    int 0x10
    cmp ax, 0x5003             ; AH=80 columns, AL=mode03
    jne fail
    cmp word [0x044a], 80
    jne fail
    cmp byte [0x0484], 24      ; BDA stores rows minus one
    jne fail
    cmp word [0x0485], 16
    jne fail
    cmp word [0x044c], 4096
    jne fail
    mov al, 'T'
    call marker

    ; The relocated partition table is at 0600+446. No guessed disk/index.
    xor bp, bp
    mov si, 0x07be
    mov cx, 4
.partition:
    mov al, [si]
    test al, al
    jz .next
    cmp al, 0x80
    jne fail
    test bp, bp
    jnz fail                  ; more than one active primary partition
    mov bp, si
.next:
    add si, 16
    loop .partition
    test bp, bp
    jz fail
    mov al, [bp+4]
    cmp al, 0x06
    je .fat
    cmp al, 0x0e
    je .fat
    sub al, 0x0b
    cmp al, 1
    ja fail
.fat:
    mov eax, [bp+8]
    test eax, eax
    jz fail
    mov [dap+8], eax
    mov ecx, [bp+12]
    test ecx, ecx
    jz fail
    add ecx, eax
    jc fail                   ; this boot profile confines MBR end to 32 bits
    mov edi, ecx              ; exclusive end of selected partition
    jmp short disk

fail:
    mov al, 'F'
    call marker
%ifdef TEST_DEBUG_EXIT
    mov dx, 0x00f4
    mov al, 0x11
    out dx, al                ; test-only isa-debug-exit, never normal builds
%endif
    cli
.halt:
    hlt
    jmp .halt

disk:
    mov dl, [drive]
    cmp dl, 0x80
    jb fail
    mov bx, 0x55aa
    mov ah, 0x41
    int 0x13
    jc fail
    cmp bx, 0xaa55
    jne fail
    test cl, 1
    jz fail
    ; AH48 parameters use private low-memory scratch, outside MBR and VBR.
    mov si, 0x0500
    mov word [si], 0x001a
    mov dl, [drive]
    mov ah, 0x48
    int 0x13
    jc fail
    cmp word [si], 0x001a
    jb fail
    cmp word [si+24], 512
    jne fail
    cmp dword [si+20], 0       ; number of disk sectors (high dword)
    jne .fits
    cmp [si+16], edi
    jb fail
.fits:
    mov al, 'D'
    call marker
    mov si, dap
    mov dl, [drive]
    mov ah, 0x42
    int 0x13
    jc fail
    cmp word [0x7dfe], 0xaa55
    jne fail
    mov al, 'C'
    call marker
%ifdef TEST_DEBUG_EXIT
    mov dx, 0x00f4
    mov al, 0x10
    out dx, al                ; only after all guards and signed VBR read
    cli
.test_halt:
    hlt
    jmp .test_halt
%endif
    ; Canonical MBR -> original Windows VBR contract. IO.SYS remains original.
    mov si, bp                ; DS:SI points to selected 16-byte MBR entry
    mov dl, [drive]
    jmp 0x0000:0x7c00

marker:
    mov [marker_byte], al
    pusha
    mov si, prefix
    mov cx, 9
.prefix:
    lodsb
    call putchar
    loop .prefix
    popa
    ret

putchar:
    pusha
    mov ah, al
    mov dx, 0x3fd
    mov cx, 0xffff
.wait:
    in al, dx
    test al, 0x20
    jnz .ready
    loop .wait
    jmp .done                 ; absent/stalled UART must not stall boot
.ready:
    mov al, ah
    mov dl, 0xf8
    out dx, al
.done:
    popa
    ret

prefix: db 'IOGOP:'
marker_byte: db '?', 13, 10
drive: db 0
align 4, db 0
dap: db 0x10, 0
     dw 1, 0x7c00, 0
     dq 0

%if ($-$$) > 440
    %error "boot probe exceeds the MBR executable area (disk identity must survive)"
%endif
times 440-($-$$) db 0
times 6 db 0                  ; caller must preserve original disk identity
times 64 db 0                 ; caller must replace with original partition table
dw 0xaa55
