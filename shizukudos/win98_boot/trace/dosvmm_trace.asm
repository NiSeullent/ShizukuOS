; SPDX-License-Identifier: GPL-2.0-or-later
; Original ShizukuOS measurement harness. No Microsoft code or binary input.
; A developer explicitly runs DOSVMM /I once in a disposable comparison boot.
; Emits bounded E9 register records; guest execution has not yet been validated.
; The resident hook chains every request and preserves the chain's result.
; It does not simulate Windows broadcasts, alter DOSMGR replies or claim support.
bits 16
cpu 386
org 0x100

    jmp install

old2f: dd 0
next_id: dw 0
dropped_id: dw 0
prefix: db 'SHZVMM1 ',0
hex_digits: db '0123456789ABCDEF'

; Saved frame: ES+0 DS+2 EDI+4 ESI+8 EBP+12 ESP+16 EBX+20
; EDX+24 ECX+28 EAX+32 FLAGS+36. No service calls or mutable DOS data.
%macro TRACE 3
    pushf
    cli
    pushad
    push ds
    push es
    mov bp,sp
    mov al,%1
    mov dx,%2
    mov si,%3
    call record
    pop es
    pop ds
    popad
    popf
%endmacro

handler:
    pushf
    cmp ax,0x1603
    je selected
    cmp ax,0x1605
    je selected
    cmp ax,0x1606
    je selected
    cmp ax,0x4601
    je selected
    cmp ax,0x4602
    je selected
    cmp ax,0x1607
    jne passthrough
    cmp bx,0x0015
    jne passthrough
selected:
    cmp word [cs:next_id],4096
    jae passthrough
    inc word [cs:next_id]
    popf
    ; Entry FLAGS comes from the caller's original interrupt frame, at +42.
    TRACE 'E', [cs:next_id], [ss:bp+42]
    push word [cs:next_id]
    ; The old handler must receive original caller FLAGS, including IF/TF.
    ; Current ISR FLAGS has IF/TF cleared and cannot seed its IRET frame.
    push bp
    mov bp,sp
    push word [ss:bp+8]
    mov bp,[ss:bp]
    call far [cs:old2f]
    pop word [cs:dropped_id] ; discard saved BP without altering returned BP/FLAGS
    ; Return FLAGS is the chain's actual result, saved at +36; local id at +38.
    TRACE 'R', [ss:bp+38], [ss:bp+36]
    pop word [cs:dropped_id]
    ; Discard the original input FLAGS; preserve returned FLAGS and registers.
    retf 2
passthrough:
    popf
    jmp far [cs:old2f]

; AL=phase, DX=id, SI=recorded flags, BP=saved caller register frame.
record:
    push ax
    push dx
    push si
    mov si,prefix
.prefix:
    mov al,[cs:si]
    inc si
    test al,al
    jz .phase
    out 0xe9, al
    jmp .prefix
.phase:
    pop di
    pop dx
    pop ax
    out 0xe9, al
    mov ax,dx
    call spaced_hex
    mov ax,[ss:bp+32]
    call spaced_hex
    mov ax,[ss:bp+20]
    call spaced_hex
    mov ax,[ss:bp+28]
    call spaced_hex
    mov ax,[ss:bp+24]
    call spaced_hex
    mov ax,[ss:bp+2]
    call spaced_hex
    mov ax,[ss:bp+8]
    call spaced_hex
    mov ax,[ss:bp+0]
    call spaced_hex
    mov ax,[ss:bp+4]
    call spaced_hex
    mov ax,[ss:bp+12]
    call spaced_hex
    mov ax,di
    call spaced_hex
    mov al,13
    out 0xe9, al
    mov al,10
    out 0xe9, al
    ret

spaced_hex:
    push ax
    mov al,' '
    out 0xe9, al
    pop dx
    mov cx,4
.hex:
    rol dx,4
    mov bx,dx
    and bx,0x000f
    mov al,[cs:hex_digits+bx]
    out 0xe9, al
    loop .hex
    ret
resident_end:

install:
    ; Activation is explicit, never part of the ordinary user AUTOEXEC profile.
    mov ax,cs
    mov ds,ax
    mov si,0x81
    xor cx,cx
    mov cl,[0x80]
.trim:
    jcxz usage
    cmp byte [si],' '
    jne .option
    inc si
    dec cx
    jmp .trim
.option:
    cmp cx,2
    jne usage
    cmp byte [si],'/'
    jne usage
    mov al,[si+1]
    and al,0xdf
    cmp al,'I'
    jne usage
    mov ax,0x352f
    int 0x21
    mov [old2f],bx
    mov [old2f+2],es
    ; Refuse a duplicate installation of this exact hook at the chain head.
    cmp bx,handler
    jne .install
    cmp word [es:old2f+8],0x4853
    je usage
.install:
    mov dx,handler
    mov ax,0x252f
    int 0x21
    mov dx,(resident_end-$$+0x100+15)/16
    mov ax,0x3100
    int 0x21
usage:
    mov dx,usage_text
    mov ah,9
    int 0x21
    mov ax,0x4c40
    int 0x21
usage_text: db 'DOSVMM /I : opt-in DOS/VMM E9 trace, once per disposable control boot.',13,10,'$'
