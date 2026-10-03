; SPDX-License-Identifier: GPL-2.0-only
; Source-written readonly DOS startup-contract observer. Never modifies Windows.
; Only an exclusively created C:\REGADM.TXT is written.
bits 16
cpu 386
org 0x100
start:
    push cs
    pop ds
    push cs
    pop es
    cld
    mov ax,0x5b00
    xor cx,cx
    mov dx,report_path
    int 0x21
    jc refuse
    mov [report],ax
    mov si,version_label
    mov ax,0x3000
    int 0x21
    call record
    mov si,trueversion_label
    mov ax,0x3306
    int 0x21
    call record
    ; Initialized inputs distinguish query output from untouched registers.
    push ds
    push es
    mov ax,0x1611
    xor bx,bx
    xor cx,cx
    xor dx,dx
    int 0x2f
    pushf
    pop word [cs:saved_flags]
    mov [cs:saved_ax],ax
    mov [cs:saved_bx],bx
    mov [cs:saved_cx],cx
    mov [cs:saved_dx],dx
    pop es
    pop ds
    mov si,mux11_label
    call record_saved
    mov si,user_path
    mov di,mux_buffer
    mov cx,user_end-user_path
    rep movsb
    push ds
    push es
    mov di,mux_buffer
    mov cx,80
    mov ax,0x1613
    xor bx,bx
    xor dx,dx
    int 0x2f
    pushf
    pop word [cs:saved_flags]
    mov [cs:saved_ax],ax
    mov [cs:saved_bx],bx
    mov [cs:saved_cx],cx
    mov [cs:saved_dx],dx
    pop es
    pop ds
    mov si,mux13_label
    call record_saved
    cmp byte [mux_before],0x5a
    jne failed
    cmp byte [mux_guard],0xa5
    jne failed
    mov di,mux_buffer
    xor cx,cx
.mux_length:
    cmp byte [di],0
    je .classify
    inc di
    inc cx
    cmp cx,80
    jb .mux_length
    jmp failed
.classify:
    mov [mux_length],cx
    mov si,mux_buffer
    mov di,user_path
    call same_ascii
    mov bx,1
    jz .classified
    mov si,mux_buffer
    mov di,system_path
    call same_ascii
    mov bx,2
    jz .classified
    xor bx,bx
.classified:
    mov ax,[mux_length]
    xor cx,cx
    xor dx,dx
    mov si,muxpath_label
    call record
    mov word [next_path],paths
.next:
    mov si,[next_path]
    lodsw
    mov [next_path],si
    test ax,ax
    jz finish
    mov [path],ax
    mov si,ax
    call write_string
    mov si,newline
    call write_string
    mov dx,[path]
    mov ax,0x4300
    int 0x21
    mov si,attr_label
    call record
    mov dx,[path]
    mov ax,0x3d00
    int 0x21
    jc .open_result
    mov [input],ax
.open_result:
    pushf
    mov si,open_label
    call record
    popf
    jc .next
    mov bx,[input]
    mov ax,0x5700
    int 0x21
    mov si,time_label
    call record
    mov word [header_before],0x5aa5
    mov word [header_after],0xa55a
    mov bx,[input]
    mov cx,24
    mov dx,header
    mov ah,0x3f
    int 0x21
    mov si,read_label
    call record
    cmp word [header_before],0x5aa5
    jne failed
    cmp word [header_after],0xa55a
    jne failed
    cmp word [saved_ax],24
    jne .share
    test word [saved_flags],1
    jnz .share
    xor ax,ax
    cmp dword [header],0x47455243
    jne .header_record
    inc ax
.header_record:
    mov bx,[header+18]
    xor cx,cx
    xor dx,dx
    mov si,header_label
    call record
.share:
    mov byte [mode],0x20
.share_next:
    mov dx,[path]
    mov al,[mode]
    mov ah,0x3d
    int 0x21
    jc .share_result
    mov [second],ax
.share_result:
    pushf
    mov si,share_label
    call record
    popf
    jc .share_done
    mov bx,[second]
    mov ah,0x3e
    int 0x21
    jc failed
    mov word [second],0xffff
.share_done:
    cmp byte [mode],0x40
    je .extended
    mov byte [mode],0x40
    jmp .share_next
.extended:
    mov si,[path]
    mov ax,0x6c00
    mov bx,0x0040
    xor cx,cx
    mov dx,1
    int 0x21
    jc .extended_result
    mov [second],ax
.extended_result:
    pushf
    mov si,extended_label
    call record
    popf
    jc .close
    mov bx,[second]
    mov ah,0x3e
    int 0x21
    jc failed
    mov word [second],0xffff
.close:
    mov bx,[input]
    mov ah,0x3e
    int 0x21
    mov word [input],0xffff
    jc failed
    jmp .next
finish:
    mov si,complete_label
    call write_string
    mov bx,[report]
    mov ah,0x68
    int 0x21
    jc failed
    mov ah,0x3e
    int 0x21
    jc refuse
    mov ax,0x4c00
    int 0x21
failed:
    mov bx,[second]
    cmp bx,0xffff
    je .input
    mov ah,0x3e
    int 0x21
.input:
    mov bx,[input]
    cmp bx,0xffff
    je .report
    mov ah,0x3e
    int 0x21
.report:
    mov bx,[report]
    mov ah,0x3e
    int 0x21
refuse:
    mov ax,0x4c01
    int 0x21
; Save the exact observed register result and flags before report I/O.
record:
    pushf
    pop word [saved_flags]
    mov [saved_ax],ax
    mov [saved_bx],bx
    mov [saved_cx],cx
    mov [saved_dx],dx
record_saved:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    call write_string
    mov ax,[saved_ax]
    call hex_word
    mov ax,[saved_bx]
    call hex_word
    mov ax,[saved_cx]
    call hex_word
    mov ax,[saved_dx]
    call hex_word
    mov ax,[saved_flags]
    call hex_word
    mov si,newline
    call write_string
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret
hex_word:
    mov di,hexbuf
    mov cx,4
.loop:
    rol ax,4
    mov bx,ax
    and bx,15
    mov dl,[digits+bx]
    mov [di],dl
    inc di
    loop .loop
    mov si,hexbuf
    call write_string
    ret
write_string:
    push ax
    push bx
    push cx
    push dx
    push si
    mov dx,si
    xor cx,cx
.count:
    cmp byte [si],0
    je .write
    inc si
    inc cx
    cmp cx,260
    jb .count
    jmp failed
.write:
    mov bx,[report]
    mov ah,0x40
    int 0x21
    jc failed
    cmp ax,cx
    jne failed
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret
same_ascii:
.loop:
    mov al,[si]
    mov ah,[di]
    cmp al,'a'
    jb .left
    cmp al,'z'
    ja .left
    sub al,32
.left:
    cmp ah,'a'
    jb .right
    cmp ah,'z'
    ja .right
    sub ah,32
.right:
    cmp al,ah
    jne .return
    inc si
    inc di
    test al,al
    jnz .loop
.return:
    ret
report dw 0xffff
input dw 0xffff
second dw 0xffff
path dw 0
next_path dw 0
mode db 0
saved_ax dw 0
saved_bx dw 0
saved_cx dw 0
saved_dx dw 0
saved_flags dw 0
mux_length dw 0
header_before dw 0x5aa5
header times 24 db 0
header_after dw 0xa55a
mux_before db 0x5a
mux_buffer times 80 db 0
mux_guard db 0xa5
hexbuf db '0000 ',0
digits db '0123456789ABCDEF'
newline db 13,10,0
version_label db 'VERSION ax bx cx dx flags=',0
trueversion_label db 'TRUEVERSION ax bx cx dx flags=',0
mux11_label db 'MUX1611 ax bx cx dx flags=',0
mux13_label db 'MUX1613 ax bx cx dx flags=',0
muxpath_label db 'MUXPATH length class(0other1user2system) cx dx flags=',0
attr_label db 'ATTR ax bx cx dx flags=',0
open_label db 'OPEN00 ax bx cx dx flags=',0
time_label db 'TIME ax bx cx dx flags=',0
read_label db 'HEADER_READ ax bx cx dx flags=',0
header_label db 'HEADER signature_valid flags_word cx dx flags=',0
share_label db 'SHARE20_THEN40 ax bx cx dx flags=',0
extended_label db 'EXTENDED_READONLY ax bx cx dx flags=',0
complete_label db 'COMPLETE readonly_observation; Windows_success=unverified',13,10,0
report_path db 'C:\REGADM.TXT',0
system_path db 'C:\WINDOWS\SYSTEM.DAT',0
user_path db 'C:\WINDOWS\USER.DAT',0
user_end:
paths dw system_path,user_path,0
