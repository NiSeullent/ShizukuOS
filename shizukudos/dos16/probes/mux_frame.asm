; SPDX-License-Identifier: GPL-2.0-only
; Source-written INT2F frame observer. No Windows files or returned pointers read.
bits 16
cpu 386
org 0x100

F_AX equ 0
F_BX equ 2
F_CX equ 4
F_DX equ 6
F_SI equ 8
F_DI equ 10
F_BP equ 12
F_DS equ 14
F_ES equ 16
F_FLAGS equ 18
FRAME_BYTES equ 20
BUFFER_BYTES equ 80
FILL equ 0xa6

; MOV/PUSH/POP do not change flags. Capture before repairing our own DS/ES/DF.
%macro SAVE_FRAME 1
 pushf
 pop word [cs:%1+F_FLAGS]
 mov [cs:%1+F_AX],ax
 mov [cs:%1+F_BX],bx
 mov [cs:%1+F_CX],cx
 mov [cs:%1+F_DX],dx
 mov [cs:%1+F_SI],si
 mov [cs:%1+F_DI],di
 mov [cs:%1+F_BP],bp
 mov [cs:%1+F_DS],ds
 mov [cs:%1+F_ES],es
%endmacro

start:
 cli
 mov ax,cs
 mov ss,ax
 mov sp,stack_end
 mov ds,ax
 mov es,ax
 sti
 cld
 ; No mode switch or pathname argument is accepted.
 xor cx,cx
 mov cl,[0x80]
 cmp cx,127
 ja refuse
 mov si,0x81
.argument:
 jcxz .arguments_done
 lodsb
 cmp al,' '
 je .space
 cmp al,9
 jne refuse
.space:
 loop .argument
.arguments_done:
 mov ax,cs
 add ax,(ds_area - $$ + 0x100) >> 4
 jc refuse
 mov [input_frame+F_DS],ax
 mov ax,cs
 add ax,(query_area - $$ + 0x100) >> 4
 jc refuse
 mov [input_frame+F_ES],ax
 mov dx,heading
 mov cx,heading_end-heading
 call write_stdout
 mov word [case_pointer],cases
 mov word [remaining],4
.case:
 mov di,query_buffer
 mov cx,BUFFER_BYTES
 mov al,FILL
 rep stosb
 mov word [query_before],0x5aa5
 mov word [query_after],0xa55a
 mov si,[case_pointer]
 lodsw
 mov [input_frame+F_AX],ax
 lodsw
 mov [input_frame+F_FLAGS],ax
 mov [case_pointer],si
 mov word [input_frame+F_BX],0xb1b1
 mov word [input_frame+F_CX],0xc2c2
 mov word [input_frame+F_DX],0xd3d3
 mov word [input_frame+F_SI],0x5151
 mov word [input_frame+F_DI],0xd1d1
 mov word [input_frame+F_BP],0xb5b5
 cmp word [input_frame+F_AX],0x1611
 jne .registry_query
 ; Probe policy: deterministic shell query DX=0. RBIL specifies AX only.
 mov word [input_frame+F_DX],0
 jmp .ready
.registry_query:
 mov word [input_frame+F_CX],BUFFER_BYTES
 mov word [input_frame+F_DI],query_buffer-query_area
.ready:
 mov ax,[cs:input_frame+F_DS]
 mov ds,ax
 mov ax,[cs:input_frame+F_ES]
 mov es,ax
 mov bx,[cs:input_frame+F_BX]
 mov cx,[cs:input_frame+F_CX]
 mov dx,[cs:input_frame+F_DX]
 mov si,[cs:input_frame+F_SI]
 mov di,[cs:input_frame+F_DI]
 mov bp,[cs:input_frame+F_BP]
 mov ax,[cs:input_frame+F_AX]
 push word [cs:input_frame+F_FLAGS]
 popf
 SAVE_FRAME input_frame
 int 0x2f
 SAVE_FRAME output_frame
 ; Output registers/flags above remain raw, irrespective of support/error.
 push cs
 pop ds
 push cs
 pop es
 push word 0x0202
 popf
 cld
 call inspect_buffer
 mov si,in_label
 mov bx,input_frame
 mov cx,10
 call emit_words
 mov si,out_label
 mov bx,output_frame
 mov cx,10
 call emit_words
 mov si,buffer_label
 mov bx,buffer_report
 mov cx,5
 call emit_words
 inc word [completed]
 dec word [remaining]
 jnz .case
 mov si,end_label
 mov bx,completed
 mov cx,1
 call emit_words
 mov al,[integrity_failure]
 mov ah,0x4c
 int 0x21

; Mask bits: 0=leading canary intact, 1=trailing intact, 2=NUL within buffer.
; Length FFFF means no NUL. Changed count compares all 80 bytes with FILL.
inspect_buffer:
 mov word [buffer_report],0
 mov word [buffer_report+6],0xffff
 mov word [buffer_report+8],0
 mov ax,[query_before]
 mov [buffer_report+2],ax
 cmp ax,0x5aa5
 jne .leading_bad
 or word [buffer_report],1
 jmp .trailing
.leading_bad:
 mov byte [integrity_failure],1
.trailing:
 mov ax,[query_after]
 mov [buffer_report+4],ax
 cmp ax,0xa55a
 jne .trailing_bad
 or word [buffer_report],2
 jmp .scan
.trailing_bad:
 mov byte [integrity_failure],1
.scan:
 mov si,query_buffer
 xor bx,bx
 mov cx,BUFFER_BYTES
.byte:
 lodsb
 cmp al,FILL
 je .unchanged
 inc word [buffer_report+8]
.unchanged:
 or al,al
 jnz .next
 cmp word [buffer_report+6],0xffff
 jne .next
 mov [buffer_report+6],bx
 or word [buffer_report],4
.next:
 inc bx
 loop .byte
 ret

; SI -> four-byte label, BX -> words, CX=count. One bounded stdout write/row.
emit_words:
 push cx
 push bx
 mov di,line_buffer
 mov cx,4
 rep movsb
 pop si
 pop cx
.word:
 lodsw
 call hex_word
 dec cx
 jz .newline
 mov al,' '
 stosb
 jmp .word
.newline:
 mov ax,0x0a0d
 stosw
 mov cx,di
 sub cx,line_buffer
 mov dx,line_buffer
 call write_stdout
 ret

hex_word:
 push cx
 mov cx,4
.digit:
 rol ax,4
 push ax
 and al,15
 add al,'0'
 cmp al,'9'
 jbe .store
 add al,7
.store:
 stosb
 pop ax
 loop .digit
 pop cx
 ret

write_stdout:
 mov [write_count],cx
 mov bx,1
 mov ah,0x40
 int 0x21
 jc refuse
 cmp ax,[write_count]
 jne refuse
 ret

refuse:
 mov ax,0x4c01
 int 0x21

heading db 'MUXFRAME V1 AX BX CX DX SI DI BP DS ES FLAGS',13,10
heading_end:
in_label db 'IN  '
out_label db 'OUT '
buffer_label db 'BUF '
end_label db 'END '
cases dw 0x1611,0x0202,0x1611,0x0203,0x1613,0x0202,0x1613,0x0203
case_pointer dw 0
remaining dw 0
completed dw 0
write_count dw 0
integrity_failure db 0
align 2
input_frame times FRAME_BYTES db 0
output_frame times FRAME_BYTES db 0
buffer_report times 5 dw 0
line_buffer times 64 db 0
align 16
ds_area times 16 db 0
align 16
query_area:
query_before dw 0x5aa5
query_buffer times BUFFER_BYTES db FILL
query_after dw 0xa55a
align 2
stack_space times 512 db 0
stack_end:
