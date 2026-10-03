; SPDX-License-Identifier: GPL-2.0-only
; Transparent diagnostic wrapper for one explicit, flat DOS COM target.
bits 16
org 100h
jmp start
CAPACITY equ 128
RECORD_BYTES equ 36
old21 dd 0
old2f dd 0
owner dw 0
child dw 0
busy db 0
armed db 0
selected_class dw 0
current_record dw 0
caller_flags dw 0
handles times 256 db 0
winpath times 80 db 0
systempath times 80 db 0
userpath times 80 db 0
sysname db 'SYSTEM.DAT',0
username db 'USER.DAT',0
logpath db 'C:\REGTRACE.BIN',0
message db 'REGTRACE metadata buffer segment:offset=', '$'
colon db ':','$'
newline db 13,10,'$'
error_msg db 'REGTRACE refused or failed; no diagnostic success claim.',13,10,'$'
; Header: magic, version, count, capacity, overflow, admitted child PSP.
trace_header db 'RT21'
dw 1
trace_count dw 0
dw CAPACITY
trace_overflow dw 0
trace_child dw 0
trace_records times CAPACITY*RECORD_BYTES db 0
trace_end:
param dw 0
cmdptr dw command_tail,0
fcb1 dw 5ch,0
fcb2 dw 6ch,0
command_tail db 0,13
header_check dw 0
log_expected dw 0

%macro HOOK 3
%1:
 pushf
 cmp byte [cs:busy],0
 jne %%chain
 popf
 pushf
 pusha
 push ds
 push es
 mov bp,sp
 mov ax,%2
 call pre_record
 jc %%unselected
 ; Original interrupt FLAGS are forwarded as the old handler's IRET frame.
 mov ax,[ss:bp+26]
 mov [cs:caller_flags],ax
 pop es
 pop ds
 popa
 popf
 push word [cs:caller_flags]
 call far [cs:%3]
 pushf
 pusha
 push ds
 push es
 mov bp,sp
 call post_record
 ; Copy the exact returned FLAGS to our original caller's interrupt frame.
 mov ax,[ss:bp+20]
 mov [ss:bp+26],ax
 pop es
 pop ds
 popa
 popf
 iret
%%unselected:
 pop es
 pop ds
 popa
 popf
 jmp far [cs:%3]
%%chain:
 popf
 jmp far [cs:%3]
%endmacro
HOOK hook21,21h,old21
HOOK hook2f,2fh,old2f

; Saved frame: ES DS DI SI BP SP BX DX CX AX entryFLAGS IP CS callerFLAGS.
; No guest data buffer or registry header contents are read by these routines.
pre_record:
 push cs
 pop es
 mov di,ax
 cmp byte [cs:armed],1
 jne .skip
 cmp di,2fh
 jne .dos
 cmp word [ss:bp+18],1611h
 jne .skip
 jmp .identity
.dos:
 mov ax,[ss:bp+18]
 cmp ah,3dh
 je .identity
 cmp ax,4301h
 je .identity
 cmp ah,3eh
 je .identity
 cmp ah,3fh
 je .identity
 cmp ah,40h
 je .identity
 cmp ah,42h
 je .identity
 cmp ah,68h
 jne .skip
.identity:
 mov byte [cs:busy],1
 ; AH=51h is the documented always-available current-PSP query.
 ; This calls the original vector directly, never our hook.
 push bp
 push di
 pushf
 mov ax,5100h
 pushf
 call far [cs:old21]
 popf
 pop di
 pop bp
 cmp bx,[cs:owner]
 je .skip
 mov ds,bx
 mov ax,[16h]
 cmp ax,[cs:owner]
 jne .skip
 cmp word [cs:child],0
 jne .known
 ; This wrapper explicitly admits only flat COM: first caller CS is its PSP.
 cmp bx,[ss:bp+24]
 jne .skip
 mov [cs:child],bx
 mov [cs:trace_child],bx
.known:
 cmp bx,[cs:child]
 jne .skip
 mov dx,bx
 xor ax,ax
 mov [cs:selected_class],ax
 cmp di,2fh
 je .allocate
 mov ax,[ss:bp+18]
 cmp ah,3dh
 je .pathname
 cmp ax,4301h
 je .pathname
 mov bx,[ss:bp+12]
 cmp bx,256
 jae .skip
 mov al,[cs:handles+bx]
 xor ah,ah
 or al,al
 jz .skip
 mov [cs:selected_class],ax
 jmp .allocate
.pathname:
 mov ds,[ss:bp+2]
 mov si,[ss:bp+14]
 mov bx,systempath
 call path_equal
 jnc .system
 mov si,[ss:bp+14]
 mov bx,userpath
 call path_equal
 jc .skip
 mov word [cs:selected_class],1
 jmp .allocate
.system:
 mov word [cs:selected_class],2
.allocate:
 cmp word [cs:trace_count],CAPACITY
 jb .room
 mov word [cs:trace_overflow],1
 jmp .skip
.room:
 mov ax,[cs:trace_count]
 inc word [cs:trace_count]
 mov bx,RECORD_BYTES
 mul bx
 mov bx,trace_records
 add bx,ax
 mov [cs:current_record],bx
 mov byte [cs:busy],1
 mov [cs:bx],di
 mov ax,[ss:bp+18]
 mov [cs:bx+2],ax
 mov ax,[ss:bp+12]
 mov [cs:bx+4],ax
 mov ax,[ss:bp+16]
 mov [cs:bx+6],ax
 mov ax,[ss:bp+14]
 mov [cs:bx+8],ax
 mov ax,[ss:bp+22]
 mov [cs:bx+10],ax
 mov ax,[ss:bp+24]
 mov [cs:bx+12],ax
 mov ax,[cs:child]
 mov [cs:bx+14],ax
 mov ax,[cs:selected_class]
 mov [cs:bx+16],ax
 clc
 ret
.skip:
 mov byte [cs:busy],0
 stc
 ret

; DS:SI compared with CS:BX; at most 79 bytes, including NUL.
; Segment wrap, missing NUL, and different paths are unclassified.
path_equal:
 push cx
 mov cx,79
.next:
 cmp si,0ffffh
 je .no
 mov al,[ds:si]
 cmp al,'a'
 jb .upper
 cmp al,'z'
 ja .upper
 sub al,32
.upper:
 cmp al,[cs:bx]
 jne .no
 inc si
 inc bx
 or al,al
 jz .yes
 loop .next
.no:
 pop cx
 stc
 ret
.yes:
 pop cx
 clc
 ret

post_record:
 mov bx,[cs:current_record]
 ; Returned AX,BX,CX,DX,SI,DI,BP,DS and FLAGS, without dereferencing buffers.
 mov ax,[ss:bp+18]
 mov [cs:bx+18],ax
 mov ax,[ss:bp+12]
 mov [cs:bx+20],ax
 mov ax,[ss:bp+16]
 mov [cs:bx+22],ax
 mov ax,[ss:bp+14]
 mov [cs:bx+24],ax
 mov ax,[ss:bp+6]
 mov [cs:bx+26],ax
 mov ax,[ss:bp+4]
 mov [cs:bx+28],ax
 mov ax,[ss:bp+8]
 mov [cs:bx+30],ax
 mov ax,[ss:bp+2]
 mov [cs:bx+32],ax
 mov ax,[ss:bp+20]
 mov [cs:bx+34],ax
 test word [ss:bp+20],1
 jnz .done
 cmp word [cs:bx],21h
 jne .done
 mov ax,[cs:bx+2]
 cmp ah,3dh
 jne .close
 mov si,[ss:bp+18]
 cmp si,256
 jae .done
 mov ax,[cs:bx+16]
 mov [cs:handles+si],al
 jmp .done
.close:
 cmp ah,3eh
 jne .done
 mov si,[cs:bx+4]
 cmp si,256
 jae .done
 mov byte [cs:handles+si],0
.done:
 mov byte [cs:busy],0
 ret

start:
 cli
 mov ax,cs
 mov ss,ax
 mov sp,stack_end
 sti
 push cs
 pop ds
 push cs
 pop es
 cld
 mov [owner],ax
 mov [cmdptr+2],ax
 mov [fcb1+2],ax
 mov [fcb2+2],ax
 ; One explicit rooted ASCII DOS83 pathname; no switches or command tail.
 xor cx,cx
 mov cl,[80h]
 cmp cx,76
 jae refused
 mov si,81h
.skipspace:
 cmp byte [si],' '
 jne .argument
 inc si
 loop .skipspace
 jmp refused
.argument:
 cmp cx,12
 jb refused
 mov di,winpath
 mov bx,0
.copy:
 lodsb
 cmp al,'a'
 jb .uppercase
 cmp al,'z'
 ja .uppercase
 sub al,32
.uppercase:
 cmp al,' '
 je refused
 cmp al,33
 jb refused
 cmp al,126
 ja refused
 stosb
 inc bx
 loop .copy
 mov byte [di],0
 cmp byte [winpath],'A'
 jb refused
 cmp byte [winpath],'Z'
 ja refused
 cmp word [winpath+1],5c3ah
 jne refused
 ; Final component must be WIN.COM; validation restricts DOS83 components.
 mov si,winpath+3
 xor dx,dx
 xor cx,cx
 xor bp,bp
.validate:
 lodsb
 or al,al
 jz .final
 cmp al,'\'
 je .separator
 cmp al,'.'
 je .dot
 cmp al,'A'
 jb .digit
 cmp al,'Z'
 jbe .char
.digit:
 cmp al,'0'
 jb .special
 cmp al,'9'
 jbe .char
.special:
 cmp al,'_'
 je .char
 cmp al,'-'
 jne refused
.char:
 inc cx
 cmp bp,0
 jne .ext
 cmp cx,8
 ja refused
 jmp .validate
.ext:
 cmp cx,3
 ja refused
 jmp .validate
.dot:
 cmp bp,0
 jne refused
 cmp cx,0
 je refused
 inc bp
 xor cx,cx
 jmp .validate
.separator:
 cmp cx,0
 je refused
 xor bp,bp
 xor cx,cx
 mov dx,si
 jmp .validate
.final:
 cmp cx,0
 je refused
 mov si,di
 sub si,7
 mov di,winname
 mov cx,8
 repe cmpsb
 jne refused
 ; Prefix length excludes WIN.COM; root-level is also explicit and supported.
 mov si,winpath
 mov di,systempath
 mov cx,bx
 sub cx,7
 push cx
 rep movsb
 mov si,sysname
 mov cx,11
 rep movsb
 pop cx
 mov si,winpath
 mov di,userpath
 rep movsb
 mov si,username
 mov cx,9
 rep movsb
 ; Read-only format gate: reject MZ and oversized/empty flat images.
 mov dx,winpath
 mov ax,3d00h
 int 21h
 jc refused
 mov bx,ax
 mov cx,2
 mov dx,header_check
 mov ah,3fh
 int 21h
 jc .format_fail
 cmp ax,2
 jne .format_fail
 cmp word [header_check],5a4dh
 je .format_fail
 mov ax,4202h
 xor cx,cx
 xor dx,dx
 int 21h
 jc .format_fail
 or dx,dx
 jnz .format_fail
 cmp ax,0ff00h
 jae .format_fail
 mov ah,3eh
 int 21h
 jc refused
 jmp .ready
.format_fail:
 mov ah,3eh
 int 21h
 jmp refused
.ready:
 mov dx,message
 mov ah,9
 int 21h
 mov ax,cs
 call hex_word
 mov dx,colon
 mov ah,9
 int 21h
 mov ax,trace_header
 call hex_word
 mov dx,newline
 mov ah,9
 int 21h
 call announcement_pause
 jc refused
 mov bx,(program_end-$$+100h+15)/16
 mov ah,4ah
 int 21h
 jc refused
 mov ax,3521h
 int 21h
 mov [old21],bx
 mov [old21+2],es
 mov ax,352fh
 int 21h
 mov [old2f],bx
 mov [old2f+2],es
 mov dx,hook21
 mov ax,2521h
 int 21h
 mov dx,hook2f
 mov ax,252fh
 int 21h
 mov byte [armed],1
 mov dx,winpath
 mov bx,param
 push cs
 pop es
 mov ax,4b00h
 int 21h
 ; Windows returned (possibly an EXEC failure); restore our vectors first.
 push cs
 pop ds
 mov byte [armed],0
 ; Never remove a callee-installed vector or free memory still in its chain.
 mov ax,3521h
 int 21h
 cmp bx,hook21
 jne retained_failure
 mov ax,es
 mov cx,cs
 cmp ax,cx
 jne retained_failure
 mov ax,352fh
 int 21h
 cmp bx,hook2f
 jne retained_failure
 mov ax,es
 cmp ax,cx
 jne retained_failure
 mov dx,[old2f]
 mov ds,[old2f+2]
 mov ax,252fh
 int 21h
 push cs
 pop ds
 mov dx,[old21]
 mov ds,[old21+2]
 mov ax,2521h
 int 21h
 push cs
 pop ds
 cmp word [trace_overflow],0
 jne refused
 cmp word [trace_count],0
 je refused
 ; CREATE_NEW only: never overwrite any existing guest file.
 mov dx,logpath
 xor cx,cx
 mov ah,5bh
 int 21h
 jc refused
 mov bx,ax
 mov ax,[trace_count]
 mov cx,RECORD_BYTES
 mul cx
 add ax,trace_records-trace_header
 mov cx,ax
 mov dx,trace_header
 mov [log_expected],cx
 mov ah,40h
 int 21h
 jc .log_fail
 cmp ax,[log_expected]
 jne .log_fail
 mov ah,3eh
 int 21h
 jc refused
 mov ax,4c00h
 int 21h
.log_fail:
 mov ah,3eh
 int 21h
 jmp refused
retained_failure:
 push cs
 pop ds
 mov word [trace_overflow],2
 mov dx,error_msg
 mov ah,9
 int 21h
 mov dx,(program_end-$$+100h+15)/16
 mov ax,3101h
 int 21h
refused:
 push cs
 pop ds
 mov dx,error_msg
 mov ah,9
 int 21h
 mov ax,4c01h
 int 21h
hex_word:
 push ax
 push bx
 push cx
 push dx
 mov bx,ax
 mov cx,4
.loop:
 rol bx,4
 mov dl,bl
 and dl,15
 add dl,'0'
 cmp dl,'9'
 jbe .emit
 add dl,7
.emit:
 mov ah,2
 int 21h
 loop .loop
 pop dx
 pop cx
 pop bx
 pop ax
 ret
; Source-written pre-EXEC observation window. BIOS 54 ticks is about 3 seconds.
; Read the BDA timer without consuming INT1A's midnight flag or changing time.
%ifndef PAUSE_POLL_BOUND
 %define PAUSE_POLL_BOUND 04000000h
%endif
%if PAUSE_POLL_BOUND < 1 || PAUSE_POLL_BOUND > 0ffffffffh
 %error Invalid finite announcement poll budget
%endif
DAY_TICKS equ 01800b0h
announcement_pause:
 pushfd
 pushad
 push es
 mov ax,40h
 mov es,ax
 call read_bios_tick
 cmp eax,DAY_TICKS
 jae .fail
 mov [cs:pause_start],eax
 mov [cs:pause_last],eax
 mov dword [cs:pause_polls],PAUSE_POLL_BOUND
.loop:
 call read_bios_tick
 cmp eax,DAY_TICKS
 jae .fail
 cmp eax,[cs:pause_last]
 jae .forward
 ; A backwards timer is accepted only across the actual daily rollover.
 cmp dword [cs:pause_last],DAY_TICKS-54
 jb .fail
 cmp eax,54
 jae .fail
.forward:
 mov [cs:pause_last],eax
 mov edx,eax
 sub edx,[cs:pause_start]
 jnc .delta
 add edx,DAY_TICKS
.delta:
 cmp edx,108
 ja .fail
 cmp edx,54
 jae .success
 dec dword [cs:pause_polls]
 jnz .loop
.fail:
 pop es
 popad
 popfd
 stc
 ret
.success:
 pop es
 popad
 popfd
 clc
 ret
read_bios_tick:
 pushf
 cli
 mov eax,[es:6ch]
 popf
 ret
pause_start dd 0
pause_last dd 0
pause_polls dd 0
winname db 'WIN.COM',0
align 2
stack_space times 1024 db 0
stack_end:
program_end:
