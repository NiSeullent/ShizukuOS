; SPDX-License-Identifier: GPL-2.0-only
; Original ShizukuOS DOS-only XMS diagnostic. NASM, 80386+, COM format.
; It uses an installed manager's actual INT2F/FAR-call entry. No Windows
; startup broadcast, fabricated installation response, or XMS emulation.
; Allocates only its own 64 KiB block, copies 256 real pattern bytes in/out,
; balances lock/unlock/free, records all checked API AX/BX/DX/ES values.
; Compile-only until a separate root-owned DOS guest review/run.
bits 16
cpu 386
org 100h

%macro AX_ONE 1
    call capture_regs
    mov si,%1
    cmp ax,1
    jne failed_test
    call passed_test
%endmacro

start:
    push cs
    pop ds
    push cs
    pop es
    cld
    mov dx,report_name
    xor cx,cx
    mov ah,3ch
    int 21h
    jc create_failed
    mov [report_handle],ax
    mov si,introduction
    call put_string

    mov ax,4300h
    int 2fh
    call capture_regs
    mov si,msg_installed
    cmp al,80h
    jne failed_test
    call passed_test

    mov ax,4310h
    int 2fh
    mov [xms_entry],bx
    mov [xms_entry+2],es
    call capture_regs
    mov si,msg_entry
    mov ax,es
    or ax,bx
    jz failed_test
    cmp dword [xms_entry],0ffffffffh
    je failed_test
    call passed_test

    xor ah,ah
    call xms_call
    call capture_regs
    mov si,msg_version
    cmp ax,0300h
    jb failed_test
    call passed_test

    mov ah,07h
    xor bl,bl                    ; RBIL02757: BL0success, BL80/81error
    call xms_call
    call capture_regs
    mov si,msg_a20
    cmp ax,1
    ja failed_test
    test bl,bl
    jnz failed_test              ; AX0boolean alone must not hide XMSerror
    call passed_test

    mov ah,08h
    xor bl,bl                    ; RBIL02758: inputBL0 for preserved-success drivers
    call xms_call
    call capture_regs
    mov si,msg_free
    cmp ax,64
    jb failed_test
    cmp dx,64
    jb failed_test
    test bl,bl
    jnz failed_test
    call passed_test

    mov dx,64
    mov ah,09h
    call xms_call
    ; Preserve any successful ownership even when a later assertion fails.
    cmp ax,1
    jne .allocation_check
    mov [owned_handle],dx
    mov [last_handle],dx
.allocation_check:
    AX_ONE msg_allocate
    test dx,dx
    jz failed_handle

    mov dx,[owned_handle]
    mov ah,0eh
    call xms_call
    call capture_regs
    mov si,msg_info
    cmp ax,1
    jne failed_test
    cmp dx,64
    jne failed_test
    cmp bh,0
    jne failed_test
    call passed_test

    mov dx,[owned_handle]
    mov ah,0ch
    call xms_call
    cmp ax,1
    jne .lock_check
    mov byte [owned_locked],1
.lock_check:
    call capture_regs
    mov si,msg_lock
    cmp ax,1
    jne failed_test
    cmp dx,0010h
    jb failed_test                 ; actual linear DX:BX >= 1 MiB
    call passed_test

    mov dx,[owned_handle]
    mov ah,0eh
    call xms_call
    call capture_regs
    mov si,msg_locked_info
    cmp ax,1
    jne failed_test
    cmp bh,1
    jne failed_test
    cmp dx,64
    jne failed_test
    call passed_test

    mov dx,[owned_handle]
    mov ah,0dh
    call xms_call
    cmp ax,1
    jne .unlock_check
    mov byte [owned_locked],0
.unlock_check:
    AX_ONE msg_unlock

    ; Initialize every source byte to its index and destination to A5h.
    push cs
    pop es
    mov di,source_bytes
    mov cx,256
    xor al,al
.fill_source:
    stosb
    inc al
    loop .fill_source
    mov di,dest_bytes
    mov cx,256
    mov al,0a5h
    rep stosb

    ; XMS move record (16 bytes): DWORD length, WORD handle/DWORD offset,
    ; WORD handle/DWORD offset. Conventional handle0 uses segment:offset.
    mov word [move_record+4],0
    mov word [move_record+6],source_bytes
    mov ax,cs
    mov [move_record+8],ax
    mov ax,[owned_handle]
    mov [move_record+10],ax
    mov dword [move_record+12],0
    mov si,move_record
    mov ah,0bh
    call xms_call
    AX_ONE msg_move_out

    mov ax,[owned_handle]
    mov [move_record+4],ax
    mov dword [move_record+6],0
    mov word [move_record+10],0
    mov word [move_record+12],dest_bytes
    mov ax,cs
    mov [move_record+14],ax
    mov si,move_record
    mov ah,0bh
    call xms_call
    AX_ONE msg_move_back

    push cs
    pop es
    mov si,source_bytes
    mov di,dest_bytes
    mov cx,256
    cld
    repe cmpsb
    pushf
    call capture_regs
    popf
    mov si,msg_pattern
    jne failed_test
    call passed_test

    mov dx,[owned_handle]
    mov ah,0ah
    call xms_call
    cmp ax,1
    jne .free_check
    mov word [owned_handle],0
.free_check:
    AX_ONE msg_free_block

    mov dx,[last_handle]
    mov ah,0eh
    call xms_call
    call capture_regs
    mov si,msg_invalid
    test ax,ax
    jne failed_test
    cmp bl,0a2h
    jne failed_test
    call passed_test

    mov ah,07h
    xor bl,bl                    ; RBIL02757: BL0success, BL80/81error
    call xms_call
    call capture_regs
    mov si,msg_final_a20
    cmp ax,1
    ja failed_test
    test bl,bl
    jnz failed_test              ; AX0boolean alone must not hide XMSerror
    call passed_test
    jmp finish

failed_handle:
    call capture_regs
    mov si,msg_handle_zero
failed_test:
    inc word [checks]
    inc word [failures]
    push si
    mov si,fail_prefix
    call put_string
    pop si
    call put_string
    call print_regs
    ; Cleanup only this probe's own block. Cleanup status is logged separately
    ; and cannot turn a failed check into a passing native result.
    cmp word [owned_handle],0
    je finish
    cmp byte [owned_locked],0
    je .cleanup_free
    mov dx,[owned_handle]
    mov ah,0dh
    call xms_call
    call capture_regs
    mov si,msg_cleanup_unlock
    call put_string
    call print_regs
.cleanup_free:
    mov dx,[owned_handle]
    mov ah,0ah
    call xms_call
    call capture_regs
    mov si,msg_cleanup_free
    call put_string
    call print_regs

finish:
    mov si,summary_checks
    call put_string
    mov ax,[checks]
    call print_decimal
    mov si,summary_failures
    call put_string
    mov ax,[failures]
    call print_decimal
    mov si,summary_io
    call put_string
    mov ax,[io_error]
    call print_decimal
    mov si,newline
    call put_string
    mov bx,[report_handle]
    mov ah,3eh
    int 21h
    jnc .closed
    mov word [io_error],1
.closed:
    mov ax,[failures]
    or ax,[io_error]
    mov ax,4c00h
    jz .exit
    mov al,1
.exit:
    int 21h
create_failed:
    mov ax,4c02h
    int 21h

xms_call:
    ; Keep the caller's data/descriptor segments stable. XMS results AX/BX/DX
    ; remain exactly the installed manager's output; no return is fabricated.
    push ds
    push es
    push si
    push di
    call far [cs:xms_entry]
    pop di
    pop si
    pop es
    pop ds
    ret

capture_regs:
    mov [raw_ax],ax
    mov [raw_bx],bx
    mov [raw_dx],dx
    mov [raw_es],es
    ret

passed_test:
    pusha
    inc word [checks]
    push si
    mov si,pass_prefix
    call put_string
    pop si
    call put_string
    call print_regs
    popa
    ret

print_regs:
    pusha
    mov si,ax_label
    call put_string
    mov ax,[raw_ax]
    call print_hex
    mov si,bx_label
    call put_string
    mov ax,[raw_bx]
    call print_hex
    mov si,dx_label
    call put_string
    mov ax,[raw_dx]
    call print_hex
    mov si,es_label
    call put_string
    mov ax,[raw_es]
    call print_hex
    mov si,newline
    call put_string
    popa
    ret

put_string:
    pusha
    mov dx,si
    xor cx,cx
.length:
    cmp byte [si],0
    je .write
    inc si
    inc cx
    jmp .length
.write:
    mov bx,[report_handle]
    mov ah,40h
    int 21h
    jc .bad
    cmp ax,cx
    je .done
.bad:
    mov word [io_error],1
.done:
    popa
    ret

print_hex:
    pusha
    mov bx,ax
    mov di,number_buffer
    mov cx,4
.digit:
    rol bx,4
    mov al,bl
    and al,0fh
    add al,'0'
    cmp al,'9'
    jbe .store
    add al,7
.store:
    mov [di],al
    inc di
    loop .digit
    mov byte [di],0
    mov si,number_buffer
    call put_string
    popa
    ret

print_decimal:
    pusha
    mov bx,10
    xor cx,cx
.divide:
    xor dx,dx
    div bx
    push dx
    inc cx
    test ax,ax
    jne .divide
    mov di,number_buffer
.store:
    pop ax
    add al,'0'
    mov [di],al
    inc di
    loop .store
    mov byte [di],0
    mov si,number_buffer
    call put_string
    popa
    ret

report_handle dw 0
checks dw 0
failures dw 0
io_error dw 0
owned_handle dw 0
last_handle dw 0
owned_locked db 0
xms_entry dd 0
raw_ax dw 0
raw_bx dw 0
raw_dx dw 0
raw_es dw 0
move_record dd 256
            dw 0
            dd 0
            dw 0
            dd 0
number_buffer times 8 db 0
report_name db 'CBXMS.TXT',0
introduction db 'CBXMS actual DOS-only XMS services; Windows startup NOT TESTED',13,10,0
pass_prefix db 'PASS ',0
fail_prefix db 'FAIL ',0
ax_label db ' AX=',0
bx_label db ' BX=',0
dx_label db ' DX=',0
es_label db ' ES=',0
newline db 13,10,0
summary_checks db 'CHECKS ',0
summary_failures db ' FAILURES ',0
summary_io db ' IO_ERROR ',0
msg_installed db 'INT2F4300 actual installed XMS manager',0
msg_entry db 'INT2F4310 actual nonnull FAR entry',0
msg_version db 'XMS interface version >=3.00',0
msg_a20 db 'A20 query returns actual boolean',0
msg_free db 'free/largest extended block at least64KiB',0
msg_allocate db 'allocate actual64KiB owned XMS block',0
msg_handle_zero db 'allocated handle must not be conventional0',0
msg_info db 'actual owned handle size64KiB locks0',0
msg_lock db 'lock actual block linear address >=1MiB',0
msg_locked_info db 'actual owned handle size64KiB locks1',0
msg_unlock db 'unlock own block',0
msg_move_out db 'move256 pattern bytes conventional toXMS',0
msg_move_back db 'move256 pattern bytes XMS toconventional',0
msg_pattern db 'actual256byte roundtrip equals every pattern byte',0
msg_free_block db 'free own XMS block',0
msg_invalid db 'freed handle rejected AX0/BLA2',0
msg_final_a20 db 'final A20 query returns actual boolean',0
msg_cleanup_unlock db 'CLEANUP unlock attempted',0
msg_cleanup_free db 'CLEANUP free attempted',0
source_bytes times 256 db 0
dest_bytes times 256 db 0
