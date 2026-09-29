; Original, bounded DOS/V86 VXDLDR diagnostic. See v86diag/REFERENCES.md.
; This is an experiment, not a Windows 98 driver compatibility claim.
bits 16
cpu 386
org 100h

%include "expected.inc"

%macro CAPTURE 0
    ; Do not alter FLAGS or trust DS/ES after the external call.
    pushf
    pop word [cs:raw_flags_value]
    mov [cs:raw_ax_value], ax
    mov [cs:raw_dx_value], dx
    push cs
    pop ds
    push cs
    pop es
    cld
%endmacro

%macro TEXT 1
    mov dx, %1
    mov cx, %1 %+ _end - %1
    call write_log
%endmacro

%macro RAW 1
    mov si, %1
    call log_raw
%endmacro

start:
    ; The DOS COM loader supplies CS=DS=ES=SS and a usable initial stack.
    ; Use our own stack, included in the image, before any external call.
    mov sp, stack_end
    push cs
    pop ds
    push cs
    pop es
    cld
    mov dx, log_path
    xor cx, cx
    mov ax, 5b00h                 ; create NEW, never replace a stale log
    int 21h
    jc create_failed
    mov [log_handle], ax
    TEXT heading
    TEXT evidence
    TEXT expected_hash
    cmp byte [io_failed], 0
    jne finish

    ; First loader operation: find the V86 entry, without assuming a pointer.
    xor ax, ax
    mov es, ax
    xor di, di
    mov ax, 1684h
    mov bx, 0027h
    int 2fh
    pushf
    pop word [cs:raw_flags_value]
    mov [cs:raw_ax_value], ax
    mov [cs:raw_dx_value], dx
    mov [cs:entry], di
    mov [cs:entry+2], es
    push cs
    pop ds
    push cs
    pop es
    cld
    RAW tag_entry
    mov ax, [entry+2]
    mov di, entry_segment
    call hex_word
    mov ax, [entry]
    mov di, entry_offset
    call hex_word
    TEXT entry_line
    cmp byte [io_failed], 0
    jne finish
    ; Reject any zero segment conservatively; never far-call 0000:xxxx.
    cmp word [entry+2], 0
    je no_entry

    xor eax, eax                 ; version result is recorded, not presumed
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    call far [cs:entry]
    CAPTURE
    RAW tag_version
    cmp byte [io_failed], 0
    jne finish

    ; Ordinary DOS read-only access proves exact candidate bytes before load.
    mov dx, driver_path
    mov ax, 3d00h
    int 21h
    CAPTURE
    test word [raw_flags_value], 1
    jnz file_open_failed
    mov ax, [raw_ax_value]
    mov [file_handle], ax
    mov byte [file_owned], 1
    RAW tag_open
    cmp byte [io_failed], 0
    jne file_cleanup
    mov bx, [file_handle]
    mov dx, read_buffer
    mov cx, EXPECTED_SIZE
    mov ah, 3fh
    int 21h
    CAPTURE
    RAW tag_read
    test word [raw_flags_value], 1
    jnz file_bad
    cmp word [raw_ax_value], EXPECTED_SIZE
    jne file_bad
    cmp byte [io_failed], 0
    jne file_cleanup
    mov si, expected_driver
    mov di, read_buffer
    mov cx, EXPECTED_SIZE
    repe cmpsb
    jne file_bad
    mov bx, [file_handle]
    mov dx, read_buffer
    mov cx, 1
    mov ah, 3fh
    int 21h
    CAPTURE
    RAW tag_eof
    test word [raw_flags_value], 1
    jnz file_bad
    cmp word [raw_ax_value], 0
    jne file_bad
    mov byte [file_exact], 1
    jmp file_cleanup

file_open_failed:
    RAW tag_open
file_bad:
    mov byte [result], 4
file_cleanup:
    cmp byte [file_owned], 0
    je after_file
    ; At most one close attempt. DOS process teardown handles any residual
    ; handle after a failed close; failure prevents the loader call.
    mov byte [file_owned], 0
    mov bx, [file_handle]
    mov ah, 3eh
    int 21h
    CAPTURE
    RAW tag_close
    test word [raw_flags_value], 1
    jz after_file
    mov byte [result], 4
after_file:
    cmp byte [result], 0
    jne finish
    cmp byte [file_exact], 1
    jne file_bad_finish
    cmp byte [io_failed], 0
    jne finish
    TEXT exact
    cmp byte [io_failed], 0
    jne finish

    mov eax, 1
    xor ebx, ebx
    xor ecx, ecx
    mov edx, driver_path
    call far [cs:entry]
    CAPTURE
    ; Ownership is recorded before any logging can fail. The saved loader
    ; pointer is never replaced by the target's possible returned ES:DI.
    test word [raw_flags_value], 1
    jnz load_failed
    cmp word [raw_ax_value], 0
    jne load_failed
    mov byte [load_owned], 1
    RAW tag_load
    jmp unload
load_failed:
    mov byte [result], 5
    RAW tag_load
    jmp finish

unload:
    ; Microsoft Windows 95 by-name convention: BX=FFFF, DDB name, no suffix.
    ; Only our successful load is unloaded, even if its log write failed.
    mov eax, 2
    mov ebx, 0000ffffh
    xor ecx, ecx
    mov edx, driver_name
    call far [cs:entry]
    CAPTURE
    test word [raw_flags_value], 1
    jnz unload_failed
    cmp word [raw_ax_value], 0
    jne unload_failed
    mov byte [load_owned], 0
    RAW tag_unload
    jmp finish
unload_failed:
    mov byte [result], 6
    RAW tag_unload
    jmp finish
no_entry:
    mov byte [result], 3
    jmp finish
file_bad_finish:
    mov byte [result], 4
finish:
    cmp byte [io_failed], 0
    je final_record
    mov byte [result], 0e0h
final_record:
    xor ax, ax
    mov al, [result]
    mov di, result_digits
    call hex_word
    TEXT result_line
    TEXT end_line
    cmp byte [io_failed], 0
    je close_log
    mov byte [result], 0e0h
close_log:
    mov bx, [log_handle]
    mov ah, 3eh
    int 21h
    jnc exit
    mov byte [cs:result], 0e1h
exit:
    push cs
    pop ds
    cld
    mov al, [result]
    mov ah, 4ch
    int 21h
create_failed:
    mov ax, 4c01h
    int 21h

; Counted write, sticky failure, no retry or extension on a short write.
; All helpers preserve caller's general registers, except hex_word AX/DI.
write_log:
    pusha
    cmp byte [cs:io_failed], 0
    jne .done
    push cs
    pop ds
    push cs
    pop es
    cld
    mov [write_count], cx
    mov bx, [log_handle]
    mov ah, 40h
    int 21h
    jc .failed
    cmp ax, [cs:write_count]
    je .done
.failed:
    mov byte [cs:io_failed], 1
.done:
    push cs
    pop ds
    push cs
    pop es
    cld
    popa
    ret

log_raw:
    pusha
    mov di, raw_line
    mov cx, 8
    rep movsb
    mov ax, [raw_flags_value]
    mov di, raw_flags
    call hex_word
    mov ax, [raw_ax_value]
    mov di, raw_ax
    call hex_word
    mov ax, [raw_dx_value]
    mov di, raw_dx
    call hex_word
    TEXT raw_line
    popa
    ret

hex_word:
    push bx
    push cx
    mov cx, 4
.next:
    rol ax, 4
    mov bx, ax
    and bx, 15
    mov bl, [hex_digits+bx]
    mov [di], bl
    inc di
    loop .next
    pop cx
    pop bx
    ret

log_path: db 'C:\NTWLAB\NTWLDR.LOG',0
driver_path: db 'C:\NTWLAB\NTWRAP9X.VXD',0
driver_name: db 'NTWRAP9X',0
heading: db 'NTWLDR FORMAT=1',13,10
heading_end:
evidence: db 'EVIDENCE=GUEST_REPORTED_ONLY',13,10
evidence_end:
expected_hash: db 'EXPECTED_SHA256=',EXPECTED_SHA256,13,10
expected_hash_end:
entry_line: db 'ENTRY SEG='
entry_segment: db '0000'
    db ' OFF='
entry_offset: db '0000',13,10
entry_line_end:
raw_line: db '........ FLAGS='
raw_flags: db '0000'
    db ' AX='
raw_ax: db '0000'
    db ' DX='
raw_dx: db '0000',13,10
raw_line_end:
exact: db 'PREFLIGHT=EXACT_9390_BYTES_AND_EOF',13,10
exact_end:
result_line: db 'RESULT_CODE='
result_digits: db '0000',13,10
result_line_end:
end_line: db 'END=BEFORE_LOG_CLOSE',13,10
end_line_end:
tag_entry: db 'ENTRY   '
tag_version: db 'VERSION '
tag_open: db 'OPEN    '
tag_read: db 'READ    '
tag_eof: db 'EOF     '
tag_close: db 'CLOSE   '
tag_load: db 'LOAD    '
tag_unload: db 'UNLOAD  '
hex_digits: db '0123456789ABCDEF'
entry: dw 0,0
raw_flags_value: dw 0
raw_ax_value: dw 0
raw_dx_value: dw 0
log_handle: dw 0
file_handle: dw 0
write_count: dw 0
file_owned: db 0
file_exact: db 0
load_owned: db 0
io_failed: db 0
result: db 0
expected_driver: incbin "expected.vxd"
expected_driver_end:
%if expected_driver_end-expected_driver != EXPECTED_SIZE
    %error "unexpected candidate size"
%endif
read_buffer: times EXPECTED_SIZE db 0
align 16, db 0
stack_begin: times 2048 db 0
stack_end:
%if stack_end-$$+100h > 0ff00h
    %error "COM image exceeds conservative one-segment bound"
%endif
