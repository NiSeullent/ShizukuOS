; SPDX-License-Identifier: GPL-2.0-only
; T_COM: DOS services from a .COM program: file create/write/close/reopen/read,
; missing-file error, memory allocation and failure, findfirst, version, PSP/env.
%include "common.inc"
start:
    ; PSP sanity: INT 20h at PSP:0, memory top field, environment segment.
    cmp word [0], 0x20cd
    jne f_psp
    mov ax, [0x2c]
    or ax, ax
    jz f_psp
    ; A .COM owns all memory above its PSP; shrink to 64 KiB so allocations can succeed.
    mov bx, 0x1000
    mov ah, 0x4a
    int 0x21
    jc f_alloc
    ; create + write
    mov dx, out_name
    xor cx, cx
    mov ah, 0x3c
    int 0x21
    jc f_create
    mov bx, ax
    mov dx, payload
    mov cx, payload_end - payload
    mov ah, 0x40
    int 0x21
    jc f_write
    cmp ax, payload_end - payload
    jne f_write
    mov ah, 0x3e
    int 0x21
    jc f_write
    ; reopen + read back into a distinct buffer
    mov dx, out_name
    mov ax, 0x3d00
    int 0x21
    jc f_open
    mov bx, ax
    mov dx, readbuf
    mov cx, 64
    mov ah, 0x3f
    int 0x21
    jc f_read
    cmp ax, payload_end - payload
    jne f_read
    mov ah, 0x3e
    int 0x21
    mov si, payload
    mov di, readbuf
    mov cx, payload_end - payload
    repe cmpsb
    jne f_compare
    ; missing file must fail with error 2 (file not found)
    mov dx, missing
    mov ax, 0x3d00
    int 0x21
    jnc f_missing
    cmp ax, 2
    jne f_missing
    ; allocate 0x100 paragraphs, free it
    mov bx, 0x100
    mov ah, 0x48
    int 0x21
    jc f_alloc
    mov es, ax
    mov ah, 0x49
    int 0x21
    jc f_alloc
    ; impossible allocation returns error 8 and the largest block in BX
    mov bx, 0xffff
    mov ah, 0x48
    int 0x21
    jnc f_alloc
    cmp ax, 8
    jne f_alloc
    cmp bx, 0x1000                ; expect >= 64 KiB still available
    jb f_alloc
    ; findfirst on the file we made
    mov dx, out_name
    xor cx, cx
    mov ah, 0x4e
    int 0x21
    jc f_find
    ; DOS version: FreeDOS reports at least 5.0
    mov ah, 0x30
    int 0x21
    cmp al, 5
    jb f_version
    ; append pass line
    mov si, pass_line
    mov cx, pass_end - pass_line
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
    FAIL f_psp, l_psp
    FAIL f_create, l_create
    FAIL f_write, l_write
    FAIL f_open, l_open
    FAIL f_read, l_read
    FAIL f_compare, l_compare
    FAIL f_missing, l_missing
    FAIL f_alloc, l_alloc
    FAIL f_find, l_find
    FAIL f_version, l_version

out_name: db 'T_COM.OUT', 0
missing:  db 'NOFILE.XYZ', 0
payload:  db 'SHZ-COM-FILE-OK 0123456789ABCDEF', 13, 10
payload_end:
pass_line: db 'T_COM PASS', 13, 10
pass_end:
l_psp: db 'T_COM FAIL psp', 13, 10
l_psp_end:
l_create: db 'T_COM FAIL create', 13, 10
l_create_end:
l_write: db 'T_COM FAIL write', 13, 10
l_write_end:
l_open: db 'T_COM FAIL reopen', 13, 10
l_open_end:
l_read: db 'T_COM FAIL read', 13, 10
l_read_end:
l_compare: db 'T_COM FAIL compare', 13, 10
l_compare_end:
l_missing: db 'T_COM FAIL missing-file-error', 13, 10
l_missing_end:
l_alloc: db 'T_COM FAIL alloc', 13, 10
l_alloc_end:
l_find: db 'T_COM FAIL findfirst', 13, 10
l_find_end:
l_version: db 'T_COM FAIL dos-version', 13, 10
l_version_end:
ok_msg: db 'T_COM: DOS file/memory services OK', 13, 10, '$'
bad_msg: db 'T_COM: FAILED', 13, 10, '$'
readbuf: times 64 db 0
