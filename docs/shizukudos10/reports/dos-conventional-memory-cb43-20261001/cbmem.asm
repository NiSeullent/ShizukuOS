; SPDX-License-Identifier: GPL-2.0-only
; Original bounded DOS memory diagnostic, ShizukuDOS contributors, 2026.
; NASM -f bin -w+all -Werror -o CBMEM.COM cbmem.asm
; Real DOS/BIOS calls only. Does not start or patch Windows.
; AH4A shrinks only the validated current PSP allocation; own code/data/stack
; remain inside KEEP_PARAS. AH48/FFFF must fail with AX=8; BX is raw largest
; available allocator block, interpreted together with actual strategy/UMB state.
; Measurements precede creating CBMEM.TXT. Never changes allocator policy.
; ERRORLEVEL 0=contracts/report I/O succeeded, 1=contract/write/close failure,
; 2=report creation failure. The text is not proof of a clean guest shutdown.
bits 16
cpu 386
org 0x100

%macro REQUIRE 1
    %1 %%ok
    inc word [checks]
    inc word [failures]
    jmp build_report
%%ok:
    inc word [checks]
%endmacro

%macro FIELD 2
    mov si, %1
    mov ax, [%2]
    call emit_field
%endmacro

jmp entry

entry:
    cli
    mov ax, cs
    mov ss, ax
stack_load:
    mov sp, stack_top
    sti
    push cs
    pop ds
    push cs
    pop es
    cld
    mov [cs_segment], ax
    mov word [phase], 1

    int 0x12
    mov [cs:bios_kb], ax
    push cs
    pop ds

    xor bx, bx
    xor dx, dx
    mov ax, 0x3306
    int 0x21
    pushf
    pop word [cs:version_flags_raw]
    mov [cs:version_ax], ax
    mov [cs:version_bx], bx
    mov [cs:version_dx], dx
    push cs
    pop ds
    mov ax, dx
    and ax, 0x1000                 ; raw DH bit4, no CONFIG inference
    mov [dos_hma_bit], ax

    mov ax, 0x5800                 ; read allocator strategy, never set it
    int 0x21
    pushf
    pop word [cs:strategy_flags]
    mov [cs:strategy_ax], ax
    push cs
    pop ds
    mov ax, 0x5802                 ; read UMB link state, never set it
    int 0x21
    pushf
    pop word [cs:umb_flags]
    mov [cs:umb_ax], ax
    push cs
    pop ds

    mov ah, 0x62
    int 0x21
    mov [cs:psp_segment], bx
    push cs
    pop ds
    mov word [phase], 2
    cmp bx, [cs_segment]           ; COM code/data must be in own PSP segment
    REQUIRE je
    test bx, bx
    REQUIRE jnz

    mov ax, bx
    dec ax
    mov es, ax                     ; read only own MCB, not a chain traversal
    xor ax, ax
    mov al, [es:0]
    mov [mcb_type_before], ax
    mov ax, [es:1]
    mov [mcb_owner_before], ax
    mov ax, [es:3]
    mov [mcb_paras_before], ax
    mov ax, [2]                    ; raw PSP allocation-end segment
    mov [psp_end_before], ax
    mov word [phase], 3
    cmp word [mcb_type_before], 'M'
    je .valid_type
    cmp word [mcb_type_before], 'Z'
    REQUIRE je
    jmp .type_done
.valid_type:
    inc word [checks]
.type_done:
    mov ax, [mcb_owner_before]
    cmp ax, [psp_segment]
    REQUIRE je
    cmp word [mcb_paras_before], KEEP_PARAS
    REQUIRE jae                    ; never grow or release our own code/stack

    mov word [phase], 4
    mov ax, [psp_segment]
    mov es, ax
shrink_site:
    mov bx, KEEP_PARAS
    mov ah, 0x4a
    stc
    int 0x21
    pushf
    pop word [cs:shrink_flags]
    mov [cs:shrink_ax], ax
    mov [cs:shrink_bx], bx
    push cs
    pop ds
    test word [shrink_flags], 1
    REQUIRE jz

    mov ax, [psp_segment]
    dec ax
    mov es, ax
    xor ax, ax
    mov al, [es:0]
    mov [mcb_type_after], ax
    mov ax, [es:1]
    mov [mcb_owner_after], ax
    mov ax, [es:3]
    mov [mcb_paras_after], ax
    mov ax, [2]                    ; recorded only; DOS need not update PSP+2
    mov [psp_end_after], ax
    mov word [phase], 5
    cmp word [mcb_type_after], 'M'
    je .valid_after_type
    cmp word [mcb_type_after], 'Z'
    REQUIRE je
    jmp .after_type_done
.valid_after_type:
    inc word [checks]
.after_type_done:
    mov ax, [mcb_owner_after]
    cmp ax, [psp_segment]
    REQUIRE je
    cmp word [mcb_paras_after], KEEP_PARAS
    REQUIRE je

    mov word [phase], 6
query_site:
    mov bx, 0xffff
    mov ah, 0x48
    stc
    int 0x21
    pushf
    pop word [cs:query_flags]
    mov [cs:query_ax], ax
    mov [cs:query_bx], bx
    push cs
    pop ds
    test word [query_flags], 1
    jnz allocation_failed
    ; Unexpected success still owns the returned block. Attempt only its release.
    inc word [checks]
    inc word [failures]
    mov [unexpected_segment], ax
    mov es, ax
release_site:
    mov ah, 0x49
    stc
    int 0x21
    pushf
    pop word [cs:release_flags]
    mov [cs:release_ax], ax
    push cs
    pop ds
    jmp build_report
allocation_failed:
    inc word [checks]
    cmp word [query_ax], 8
    REQUIRE je
    mov ax, [query_bx]
    shr ax, 6                      ; floor raw paragraphs/64, not XMS or INT12
    mov [largest_kb_floor], ax
    mov word [phase], 7

build_report:
    push cs
    pop ds
    push cs
    pop es
    cld
    mov di, report_buffer
    mov si, report_header
    call emit_text
    FIELD name_phase, phase
    FIELD name_bios, bios_kb
    FIELD name_cs, cs_segment
    FIELD name_psp, psp_segment
    FIELD name_vax, version_ax
    FIELD name_vbx, version_bx
    FIELD name_vdx, version_dx
    FIELD name_vflags, version_flags_raw
    FIELD name_hma, dos_hma_bit
    FIELD name_strategy, strategy_ax
    FIELD name_sflags, strategy_flags
    FIELD name_umb, umb_ax
    FIELD name_uflags, umb_flags
    FIELD name_type_before, mcb_type_before
    FIELD name_owner_before, mcb_owner_before
    FIELD name_paras_before, mcb_paras_before
    FIELD name_end_before, psp_end_before
    mov si, name_keep
    mov ax, KEEP_PARAS
    call emit_field
    FIELD name_shrink_ax, shrink_ax
    FIELD name_shrink_bx, shrink_bx
    FIELD name_shrink_flags, shrink_flags
    FIELD name_type_after, mcb_type_after
    FIELD name_owner_after, mcb_owner_after
    FIELD name_paras_after, mcb_paras_after
    FIELD name_end_after, psp_end_after
    FIELD name_query_ax, query_ax
    FIELD name_query_bx, query_bx
    FIELD name_query_flags, query_flags
    FIELD name_largest_kb, largest_kb_floor
    FIELD name_unexpected, unexpected_segment
    FIELD name_release_ax, release_ax
    FIELD name_release_flags, release_flags
    FIELD name_checks, checks
    FIELD name_failures, failures
    mov si, report_footer
    call emit_text
    mov ax, di
    sub ax, report_buffer
    mov [report_length], ax
    cmp di, report_end
    ja report_creation_failure       ; compile-time buffer bounds checked too

    xor cx, cx
    mov dx, report_filename
    mov ah, 0x3c
    int 0x21
    jc report_creation_failure
    mov [cs:report_handle], ax
    push cs
    pop ds
    mov bx, ax
    mov cx, [report_length]
    mov dx, report_buffer
    mov ah, 0x40
    int 0x21
    jc .write_failed
    cmp ax, [cs:report_length]
    je .close_report
.write_failed:
    mov word [cs:io_failure], 1
.close_report:
    mov bx, [cs:report_handle]
    mov ah, 0x3e
    int 0x21
    jnc .closed
    mov word [cs:io_failure], 1
.closed:
    mov ax, [cs:failures]
    or ax, [cs:io_failure]
    jz .success
    mov ax, 0x4c01
    int 0x21
.success:
    mov ax, 0x4c00
    int 0x21
report_creation_failure:
    mov ax, 0x4c02
    int 0x21

; DS/ES=CS, DI points inside the retained report buffer. No DOS calls here.
emit_field:
    push ax
    call emit_text
    pop ax
    mov bx, ax
    mov cx, 4
.hex:
    rol bx, 4
    mov ax, bx
    and ax, 15
    add al, '0'
    cmp al, '9'
    jbe .digit
    add al, 7
.digit:
    stosb
    loop .hex
    mov ax, 0x0a0d
    stosw
    ret
emit_text:
    lodsb
    test al, al
    jz .done
    stosb
    jmp emit_text
.done:
    ret

align 2
layout_record:
    db 'CBMEM-LAYOUT-V1',0
    dw entry, shrink_site, query_site, release_site, report_buffer, report_end
    dw stack_bottom, stack_top, image_end, KEEP_PARAS, shrink_site+1, stack_load+1

phase dw 0
bios_kb dw 0xffff
cs_segment dw 0
psp_segment dw 0
version_ax dw 0xffff
version_bx dw 0xffff
version_dx dw 0xffff
version_flags_raw dw 0xffff
dos_hma_bit dw 0xffff
strategy_ax dw 0xffff
strategy_flags dw 0xffff
umb_ax dw 0xffff
umb_flags dw 0xffff
mcb_type_before dw 0xffff
mcb_owner_before dw 0xffff
mcb_paras_before dw 0xffff
psp_end_before dw 0xffff
shrink_ax dw 0xffff
shrink_bx dw 0xffff
shrink_flags dw 0xffff
mcb_type_after dw 0xffff
mcb_owner_after dw 0xffff
mcb_paras_after dw 0xffff
psp_end_after dw 0xffff
query_ax dw 0xffff
query_bx dw 0xffff
query_flags dw 0xffff
largest_kb_floor dw 0xffff
unexpected_segment dw 0xffff
release_ax dw 0xffff
release_flags dw 0xffff
checks dw 0
failures dw 0
io_failure dw 0
report_handle dw 0xffff
report_length dw 0

report_filename db 'CBMEM.TXT',0
report_header db 'CB43 DOS MEMORY V1',13,10,'All values are raw 16-bit hexadecimal; FFFF can mean not measured.',13,10,0
name_phase db 'PHASE=',0
name_bios db 'INT12_TOTAL_KB=',0
name_cs db 'COM_CS=',0
name_psp db 'CURRENT_PSP=',0
name_vax db 'AX3306_AX=',0
name_vbx db 'AX3306_BX=',0
name_vdx db 'AX3306_DX=',0
name_vflags db 'AX3306_FLAGS=',0
name_hma db 'AX3306_DH_BIT4_RAW=',0
name_strategy db 'AX5800_STRATEGY=',0
name_sflags db 'AX5800_FLAGS=',0
name_umb db 'AX5802_RAW_AX=',0
name_uflags db 'AX5802_FLAGS=',0
name_type_before db 'MCB_TYPE_BEFORE=',0
name_owner_before db 'MCB_OWNER_BEFORE=',0
name_paras_before db 'MCB_PARAS_BEFORE=',0
name_end_before db 'PSP_END_BEFORE=',0
name_keep db 'SELF_KEEP_PARAS=',0
name_shrink_ax db 'AH4A_AX=',0
name_shrink_bx db 'AH4A_BX=',0
name_shrink_flags db 'AH4A_FLAGS=',0
name_type_after db 'MCB_TYPE_AFTER=',0
name_owner_after db 'MCB_OWNER_AFTER=',0
name_paras_after db 'MCB_PARAS_AFTER=',0
name_end_after db 'PSP_END_AFTER=',0
name_query_ax db 'AH48_AX=',0
name_query_bx db 'AH48_LARGEST_PARAS=',0
name_query_flags db 'AH48_FLAGS=',0
name_largest_kb db 'LARGEST_KB_FLOOR=',0
name_unexpected db 'UNEXPECTED_OWN_SEG=',0
name_release_ax db 'CLEANUP_AH49_AX=',0
name_release_flags db 'CLEANUP_AH49_FLAGS=',0
name_checks db 'CHECKS=',0
name_failures db 'FAILURES=',0
report_footer db 'END=0001',13,10,'I/O and process outcome require actual DOS ERRORLEVEL.',13,10,0
align 16
report_buffer times 2048 db 0
report_end:
stack_bottom:
    times 1024 db 0
stack_top:
image_end:
KEEP_PARAS equ (image_end - $$ + 0x100 + 15) / 16
