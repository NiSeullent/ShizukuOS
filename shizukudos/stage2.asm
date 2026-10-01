; ShizukuDOS experimental real-mode shell. Original code, 386+.
; This is intentionally independent of proprietary Windows 98 DOS files.
bits 16
org 0

FAT_LBA equ 32
FAT_SECTORS equ 9
ROOT_LBA equ 50
ROOT_SECTORS equ 14
DATA_LBA equ 64
COM_SEGMENT equ 0x5000
COM_MAX_BYTES equ 0xfe00

start:
    cli
    cld
    mov ax, cs
    mov ds, ax
    ; Stage1 leaves a safe temporary stack at 0000:7C00. Reject guests whose
    ; conventional RAM cannot contain the fixed COM region and shell stack.
    sti
    int 0x12
    push ax
    mov ax, cs
    mov ds, ax
    pop ax
    cmp ax, 448              ; 448 KiB ends at physical 70000h
    jb low_conventional_memory
    cli
    mov ax, 0x6000           ; stack top 6FFFEh, below the 448 KiB boundary
    mov ss, ax
    mov sp, 0xfffe
    sti
    mov [boot_drive], dl
    call serial_init
    call csmwrap_real_enter
    call cpu_detect
    mov si, banner
    call puts
    call load_fat
    jc fatal_disk_error
    jmp shell

low_conventional_memory:
    call serial_init
    mov si, low_memory_text
    call puts
.halt:
    cli
    hlt
    jmp .halt

shell:
    cld
    mov si, prompt
    call puts
    call readline
    cmp byte [input_buffer], 0
    je shell

    mov si, input_buffer
    mov di, cmd_help
    call match_cmd
    test al, al
    jnz do_help
    mov si, input_buffer
    mov di, cmd_dir
    call match_cmd
    test al, al
    jnz do_dir
    mov si, input_buffer
    mov di, cmd_type
    call match_cmd
    test al, al
    jnz do_type
    mov si, input_buffer
    mov di, cmd_exec
    call match_cmd
    test al, al
    jnz do_exec
    mov si, input_buffer
    mov di, cmd_stack
    call match_cmd
    test al, al
    jnz do_stack
    mov si, input_buffer
    mov di, cmd_cls
    call match_cmd
    test al, al
    jnz do_cls
    mov si, input_buffer
    mov di, cmd_ver
    call match_cmd
    test al, al
    jnz do_ver
    mov si, input_buffer
    mov di, cmd_mem
    call match_cmd
    test al, al
    jnz do_mem
    mov si, input_buffer
    mov di, cmd_pci
    call match_cmd
    test al, al
    jnz do_pci
    mov si, input_buffer
    mov di, cmd_cpu
    call match_cmd
    test al, al
    jnz do_cpu
    mov si, input_buffer
    mov di, cmd_boot
    call match_cmd
    test al, al
    jnz do_boot
    mov si, input_buffer
    mov di, cmd_bootc
    call match_cmd
    test al, al
    jnz do_bootc
    mov si, input_buffer
    mov di, cmd_reboot
    call match_cmd
    test al, al
    jnz do_reboot
    mov si, unknown_text
    call puts
    jmp shell

do_help:
    mov si, help_text
    call puts
    jmp shell
do_ver:
    mov si, banner
    call puts
    jmp shell
do_cls:
    mov ax, 0x0003
    int 0x10
    mov si, cls_text
    call puts
    jmp shell
do_mem:
    int 0x12
    mov si, conventional_text
    call puts
    call print_u16
    mov si, kb_text
    call puts
    mov ah, 0x88
    int 0x15
    jc .extended_unavailable
    push ax
    mov si, extended_text
    call puts
    pop ax
    call print_u16
    mov si, kb_text
    call puts
    jmp shell
.extended_unavailable:
    mov si, extended_unavailable_text
    call puts
    jmp shell

do_stack:
    mov si, stack_text
    call puts
    mov ax, ss
    call print_hex16
    mov al, ':'
    call putc
    mov ax, sp
    call print_hex16
    call newline
    jmp shell

do_cpu:
    mov si, cpu_header_text
    call puts
    cmp byte [cpu_has_cpuid], 0
    jne .with_cpuid
    mov si, cpu_legacy_text
    call puts
    mov al, [cpu_legacy_class]
    add al, '0'
    call putc
    mov si, cpu_legacy_suffix
    call puts
    jmp shell
.with_cpuid:
    mov si, cpu_vendor_text
    call puts
    mov si, cpu_vendor
    call puts
    call newline
    cmp dword [cpu_max_basic], 1
    jae .leaf1_available
    mov si, cpu_leaf1_unavailable_text
    call puts
    jmp shell
.leaf1_available:
    mov si, cpu_family_text
    call puts
    mov ax, [cpu_family]
    call print_u16
    mov si, cpu_model_text
    call puts
    mov ax, [cpu_model]
    call print_u16
    mov si, cpu_stepping_text
    call puts
    mov ax, [cpu_stepping]
    call print_u16
    call newline
    mov si, cpu_logical_text
    call puts
    mov ax, [cpu_logical]
    call print_u16
    mov si, cpu_cores_text
    call puts
    cmp word [cpu_cores], 0
    je .unknown_cores
    mov ax, [cpu_cores]
    call print_u16
    jmp .threads
.unknown_cores:
    mov si, cpu_unknown_text
    call puts
.threads:
    mov si, cpu_threads_text
    call puts
    cmp word [cpu_cores], 0
    je .unknown_threads
    mov ax, [cpu_threads]
    call print_u16
    jmp .feature_lines
.unknown_threads:
    mov si, cpu_unknown_text
    call puts
.feature_lines:
    call newline
    mov si, cpu_top_source_text
    call puts
    xor bx, bx
    mov bl, [cpu_top_source]
    shl bx, 1
    mov si, [cpu_top_source_labels+bx]
    call puts
    call newline
    mov si, cpu_pae_text
    call puts
    mov edx, [cpu_leaf1_edx]
    bt edx, 6
    call cpu_put_cf_yesno
    mov si, cpu_xsave_text
    call puts
    mov edx, [cpu_leaf1_ecx]
    bt edx, 26
    call cpu_put_cf_yesno
    mov si, cpu_osxsave_text
    call puts
    bt edx, 27
    call cpu_put_cf_yesno
    mov si, cpu_avx_hw_text
    call puts
    bt edx, 28
    call cpu_put_cf_yesno
    mov si, cpu_avx_active_text
    call puts
    cmp byte [cpu_avx_eligible], 0
    je .avx_inactive
    stc
    jmp .print_avx_active
.avx_inactive:
    clc
.print_avx_active:
    call cpu_put_cf_yesno
    call newline
    jmp shell

cpu_put_cf_yesno:
    push ax
    mov al, 'N'
    jnc .emit
    mov al, 'Y'
.emit:
    call putc
    pop ax
    ret

do_pci:
    mov ax, 0xb101             ; PCI BIOS installation check
    int 0x1a
    jc .unavailable
    cmp ah, 0
    jne .unavailable
    cmp edx, 0x20494350       ; 'PCI '
    jne .unavailable
    mov si, pci_header_text
    call puts
    mov dword [pci_class], 0x010601 ; AHCI: mass storage/SATA/AHCI
    mov si, pci_ahci_text
    call pci_enum_class
    mov dword [pci_class], 0x0c0330 ; xHCI: serial bus/USB/xHCI
    mov si, pci_xhci_text
    call pci_enum_class
    jmp shell
.unavailable:
    mov si, pci_unavailable_text
    call puts
    jmp shell

pci_enum_class:
    call puts
    mov word [pci_index], 0
    mov byte [pci_found], 0
.find:
    mov ax, 0xb103             ; find PCI class code, index SI
    mov ecx, [pci_class]
    mov si, [pci_index]
    int 0x1a
    jc .done
    cmp ah, 0
    jne .done
    mov [pci_bdf], bx
    inc word [pci_index]
    inc byte [pci_found]
    mov si, pci_indent_text
    call puts
    mov bx, [pci_bdf]
    mov al, bh
    call print_hex8
    mov al, ':'
    call putc
    mov bx, [pci_bdf]
    mov al, bl
    shr al, 3
    call print_hex8
    mov al, '.'
    call putc
    mov bx, [pci_bdf]
    mov al, bl
    and al, 7
    add al, '0'
    call putc
    mov bx, [pci_bdf]
    xor di, di
    mov ax, 0xb10a             ; read-only vendor/device ID dword
    int 0x1a
    jc .line_end
    cmp ah, 0
    jne .line_end
    mov [pci_id], ecx
    mov si, pci_id_text
    call puts
    mov ax, [pci_id]
    call print_hex16
    mov al, ':'
    call putc
    mov ax, [pci_id+2]
    call print_hex16
.line_end:
    call newline
    cmp word [pci_index], 256 ; defensive bound on unusual BIOS implementations
    jb .find
.done:
    cmp byte [pci_found], 0
    jne .return
    mov si, pci_none_text
    call puts
.return:
    ret

do_dir:
    mov si, dir_heading
    call puts
    mov word [root_sector], ROOT_LBA
.sector:
    mov ax, [root_sector]
    call load_root_sector
    jc fatal_disk_error
    xor si, si
.entry:
    cmp byte [es:si], 0
    je shell
    cmp byte [es:si], 0xe5
    je .next_entry
    mov al, [es:si+11]
    cmp al, 0x0f
    je .next_entry
    test al, 0x08
    jnz .next_entry
    call print_dir_name
.next_entry:
    add si, 32
    cmp si, 512
    jb .entry
    inc word [root_sector]
    cmp word [root_sector], ROOT_LBA+ROOT_SECTORS
    jb .sector
    jmp shell

do_type:
    mov si, input_buffer+4
    call parse_name
    jc .missing_name
    mov word [root_sector], ROOT_LBA
.sector:
    mov ax, [root_sector]
    call load_root_sector
    jc fatal_disk_error
    xor si, si
.entry:
    cmp byte [es:si], 0
    je .not_found
    cmp byte [es:si], 0xe5
    je .next_entry
    mov al, [es:si+11]
    test al, 0x18                 ; skip volume names and directories
    jnz .next_entry
    cmp al, 0x0f
    je .next_entry
    push si
    mov di, target_name
    mov cx, 11
.compare:
    mov al, [es:si]
    cmp al, [di]
    jne .mismatch
    inc si
    inc di
    loop .compare
    pop si
    mov ax, [es:si+26]
    mov [file_cluster], ax
    mov ax, [es:si+28]
    mov [remaining_lo], ax
    mov ax, [es:si+30]
    mov [remaining_hi], ax
    call print_file
    jmp shell
.mismatch:
    pop si
.next_entry:
    add si, 32
    cmp si, 512
    jb .entry
    inc word [root_sector]
    cmp word [root_sector], ROOT_LBA+ROOT_SECTORS
    jb .sector
.not_found:
    mov si, file_missing_text
    call puts
    jmp shell
.missing_name:
    mov si, type_usage
    call puts
    jmp shell

do_exec:
    mov si, input_buffer+4
    call parse_name
    jc .usage
    cmp byte [target_name+8], 'C'
    jne .usage
    cmp byte [target_name+9], 'O'
    jne .usage
    cmp byte [target_name+10], 'M'
    jne .usage
    mov word [root_sector], ROOT_LBA
.sector:
    mov ax, [root_sector]
    call load_root_sector
    jc fatal_disk_error
    xor si, si
.entry:
    cmp byte [es:si], 0
    je .not_found
    cmp byte [es:si], 0xe5
    je .next_entry
    mov al, [es:si+11]
    test al, 0x18
    jnz .next_entry
    push si
    mov di, target_name
    mov cx, 11
.compare:
    mov al, [es:si]
    cmp al, [di]
    jne .mismatch
    inc si
    inc di
    loop .compare
    pop si
    mov ax, [es:si+26]
    mov [file_cluster], ax
    mov ax, [es:si+28]
    mov [remaining_lo], ax
    mov ax, [es:si+30]
    mov [remaining_hi], ax
    cmp word [remaining_hi], 0
    jne .too_large
    cmp word [remaining_lo], 0
    je .too_large
    cmp word [remaining_lo], COM_MAX_BYTES
    ja .too_large
    call load_com
    jc .bad_file
    ; This is a non-returning transfer. A CALL would leave its return address
    ; on the shell stack, since INT 21h termination resumes via JMP shell.
    jmp start_com
.mismatch:
    pop si
.next_entry:
    add si, 32
    cmp si, 512
    jb .entry
    inc word [root_sector]
    cmp word [root_sector], ROOT_LBA+ROOT_SECTORS
    jb .sector
.not_found:
    mov si, file_missing_text
    call puts
    jmp shell
.usage:
    mov si, exec_usage
    call puts
    jmp shell
.too_large:
    mov si, exec_size_text
    call puts
    jmp shell
.bad_file:
    mov si, bad_chain_text
    call puts
    jmp shell

; Load a root-directory COM file to PSP segment:0100h. Each BIOS read writes a
; whole sector, so the maximum keeps the final sector clear of the COM stack.
load_com:
    mov ax, [remaining_lo]
    mov [com_bytes_left], ax
    mov word [com_offset], 0x0100
.cluster:
    mov ax, [file_cluster]
    cmp ax, 2
    jb .invalid
    cmp ax, 2817
    ja .invalid
    sub ax, 2
    add ax, DATA_LBA
    mov bx, COM_SEGMENT
    mov es, bx
    mov bx, [com_offset]
    call read_lba
    jc .invalid
    add word [com_offset], 512
    cmp word [com_bytes_left], 512
    jbe .done
    sub word [com_bytes_left], 512
    mov ax, [file_cluster]
    call next_cluster
    mov [file_cluster], ax
    jmp .cluster
.done:
    clc
    ret
.invalid:
    stc
    ret

start_com:
    mov ax, COM_SEGMENT
    mov es, ax
    cld
    xor di, di
    xor ax, ax
    mov cx, 128
    rep stosw                 ; a minimal zeroed 256-byte PSP
    mov word [es:0], 0x20cd  ; INT 20h for a COM program's near RET path
    mov word [es:2], COM_SEGMENT+0x1000
    mov byte [es:0x80], 0    ; empty command tail
    mov byte [es:0x81], 13
    mov word [es:0xfffe], 0  ; near RET lands at PSP:0000

    mov ax, ss
    mov [shell_ss], ax
    mov [shell_sp], sp
    call install_dos_vectors
    mov si, exec_start_text
    call puts
    cli
    mov ax, COM_SEGMENT
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0xfffe
    sti
    jmp COM_SEGMENT:0x0100

install_dos_vectors:
    cli
    xor ax, ax
    mov es, ax
    mov ax, [es:0x80]
    mov [old20_offset], ax
    mov ax, [es:0x82]
    mov [old20_segment], ax
    mov ax, [es:0x84]
    mov [old21_offset], ax
    mov ax, [es:0x86]
    mov [old21_segment], ax
    mov word [es:0x80], int20_handler
    mov word [es:0x84], int21_handler
    mov ax, cs
    mov [es:0x82], ax
    mov [es:0x86], ax
    sti
    ret

restore_dos_vectors:
    cli
    xor ax, ax
    mov es, ax
    mov ax, [old20_offset]
    mov [es:0x80], ax
    mov ax, [old20_segment]
    mov [es:0x82], ax
    mov ax, [old21_offset]
    mov [es:0x84], ax
    mov ax, [old21_segment]
    mov [es:0x86], ax
    sti
    ret

int20_handler:
    xor al, al
    jmp int21_terminate

int21_handler:
    cmp ah, 0x02
    je .put_character
    cmp ah, 0x09
    je .put_dollar_string
    cmp ah, 0x30
    je .version
    cmp ah, 0x4c
    je int21_terminate
    mov ax, 1                ; unsupported function
    push bp
    mov bp, sp
    or word [ss:bp+6], 1     ; CF=1 in the saved interrupt FLAGS
    pop bp
    iret
.put_character:
    mov al, dl
    call putc
    jmp int21_success
.put_dollar_string:
    push cx
    push si
    mov si, dx               ; caller DS still addresses the COM data
    mov cx, 0xffff
    cld                      ; IRET restores the caller's original DF
.next:
    lodsb
    cmp al, '$'
    je .string_done
    call putc
    loop .next
.string_done:
    pop si
    pop cx
    mov al, '$'
    jmp int21_success
.version:
    mov ax, 0x0100           ; AL=0 major, AH=1 minor: ShizukuDOS 0.1
    xor bx, bx
    xor cx, cx
    jmp int21_success

int21_success:
    push bp
    mov bp, sp
    and word [ss:bp+6], 0xfffe ; clear CF in the saved FLAGS
    pop bp
    iret

int21_terminate:
    mov [cs:last_exit_code], al
    cli
    mov ax, cs
    mov ds, ax
    mov ax, [shell_ss]
    mov ss, ax
    mov sp, [shell_sp]
    sti
    cld                      ; COM programs may terminate with DF set
    call restore_dos_vectors
    mov si, exec_end_text
    call puts
    mov al, [last_exit_code]
    call print_hex8
    call newline
    jmp shell

print_file:
    cmp word [remaining_hi], 0
    jne .cluster
    cmp word [remaining_lo], 0
    je .done
.cluster:
    mov ax, [file_cluster]
    cmp ax, 2
    jb .bad_chain
    cmp ax, 2817                 ; last data cluster on this 1.44 MiB disk
    ja .bad_chain
    sub ax, 2
    add ax, DATA_LBA
    mov bx, 0x4000
    mov es, bx
    xor bx, bx
    call read_lba
    jc fatal_disk_error
    mov byte [last_cluster], 0
    mov cx, 512
    cmp word [remaining_hi], 0
    jne .print
    cmp word [remaining_lo], 512
    ja .print
    mov cx, [remaining_lo]
    mov byte [last_cluster], 1
.print:
    xor si, si
.character:
    mov al, [es:si]
    call putc
    inc si
    loop .character
    cmp byte [last_cluster], 1
    je .done
    sub word [remaining_lo], 512
    sbb word [remaining_hi], 0
    mov ax, [file_cluster]
    call next_cluster
    mov [file_cluster], ax
    jmp .cluster
.bad_chain:
    mov si, bad_chain_text
    call puts
    ret
.done:
    call newline
    ret

next_cluster:
    push bx
    push dx
    mov dx, ax
    mov bx, ax
    shr bx, 1
    add bx, ax
    mov ax, 0x3000
    mov es, ax
    mov ax, [es:bx]
    test dx, 1
    jz .even
    shr ax, 4
    jmp .done
.even:
    and ax, 0x0fff
.done:
    pop dx
    pop bx
    ret

parse_name:
    push ax
    push cx
    push di
.skip_spaces:
    cmp byte [si], ' '
    jne .begin
    inc si
    jmp .skip_spaces
.begin:
    cmp byte [si], 0
    je .fail
    mov di, target_name
    mov cx, 11
    mov al, ' '
.fill:
    mov [di], al
    inc di
    loop .fill
    mov di, target_name
    mov cx, 8
.base:
    mov al, [si]
    cmp al, '.'
    je .extension
    cmp al, ' '
    je .success
    test al, al
    jz .success
    test cx, cx
    jz .fail
    mov [di], al
    inc di
    inc si
    dec cx
    jmp .base
.extension:
    inc si
    mov di, target_name+8
    mov cx, 3
.ext_char:
    mov al, [si]
    cmp al, ' '
    je .success
    test al, al
    jz .success
    test cx, cx
    jz .fail
    mov [di], al
    inc di
    inc si
    dec cx
    jmp .ext_char
.success:
    clc
    jmp .return
.fail:
    stc
.return:
    pop di
    pop cx
    pop ax
    ret

print_dir_name:
    push ax
    push cx
    push si
    mov cx, 8
.base:
    mov al, [es:si]
    call putc
    inc si
    loop .base
    mov al, '.'
    call putc
    mov cx, 3
.extension:
    mov al, [es:si]
    call putc
    inc si
    loop .extension
    call newline
    pop si
    pop cx
    pop ax
    ret

load_root_sector:
    mov bx, 0x2000
    mov es, bx
    xor bx, bx
    call read_lba
    ret

load_fat:
    mov ax, 0x3000
    mov es, ax
    mov si, FAT_LBA
    xor bx, bx
    mov cx, FAT_SECTORS
.loop:
    mov ax, si
    call read_lba
    jc .failed
    add bx, 512
    inc si
    loop .loop
    clc
.failed:
    ret

; AX=absolute LBA (0..2879), ES:BX=buffer. Preserves registers, returns CF.
read_lba:
    push ax
    push bx
    push cx
    push dx
    xor dx, dx
    div word [sectors_per_track]
    mov cl, dl
    inc cl
    xor dx, dx
    div word [head_count]
    mov ch, al
    mov dh, dl
    mov dl, [boot_drive]
    mov ax, 0x0201
    int 0x13
    pop dx
    pop cx
    pop bx
    pop ax
    ret

do_boot:
    mov si, boot_text
    call puts
    xor ax, ax
    mov es, ax
    mov bx, 0x7c00
    mov ax, 0x0201
    mov cx, 0x0001
    mov dx, 0x0080
    int 0x13
    jc .failed
    xor ax, ax
    mov es, ax
    cmp word [es:0x7dfe], 0xaa55
    jne .failed
    jmp prepare_hard_disk_boot
.failed:
    mov si, no_hdd_text
    call puts
    jmp shell

do_bootc:
    mov si, bootc_text
    call puts
    ; Read MBR to 0000:7C00, then select its active partition entry.
    xor ax, ax
    mov es, ax
    mov bx, 0x7c00
    mov ax, 0x0201
    mov cx, 0x0001
    mov dx, 0x0080
    int 0x13
    jc .failed
    cmp word [es:0x7dfe], 0xaa55
    jne .failed
    mov bx, 0x7dbe
    mov cx, 4
.partition:
    cmp byte [es:bx], 0x80
    je .active
    add bx, 16
    loop .partition
    jmp .failed
.active:
    mov al, [es:bx+1]
    mov [partition_head], al
    mov al, [es:bx+2]
    mov [partition_sector], al
    mov al, [es:bx+3]
    mov [partition_cylinder], al
    mov ax, [es:bx+8]
    mov [dap_lba], ax
    mov ax, [es:bx+10]
    mov [dap_lba+2], ax
    ; Prefer BIOS Enhanced Disk Drive LBA reads, with MBR CHS fallback.
    mov bx, 0x55aa
    mov ah, 0x41
    mov dl, 0x80
    int 0x13
    jc .chs
    cmp bx, 0xaa55
    jne .chs
    test cx, 1
    jz .chs
    mov si, dap
    mov ah, 0x42
    mov dl, 0x80
    int 0x13
    jnc .verify
.chs:
    xor ax, ax
    mov es, ax
    mov bx, 0x7c00
    mov ch, [partition_cylinder]
    mov cl, [partition_sector]
    mov dh, [partition_head]
    mov dl, 0x80
    mov ax, 0x0201
    int 0x13
    jc .failed
.verify:
    xor ax, ax
    mov es, ax
    cmp word [es:0x7dfe], 0xaa55
    jne .failed
    jmp prepare_hard_disk_boot
.failed:
    mov si, no_partition_text
    call puts
    jmp shell

; Match the conventional real-mode BIOS handoff as closely as possible.
; Entered only after a valid target sector has been loaded at 0000:7C00.
prepare_hard_disk_boot:
    call csmwrap_allow_win98
    jnc .csmwrap_ok
    mov si, csmwrap_blocked_text
    call puts
    jmp shell
.csmwrap_ok:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    mov dl, 0x80
    sti
    jmp 0x0000:0x7c00

do_reboot:
    call csmwrap_allow_win98
    jc .blocked
    int 0x19
    jmp shell
.blocked:
    mov si, csmwrap_blocked_text
    call puts
    jmp shell

fatal_disk_error:
    mov si, disk_error_text
    call puts
.halt:
    cli
    hlt
    jmp .halt

match_cmd:
    push si
    push di
.compare:
    mov al, [di]
    test al, al
    jz .terminator
    cmp al, [si]
    jne .no
    inc si
    inc di
    jmp .compare
.terminator:
    cmp byte [si], 0
    je .yes
    cmp byte [si], ' '
    je .yes
.no:
    xor al, al
    jmp .return
.yes:
    mov al, 1
.return:
    pop di
    pop si
    ret

readline:
    push ax
    push cx
    push di
    mov di, input_buffer
    mov cx, 79
.read:
    call getch
    cmp al, 13
    je .done
    cmp al, 10
    je .done
    cmp al, 8
    je .backspace
    cmp al, 32
    jb .read
    cmp al, 126
    ja .read
    test cx, cx
    jz .read
    cmp al, 'a'
    jb .save
    cmp al, 'z'
    ja .save
    sub al, 32
.save:
    mov [di], al
    inc di
    dec cx
    call putc
    jmp .read
.backspace:
    cmp di, input_buffer
    jbe .read
    dec di
    inc cx
    mov al, 8
    call putc
    mov al, ' '
    call putc
    mov al, 8
    call putc
    jmp .read
.done:
    mov byte [di], 0
    call newline
    pop di
    pop cx
    pop ax
    ret

getch:
.poll:
    mov dx, 0x3fd
    in al, dx
    test al, 1
    jnz .serial
    mov ah, 1
    int 0x16
    jz .poll
    xor ah, ah
    int 0x16
    ret
.serial:
    mov dx, 0x3f8
    in al, dx
    ret

serial_init:
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 12                 ; 9600 baud, 8N1
    out dx, al
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 3
    out dx, al
    ret

putc:
    push ax
    push bx
    push cx
    push dx
    push si
    mov bl, al
    mov ah, 0x0e
    mov bh, 0
    int 0x10
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    mov dx, 0x3f8
    mov al, bl
    out dx, al
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

puts:
    push ax
    push si
.next:
    lodsb
    test al, al
    jz .done
    call putc
    jmp .next
.done:
    pop si
    pop ax
    ret

newline:
    push ax
    mov al, 13
    call putc
    mov al, 10
    call putc
    pop ax
    ret

print_u16:
    push ax
    push bx
    push cx
    push dx
    xor cx, cx
    mov bx, 10
.convert:
    xor dx, dx
    div bx
    push dx
    inc cx
    test ax, ax
    jnz .convert
.digit:
    pop ax
    add al, '0'
    call putc
    loop .digit
    pop dx
    pop cx
    pop bx
    pop ax
    ret

print_hex16:
    push ax
    mov al, ah
    call print_hex8
    pop ax
    call print_hex8
    ret

print_hex8:
    push ax
    push bx
    mov bl, al
    shr al, 4
    call print_hex_nibble
    mov al, bl
    and al, 0x0f
    call print_hex_nibble
    pop bx
    pop ax
    ret

print_hex_nibble:
    cmp al, 9
    jbe .decimal
    add al, 7
.decimal:
    add al, '0'
    call putc
    ret

%include "cpu_detect.inc"
%include "csmwrap/handoff/gate.asm"

boot_drive: db 0
root_sector: dw 0
file_cluster: dw 0
remaining_lo: dw 0
remaining_hi: dw 0
last_cluster: db 0
com_bytes_left: dw 0
com_offset: dw 0
shell_ss: dw 0
shell_sp: dw 0
old20_offset: dw 0
old20_segment: dw 0
old21_offset: dw 0
old21_segment: dw 0
last_exit_code: db 0
pci_class: dd 0
pci_index: dw 0
pci_bdf: dw 0
pci_id: dd 0
pci_found: db 0
partition_head: db 0
partition_sector: db 0
partition_cylinder: db 0
dap:
    db 0x10, 0
    dw 1
    dw 0x7c00, 0
dap_lba: dd 0
    dd 0
target_name: times 11 db ' '
input_buffer: times 80 db 0
sectors_per_track: dw 18
head_count: dw 2

cmd_help: db 'HELP',0
cmd_dir: db 'DIR',0
cmd_type: db 'TYPE',0
cmd_exec: db 'EXEC',0
cmd_stack: db 'STACK',0
cmd_cls: db 'CLS',0
cmd_ver: db 'VER',0
cmd_mem: db 'MEM',0
cmd_pci: db 'PCI',0
cmd_cpu: db 'CPU',0
cmd_boot: db 'BOOT',0
cmd_bootc: db 'BOOTC',0
cmd_reboot: db 'REBOOT',0
banner: db 13,10,'ShizukuDOS 0.1 - experimental real-mode shell',13,10,0
prompt: db 'A:\> ',0
help_text: db 'HELP DIR TYPE filename EXEC file.COM CLS VER MEM STACK CPU PCI BOOT BOOTC REBOOT',13,10,0
dir_heading: db 'FAT12 root directory:',13,10,0
type_usage: db 'Usage: TYPE 8.3NAME',13,10,0
exec_usage: db 'Usage: EXEC 8.3NAME.COM',13,10,0
exec_size_text: db 'COM file is empty or exceeds 65024 bytes.',13,10,0
exec_start_text: db 'Starting COM program...',13,10,0
exec_end_text: db 'COM program exit code 0x',0
unknown_text: db 'Unknown command. Type HELP.',13,10,0
file_missing_text: db 'File not found.',13,10,0
bad_chain_text: db 13,10,'FAT12 chain is invalid or truncated.',13,10,0
disk_error_text: db 13,10,'Floppy read error.',13,10,0
boot_text: db 'Chainloading first hard disk MBR...',13,10,0
bootc_text: db 'Chainloading active partition on first hard disk...',13,10,0
no_hdd_text: db 'No bootable first hard disk MBR.',13,10,0
no_partition_text: db 'No bootable active partition or unreadable boot sector.',13,10,0
conventional_text: db 'Conventional memory: ',0
extended_text: db 'Extended memory (BIOS AH=88h): ',0
extended_unavailable_text: db 'Extended memory unavailable from BIOS.',13,10,0
stack_text: db 'Shell SS:SP=',0
low_memory_text: db 'ShizukuDOS requires at least 448 KB conventional RAM.',13,10,0
kb_text: db ' KB',13,10,0
cls_text: db 'Screen cleared.',13,10,0
pci_header_text: db 'PCI BIOS read-only class probe:',13,10,0
pci_ahci_text: db 'AHCI (01:06:01):',13,10,0
pci_xhci_text: db 'xHCI (0C:03:30):',13,10,0
pci_indent_text: db '  ',0
pci_id_text: db ' ID ',0
pci_none_text: db '  none',13,10,0
pci_unavailable_text: db 'PCI BIOS service unavailable.',13,10,0
