; ShizukuDOS boot sector. Original code, 386+ real mode.
; The next 31 reserved sectors contain stage2; the FAT12 data starts after them.
bits 16
org 0x7c00

    jmp short start
    nop
    db 'SHIZUKU '
bytes_per_sector:    dw 512
sectors_per_cluster: db 1
reserved_sectors:    dw 32
fat_count:           db 2
root_entries:        dw 224
total_sectors:       dw 2880
media_descriptor:    db 0xf0
sectors_per_fat:     dw 9
sectors_per_track:   dw 18
head_count:          dw 2
hidden_sectors:      dd 0
large_sectors:       dd 0
drive_number:        db 0
                    db 0
boot_signature:      db 0x29
volume_id:           dd 0x53485a44
volume_label:        db 'SHIZUKUDOS '
filesystem_type:    db 'FAT12   '

start:
    cli
    xor ax, ax
    mov ds, ax
    mov ss, ax
    mov sp, 0x7c00
    sti
    mov [boot_drive], dl
    mov ax, 0x1000
    mov es, ax
    xor di, di
    mov si, 1
.load_stage2:
    ; Convert an absolute floppy sector to BIOS cylinder/head/sector.
    mov ax, si
    xor dx, dx
    div word [sectors_per_track]
    mov cl, dl
    inc cl
    xor dx, dx
    div word [head_count]
    mov ch, al
    mov dh, dl
    mov dl, [boot_drive]
    mov bx, di
    mov ax, 0x0201
    int 0x13
    jc disk_error
    add di, 512
    inc si
    cmp si, 32
    jb .load_stage2
    mov dword [0x0500], 0x574D5343
    mov dword [0x0504], 0x00504152
    mov dl, [boot_drive]
    jmp 0x1000:0x0000

disk_error:
    mov si, error_text
.print:
    lodsb
    test al, al
    jz .halt
    mov ah, 0x0e
    int 0x10
    jmp .print
.halt:
    cli
    hlt
    jmp .halt

boot_drive: db 0
error_text: db 'ShizukuDOS boot read error', 0

times 510-($-$$) db 0
dw 0xaa55
