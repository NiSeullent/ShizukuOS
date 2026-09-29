; SPDX-License-Identifier: GPL-2.0-only
; ShizukuDOS virtual BIOS (vBIOS), 64 KiB image placed at guest-physical F0000.
;
; Original code. It provides what a DOS or bootloader expects at power-on: the
; F000:FFF0 reset vector, real PIC/PIT programming (trapped by the Supervisor's
; device models), an interrupt vector table, the INT 08h timer tick maintained in
; the BIOS Data Area, and INT 10h/13h/15h/16h/1Ah/14h/17h/19h entry stubs. A stub
; is `out <0xE0..0xEF>, al` followed by `iret`: the port write is a hypercall that
; makes the Supervisor perform the service on the saved registers, storing the
; result flags into the stacked FLAGS image.
bits 16
cpu 386
org 0

; ------------------------------------------------------------ boot entry
bios_start:
    cli
    cld
    xor ax, ax
    mov ss, ax
    mov sp, 0x7000
    mov ds, ax
    mov es, ax

    ; 8259A pair: master vectors 08h, slave vectors 70h.
    mov al, 0x11
    out 0x20, al
    out 0xa0, al
    mov al, 0x08
    out 0x21, al
    mov al, 0x70
    out 0xa1, al
    mov al, 0x04
    out 0x21, al
    mov al, 0x02
    out 0xa1, al
    mov al, 0x01
    out 0x21, al
    out 0xa1, al
    mov al, 0xb8                    ; unmask IRQ0 (timer), IRQ1, IRQ2 (cascade), IRQ6
    out 0x21, al
    mov al, 0xff
    out 0xa1, al

    ; 8254 channel 0: mode 3, divisor 65536 (18.2065 Hz).
    mov al, 0x36
    out 0x43, al
    xor al, al
    out 0x40, al
    out 0x40, al

    ; Every vector defaults to a bare IRET.
    xor di, di
    mov cx, 256
.fill:
    mov ax, default_handler
    stosw
    mov ax, 0xf000
    stosw
    loop .fill

    ; Real handlers from the table: vector byte, handler offset word, 0 terminates.
    mov si, vector_table
.install:
    xor bx, bx
    mov bl, [cs:si]
    or bl, bl
    jz .installed
    inc si
    shl bx, 2
    mov ax, [cs:si]
    add si, 2
    mov [bx], ax
    mov word [bx + 2], 0xf000
    jmp .install
.installed:
    sti
    mov si, banner
.banner:
    lodsb
    or al, al
    jz .banner_done
    mov ah, 0x0e
    xor bx, bx
    int 0x10
    jmp .banner
.banner_done:
    mov al, 13
    mov ah, 0x0e
    int 0x10
    mov al, 10
    mov ah, 0x0e
    int 0x10
    int 0x19                        ; boot; never returns on success
    int 0x18

; ------------------------------------------------------------ interrupt handlers
default_handler:
    iret

; INT 08h: IRQ0 system timer. Maintains the BDA tick count and midnight flag.
int08_handler:
    push ds
    push ax
    mov ax, 0x40
    mov ds, ax
    inc word [0x6c]
    jnz .no_carry
    inc word [0x6e]
.no_carry:
    cmp word [0x6e], 0x18
    jne .done
    cmp word [0x6c], 0xb0
    jne .done
    mov word [0x6c], 0              ; 24 h elapsed
    mov word [0x6e], 0
    mov byte [0x70], 1
.done:
    int 0x1c                        ; user timer hook
    mov al, 0x20
    out 0x20, al
    pop ax
    pop ds
    iret

; INT 09h: IRQ1. Keystrokes are delivered through INT 16h by the Supervisor, so this
; only drains the controller and acknowledges the interrupt.
int09_handler:
    push ax
    in al, 0x60
    mov al, 0x20
    out 0x20, al
    pop ax
    iret

; INT 70h-77h: slave PIC IRQs (acknowledge both controllers).
irq_slave_handler:
    push ax
    mov al, 0x20
    out 0xa0, al
    out 0x20, al
    pop ax
    iret

int11_handler:                      ; equipment list from the BDA
    push ds
    push bx
    mov bx, 0x40
    mov ds, bx
    mov ax, [0x10]
    pop bx
    pop ds
    iret

int12_handler:                      ; conventional memory size in KiB
    push ds
    mov ax, 0x40
    mov ds, ax
    mov ax, [0x13]
    pop ds
    iret

%macro SERVICE 2
%1:
    out %2, al
    iret
%endmacro

    SERVICE int10_handler, 0xe0
    SERVICE int13_handler, 0xe1
    SERVICE int14_handler, 0xe5
    SERVICE int15_handler, 0xe2
    SERVICE int17_handler, 0xe6
    SERVICE int1a_handler, 0xe4

; INT 16h: keyboard. The Supervisor sets ZF=1 when a blocking read has no key yet;
; the stub then halts until the next interrupt and retries, keeping the timer
; interrupt (and the BDA clock) running while it waits.
int16_handler:
    sti
.again:
    out 0xe3, al
    jnz .done
    hlt
    jmp .again
.done:
    iret

int18_handler:                      ; no bootable device
    mov si, msg_noboot
.print:
    lodsb
    or al, al
    jz .halt
    mov ah, 0x0e
    xor bx, bx
    int 0x10
    jmp .print
.halt:
    cli
    hlt
    jmp .halt

int19_handler:                      ; bootstrap: load the MBR of the first disk to 0000:7C00
    cli
    cld
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    mov dl, 0x80
    out 0xe8, al                    ; Supervisor copies the boot sector, CF=1 on failure
    jc int18_handler
    sti
    jmp 0x0000:0x7c00

msg_noboot: db 13, 10, 'Shizuku vBIOS: no bootable device', 13, 10, 0

; ------------------------------------------------------------ tables
vector_table:
    db 0x08
    dw int08_handler
    db 0x09
    dw int09_handler
    db 0x10
    dw int10_handler
    db 0x11
    dw int11_handler
    db 0x12
    dw int12_handler
    db 0x13
    dw int13_handler
    db 0x14
    dw int14_handler
    db 0x15
    dw int15_handler
    db 0x16
    dw int16_handler
    db 0x17
    dw int17_handler
    db 0x18
    dw int18_handler
    db 0x19
    dw int19_handler
    db 0x1a
    dw int1a_handler
    db 0x70
    dw irq_slave_handler
    db 0x71
    dw irq_slave_handler
    db 0x72
    dw irq_slave_handler
    db 0x73
    dw irq_slave_handler
    db 0x74
    dw irq_slave_handler
    db 0x75
    dw irq_slave_handler
    db 0x76
    dw irq_slave_handler
    db 0x77
    dw irq_slave_handler
    db 0

banner: db 'ShizukuDOS vBIOS 10.0-dev (Supervisor virtual Real Mode)', 0

times 0xe6f5 - ($ - $$) db 0
; INT 15h AH=C0h system configuration table
    dw 8
    db 0xfc                         ; model: AT
    db 0x01                         ; submodel
    db 0x00                         ; BIOS revision
    db 0x74                         ; feature byte 1: 2nd 8259, RTC, INT 15h/4Fh
    db 0, 0, 0, 0

times 0xfff0 - ($ - $$) db 0
reset_vector:
    jmp 0xf000:bios_start
    db '09/29/26'                   ; build date at F000:FFF5
    db 0
    db 0xfc                         ; F000:FFFE machine model byte
    db 0                            ; checksum placeholder
