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
;
; A few services are complete in this ROM because they only need guest-visible
; hardware: INT 1Ah AH=02h-05h (RTC time/date through the CMOS ports 70h/71h) and
; the INT 1Eh diskette parameter table. They were written for ShizukuDOS from the
; documented interface (Ralf Brown's Interrupt List: INT 1A/AH=02h..05h, INT 1E;
; Motorola MC146818A data sheet for the RTC register protocol) and checked against
; the behaviour of SeaBIOS src/clock.c:handle_1a02..handle_1a05 and
; src/misc.c:diskette_param_table (F000:EFC7) / src/hw/floppy.c:floppy_setup. No
; SeaBIOS (LGPL-3.0) code is copied into this GPL-2.0-only file; the behaviour was
; verified under QEMU by shizukudos/supervisor/test_vbios.py. See
; docs/shizukudos10/VBIOS_INT_AUDIT.md.
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

; INT 1Ah: time of day. AH=00h/01h (BDA tick count) and the rest (PCI BIOS query,
; alarms) are Supervisor services; AH=02h-05h are the RTC functions below.
int1a_handler:
    cmp ah, 0x02
    jb .service
    cmp ah, 0x05
    jbe rtc_service
.service:
    out 0xe4, al
    iret

; ------------------------------------------------------------ INT 1Ah RTC (AH=02h-05h)
; RBIL semantics:
;   AH=02h read time  -> CH=hours CL=minutes DH=seconds (BCD, 24 h), DL=DST flag, CF=0
;   AH=03h set time   <- CH/CL/DH as above, DL=DST flag (bit 0)          -> CF=0
;   AH=04h read date  -> CH=century CL=year DH=month DL=day (BCD),        CF=0
;   AH=05h set date   <- CH/CL/DH/DL as above                             -> CF=0
; On success AH=00h. CF=1 (registers otherwise unchanged) when the clock never
; leaves its update cycle, or when a set request carries a non-BCD or out-of-range
; field (a real MC146818 would store such a value and then count from garbage).
; The RTC may run in binary or 12-hour mode (register B bits 2 and 1); values are
; converted so the caller always sees BCD, 24-hour. Under the Supervisor the CMOS
; model forwards reads of registers 00h-0Dh and 32h to the platform RTC and does
; not let a guest change the platform clock (shizukudos/supervisor/src/devices.c).
CMOS_SEC equ 0x00
CMOS_MIN equ 0x02
CMOS_HOUR equ 0x04
CMOS_DAY equ 0x07
CMOS_MONTH equ 0x08
CMOS_YEAR equ 0x09
CMOS_REG_A equ 0x0a
CMOS_REG_B equ 0x0b
CMOS_CENTURY equ 0x32
RTC_B_SET equ 0x80
RTC_B_BINARY equ 0x04
RTC_B_24H equ 0x02
RTC_B_DST equ 0x01

rtc_service:
    push bp
    mov bp, sp                      ; [bp+2]=IP [bp+4]=CS [bp+6]=FLAGS of the caller
    push ax
    push bx
    mov bl, ah                      ; function
    mov al, CMOS_REG_B
    call cmos_read
    mov bh, al                      ; BH = register B for every conversion below
    cmp bl, 0x03
    je .set_time
    cmp bl, 0x05
    je .set_date
    call rtc_wait_ready             ; reads: wait for a stable snapshot window
    jc .fail
    cmp bl, 0x04
    je .get_date

.get_time:                          ; AH=02h
    mov al, CMOS_SEC
    call rtc_get
    mov dh, al
    mov al, CMOS_MIN
    call rtc_get
    mov cl, al
    mov al, CMOS_HOUR
    call cmos_read
    call rtc_hour_to_bcd24
    mov ch, al
    mov dl, bh
    and dl, RTC_B_DST
    jmp .ok

.get_date:                          ; AH=04h
    mov al, CMOS_YEAR
    call rtc_get
    mov cl, al
    mov al, CMOS_MONTH
    call rtc_get
    mov dh, al
    mov al, CMOS_DAY
    call rtc_get
    mov dl, al
    mov al, CMOS_CENTURY
    call rtc_get
    call bcd_check                  ; the century byte is absent or garbage on some
    jc .guess_century               ; platforms: then use a 1980..2079 window on the year
    cmp al, 0x19
    jb .guess_century
    cmp al, 0x29
    ja .guess_century
    mov ch, al
    jmp .ok
.guess_century:
    mov ch, 0x20
    cmp cl, 0x80
    jb .ok
    mov ch, 0x19
    jmp .ok

.set_time:                          ; AH=03h
    mov al, ch
    mov ah, 0x23
    call bcd_check_max
    jc .fail
    mov al, cl
    mov ah, 0x59
    call bcd_check_max
    jc .fail
    mov al, dh
    mov ah, 0x59
    call bcd_check_max
    jc .fail
    call rtc_halt
    mov al, CMOS_SEC
    mov ah, dh
    call rtc_put
    mov al, CMOS_MIN
    mov ah, cl
    call rtc_put
    mov al, ch
    call rtc_hour_from_bcd24
    mov ah, al
    mov al, CMOS_HOUR
    call cmos_write
    mov ah, bh                      ; resume updates; DST flag from DL bit 0
    and ah, ~(RTC_B_SET | RTC_B_DST) & 0xff
    mov al, dl
    and al, RTC_B_DST
    or ah, al
    mov al, CMOS_REG_B
    call cmos_write
    jmp .ok

.set_date:                          ; AH=05h
    mov al, ch
    mov ah, 0x99
    call bcd_check_max
    jc .fail
    mov al, cl
    mov ah, 0x99
    call bcd_check_max
    jc .fail
    mov al, dh
    mov ah, 0x12
    call bcd_check_max
    jc .fail
    or dh, dh
    jz .fail
    mov al, dl
    mov ah, 0x31
    call bcd_check_max
    jc .fail
    or dl, dl
    jz .fail
    call rtc_halt
    mov al, CMOS_YEAR
    mov ah, cl
    call rtc_put
    mov al, CMOS_MONTH
    mov ah, dh
    call rtc_put
    mov al, CMOS_DAY
    mov ah, dl
    call rtc_put
    mov al, CMOS_CENTURY
    mov ah, ch
    call rtc_put
    mov ah, bh                      ; resume updates
    and ah, ~RTC_B_SET & 0xff
    mov al, CMOS_REG_B
    call cmos_write

.ok:                                ; AH=00h, AL and every other input register preserved
    pop bx
    pop ax
    xor ah, ah
    and byte [bp + 6], 0xfe         ; CF=0 in the caller's FLAGS
    pop bp
    iret
.fail:                              ; all registers as on entry
    pop bx
    pop ax
    or byte [bp + 6], 0x01          ; CF=1
    pop bp
    iret

; AL=index -> AL=value
cmos_read:
    out 0x70, al
    in al, 0x71
    ret

; AL=index, AH=value
cmos_write:
    out 0x70, al
    mov al, ah
    out 0x71, al
    ret

; Waits until register A reports no update in progress (UIP=0); the MC146818 then
; guarantees at least 244 us before the next update starts. CF=1 if it never clears.
rtc_wait_ready:
    push cx
    mov cx, 0xffff
.poll:
    mov al, CMOS_REG_A
    call cmos_read
    test al, 0x80
    jz .ready
    loop .poll
    pop cx
    stc
    ret
.ready:
    pop cx
    clc
    ret

; Sets register B's SET bit (BH = register B): the clock stops updating while
; fields are written, and an update already in progress is aborted.
rtc_halt:
    mov ah, bh
    or ah, RTC_B_SET
    mov al, CMOS_REG_B
    jmp cmos_write

; AL=index -> AL=value as BCD (converted when the RTC runs in binary mode)
rtc_get:
    call cmos_read
    test bh, RTC_B_BINARY
    jz .done
    call bin_to_bcd
.done:
    ret

; AL=index, AH=BCD value -> stored in the RTC's format
rtc_put:
    test bh, RTC_B_BINARY
    jz .store
    xchg al, ah
    call bcd_to_bin
    xchg al, ah
.store:
    jmp cmos_write

; AL=raw hours register -> AL=BCD, 24-hour
rtc_hour_to_bcd24:
    test bh, RTC_B_24H
    jnz .h24
    mov ah, al
    and ah, 0x80                    ; AH = PM flag of the 12-hour format
    and al, 0x7f
    test bh, RTC_B_BINARY
    jnz .bin12
    call bcd_to_bin
.bin12:
    cmp al, 12
    jne .not12
    xor al, al                      ; 12 AM is hour 0, 12 PM becomes 12 below
.not12:
    or ah, ah
    jz .to_bcd
    add al, 12
.to_bcd:
    jmp bin_to_bcd
.h24:
    test bh, RTC_B_BINARY
    jz .done
    call bin_to_bcd
.done:
    ret

; AL=BCD, 24-hour -> AL=hours register value in the RTC's format
rtc_hour_from_bcd24:
    test bh, RTC_B_24H
    jnz .h24
    call bcd_to_bin                 ; 0..23
    mov ah, 0                       ; AH = PM flag
    cmp al, 12
    jb .am
    mov ah, 0x80
    sub al, 12
.am:
    or al, al
    jnz .have
    mov al, 12                      ; hour 0 of either half is written as 12
.have:
    test bh, RTC_B_BINARY
    jnz .flag
    call bin_to_bcd
.flag:
    or al, ah
    ret
.h24:
    test bh, RTC_B_BINARY
    jz .done
    call bcd_to_bin
.done:
    ret

; AL=BCD -> AL=binary (AH preserved)
bcd_to_bin:
    push cx
    mov ch, ah
    mov cl, al
    and cl, 0x0f                    ; units
    shr al, 4                       ; tens
    mov ah, 10
    mul ah                          ; AX = tens * 10
    add al, cl
    mov ah, ch
    pop cx
    ret

; AL=binary 0..99 -> AL=BCD (AH preserved)
bin_to_bcd:
    push cx
    mov ch, ah
    xor ah, ah
    mov cl, 10
    div cl                          ; AL = tens, AH = units
    shl al, 4
    or al, ah
    mov ah, ch
    pop cx
    ret

; CF=1 unless AL holds two valid BCD digits
bcd_check:
    push ax
    and al, 0x0f
    cmp al, 9
    pop ax
    ja .bad
    cmp al, 0xa0
    jae .bad
    clc
    ret
.bad:
    stc
    ret

; CF=1 unless AL is valid BCD and AL <= AH
bcd_check_max:
    call bcd_check
    jc .ret
    cmp ah, al
.ret:
    ret

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
    db 0x1e                         ; data pointer, not code: diskette parameter table
    dw diskette_param_table
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

; INT 1Eh diskette parameter table (RBIL "Format of diskette parameter table"),
; 3.5" 1.44 MB values, at the address IBM-compatible BIOSes use (F000:EFC7).
; There is no diskette controller in the Supervisor; DOS still copies and patches
; this table at boot (FreeDOS kernel/initdisk.c ReadAllPartitionTables).
times 0xefc7 - ($ - $$) db 0
diskette_param_table:
    db 0xaf                         ; step rate 0Ah, head unload time 0Fh
    db 0x02                         ; head load time 1, DMA mode
    db 0x25                         ; motor-off delay: 37 ticks
    db 0x02                         ; 512 bytes per sector
    db 18                           ; sectors per track
    db 0x1b                         ; gap length between sectors (3.5")
    db 0xff                         ; data length (unused with 512-byte sectors)
    db 0x6c                         ; gap length when formatting (3.5")
    db 0xf6                         ; format filler byte
    db 0x0f                         ; head settle time, ms
    db 0x08                         ; motor start time, 1/8 s

times 0xfff0 - ($ - $$) db 0
reset_vector:
    jmp 0xf000:bios_start
    db '09/29/26'                   ; build date at F000:FFF5
    db 0
    db 0xfc                         ; F000:FFFE machine model byte
    db 0                            ; checksum placeholder
