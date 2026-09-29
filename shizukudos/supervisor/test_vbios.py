#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-side checks of the Shizuku vBIOS that do not need Intel VMX.

The vBIOS only runs for real inside the Supervisor's DOS16 domain, which needs VMX
(unavailable on this host). What CAN be checked without it:

  1. ROM image: the built guest/vbios.bin is 64 KiB, reproducible from the source,
     has the F000:FFF0 far jump, the IBM-fixed tables (INT 15h/C0h at E6F5, INT 1Eh
     diskette parameters at EFC7) and the expected handler shapes (hypercall stubs
     are `out <port>, al; iret`).
  2. ROM execution under QEMU TCG with the ROM as the machine BIOS (`-bios`): the
     reset path (PIC/PIT/IVT set-up, INT 19h hand-off to 0000:7C00) and every service
     the ROM implements by itself -- INT 1Ah AH=02h-05h against QEMU's MC146818 RTC in
     BCD/binary x 24/12-hour modes, invalid-input rejection, register preservation,
     and the INT 1Eh table. A small real-mode probe at 7C00h drives it and reports on
     COM1. Hypercall-backed services (INT 10h/13h/15h/16h/...) are no-ops here.
  3. The Supervisor service back end (src/bios.c) compiled for the host against mock
     VMCS/device headers and driven like the ROM stubs drive it (INT 13h CHS/EDD incl.
     AH=44h/47h/48h, INT 15h, INT 16h, INT 1Ah AH=00h/01h), under ASan/UBSan.
None of this is a VMX run; the record says so.
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0] / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, REPO, run, sha256_file  # noqa: E402

OUT = BUILD / "supervisor"
RESULT = OUT / "vbios-host-test"


def check(name, ok, detail=""):
    return {"check": name, "status": "PASS" if ok else "FAIL", "detail": str(detail)[:300]}


# ------------------------------------------------------------------ 1. ROM image
def rom_checks(work):
    rom = OUT / "vbios.bin"
    receipt = OUT / "build-result.json"
    if not rom.exists() or not receipt.exists():
        raise SystemExit("Run shizukudos/supervisor/build.py first")
    built = json.loads(receipt.read_text())
    stale = [n for n, d in built["sources_sha256"].items() if sha256_file(REPO / n) != d]
    if stale:
        raise SystemExit(f"Stale Supervisor build, source changed: {stale}")
    (work / "map.inc").write_text("[map symbols vbios.map]\n")
    fresh = work / "vbios.bin"
    run(["nasm", "-f", "bin", "-w+all", "-P", work / "map.inc", "-o", fresh, HERE / "guest" / "vbios.asm"], cwd=work)
    syms = {}
    for line in (work / "vbios.map").read_text().splitlines():
        m = re.match(r"\s+([0-9A-F]+)\s+[0-9A-F]+\s+(\S+)$", line)
        if m:
            syms[m.group(2)] = int(m.group(1), 16)
    data = rom.read_bytes()
    c = [check("vBIOS: build output equals a fresh `nasm -w+all` of the source", data == fresh.read_bytes(),
               sha256_file(rom)[:16]),
         check("vBIOS: 64 KiB with far jump F000:xxxx at FFF0", len(data) == 0x10000 and data[0xfff0] == 0xea
               and data[0xfff3:0xfff5] == b"\x00\xf0", data[0xfff0:0xfff5].hex()),
         check("vBIOS: INT 15h/C0h configuration table at F000:E6F5", data[0xe6f5:0xe6f8] == b"\x08\x00\xfc",
               data[0xe6f5:0xe6ff].hex()),
         check("vBIOS: INT 1Eh diskette parameter table at F000:EFC7 (RBIL layout, 1.44 MB)",
               syms.get("diskette_param_table") == 0xefc7 and
               data[0xefc7:0xefd2] == bytes([0xaf, 0x02, 0x25, 0x02, 18, 0x1b, 0xff, 0x6c, 0xf6, 0x0f, 0x08]),
               data[0xefc7:0xefd2].hex())]
    for name, port in (("int10_handler", 0xe0), ("int13_handler", 0xe1), ("int14_handler", 0xe5),
                       ("int15_handler", 0xe2), ("int17_handler", 0xe6)):
        off = syms.get(name, 0)
        c.append(check(f"vBIOS: {name} is the hypercall stub `out {port:#x}, al; iret`",
                       data[off:off + 3] == bytes([0xe6, port, 0xcf]), data[off:off + 3].hex()))
    off = syms.get("int1a_handler", 0)
    c.append(check("vBIOS: INT 1Ah dispatches AH=02h..05h to the ROM RTC code, the rest to port E4h",
                   data[off:off + 3] == b"\x80\xfc\x02" and bytes([0xe6, 0xe4, 0xcf]) in data[off:off + 16],
                   data[off:off + 16].hex()))
    code_end = max(v for k, v in syms.items() if k.startswith(("rtc_", "bcd_", "bin_", "cmos_")))
    c.append(check("vBIOS: code and data stay below the fixed tables at E6F5", code_end < 0xe6f5, hex(code_end)))
    return c, syms, data


# ------------------------------------------------------------------ 2. ROM under QEMU
PROBE = r"""
bits 16
cpu 386
org 0x7c00
start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    mov si, m_ivt
    call puts
    xor si, si
    mov cx, 0x200                   ; vectors 00h..7Fh
    call hexdump
    call crlf
    mov si, m_dpt
    call puts
    push ds
    lds si, [0x1e * 4]
    mov cx, 11
    call hexdump
    pop ds
    call crlf

    mov si, modes
.mode:
    lodsb
    cmp al, 0xff
    je .modes_done
    mov [cur_b], al
    push si
    mov si, m_mode
    call puts
    mov al, [cur_b]
    call hex8
    call crlf
    mov al, 0x0b
    out 0x70, al
    mov al, [cur_b]
    out 0x71, al
    mov ax, 0x0500                  ; set date 2026-09-29
    mov cx, 0x2026
    mov dx, 0x0929
    call sentinels
    int 0x1a
    call dump_regs
    mov si, raw_date
    call dump_cmos
    mov si, hours
.hour:
    lodsb
    cmp al, 0xff
    je .hours_done
    push si
    mov ch, al
    mov ax, 0x0300                  ; set time hh:34:56, DST on
    mov cl, 0x34
    mov dx, 0x5601
    call sentinels
    int 0x1a
    call dump_regs
    mov si, raw_time
    call dump_cmos
    mov ax, 0x0277                  ; read time (AL=77h must survive)
    xor cx, cx
    xor dx, dx
    call sentinels
    int 0x1a
    call dump_regs
    pop si
    jmp .hour
.hours_done:
    mov ax, 0x0455                  ; read date (AL=55h must survive)
    xor cx, cx
    xor dx, dx
    call sentinels
    int 0x1a
    call dump_regs
    pop si
    jmp .mode
.modes_done:
    mov al, 0x0b                    ; back to BCD / 24 h
    out 0x70, al
    mov al, 0x02
    out 0x71, al
    mov si, m_bad
    call puts
    call crlf
    mov si, raw_all
    call dump_cmos
    mov si, bad_calls
.bad:
    lodsw
    cmp ax, 0xffff
    je .bad_done
    mov bx, ax
    lodsw
    mov cx, ax
    lodsw
    mov dx, ax
    push si
    mov ax, bx
    call sentinels
    int 0x1a
    call dump_regs
    pop si
    jmp .bad
.bad_done:
    mov si, raw_all
    call dump_cmos
    mov ax, 0x00aa                  ; AH=00h goes to the hypercall port (no-op here)
    call sentinels
    int 0x1a
    call dump_regs
    mov si, m_end
    call puts
    call crlf
.halt:
    cli
    hlt
    jmp .halt

sentinels:
    mov bx, 0x1234
    mov si, 0x5678
    mov di, 0x9abc
    mov bp, 0xdef0
    ret

dump_regs:                          ; "R ax bx cx dx si di bp flags" right after an INT
    pushf
    pusha
    mov bp, sp
    push ax
    mov al, 'R'
    call putc
    pop ax
    mov ax, [bp + 14]
    call hex16s
    mov ax, [bp + 8]
    call hex16s
    mov ax, [bp + 12]
    call hex16s
    mov ax, [bp + 10]
    call hex16s
    mov ax, [bp + 2]
    call hex16s
    mov ax, [bp + 0]
    call hex16s
    mov ax, [bp + 4]
    call hex16s
    mov ax, [bp + 16]
    call hex16s
    call crlf
    popa
    popf
    ret

dump_cmos:                          ; SI -> index list (FFh ends): "C ii=vv ..."
    mov al, 'C'
    call putc
.next:
    lodsb
    cmp al, 0xff
    je .done
    mov ah, al
    mov al, ' '
    call putc
    mov al, ah
    call hex8
    mov al, '='
    call putc
    mov al, ah
    out 0x70, al
    in al, 0x71
    call hex8
    jmp .next
.done:
    jmp crlf

hexdump:                            ; CX bytes at DS:SI
    lodsb
    call hex8
    loop hexdump
    ret

hex16s:
    push ax
    mov al, ' '
    call putc
    pop ax
    push ax
    mov al, ah
    call hex8
    pop ax
hex8:
    push ax
    shr al, 4
    call nib
    pop ax
    push ax
    and al, 0x0f
    call nib
    pop ax
    ret
nib:
    add al, '0'
    cmp al, '9'
    jbe putc
    add al, 7
putc:
    push dx
    push ax
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    pop ax
    mov dx, 0x3f8
    out dx, al
    pop dx
    ret
crlf:
    mov al, 13
    call putc
    mov al, 10
    jmp putc
puts:
    lodsb
    or al, al
    jz .done
    call putc
    jmp puts
.done:
    ret

m_ivt: db 'IVT ', 0
m_dpt: db 'DPT ', 0
m_mode: db 'MODE ', 0
m_bad: db 'BAD', 0
m_end: db 'PROBE-END', 0
cur_b: db 0
modes: db 0x02, 0x06, 0x00, 0x04, 0xff
hours: db 0x00, 0x09, 0x12, 0x15, 0x23, 0xff
raw_date: db 0x07, 0x08, 0x09, 0x32, 0xff
raw_time: db 0x00, 0x02, 0x04, 0x0b, 0xff
raw_all: db 0x02, 0x04, 0x07, 0x08, 0x09, 0x32, 0xff
bad_calls:                          ; AX, CX, DX
    dw 0x0301, 0x127a, 0x0000       ; minutes 7Ah: not BCD
    dw 0x0302, 0x2400, 0x0000       ; hour 24
    dw 0x0303, 0x1260, 0x0000       ; minutes 60
    dw 0x0304, 0x1200, 0x6000       ; seconds 60
    dw 0x0505, 0x2026, 0x1301       ; month 13
    dw 0x0506, 0x2026, 0x0001       ; month 0
    dw 0x0507, 0x2026, 0x0900       ; day 0
    dw 0x0508, 0x2026, 0x0932       ; day 32
    dw 0x0509, 0x209a, 0x0929       ; year 9Ah
    dw 0x050a, 0x2a26, 0x0929       ; century 2Ah
    dw 0xffff
"""


def bcd(v):
    return (v // 10) << 4 | v % 10


def unbcd(v):
    return (v >> 4) * 10 + (v & 15)


def rtc_raw_hour(bcd24, regb):
    h = unbcd(bcd24)
    binary = regb & 4
    if regb & 2:
        return h if binary else bcd24
    pm = 0x80 if h >= 12 else 0
    h12 = h % 12 or 12
    return (h12 if binary else bcd(h12)) | pm


def qemu_rom_checks(work, syms, args_qemu):
    (work / "probe.asm").write_text(PROBE)
    probe = work / "probe.bin"
    run(["nasm", "-f", "bin", "-w+all", "-o", probe, work / "probe.asm"])
    serial = work / "probe-serial.log"
    command = [args_qemu, "-name", "shz-vbios-probe", "-machine", "pc", "-accel", "tcg", "-cpu", "qemu64", "-m", "16",
               "-bios", OUT / "vbios.bin", "-device", f"loader,file={probe},addr=0x7c00,force-raw=on",
               "-display", "none", "-monitor", "none", "-vga", "none", "-net", "none", "-no-reboot",
               "-serial", f"file:{serial}"]
    proc = subprocess.Popen([str(x) for x in command], stdout=subprocess.DEVNULL, stderr=open(work / "qemu.stderr", "wb"))
    try:
        ok = qemu.wait_for(serial, "PROBE-END", 120)
    finally:
        proc.kill()                                  # only the QEMU this test started
        proc.wait(timeout=20)
    text = serial.read_text(errors="replace") if serial.exists() else ""
    c = [check("ROM under QEMU: reset vector -> IVT set-up -> INT 19h -> probe at 0000:7C00 ran to completion", ok,
               f"{len(text)} bytes of COM1 output")]
    if not ok:
        return c, command, text
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    ivt = bytes.fromhex(next(l for l in lines if l.startswith("IVT "))[4:])
    vec = {n: int.from_bytes(ivt[4 * n:4 * n + 2], "little") | int.from_bytes(ivt[4 * n + 2:4 * n + 4], "little") << 16
           for n in range(0x80)}
    want = {0x08: "int08_handler", 0x09: "int09_handler", 0x10: "int10_handler", 0x11: "int11_handler",
            0x12: "int12_handler", 0x13: "int13_handler", 0x14: "int14_handler", 0x15: "int15_handler",
            0x16: "int16_handler", 0x17: "int17_handler", 0x18: "int18_handler", 0x19: "int19_handler",
            0x1a: "int1a_handler", 0x1e: "diskette_param_table", **{v: "irq_slave_handler" for v in range(0x70, 0x78)}}
    bad = [f"{n:02x}={vec[n]:08x}" for n in range(0x80)
           if vec[n] != (0xf000 << 16 | syms[want.get(n, "default_handler")])]
    c.append(check("ROM under QEMU: all 128 low vectors point where the ROM's table says (F000:handler)", not bad,
                   ", ".join(bad[:6]) or "vectors 08-1A, 1E, 70-77 installed, the rest -> IRET"))
    dpt = next(l for l in lines if l.startswith("DPT "))[4:]
    c.append(check("ROM under QEMU: INT 1Eh vector reaches the 11-byte diskette parameter table", dpt == "AF022502121BFF6CF60F08",
                   dpt))
    regs = [l for l in lines if l.startswith("R ")]
    cmos = [l for l in lines if l.startswith("C ")]

    def parse_r(l):
        return [int(x, 16) for x in l.split()[1:]]

    def parse_c(l):
        return {int(k, 16): int(v, 16) for k, v in (p.split("=") for p in l.split()[1:])}

    ri = ci = 0
    problems = []
    rtc_cases = 0
    for regb in (0x02, 0x06, 0x00, 0x04):
        mode = f"regB={regb:02x} ({'binary' if regb & 4 else 'BCD'}, {'24' if regb & 2 else '12'} h)"
        binary = regb & 4
        r = parse_r(regs[ri]); ri += 1
        d = parse_c(cmos[ci]); ci += 1
        conv = (lambda v: unbcd(v)) if binary else (lambda v: v)
        if r[0] != 0x0000 or r[7] & 1 or r[1:3] != [0x1234, 0x2026] or r[3] != 0x0929 or r[4:7] != [0x5678, 0x9abc, 0xdef0]:
            problems.append(f"{mode} AH=05h regs {r}")
        if [d[7], d[8], d[9], d[0x32]] != [conv(0x29), conv(0x09), conv(0x26), conv(0x20)]:
            problems.append(f"{mode} AH=05h raw date {d}")
        for hh in (0x00, 0x09, 0x12, 0x15, 0x23):
            rtc_cases += 1
            r = parse_r(regs[ri]); ri += 1
            t = parse_c(cmos[ci]); ci += 1
            rr = parse_r(regs[ri]); ri += 1
            if r[0] != 0x0000 or r[7] & 1 or r[2] != (hh << 8 | 0x34) or r[3] != 0x5601:
                problems.append(f"{mode} AH=03h {hh:02x} regs {r}")
            if t[4] != rtc_raw_hour(hh, regb) or t[2] != conv(0x34) or not conv(0x56) <= t[0] <= conv(0x59) or \
                    t[0xb] != ((regb & 0x7e) | 1):
                problems.append(f"{mode} AH=03h {hh:02x} raw {t} want hour {rtc_raw_hour(hh, regb):02x}")
            if rr[0] != 0x0077 or rr[7] & 1 or rr[2] != (hh << 8 | 0x34) or not 0x5601 <= rr[3] <= 0x5901 or \
                    rr[3] & 0xff != 1 or rr[1] != 0x1234 or rr[4:7] != [0x5678, 0x9abc, 0xdef0]:
                problems.append(f"{mode} AH=02h after {hh:02x}: {rr}")
        r = parse_r(regs[ri]); ri += 1
        if r[0] != 0x0055 or r[7] & 1 or r[2:4] != [0x2026, 0x0929]:
            problems.append(f"{mode} AH=04h regs {r}")
    c.append(check(f"ROM under QEMU: INT 1Ah AH=05h/03h/02h/04h round-trip in 4 RTC modes x 5 hours "
                   f"({rtc_cases} set/read pairs; raw registers in the RTC's own format; AL/BX/SI/DI/BP kept)",
                   not problems, "; ".join(problems[:3])))
    before = parse_c(cmos[ci]); ci += 1
    bad_regs = [parse_r(regs[ri + k]) for k in range(10)]
    ri += 10
    after = parse_c(cmos[ci]); ci += 1
    inputs = [(0x0301, 0x127a, 0x0000), (0x0302, 0x2400, 0x0000), (0x0303, 0x1260, 0x0000), (0x0304, 0x1200, 0x6000),
              (0x0505, 0x2026, 0x1301), (0x0506, 0x2026, 0x0001), (0x0507, 0x2026, 0x0900), (0x0508, 0x2026, 0x0932),
              (0x0509, 0x209a, 0x0929), (0x050a, 0x2a26, 0x0929)]
    rejected = [r[7] & 1 and r[0] == ax and r[2] == cx and r[3] == dx for r, (ax, cx, dx) in zip(bad_regs, inputs)]
    c.append(check("ROM under QEMU: 10 invalid set requests (non-BCD, hour 24, minute/second 60, month 0/13, day 0/32, "
                   "bad year/century) -> CF=1, registers unchanged", all(rejected), [hex(r[7]) for r in bad_regs]))
    c.append(check("ROM under QEMU: rejected requests did not write the RTC", {k: before[k] for k in before} ==
                   {k: after[k] for k in after}, f"{before} -> {after}"))
    r = parse_r(regs[ri])
    c.append(check("ROM under QEMU: INT 1Ah AH=00h still goes to the Supervisor port (no-op without it) and returns",
                   r[0] == 0x00aa and r[1] == 0x1234, r))
    return c, command, text


# ------------------------------------------------------------------ 3. bios.c on the host
MOCK_CPU_H = r"""
/* Host test double for shizukudos/supervisor/src/cpu.h (test_vbios.py) */
#ifndef SHZ_CPU_H
#define SHZ_CPU_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
uint64_t mock_vmread(uint64_t field);
void mock_vmwrite(uint64_t field, uint64_t value);
extern uint64_t mock_tsc;
static inline uint64_t vmread(uint64_t field) { return mock_vmread(field); }
static inline int vmwrite(uint64_t field, uint64_t value) { mock_vmwrite(field, value); return 0; }
static inline uint64_t rdtsc(void) { return mock_tsc += 1000; }
static inline void pause_cpu(void) {}
#endif
"""

HOST_DRIVER = r"""
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "bios.h"
#include "console.h"
#include "cpu.h"
#include "devices.h"
#include "guest.h"
#include "video.h"

guest_t G;
uint64_t mock_tsc;
static vcpu_t vc;
static shz_info_t info;
static uint8_t *ram, *disk;
static uint64_t f_ss, f_rsp, f_rflags = 0x2, f_es, f_ds, f_es_base;
static int a20 = 1, fails, checks;
static const char *pending_keys = "";
void (*dev_uart_tx_hook)(uint8_t);
volatile int dev_a20_dirty;

uint64_t mock_vmread(uint64_t f)
{
    switch (f) {
    case VMCS_GUEST_SS_SEL: return f_ss;
    case VMCS_GUEST_RSP: return f_rsp;
    case VMCS_GUEST_RFLAGS: return f_rflags;
    case VMCS_GUEST_ES_SEL: return f_es;
    case VMCS_GUEST_DS_SEL: return f_ds;
    default: fprintf(stderr, "unexpected vmread %#llx\n", (unsigned long long)f); abort();
    }
}
void mock_vmwrite(uint64_t f, uint64_t v)
{
    switch (f) {
    case VMCS_GUEST_RFLAGS: f_rflags = v; break;
    case VMCS_GUEST_ES_SEL: f_es = v; break;
    case VMCS_GUEST_ES_BASE: f_es_base = v; break;
    default: fprintf(stderr, "unexpected vmwrite %#llx\n", (unsigned long long)f); abort();
    }
}
int dev_a20_get(void) { return a20; }
void dev_a20_set(int e) { a20 = e != 0; }
void dev_uart_rx_push(uint8_t b) { (void)b; }
int dev_pio_in(uint16_t port, int size, uint32_t *v) { (void)port; (void)size; *v = 0x60; return 1; }
uint8_t dev_cmos_read(uint8_t i) { (void)i; abort(); }
int serial_getc_nonblock(void) { return *pending_keys ? *pending_keys++ : -1; }
void serial_putc(char c) { (void)c; }
void kprintf(const char *fmt, ...) { (void)fmt; }
void video_int10(void) {}
void video_init(void) {}

#define FLAGS_AT 0x6ffe                         /* stacked FLAGS of the INT frame at SS:SP+4 */
typedef struct { uint16_t ax, bx, cx, dx, si, di, ds, es; } regs_t;

static void call(uint16_t port, regs_t *r)
{
    vc.gpr[GPR_RAX] = 0xdead0000u | r->ax; vc.gpr[GPR_RBX] = r->bx; vc.gpr[GPR_RCX] = r->cx;
    vc.gpr[GPR_RDX] = r->dx; vc.gpr[GPR_RSI] = r->si; vc.gpr[GPR_RDI] = r->di;
    f_ds = r->ds; f_es = r->es; f_ss = 0; f_rsp = FLAGS_AT - 4; f_rflags = 0x2;
    *(uint16_t *)(ram + FLAGS_AT) = 0x0202;
    if (!bios_hypercall(port)) { printf("FAIL port %#x not handled\n", port); ++fails; }
    r->ax = (uint16_t)vc.gpr[GPR_RAX]; r->bx = (uint16_t)vc.gpr[GPR_RBX]; r->cx = (uint16_t)vc.gpr[GPR_RCX];
    r->dx = (uint16_t)vc.gpr[GPR_RDX]; r->es = (uint16_t)f_es;
}
static int cf(void) { return *(uint16_t *)(ram + FLAGS_AT) & 1; }
static int zf(void) { return (*(uint16_t *)(ram + FLAGS_AT) >> 6) & 1; }
static void expect(const char *name, int ok)
{
    ++checks;
    if (!ok) { ++fails; printf("FAIL %s\n", name); }
    else printf("ok   %s\n", name);
}
static void dap(uint16_t at, uint8_t size, uint16_t count, uint16_t off, uint16_t seg, uint64_t lba)
{
    uint8_t *p = ram + at;
    memset(p, 0, 16);
    p[0] = size; *(uint16_t *)(p + 2) = count; *(uint16_t *)(p + 4) = off; *(uint16_t *)(p + 6) = seg;
    memcpy(p + 8, &lba, 8);
}

int main(void)
{
    const uint64_t ram_size = 64ull << 20, sectors = 65520;
    regs_t r;
    unsigned i;
    ram = calloc(1, ram_size);
    disk = malloc(sectors * 512);
    for (i = 0; i < sectors * 512; ++i) disk[i] = (uint8_t)(i * 7 + i / 512);
    G.vc = &vc; G.ram_base = (uintptr_t)ram; G.ram_size = ram_size; G.info = &info; G.tsc_hz = 1000000000;
    info.disk_base = (uintptr_t)disk; info.disk_size = sectors * 512;
    bios_init();
    bios_prepare_guest_memory();

    /* ---- INT 13h */
    r = (regs_t){.ax = 0x4100, .bx = 0x55aa, .dx = 0x0080}; call(0xe1, &r);
    expect("13h/41h: BX=AA55, AH=21h, CX bit0 (42h-44h,47h,48h subset), CF=0", r.bx == 0xaa55 && r.ax >> 8 == 0x21 && r.cx == 1 && !cf());
    r = (regs_t){.ax = 0x0800, .dx = 0x0080}; call(0xe1, &r);
    expect("13h/08h: 65 cyl x 16 x 63, one disk", !cf() && r.cx == 0x403f && r.dx == 0x0f01 && r.ax >> 8 == 0);
    r = (regs_t){.ax = 0x1500, .dx = 0x0080}; call(0xe1, &r);
    expect("13h/15h: fixed disk, CX:DX = sectors", !cf() && r.ax >> 8 == 3 && ((uint32_t)r.cx << 16 | r.dx) == sectors);
    r = (regs_t){.ax = 0x0201, .cx = 0x0001, .dx = 0x0080, .bx = 0x8000, .es = 0}; call(0xe1, &r);
    expect("13h/02h: CHS 0/0/1 reads LBA 0", !cf() && (r.ax & 0xff) == 1 && !memcmp(ram + 0x8000, disk, 512));
    dap(0x600, 0x10, 2, 0x0000, 0x0900, 100); r = (regs_t){.ax = 0x4200, .dx = 0x80, .si = 0x600}; call(0xe1, &r);
    expect("13h/42h: LBA 100 x2 read", !cf() && !memcmp(ram + 0x9000, disk + 100 * 512, 1024));
    memset(ram + 0xa000, 0x5a, 512);
    dap(0x600, 0x10, 1, 0x0000, 0x0a00, 200); r = (regs_t){.ax = 0x4300, .dx = 0x80, .si = 0x600}; call(0xe1, &r);
    expect("13h/43h: LBA 200 written", !cf() && disk[200 * 512] == 0x5a && disk[200 * 512 + 511] == 0x5a);
    {
        uint8_t before[64];
        memcpy(before, disk + 300 * 512, 64);
        memset(ram + 0xb000, 0xee, 1024);
        dap(0x600, 0x10, 2, 0x0000, 0x0b00, 300); r = (regs_t){.ax = 0x4400, .dx = 0x80, .si = 0x600}; call(0xe1, &r);
        expect("13h/44h: verify LBA 300 x2 -> AH=0 CF=0, no data moved either way",
               !cf() && r.ax >> 8 == 0 && ram[0xb000] == 0xee && !memcmp(before, disk + 300 * 512, 64));
    }
    dap(0x600, 0x10, 1, 0, 0x0b00, sectors - 1); r = (regs_t){.ax = 0x4400, .dx = 0x80, .si = 0x600}; call(0xe1, &r);
    expect("13h/44h: last sector verifies", !cf() && r.ax >> 8 == 0);
    dap(0x600, 0x10, 2, 0, 0x0b00, sectors - 1); r = (regs_t){.ax = 0x4400, .dx = 0x80, .si = 0x600}; call(0xe1, &r);
    expect("13h/44h: range past the end -> CF=1 AH=04h", cf() && r.ax >> 8 == 4);
    dap(0x600, 0x10, 1, 0, 0x0b00, sectors); r = (regs_t){.ax = 0x4400, .dx = 0x80, .si = 0x600}; call(0xe1, &r);
    expect("13h/44h: LBA = size -> CF=1 AH=04h", cf() && r.ax >> 8 == 4);
    dap(0x600, 0x10, 0, 0, 0x0b00, 5); r = (regs_t){.ax = 0x4400, .dx = 0x80, .si = 0x600}; call(0xe1, &r);
    expect("13h/44h: zero blocks -> success", !cf());
    dap(0x600, 0x08, 1, 0, 0x0b00, 5); r = (regs_t){.ax = 0x4400, .dx = 0x80, .si = 0x600}; call(0xe1, &r);
    expect("13h/44h: DAP shorter than 10h -> CF=1 AH=01h", cf() && r.ax >> 8 == 1);
    r = (regs_t){.ax = 0x0100, .dx = 0x80}; call(0xe1, &r);
    expect("13h/01h: last status is 01h", r.ax >> 8 == 1);
    dap(0x600, 0x10, 99, 0, 0, sectors - 1); r = (regs_t){.ax = 0x4700, .dx = 0x80, .si = 0x600}; call(0xe1, &r);
    expect("13h/47h: seek to the last sector (count ignored)", !cf() && r.ax >> 8 == 0);
    dap(0x600, 0x10, 1, 0, 0, sectors + 5); r = (regs_t){.ax = 0x4700, .dx = 0x80, .si = 0x600}; call(0xe1, &r);
    expect("13h/47h: seek past the end -> CF=1 AH=04h", cf() && r.ax >> 8 == 4);
    {
        uint8_t *b = ram + 0x700;
        memset(b, 0xcc, 0x50); *(uint16_t *)b = 0x1e;
        r = (regs_t){.ax = 0x4800, .dx = 0x80, .si = 0x700}; call(0xe1, &r);
        expect("13h/48h: 1Eh buffer -> 1Ah-byte EDD 1.x result, geometry valid, DPTE area untouched",
               !cf() && *(uint16_t *)b == 0x1a && *(uint16_t *)(b + 2) == 2 && *(uint32_t *)(b + 4) == 65 &&
               *(uint32_t *)(b + 8) == 16 && *(uint32_t *)(b + 12) == 63 && *(uint64_t *)(b + 16) == sectors &&
               *(uint16_t *)(b + 24) == 512 && b[26] == 0xcc && b[29] == 0xcc);
        memset(b, 0xcc, 0x50); *(uint16_t *)b = 0x1a;
        r = (regs_t){.ax = 0x4800, .dx = 0x80, .si = 0x700}; call(0xe1, &r);
        expect("13h/48h: exact 1Ah buffer, nothing written past it", !cf() && *(uint16_t *)b == 0x1a && b[26] == 0xcc);
        memset(b, 0xcc, 0x50); *(uint16_t *)b = 0x19;
        r = (regs_t){.ax = 0x4800, .dx = 0x80, .si = 0x700}; call(0xe1, &r);
        expect("13h/48h: buffer smaller than 1Ah -> CF=1 AH=01h, buffer untouched",
               cf() && r.ax >> 8 == 1 && *(uint16_t *)b == 0x19 && b[2] == 0xcc);
        memset(b, 0xcc, 0x50); *(uint16_t *)b = 0x42;
        r = (regs_t){.ax = 0x4800, .dx = 0x80, .si = 0x700}; call(0xe1, &r);
        expect("13h/48h: EDD 3.0-sized request still answered with 1Ah", !cf() && *(uint16_t *)b == 0x1a && b[0x1a] == 0xcc);
    }
    r = (regs_t){.ax = 0x0800, .dx = 0x0081}; call(0xe1, &r);
    expect("13h: second hard disk absent -> CF=1", cf());

    /* ---- INT 15h */
    {
        uint32_t ebx = 0; unsigned n = 0; int sane = 1; uint64_t ram_sum = 0;
        do {
            vc.gpr[GPR_RAX] = 0xe820; vc.gpr[GPR_RBX] = ebx; vc.gpr[GPR_RCX] = 20; vc.gpr[GPR_RDX] = 0x534d4150;
            vc.gpr[GPR_RDI] = 0x800; f_es = 0; f_ss = 0; f_rsp = FLAGS_AT - 4; *(uint16_t *)(ram + FLAGS_AT) = 0x202;
            bios_hypercall(0xe2);
            if (cf() || (uint32_t)vc.gpr[GPR_RAX] != 0x534d4150 || (uint32_t)vc.gpr[GPR_RCX] != 20) sane = 0;
            if (*(uint32_t *)(ram + 0x810) == 1) ram_sum += *(uint64_t *)(ram + 0x808);
            ebx = (uint32_t)vc.gpr[GPR_RBX];
        } while (ebx && ++n < 16);
        expect("15h/E820: 4 entries, SMAP echoed, RAM = 639 KiB + (64 MiB - 1 MiB)", sane && n == 3 &&
               ram_sum == 0x9fc00 + ram_size - 0x100000);
    }
    r = (regs_t){.ax = 0xe801}; call(0xe2, &r);
    expect("15h/E801: 15 MiB below 16M, 48 MiB above in 64K blocks", !cf() && r.ax == 0x3c00 && r.cx == 0x3c00 && r.bx == 768 && r.dx == 768);
    r = (regs_t){.ax = 0x8800}; call(0xe2, &r);
    expect("15h/88h: 63 MiB (capped FC00h KiB)", !cf() && r.ax == 0xfc00);
    r = (regs_t){.ax = 0xc000}; call(0xe2, &r);
    expect("15h/C0h: ES:BX = F000:E6F5", !cf() && r.bx == 0xe6f5 && r.es == 0xf000 && f_es_base == 0xf0000);
    r = (regs_t){.ax = 0x2403}; call(0xe2, &r);
    expect("15h/2403h: A20 via KBC and port 92h", !cf() && r.bx == 3 && r.ax >> 8 == 0);
    r = (regs_t){.ax = 0x2400}; call(0xe2, &r); r = (regs_t){.ax = 0x2402}; call(0xe2, &r);
    expect("15h/2400h+2402h: A20 off reported", !cf() && (r.ax & 0xff) == 0 && !a20);
    r = (regs_t){.ax = 0x2401}; call(0xe2, &r);
    expect("15h/2401h: A20 on", !cf() && a20);
    r = (regs_t){.ax = 0xc100}; call(0xe2, &r);
    expect("15h/C1h: not implemented -> AH=86h CF=1 (documented gap)", cf() && r.ax >> 8 == 0x86);

    /* ---- INT 16h */
    r = (regs_t){.ax = 0x0100}; call(0xe3, &r);
    expect("16h/01h: no key -> ZF=1", zf());
    pending_keys = "a";
    r = (regs_t){.ax = 0x0100}; call(0xe3, &r);
    expect("16h/01h: key waiting -> ZF=0, AX=1E61h", !zf() && r.ax == 0x1e61);
    r = (regs_t){.ax = 0x0000}; call(0xe3, &r);
    expect("16h/00h: returns and removes the key", r.ax == 0x1e61 && !(f_rflags & 0x40));
    r = (regs_t){.ax = 0x0000}; call(0xe3, &r);
    expect("16h/00h: empty queue -> stub asked to HLT and retry (current ZF=1)", (f_rflags & 0x40) != 0);

    /* ---- INT 1Ah (Supervisor part) */
    r = (regs_t){.ax = 0x0100, .cx = 0x0012, .dx = 0x3456}; call(0xe4, &r);
    r = (regs_t){.ax = 0x0000}; call(0xe4, &r);
    expect("1Ah/01h+00h: BDA tick count round trip", r.cx == 0x0012 && r.dx == 0x3456 && (r.ax & 0xff) == 0);
    r = (regs_t){.ax = 0x0200}; call(0xe4, &r);
    expect("1Ah/02h no longer reaches the back end (served by the ROM): CF=1", cf());
    printf("SUMMARY checks=%d fails=%d\n", checks, fails);
    free(ram); free(disk);
    return fails ? 1 : 0;
}
"""


def host_backend_checks(work):
    src = work / "backend" / "src"
    inc = work / "backend" / "include"
    src.mkdir(parents=True)
    inc.mkdir(parents=True)
    for name in ("bios.c", "bios.h", "guest.h", "vmx.h", "devices.h", "console.h", "video.h", "ept.h"):
        shutil.copyfile(HERE / "src" / name, src / name)
    shutil.copyfile(HERE / "include" / "shz_info.h", inc / "shz_info.h")
    (src / "cpu.h").write_text(MOCK_CPU_H)
    (src / "driver.c").write_text(HOST_DRIVER)
    exe = work / "backend" / "bios_host"
    # bios.c reads/writes 16/32-bit fields of guest structures (BDA, DAP, EDD buffer) at
    # whatever alignment the guest chose, which x86 permits; UBSan's alignment check is
    # therefore off. Every other UBSan check and ASan stay on.
    cmd = ["gcc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
           "-fsanitize=address,undefined", "-fno-sanitize=alignment", "-fno-sanitize-recover=all", "-I", src,
           src / "bios.c", src / "driver.c", "-o", exe]
    run(cmd, capture=True)
    proc = subprocess.run([str(exe)], capture_output=True, text=True, timeout=120)
    (work / "backend-output.txt").write_text(proc.stdout + proc.stderr)
    c = []
    for line in proc.stdout.splitlines():
        if line.startswith(("ok   ", "FAIL ")):
            c.append(check("bios.c on host: " + line[5:], line.startswith("ok")))
    c.append(check("bios.c on host: harness ran clean under ASan/UBSan", proc.returncode == 0 and "SUMMARY" in proc.stdout
                   and "runtime error" not in proc.stderr, (proc.stdout.splitlines() or [""])[-1] + proc.stderr[-200:]))
    return c, " ".join(str(x) for x in cmd)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--qemu", default=shutil.which("qemu-system-x86_64") or qemu.DEFAULT_QEMU)
    parser.add_argument("--verbose", action="store_true", help="print every check, not only failures")
    args = parser.parse_args()
    RESULT.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%dT%H%M%S-"), dir=RESULT))
    record = {"test": "shizukudos/supervisor/test_vbios.py", "utc": shzlib.utc_now(), "git": shzlib.git_state(),
              "work": str(work), "qemu": qemu.qemu_version(args.qemu),
              "scope": "vBIOS ROM + Supervisor service back end, host-side; NOT a run inside the Supervisor (needs VMX)"}
    checks, syms, _ = rom_checks(work)
    q, command, serial = qemu_rom_checks(work, syms, args.qemu)
    checks += q
    record["qemu_command"] = [str(x) for x in command]
    record["probe_serial_head"] = serial[:1500]
    b, cmd = host_backend_checks(work)
    checks += b
    record["backend_command"] = cmd
    status = "PASS" if checks and all(c["status"] == "PASS" for c in checks) else "FAIL"
    record.update({"status": status, "checks": checks})
    shzlib.write_json(work / "result.json", record)
    shzlib.write_json(RESULT / "result.json", record)
    for c in checks:
        if c["status"] != "PASS" or args.verbose:
            print(f"  [{c['status']}] {c['check']}  {c['detail']}")
    print(f"{sum(c['status'] == 'PASS' for c in checks)}/{len(checks)} checks passed; record {RESULT / 'result.json'}")
    print(status)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
