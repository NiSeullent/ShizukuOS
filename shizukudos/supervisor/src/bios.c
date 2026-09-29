/* SPDX-License-Identifier: GPL-2.0-only */
#include "bios.h"
#include "console.h"
#include "cpu.h"
#include "devices.h"
#include "ept.h"
#include "guest.h"
#include "video.h"

#define HD_HEADS 16
#define HD_SPT 63
#define BDA 0x400

static uint16_t keyq[32];
static unsigned key_head, key_tail;
static uint8_t disk_status;
static uint32_t e820_state;
static uint32_t stat_disk_reads, stat_disk_writes;

/* --------------------------------------------------------------- helpers */
static uint16_t *stacked_flags(void)
{
    const uint64_t ss = vmread(VMCS_GUEST_SS_SEL) & 0xffff;
    const uint64_t sp = vmread(VMCS_GUEST_RSP) & 0xffff;
    return (uint16_t *)gpa_ptr((ss << 4) + ((sp + 4) & 0xffff), 2);
}

static void ret_cf(int cf)
{
    uint16_t *f = stacked_flags();
    if (f)
        *f = (uint16_t)((*f & ~1u) | (cf ? 1u : 0u));
}

static void ret_zf(int zf)
{
    uint16_t *f = stacked_flags();
    if (f)
        *f = (uint16_t)((*f & ~0x40u) | (zf ? 0x40u : 0u));
}

/* Flags of the running code (for stubs that continue instead of returning). */
static void cur_flags(uint64_t clear, uint64_t set)
{
    vmwrite(VMCS_GUEST_RFLAGS, (vmread(VMCS_GUEST_RFLAGS) & ~clear) | set);
}

static uint64_t seg_base(unsigned field)
{
    return (vmread(field) & 0xffffull) << 4;
}

uint64_t bios_disk_sectors(void) { return G.info->disk_size / 512; }

/* --------------------------------------------------------------- memory & BDA */
void bios_prepare_guest_memory(void)
{
    uint8_t *bda = gpa_ptr(BDA, 0x100);
    const uint64_t ram_kb = G.ram_size >> 10;
    uint8_t *ebda = gpa_ptr(0x9fc00, 0x400);
    if (!bda || !ebda)
        return;
    memset(bda, 0, 0x100);
    memset(ebda, 0, 0x400);
    ebda[0] = 1;                                    /* EBDA size in KiB */
    *(uint16_t *)(bda + 0x00) = 0x3f8;              /* COM1 */
    *(uint16_t *)(bda + 0x0e) = 0x9fc0;             /* EBDA segment */
    *(uint16_t *)(bda + 0x10) = 0x0222;             /* equipment: 80x25 colour, FPU, COM1 */
    *(uint16_t *)(bda + 0x13) = 639;                /* conventional memory in KiB */
    *(uint16_t *)(bda + 0x1a) = 0x1e;               /* keyboard buffer head/tail */
    *(uint16_t *)(bda + 0x1c) = 0x1e;
    *(uint16_t *)(bda + 0x80) = 0x1e;
    *(uint16_t *)(bda + 0x82) = 0x3e;
    bda[0x75] = 1;                                  /* one fixed disk */
    (void)ram_kb;
    video_init();
}

/* --------------------------------------------------------------- keyboard */
static const char scan_rows[] = "qwertyuiop[]asdfghjkl;'`\\zxcvbnm,./";
static const uint8_t scan_map[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35};

static uint16_t ascii_to_key(uint8_t c)
{
    unsigned i;
    uint8_t lower = c;
    if (c == '\r' || c == '\n') return 0x1c0d;
    if (c == 8 || c == 0x7f) return 0x0e08;
    if (c == 0x1b) return 0x011b;
    if (c == '\t') return 0x0f09;
    if (c == ' ') return 0x3920;
    if (c >= '1' && c <= '9') return (uint16_t)(((c - '1' + 2) << 8) | c);
    if (c == '0') return (uint16_t)(0x0b00 | c);
    if (c >= 'A' && c <= 'Z') lower = (uint8_t)(c - 'A' + 'a');
    for (i = 0; i < sizeof scan_map; ++i)
        if (scan_rows[i] == (char)lower) return (uint16_t)((scan_map[i] << 8) | c);
    return c;
}

void bios_poll_input(void)
{
    int c;
    while ((c = serial_getc_nonblock()) >= 0) {
        const unsigned next = (key_head + 1) % 32;
        /* Received bytes feed both the BIOS keystroke queue and the virtual UART. */
        dev_uart_rx_push((uint8_t)c);
        if (next != key_tail) {
            keyq[key_head] = ascii_to_key((uint8_t)c);
            key_head = next;
        }
    }
}

int bios_key_available(void) { return key_head != key_tail; }

static void bios_keyboard(void)
{
    const uint8_t func = AH;
    /* The stub retries only when ZF=1 on return, so every call defines ZF explicitly;
     * only a blocking read with no key sets it (the stacked flags carry the result). */
    cur_flags(0x40, 0);
    switch (func) {
    case 0x00:
    case 0x10:
        bios_poll_input();
        if (key_head == key_tail) {
            cur_flags(0x40, 0x40);                  /* ZF=1: stub halts and retries */
            return;
        }
        set_reg16(GPR_RAX, keyq[key_tail]);
        key_tail = (key_tail + 1) % 32;
        cur_flags(0x40, 0);
        break;
    case 0x01:
    case 0x11:
        bios_poll_input();
        if (key_head == key_tail) {
            ret_zf(1);
        } else {
            set_reg16(GPR_RAX, keyq[key_tail]);
            ret_zf(0);
        }
        break;
    case 0x02:
    case 0x12:
        set_reg8l(GPR_RAX, 0);
        break;
    case 0x05: {
        const unsigned next = (key_head + 1) % 32;
        if (next != key_tail) {
            keyq[key_head] = CX;
            key_head = next;
            set_reg8l(GPR_RAX, 0);
        } else {
            set_reg8l(GPR_RAX, 1);
        }
        break;
    }
    case 0x09:
        set_reg8l(GPR_RAX, 0x20);                   /* enhanced keyboard functions available */
        break;
    default:
        break;
    }
}

/* --------------------------------------------------------------- disk */
static void disk_result(uint8_t status, int sectors)
{
    disk_status = status;
    set_reg8h(GPR_RAX, status);
    if (sectors >= 0)
        set_reg8l(GPR_RAX, (uint8_t)sectors);
    ret_cf(status != 0);
}

static int disk_transfer(uint64_t lba, uint32_t count, uint64_t buffer_gpa, int write)
{
    uint8_t *mem;
    uint8_t *dsk;
    if (!count || lba + count > bios_disk_sectors())
        return 0x04;                                /* sector not found */
    mem = gpa_ptr(buffer_gpa, (uint64_t)count * 512);
    if (!mem)
        return 0x09;                                /* DMA boundary/segment error */
    dsk = (uint8_t *)(uintptr_t)(G.info->disk_base + lba * 512);
    if (write) {
        memcpy(dsk, mem, (uint64_t)count * 512);
        stat_disk_writes += count;
    } else {
        memcpy(mem, dsk, (uint64_t)count * 512);
        stat_disk_reads += count;
    }
    return 0;
}

static void bios_disk(void)
{
    const uint8_t func = AH;
    const uint8_t drive = DL;
    const uint64_t total = bios_disk_sectors();
    uint32_t cyls = (uint32_t)(total / (HD_HEADS * HD_SPT));
    int st;

    if (cyls > 1023) cyls = 1023;
    if (drive != 0x80 && func != 0x00 && func != 0x01) {
        disk_result(0x01, -1);                      /* invalid function for this drive */
        return;
    }
    switch (func) {
    case 0x00: case 0x0d:
        disk_status = 0;
        set_reg8h(GPR_RAX, 0);
        ret_cf(0);
        break;
    case 0x01:
        set_reg8h(GPR_RAX, disk_status);
        ret_cf(0);
        break;
    case 0x02: case 0x03: case 0x04: {
        const uint32_t count = AL;
        const uint32_t cyl = CH | ((uint32_t)(CL & 0xc0) << 2);
        const uint32_t sec = CL & 0x3f;
        const uint32_t head = DH;
        const uint64_t lba = ((uint64_t)cyl * HD_HEADS + head) * HD_SPT + (sec ? sec - 1 : 0);
        if (!sec || head >= HD_HEADS || sec > HD_SPT) {
            disk_result(0x04, 0);
            break;
        }
        if (func == 0x04) {
            disk_result(lba + count <= total ? 0 : 0x04, count);
            break;
        }
        st = disk_transfer(lba, count, seg_base(VMCS_GUEST_ES_SEL) + BX, func == 0x03);
        disk_result((uint8_t)st, st ? 0 : (int)count);
        break;
    }
    case 0x08:
        set_reg8h(GPR_RAX, 0);
        set_reg8l(GPR_RBX, 0);
        set_reg16(GPR_RCX, (uint16_t)((((cyls - 1) & 0xff) << 8) | (((cyls - 1) >> 8) << 6) | HD_SPT));
        set_reg8h(GPR_RDX, HD_HEADS - 1);
        set_reg8l(GPR_RDX, 1);
        ret_cf(0);
        break;
    case 0x0c: case 0x10: case 0x11: case 0x14:
        disk_result(0, -1);
        break;
    case 0x15:
        set_reg8h(GPR_RAX, 3);                      /* fixed disk */
        set_reg16(GPR_RCX, (uint16_t)(total >> 16));
        set_reg16(GPR_RDX, (uint16_t)total);
        ret_cf(0);
        break;
    case 0x41:
        if (BX == 0x55aa) {
            set_reg16(GPR_RBX, 0xaa55);
            set_reg8h(GPR_RAX, 0x21);
            /* bit 0: "fixed disk access subset" = AH=42h, 43h, 44h, 47h and 48h (EDD 1.1) */
            set_reg16(GPR_RCX, 0x0001);
            ret_cf(0);
        } else {
            disk_result(0x01, -1);
        }
        break;
    case 0x42: case 0x43: {
        const uint8_t *pkt = gpa_ptr(seg_base(VMCS_GUEST_DS_SEL) + SI, 16);
        uint64_t lba, buf;
        uint32_t count;
        if (!pkt || pkt[0] < 0x10) {
            disk_result(0x01, -1);
            break;
        }
        count = *(const uint16_t *)(pkt + 2);
        buf = ((uint64_t)*(const uint16_t *)(pkt + 6) << 4) + *(const uint16_t *)(pkt + 4);
        lba = *(const uint64_t *)(pkt + 8);
        st = disk_transfer(lba, count, buf, func == 0x43);
        disk_result((uint8_t)st, -1);
        break;
    }
    case 0x44: case 0x47: {
        /* Extended verify / extended seek (RBIL INT 13/AH=44h, 47h; same checks as
         * SeaBIOS src/disk.c:disk_1344/disk_1347 -> extended_access, written anew):
         * the DAP names an LBA range that must lie on the disk. The RAM-backed image
         * cannot have unreadable sectors, so a range check is the whole verify.
         * FreeDOS issues AH=44h after every AH=43h write when VERIFY is ON and the
         * drive does not report write-with-verify (kernel/dsk.c LBA_WRITE_VERIFY). */
        const uint8_t *pkt = gpa_ptr(seg_base(VMCS_GUEST_DS_SEL) + SI, 16);
        uint64_t lba;
        uint32_t count;
        if (!pkt || pkt[0] < 0x10) {
            disk_result(0x01, -1);
            break;
        }
        count = func == 0x47 ? 1 : *(const uint16_t *)(pkt + 2);
        lba = *(const uint64_t *)(pkt + 8);
        if (lba >= total || count > total - lba) {
            disk_result(0x04, -1);                  /* sector not found; DAP count left as given */
            break;
        }
        disk_result(0, -1);
        break;
    }
    case 0x48: {
        /* EDD get drive parameters (RBIL INT 13/AH=48h; SeaBIOS src/block.c:fill_generic_edd
         * for the size rules): the caller's buffer size word must be >= 1Ah; this drive
         * has no Device Parameter Table Extension, so exactly the 1Ah-byte EDD 1.x
         * result is written and reported, whatever larger size the caller offered. */
        uint8_t *out = gpa_ptr(seg_base(VMCS_GUEST_DS_SEL) + SI, 0x1a);
        if (!out || *(const uint16_t *)out < 0x1a) {
            disk_result(0x01, -1);
            break;
        }
        memset(out + 2, 0, 0x18);
        *(uint16_t *)out = 0x1a;
        /* Physical geometry (not the 1023-cylinder INT 13h/08h view); bit 1 = CHS valid
         * unless the disk is beyond what 16383 cylinders can describe. */
        *(uint16_t *)(out + 2) = total / (HD_HEADS * HD_SPT) > 0x3fff ? 0x0000 : 0x0002;
        *(uint32_t *)(out + 4) = (uint32_t)(total / (HD_HEADS * HD_SPT) > 0x3fff ? 0x3fff : total / (HD_HEADS * HD_SPT));
        *(uint32_t *)(out + 8) = HD_HEADS;
        *(uint32_t *)(out + 12) = HD_SPT;
        *(uint64_t *)(out + 16) = total;
        *(uint16_t *)(out + 24) = 512;
        disk_result(0, -1);
        break;
    }
    default:
        disk_result(0x01, -1);
    }
}

/* --------------------------------------------------------------- system */
static uint64_t gdt_desc_base(const uint8_t *d)
{
    return (uint64_t)d[2] | ((uint64_t)d[3] << 8) | ((uint64_t)d[4] << 16) | ((uint64_t)d[7] << 24);
}

static void bios_system(void)
{
    const uint8_t func = AH;
    const uint64_t ram = G.ram_size;
    switch (func) {
    case 0x24:                                      /* A20 gate support */
        switch (AL) {
        case 0: dev_a20_set(0); set_reg8h(GPR_RAX, 0); ret_cf(0); break;
        case 1: dev_a20_set(1); set_reg8h(GPR_RAX, 0); ret_cf(0); break;
        case 2: set_reg8h(GPR_RAX, 0); set_reg8l(GPR_RAX, (uint8_t)dev_a20_get()); ret_cf(0); break;
        case 3: set_reg8h(GPR_RAX, 0); set_reg16(GPR_RBX, 3); ret_cf(0); break;
        default: set_reg8h(GPR_RAX, 0x86); ret_cf(1);
        }
        break;
    case 0x86: {                                    /* wait CX:DX microseconds */
        const uint64_t us = ((uint64_t)CX << 16) | DX;
        const uint64_t end = rdtsc() + us * (G.tsc_hz / 1000000);
        while (rdtsc() < end)
            pause_cpu();
        ret_cf(0);
        break;
    }
    case 0x87: {                                    /* copy extended memory via GDT at ES:SI */
        const uint8_t *gdt = gpa_ptr(seg_base(VMCS_GUEST_ES_SEL) + SI, 48);
        const uint64_t bytes = (uint64_t)CX * 2;
        uint8_t *src, *dst;
        if (!gdt) { set_reg8h(GPR_RAX, 0x02); ret_cf(1); break; }
        src = gpa_ptr(gdt_desc_base(gdt + 16), bytes);
        dst = gpa_ptr(gdt_desc_base(gdt + 24), bytes);
        if (!src || !dst) { set_reg8h(GPR_RAX, 0x03); ret_cf(1); break; }
        memmove(dst, src, bytes);
        set_reg8h(GPR_RAX, 0);
        ret_cf(0);
        break;
    }
    case 0x88: {
        uint64_t kb = ram > (1ull << 20) ? (ram - (1ull << 20)) >> 10 : 0;
        if (kb > 0xfc00) kb = 0xfc00;
        set_reg16(GPR_RAX, (uint16_t)kb);
        ret_cf(0);
        break;
    }
    case 0xc0:                                      /* system configuration table (in vBIOS ROM) */
        set_reg16(GPR_RBX, 0xe6f5);
        vmwrite(VMCS_GUEST_ES_SEL, 0xf000);
        vmwrite(VMCS_GUEST_ES_BASE, 0xf0000);
        set_reg8h(GPR_RAX, 0);
        ret_cf(0);
        break;
    case 0xe8:
        if (AL == 0x01) {                           /* E801 */
            uint64_t low = ram > (1ull << 20) ? (ram - (1ull << 20)) >> 10 : 0;
            uint64_t high = ram > (16ull << 20) ? (ram - (16ull << 20)) >> 16 : 0;
            if (low > 0x3c00) low = 0x3c00;
            set_reg16(GPR_RAX, (uint16_t)low);
            set_reg16(GPR_RCX, (uint16_t)low);
            set_reg16(GPR_RBX, (uint16_t)high);
            set_reg16(GPR_RDX, (uint16_t)high);
            ret_cf(0);
            break;
        }
        set_reg8h(GPR_RAX, 0x86);
        ret_cf(1);
        break;
    default:
        set_reg8h(GPR_RAX, 0x86);
        ret_cf(1);
    }
}

/* INT 15h AX=E820 arrives here with the full 32-bit registers. */
static int bios_e820(void)
{
    uint64_t base, len;
    uint32_t type;
    uint8_t *out;
    uint32_t idx = (uint32_t)G.vc->gpr[GPR_RBX];
    if ((uint32_t)G.vc->gpr[GPR_RDX] != 0x534d4150u || (uint32_t)G.vc->gpr[GPR_RCX] < 20) {
        ret_cf(1);
        return 1;
    }
    switch (idx) {
    case 0: base = 0; len = 0x9fc00; type = 1; break;
    case 1: base = 0x9fc00; len = 0x400; type = 2; break;
    case 2: base = 0xf0000; len = 0x10000; type = 2; break;
    case 3: base = 0x100000; len = G.ram_size - 0x100000; type = 1; break;
    default: ret_cf(1); return 1;
    }
    out = gpa_ptr(seg_base(VMCS_GUEST_ES_SEL) + DI, 20);
    if (!out) {
        ret_cf(1);
        return 1;
    }
    *(uint64_t *)out = base;
    *(uint64_t *)(out + 8) = len;
    *(uint32_t *)(out + 16) = type;
    G.vc->gpr[GPR_RAX] = 0x534d4150u;
    G.vc->gpr[GPR_RCX] = 20;
    G.vc->gpr[GPR_RBX] = idx + 1 >= 4 ? 0 : idx + 1;
    ret_cf(0);
    (void)e820_state;
    return 1;
}

/* --------------------------------------------------------------- time */
/* INT 1Ah AH=02h-05h (RTC time/date, read and set) never arrive here: the vBIOS ROM
 * implements them itself through the CMOS ports (guest/vbios.asm rtc_service), which
 * the device model backs with the platform RTC (devices.c dev_cmos_read). */
static void bios_time(void)
{
    uint8_t *bda = gpa_ptr(BDA, 0x100);
    switch (AH) {
    case 0x00:
        if (!bda) break;
        set_reg16(GPR_RCX, *(uint16_t *)(bda + 0x6e));
        set_reg16(GPR_RDX, *(uint16_t *)(bda + 0x6c));
        set_reg8l(GPR_RAX, bda[0x70]);
        bda[0x70] = 0;
        break;
    case 0x01:
        if (!bda) break;
        *(uint16_t *)(bda + 0x6e) = CX;
        *(uint16_t *)(bda + 0x6c) = DX;
        bda[0x70] = 0;
        break;
    case 0xb1:                                      /* PCI BIOS: not present */
        set_reg8h(GPR_RAX, 0x81);
        ret_cf(1);
        break;
    default:
        ret_cf(1);                                  /* RTC set/alarm not supported */
    }
}

/* --------------------------------------------------------------- serial/printer */
static void bios_serial(void)
{
    switch (AH) {
    case 0x00:
    case 0x03:
        set_reg16(GPR_RAX, 0x6000);                 /* THR/TSR empty; no modem status modelled */
        break;
    case 0x01:
        if (dev_uart_tx_hook)
            dev_uart_tx_hook(AL);
        set_reg8h(GPR_RAX, 0);
        break;
    case 0x02: {
        uint32_t v;
        dev_pio_in(0x3fd, 1, &v);
        if (v & 1) {
            dev_pio_in(0x3f8, 1, &v);
            set_reg16(GPR_RAX, (uint16_t)(v & 0xff));
        } else {
            set_reg16(GPR_RAX, 0x8000);             /* timeout */
        }
        break;
    }
    default: break;
    }
}

/* --------------------------------------------------------------- boot */
static void bios_boot(void)
{
    uint8_t *dst = gpa_ptr(0x7c00, 512);
    if (!dst || bios_disk_sectors() == 0) {
        cur_flags(0, 1);
        return;
    }
    memcpy(dst, (const void *)(uintptr_t)G.info->disk_base, 512);
    if (dst[510] != 0x55 || dst[511] != 0xaa) {
        cur_flags(0, 1);
        return;
    }
    set_reg8l(GPR_RDX, 0x80);
    cur_flags(1, 0);
    kprintf("SHZ: vBIOS boot: MBR loaded from RAM-backed disk (%llu sectors)\n", bios_disk_sectors());
}

int bios_hypercall(uint16_t port)
{
    ++G.info->hypercalls;
    switch (port) {
    case BIOS_PORT_VIDEO: video_int10(); break;
    case BIOS_PORT_DISK: bios_disk(); break;
    case BIOS_PORT_SYSTEM:
        if (AX == 0xe820) bios_e820(); else bios_system();
        break;
    case BIOS_PORT_KEYBOARD: bios_keyboard(); break;
    case BIOS_PORT_TIME: bios_time(); break;
    case BIOS_PORT_SERIAL: bios_serial(); break;
    case BIOS_PORT_PRINTER: set_reg8h(GPR_RAX, 0x30); break;
    case BIOS_PORT_BOOT: bios_boot(); break;
    case BIOS_PORT_DEBUG: {
        const char *s = (const char *)gpa_ptr(seg_base(VMCS_GUEST_DS_SEL) + SI, 1);
        unsigned i;
        kprintf("SHZ: guest-debug: ");
        for (i = 0; s && i < 120 && s[i]; ++i)
            serial_putc(s[i]);
        serial_putc('\n');
        break;
    }
    case BIOS_PORT_EXIT:
        G.info->guest_exit_code = AL;
        G.info->guest_exit_requested = 1;
        break;
    default:
        return 0;
    }
    return 1;
}

void bios_init(void)
{
    key_head = key_tail = 0;
    disk_status = 0;
    stat_disk_reads = stat_disk_writes = 0;
}
