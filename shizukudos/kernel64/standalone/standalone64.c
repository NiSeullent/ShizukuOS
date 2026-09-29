/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 "standalone" services: the hypercall ABI (abi/shz_abi.h) served by the kernel itself so the
 * Long Mode kernel and its Win64 processes can run without the Supervisor, e.g. under QEMU TCG where Intel VMX
 * does not exist. This is a test/bring-up profile: it is NOT the multikernel product path and never claims
 * Supervisor or VMX behaviour.
 *
 *   console   -> COM1 (0x3F8)           exit   -> "SHZ-EXIT:<code>" on COM1, then QEMU isa-debug-exit (0xF4)
 *   evidence  -> "SHZ-EV <slot> <hex>" on COM1, parsed by tests/run_k64_standalone.py
 *   timer     -> PIT channel 0 through the 8259 master remapped to vector 0x20 (== VEC_TIMER)
 *   time      -> timer ticks; walltime -> CMOS RTC; doorbells/notify -> SHZ_E_UNSUPPORTED (no peers)
 */
#include "k64.h"

#define COM1 0x3f8
static inline void outb(uint16_t p, uint8_t v) { __asm__ volatile("outb %0, %1" : : "a"(v), "Nd"(p)); }
static inline uint8_t inb(uint16_t p) { uint8_t v; __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(p)); return v; }

extern uint64_t arch_timer_irqs(void);
static int serial_ready;

static void serial_init(void)
{
    outb(COM1 + 1, 0x00);       /* no UART interrupts */
    outb(COM1 + 3, 0x80);       /* DLAB */
    outb(COM1 + 0, 0x01);       /* 115200 baud */
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);       /* 8N1 */
    outb(COM1 + 2, 0xc7);       /* FIFO on */
    outb(COM1 + 4, 0x03);
    serial_ready = 1;
}

static void serial_putc(char c)
{
    unsigned spin = 0;
    if (!serial_ready)
        serial_init();
    while (!(inb(COM1 + 5) & 0x20) && ++spin < 1000000u)
        ;
    outb(COM1, (uint8_t)c);
}
static void serial_puts(const char *s) { while (*s) serial_putc(*s++); }
static void serial_hex(uint64_t v)
{
    char tmp[17];
    int n = 0;
    if (!v) tmp[n++] = '0';
    while (v) { tmp[n++] = "0123456789abcdef"[v & 15]; v >>= 4; }
    while (n) serial_putc(tmp[--n]);
}

/* ---- 8259 + PIT ---- */
static int pic_ready;
static void pic_init(void)
{
    outb(0x20, 0x11); outb(0xa0, 0x11);         /* ICW1: init, ICW4 needed */
    outb(0x21, 0x20); outb(0xa1, 0x28);         /* ICW2: master at 0x20 (IRQ0 == VEC_TIMER), slave at 0x28 */
    outb(0x21, 0x04); outb(0xa1, 0x02);         /* ICW3 */
    outb(0x21, 0x01); outb(0xa1, 0x01);         /* ICW4: 8086 */
    outb(0x21, 0xff); outb(0xa1, 0xff);         /* everything masked until the timer is armed */
    pic_ready = 1;
}
void standalone_eoi(void) { outb(0x20, 0x20); }

static long timer_set(uint64_t vector, uint64_t period_us)
{
    uint64_t div;
    if (vector != VEC_TIMER)
        return SHZ_E_INVALID;
    if (!pic_ready)
        pic_init();
    if (!period_us) {
        outb(0x21, 0xff);
        return SHZ_OK;
    }
    div = period_us * 1193182ull / 1000000ull;
    if (div < 1) div = 1;
    if (div > 65535) div = 65535;
    outb(0x43, 0x34);                           /* channel 0, lobyte/hibyte, mode 2 (rate generator) */
    outb(0x40, (uint8_t)div);
    outb(0x40, (uint8_t)(div >> 8));
    outb(0x21, 0xfe);                           /* unmask IRQ0 only */
    return SHZ_OK;
}

/* ---- CMOS RTC -> Unix seconds ---- */
static uint8_t cmos(uint8_t reg) { outb(0x70, reg); return inb(0x71); }
static uint64_t rtc_epoch(void)
{
    uint32_t sec, min, hour, day, mon, year, guard = 0;
    const uint8_t regb = cmos(0x0b);
    while ((cmos(0x0a) & 0x80) && ++guard < 1000000u)
        ;
    sec = cmos(0); min = cmos(2); hour = cmos(4); day = cmos(7); mon = cmos(8); year = cmos(9);
    if (!(regb & 4)) {                          /* BCD */
#define BCD(x) (((x) & 15) + ((x) >> 4) * 10)
        sec = BCD(sec); min = BCD(min); hour = BCD(hour & 0x7f) | (hour & 0x80); day = BCD(day); mon = BCD(mon); year = BCD(year);
#undef BCD
    }
    year += 2000;
    {   /* days from civil (Howard Hinnant) */
        int64_t y = (int64_t)year - (mon <= 2), era = (y >= 0 ? y : y - 399) / 400;
        uint64_t yoe = (uint64_t)(y - era * 400), doy = (153 * (mon + (mon > 2 ? -3 : 9)) + 2) / 5 + day - 1;
        uint64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        int64_t days = era * 146097 + (int64_t)doe - 719468;
        return (uint64_t)days * 86400ull + hour * 3600ull + min * 60ull + sec;
    }
}

long shz_standalone_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value_out)
{
    hcreg_t v = 0;
    long st = SHZ_OK;
    switch (op) {
    case SHZ_HC_CONSOLE_WRITE: {
        const char *s = (const char *)p2v(a);
        uint64_t i;
        if (b > 512) { st = SHZ_E_RANGE; break; }
        for (i = 0; i < b; ++i)
            serial_putc(s[i]);
        break;
    }
    case SHZ_HC_EXIT:
        serial_puts("SHZ-EXIT:");
        serial_hex(a);
        serial_putc('\n');
        outb(0xf4, (uint8_t)a);                 /* QEMU isa-debug-exit: process exit status (a << 1) | 1 */
        for (;;)
            __asm__ volatile("cli; hlt");
    case SHZ_HC_TIMER_SET: st = timer_set(a, b); break;
    case SHZ_HC_WAIT: __asm__ volatile("sti; hlt"); break;
    case SHZ_HC_TIME: v = arch_timer_irqs() * TICK_US * 1000ull; break;
    case SHZ_HC_EVIDENCE:
        if (a > 31) { st = SHZ_E_RANGE; break; }
        serial_puts("SHZ-EV ");
        serial_hex(a);
        serial_putc(' ');
        serial_hex(b);
        serial_putc('\n');
        break;
    case SHZ_HC_ABI_VERSION: v = ((hcreg_t)SHZ_ABI_MAJOR << 16) | SHZ_ABI_MINOR; break;
    case SHZ_HC_WALLTIME: v = rtc_epoch(); break;
    case SHZ_HC_NOTIFY:
    case SHZ_HC_SET_DOORBELL_VECTOR:
    case SHZ_HC_DOORBELL_ACK:
    case SHZ_HC_DOMAIN_STATE:
        st = SHZ_E_UNSUPPORTED;                 /* single domain, no peers */
        break;
    default:
        st = SHZ_E_INVALID;
        break;
    }
    if (value_out)
        *value_out = v;
    return st;
}
