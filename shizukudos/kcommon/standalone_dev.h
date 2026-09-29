/* SPDX-License-Identifier: GPL-2.0-only
 * Platform devices for the STANDALONE guest profile (Kernel32/Kernel64 booted by the standalone boot stubs under
 * QEMU without the Supervisor): COM1, the 8259 pair, PIT channel 0, the CMOS RTC and QEMU's isa-debug-exit.
 * Header-only and free of 64-bit division so the same code builds into the i486 freestanding Kernel32.
 */
#ifndef SHZ_STANDALONE_DEV_H
#define SHZ_STANDALONE_DEV_H
#include <stdint.h>
#include "../abi/shz_abi.h"

#define SA_COM1 0x3f8
static inline void sa_outb(uint16_t p, uint8_t v) { __asm__ volatile("outb %0, %1" : : "a"(v), "Nd"(p)); }
static inline uint8_t sa_inb(uint16_t p) { uint8_t v; __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(p)); return v; }

static int sa_serial_ready;
static inline void sa_serial_putc(char c)
{
    unsigned spin = 0;
    if (!sa_serial_ready) {
        sa_outb(SA_COM1 + 1, 0x00); sa_outb(SA_COM1 + 3, 0x80); sa_outb(SA_COM1 + 0, 0x01); sa_outb(SA_COM1 + 1, 0x00);
        sa_outb(SA_COM1 + 3, 0x03); sa_outb(SA_COM1 + 2, 0xc7); sa_outb(SA_COM1 + 4, 0x03);
        sa_serial_ready = 1;
    }
    while (!(sa_inb(SA_COM1 + 5) & 0x20) && ++spin < 1000000u)
        ;
    sa_outb(SA_COM1, (uint8_t)c);
}
static inline void sa_serial_puts(const char *s) { while (*s) sa_serial_putc(*s++); }
static inline void sa_serial_hex(uint64_t v)
{
    char tmp[17];
    int n = 0;
    if (!v) tmp[n++] = '0';
    while (v) { tmp[n++] = "0123456789abcdef"[(unsigned)(v & 15)]; v >>= 4; }
    while (n) sa_serial_putc(tmp[--n]);
}

/* Guest exit: report on COM1, then ask QEMU to quit (isa-debug-exit iobase=0xf4: exit status (code << 1) | 1). */
static inline void __attribute__((noreturn)) sa_exit(unsigned code)
{
    sa_serial_puts("SHZ-EXIT:");
    sa_serial_hex(code);
    sa_serial_putc('\n');
    sa_outb(0xf4, (uint8_t)code);
    for (;;)
        __asm__ volatile("cli; hlt");
}

static inline void sa_evidence(unsigned slot, uint64_t value)
{
    sa_serial_puts("SHZ-EV ");
    sa_serial_hex(slot);
    sa_serial_putc(' ');
    sa_serial_hex(value);
    sa_serial_putc('\n');
}

/* ---- 8259 + PIT: vector base = the timer vector (must be a multiple of 8) so IRQ0 arrives as `vector`. ---- */
static int sa_pic_ready;
static unsigned sa_pic_base;
static inline long sa_timer_set(unsigned vector, uint32_t period_us)
{
    uint32_t div;
    if (vector & 7)
        return SHZ_E_INVALID;
    if (!sa_pic_ready) {
        sa_outb(0x20, 0x11); sa_outb(0xa0, 0x11);
        sa_outb(0x21, (uint8_t)vector); sa_outb(0xa1, (uint8_t)(vector + 8));
        sa_outb(0x21, 0x04); sa_outb(0xa1, 0x02);
        sa_outb(0x21, 0x01); sa_outb(0xa1, 0x01);
        sa_outb(0x21, 0xff); sa_outb(0xa1, 0xff);
        sa_pic_base = vector;
        sa_pic_ready = 1;
    }
    if (!period_us) {
        sa_outb(0x21, 0xff);
        return SHZ_OK;
    }
    div = period_us <= 54925u ? (uint32_t)(((uint64_t)period_us * 1193182u) / 1000000u) : 65535u;   /* 64-bit mul, 32-bit result */
    if (div < 1) div = 1;
    sa_outb(0x43, 0x34);                        /* channel 0, lobyte/hibyte, mode 2 */
    sa_outb(0x40, (uint8_t)div);
    sa_outb(0x40, (uint8_t)(div >> 8));
    sa_outb(0x21, 0xfe);                        /* unmask IRQ0 only */
    return SHZ_OK;
}
static inline void sa_eoi(void) { sa_outb(0x20, 0x20); }
/* Per-line control for device IRQs (0..15). The timer call above initialises the PIC first. Lines >= 8 sit behind the
 * cascade on IRQ2, which is unmasked together with the first slave line. */
static uint8_t sa_irq_mask_m = 0xfe, sa_irq_mask_s = 0xff;
static inline void sa_irq_unmask(unsigned irq)
{
    if (irq < 8) {
        sa_irq_mask_m &= (uint8_t)~(1u << irq);
    } else {
        sa_irq_mask_s &= (uint8_t)~(1u << (irq - 8));
        sa_irq_mask_m &= (uint8_t)~(1u << 2);
    }
    sa_outb(0x21, sa_irq_mask_m);
    sa_outb(0xa1, sa_irq_mask_s);
}
static inline void sa_irq_mask(unsigned irq)
{
    if (irq < 8) sa_irq_mask_m |= (uint8_t)(1u << irq); else sa_irq_mask_s |= (uint8_t)(1u << (irq - 8));
    sa_outb(0x21, sa_irq_mask_m);
    sa_outb(0xa1, sa_irq_mask_s);
}
static inline void sa_eoi_irq(unsigned irq) { if (irq >= 8) sa_outb(0xa0, 0x20); sa_outb(0x20, 0x20); }
static inline unsigned sa_irq_vector(unsigned irq) { return sa_pic_base + irq; }

/* ---- CMOS RTC -> seconds since 1970 (32-bit arithmetic only) ---- */
static inline uint8_t sa_cmos(uint8_t reg) { sa_outb(0x70, reg); return sa_inb(0x71); }
static inline uint32_t sa_rtc_epoch(void)
{
    static const uint8_t mdays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    uint32_t sec, min, hour, day, mon, year, days, y, m, guard = 0;
    const uint8_t regb = sa_cmos(0x0b);
    while ((sa_cmos(0x0a) & 0x80) && ++guard < 1000000u)
        ;
    sec = sa_cmos(0); min = sa_cmos(2); hour = sa_cmos(4); day = sa_cmos(7); mon = sa_cmos(8); year = sa_cmos(9);
    if (!(regb & 4)) {                          /* BCD */
#define SA_BCD(x) (((x) & 15u) + ((x) >> 4) * 10u)
        sec = SA_BCD(sec); min = SA_BCD(min); hour = SA_BCD(hour & 0x7fu); day = SA_BCD(day); mon = SA_BCD(mon); year = SA_BCD(year);
#undef SA_BCD
    }
    year += 2000;
    days = 0;
    for (y = 1970; y < year; ++y)
        days += 365 + ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0);
    for (m = 1; m < mon && m <= 12; ++m)
        days += mdays[m - 1] + (m == 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0));
    days += day ? day - 1 : 0;
    return days * 86400u + hour * 3600u + min * 60u + sec;
}
#endif
