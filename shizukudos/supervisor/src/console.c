/* SPDX-License-Identifier: GPL-2.0-only
 * Supervisor log console: the real COM1 UART (115200 8N1). In the QEMU test
 * setup this is a chardev file the harness reads; it is separate from the
 * *virtual* UART the DOS guest sees.
 */
#include "console.h"
#include "cpu.h"

#define COM1 0x3f8

void serial_init(void)
{
    outb(COM1 + 1, 0x00);       /* no interrupts */
    outb(COM1 + 3, 0x80);       /* DLAB */
    outb(COM1 + 0, 0x01);       /* 115200 */
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);       /* 8N1 */
    outb(COM1 + 2, 0xc7);       /* FIFO on, cleared */
    outb(COM1 + 4, 0x03);       /* DTR|RTS, no loopback, no IRQ */
}

void serial_putc(char c)
{
    unsigned spins = 0;
    if (c == '\n')
        serial_putc('\r');
    while (!(inb(COM1 + 5) & 0x20) && ++spins < 100000)
        pause_cpu();
    outb(COM1, (uint8_t)c);
}

int serial_getc_nonblock(void)
{
    if (inb(COM1 + 5) & 1)
        return inb(COM1);
    return -1;
}

void kputs(const char *s)
{
    while (*s)
        serial_putc(*s++);
}

static void put_num(void (*out)(char, void *), void *ctx, uint64_t v, unsigned base,
                    int width, char pad, int negative, int upper)
{
    char tmp[24];
    int n = 0;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    if (!v)
        tmp[n++] = '0';
    while (v) {
        tmp[n++] = digits[v % base];
        v /= base;
    }
    if (negative)
        tmp[n++] = '-';
    while (width > n) {
        out(pad, ctx);
        --width;
    }
    while (n)
        out(tmp[--n], ctx);
}

static void vformat(void (*out)(char, void *), void *ctx, const char *fmt, va_list ap)
{
    for (; *fmt; ++fmt) {
        int width = 0, longs = 0, upper = 0;
        char pad = ' ';
        if (*fmt != '%') {
            out(*fmt, ctx);
            continue;
        }
        ++fmt;
        if (*fmt == '0') {
            pad = '0';
            ++fmt;
        }
        while (*fmt >= '0' && *fmt <= '9')
            width = width * 10 + (*fmt++ - '0');
        while (*fmt == 'l' || *fmt == 'z') {
            ++longs;
            ++fmt;
        }
        switch (*fmt) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s)
                s = "(null)";
            while (*s)
                out(*s++, ctx);
            break;
        }
        case 'c':
            out((char)va_arg(ap, int), ctx);
            break;
        case 'd': {
            int64_t v = longs ? va_arg(ap, int64_t) : va_arg(ap, int);
            put_num(out, ctx, v < 0 ? (uint64_t)-v : (uint64_t)v, 10, width, pad, v < 0, 0);
            break;
        }
        case 'u':
            put_num(out, ctx, longs ? va_arg(ap, uint64_t) : va_arg(ap, unsigned), 10, width, pad, 0, 0);
            break;
        case 'X':
            upper = 1;
            /* fall through */
        case 'x':
            put_num(out, ctx, longs ? va_arg(ap, uint64_t) : va_arg(ap, unsigned), 16, width, pad, 0, upper);
            break;
        case 'p':
            out('0', ctx);
            out('x', ctx);
            put_num(out, ctx, (uint64_t)(uintptr_t)va_arg(ap, void *), 16, 16, '0', 0, 0);
            break;
        case '%':
            out('%', ctx);
            break;
        default:
            out('%', ctx);
            if (*fmt)
                out(*fmt, ctx);
            else
                return;
        }
    }
}

static void to_serial(char c, void *ctx) { (void)ctx; serial_putc(c); }

void kvprintf(const char *fmt, va_list ap) { vformat(to_serial, 0, fmt, ap); }

void kprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    kvprintf(fmt, ap);
    va_end(ap);
}

struct capture { char *dst; unsigned size, len; };
static void to_buf(char c, void *ctx)
{
    struct capture *cap = ctx;
    if (cap->len + 1 < cap->size)
        cap->dst[cap->len++] = c;
}

void log_capture_v(char *dst, unsigned size, const char *fmt, va_list ap)
{
    struct capture cap = {dst, size, 0};
    vformat(to_buf, &cap, fmt, ap);
    if (size)
        dst[cap.len] = 0;
}

void log_capture(char *dst, unsigned size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_capture_v(dst, size, fmt, ap);
    va_end(ap);
}
