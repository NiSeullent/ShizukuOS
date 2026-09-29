/* SPDX-License-Identifier: GPL-2.0-only */
#include "k64.h"

void *memcpy(void *d, const void *s, size_t n)
{
    void *r = d;
    __asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(n) :: "memory");
    return r;
}
void *memset(void *d, int c, size_t n)
{
    void *r = d;
    __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(c) : "memory");
    return r;
}
void *memmove(void *d, const void *s, size_t n)
{
    unsigned char *dd = d;
    const unsigned char *ss = s;
    if (dd == ss || !n) return d;
    if (dd < ss || dd >= ss + n) return memcpy(d, s, n);
    while (n--) dd[n] = ss[n];
    return d;
}
int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    while (n--) {
        if (*x != *y) return *x - *y;
        ++x; ++y;
    }
    return 0;
}
size_t strlen(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }
int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (unsigned char)*a - (unsigned char)*b;
}
int strncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b) { ++a; ++b; --n; }
    return n ? (unsigned char)*a - (unsigned char)*b : 0;
}

static char line[200];
static unsigned line_len;

static void flush_line(void)
{
    if (!line_len)
        return;
    shz_console_write(kimage_v2p((uint64_t)line), line_len);      /* .bss lives in the kernel image */
    line_len = 0;
}
static void putc_line(char c)
{
    line[line_len++] = c;
    if (c == '\n' || line_len >= sizeof line)
        flush_line();
}
static void put_num(uint64_t v, unsigned base, int width, char pad, int neg, int upper)
{
    char tmp[24];
    int n = 0;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    if (!v) tmp[n++] = '0';
    while (v) { tmp[n++] = digits[v % base]; v /= base; }
    if (neg) tmp[n++] = '-';
    while (width > n) { putc_line(pad); --width; }
    while (n) putc_line(tmp[--n]);
}

void kvprintf(const char *fmt, __builtin_va_list ap)
{
    uint64_t f = irq_save();
    for (; *fmt; ++fmt) {
        int width = 0, ll = 0;
        char pad = ' ';
        if (*fmt != '%') { putc_line(*fmt); continue; }
        ++fmt;
        if (*fmt == '0') { pad = '0'; ++fmt; }
        while (*fmt >= '0' && *fmt <= '9') width = width * 10 + (*fmt++ - '0');
        while (*fmt == 'l' || *fmt == 'z') { ++ll; ++fmt; }
        switch (*fmt) {
        case 's': { const char *s = __builtin_va_arg(ap, const char *); if (!s) s = "(null)"; while (*s) putc_line(*s++); break; }
        case 'c': putc_line((char)__builtin_va_arg(ap, int)); break;
        case 'd': {
            int64_t v = ll ? __builtin_va_arg(ap, int64_t) : __builtin_va_arg(ap, int);
            put_num(v < 0 ? (uint64_t)-v : (uint64_t)v, 10, width, pad, v < 0, 0);
            break;
        }
        case 'u': put_num(ll ? __builtin_va_arg(ap, uint64_t) : __builtin_va_arg(ap, unsigned), 10, width, pad, 0, 0); break;
        case 'x': put_num(ll ? __builtin_va_arg(ap, uint64_t) : __builtin_va_arg(ap, unsigned), 16, width, pad, 0, 0); break;
        case 'p': putc_line('0'); putc_line('x'); put_num((uint64_t)__builtin_va_arg(ap, void *), 16, 16, '0', 0, 0); break;
        case '%': putc_line('%'); break;
        default: putc_line('%'); if (*fmt) putc_line(*fmt); else goto done;
        }
    }
done:
    flush_line();
    irq_restore(f);
}
void kprintf(const char *fmt, ...)
{
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    kvprintf(fmt, ap);
    __builtin_va_end(ap);
}
void kpanic(const char *fmt, ...)
{
    __builtin_va_list ap;
    cli();
    kprintf("K64 PANIC: ");
    __builtin_va_start(ap, fmt);
    kvprintf(fmt, ap);
    __builtin_va_end(ap);
    kprintf("\n");
    shz_evidence(31, 0xdead0064);
    shz_exit(99);
}
