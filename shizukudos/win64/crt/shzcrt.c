/* SPDX-License-Identifier: GPL-2.0-only */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include "shzcrt.h"

extern int main(int argc, char **argv);

/* ---- compiler support ---- */
void *memcpy(void *d, const void *s, size_t n) { unsigned char *a = d; const unsigned char *b = s; while (n--) *a++ = *b++; return d; }
void *memmove(void *d, const void *s, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    if (a < b) while (n--) *a++ = *b++;
    else { a += n; b += n; while (n--) *--a = *--b; }
    return d;
}
void *memset(void *d, int c, size_t n) { unsigned char *a = d; while (n--) *a++ = (unsigned char)c; return d; }
int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    while (n--) { if (*x != *y) return *x - *y; ++x; ++y; }
    return 0;
}
size_t strlen(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }
int strcmp(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return (unsigned char)*a - (unsigned char)*b; }
char *strcpy(char *d, const char *s) { char *r = d; while ((*d++ = *s++)) { } return r; }
void __main(void) { }
/* 64 KiB+ stack frames probe pages in order; the kernel commits stack pages on demand. */
__asm__(".globl ___chkstk_ms\n___chkstk_ms:\n push %rcx\n push %rax\n cmp $0x1000, %rax\n lea 24(%rsp), %rcx\n jb 2f\n"
        "1: sub $0x1000, %rcx\n orq $0, (%rcx)\n sub $0x1000, %rax\n cmp $0x1000, %rax\n ja 1b\n"
        "2: sub %rax, %rcx\n orq $0, (%rcx)\n pop %rax\n pop %rcx\n ret\n");

/* ---- heap ---- */
void *shz_malloc(size_t n) { return HeapAlloc(GetProcessHeap(), 0, n ? n : 1); }
void *shz_calloc(size_t n, size_t m) { if (m && n > (size_t)-1 / m) return 0; return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (n && m) ? n * m : 1); }
void *shz_realloc(void *p, size_t n) { return p ? HeapReAlloc(GetProcessHeap(), 0, p, n ? n : 1) : shz_malloc(n); }
void shz_free(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }

uint32_t shz_crc32(const void *data, size_t n)
{
    const unsigned char *p = data;
    uint32_t crc = 0xffffffffu;
    while (n--) {
        int b;
        crc ^= *p++;
        for (b = 0; b < 8; ++b) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

int shz_evidence(unsigned slot, unsigned long long v)
{
    extern unsigned long __stdcall NtShzEvidence(unsigned long, unsigned long long);
    return (int)NtShzEvidence(slot, v);
}

/* ---- printf family ---- */
static void put_uint(char **o, char *end, unsigned long long v, unsigned base, int width, char pad, int neg, int upper)
{
    char tmp[24];
    int n = 0;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    if (!v) tmp[n++] = '0';
    while (v) { tmp[n++] = digits[v % base]; v /= base; }
    if (neg) tmp[n++] = '-';
    while (width > n) { if (*o < end) *(*o)++ = pad; --width; }
    while (n) { if (*o < end) *(*o)++ = tmp[--n]; }
}

int shz_vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap)
{
    char *o = buf, *end = buf + (cap ? cap - 1 : 0);
    size_t total = 0;
    for (; *fmt; ++fmt) {
        int width = 0, ll = 0, left = 0;
        char pad = ' ';
        if (*fmt != '%') { if (o < end) *o++ = *fmt; ++total; continue; }
        ++fmt;
        if (*fmt == '-') { left = 1; ++fmt; }
        if (*fmt == '0') { pad = '0'; ++fmt; }
        while (*fmt >= '0' && *fmt <= '9') width = width * 10 + (*fmt++ - '0');
        while (*fmt == 'l' || *fmt == 'z' || *fmt == 'I') { ++ll; ++fmt; if (*fmt == '6' && fmt[1] == '4') fmt += 2; }
        (void)left;
        switch (*fmt) {
        case 's': { const char *s = va_arg(ap, const char *); if (!s) s = "(null)"; while (*s) { if (o < end) *o++ = *s; ++s; ++total; } break; }
        case 'c': if (o < end) *o++ = (char)va_arg(ap, int); ++total; break;
        case 'd': case 'i': { long long v = ll ? va_arg(ap, long long) : va_arg(ap, int); char *s = o; put_uint(&o, end, v < 0 ? (unsigned long long)-v : (unsigned long long)v, 10, width, pad, v < 0, 0); total += (size_t)(o - s); break; }
        case 'u': { char *s = o; put_uint(&o, end, ll ? va_arg(ap, unsigned long long) : va_arg(ap, unsigned), 10, width, pad, 0, 0); total += (size_t)(o - s); break; }
        case 'x': case 'X': { char *s = o; put_uint(&o, end, ll ? va_arg(ap, unsigned long long) : va_arg(ap, unsigned), 16, width, pad, 0, *fmt == 'X'); total += (size_t)(o - s); break; }
        case 'p': { char *s = o; if (o < end) *o++ = '0'; if (o < end) *o++ = 'x'; put_uint(&o, end, (unsigned long long)(uintptr_t)va_arg(ap, void *), 16, 16, '0', 0, 0); total += (size_t)(o - s); break; }
        case '%': if (o < end) *o++ = '%'; ++total; break;
        default: if (o < end) *o++ = '%'; ++total; if (*fmt) { if (o < end) *o++ = *fmt; ++total; } else goto done;
        }
    }
done:
    if (cap) *o = 0;
    return (int)total;
}
int shz_snprintf(char *buf, size_t cap, const char *fmt, ...)
{
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = shz_vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
    return r;
}
void shz_puts(const char *s)
{
    DWORD n;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, (DWORD)strlen(s), &n, 0);
}
int shz_printf(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = shz_vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    shz_puts(buf);
    return r;
}

/* ---- startup: split the UTF-8 command line into argv, call main, exit ---- */
static char *g_argv[64];
int ShzStart(void)
{
    LPWSTR w = GetCommandLineW();
    char *cmd;
    int argc = 0, n, i;
    n = WideCharToMultiByte(CP_UTF8, 0, w, -1, 0, 0, 0, 0);
    cmd = HeapAlloc(GetProcessHeap(), 0, (size_t)n + 1);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, cmd, n, 0, 0);
    for (i = 0; cmd[i] && argc < 63; ) {
        while (cmd[i] == ' ') ++i;
        if (!cmd[i]) break;
        if (cmd[i] == '"') { g_argv[argc++] = &cmd[++i]; while (cmd[i] && cmd[i] != '"') ++i; }
        else { g_argv[argc++] = &cmd[i]; while (cmd[i] && cmd[i] != ' ') ++i; }
        if (cmd[i]) cmd[i++] = 0;
    }
    g_argv[argc] = 0;
    ExitProcess((UINT)main(argc, g_argv));
    return 0;
}
