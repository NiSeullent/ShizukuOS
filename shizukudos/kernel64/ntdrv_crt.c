/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the C runtime ntoskrnl.exe exports to drivers (the narrow and wide
 * printf family, the str/wcs functions and their case-insensitive variants) and the Rtl helpers built on
 * them -- code-page conversion (RtlMultiByteToUnicodeN & co.: the ANSI code page here is
 * the Latin-1 subset of Windows-1252, single-byte), counted-string utilities, integer parsing,
 * bitmaps, time fields, GUID strings, version verification, image directory / message-table
 * lookup, stack capture, range lists and the Cm/Io resource-descriptor encoders. Every export is
 * NTAPI (Microsoft x64), every vararg entry reads the Microsoft variadic register layout.
 *
 * The formatter is one engine for four combinations (narrow/wide format string, narrow/wide
 * output) so DbgPrint, sprintf and swprintf agree on every conversion.
 */
#include "ntdrv.h"
#define STATUS_NAME_TOO_LONG ((int32_t)0xC0000106)

/* ================================================================ printf engine */
typedef struct { void *buf; uint64_t cap, n; int wide; } out_t;

static void out_ch(out_t *o, uint32_t c)
{
    if (o->n + 1 < o->cap) {
        if (o->wide) ((WCHAR *)o->buf)[o->n] = (WCHAR)c;
        else ((char *)o->buf)[o->n] = (char)c;
    }
    o->n++;
}
static void out_term(out_t *o)
{
    uint64_t at = o->n + 1 < o->cap ? o->n : (o->cap ? o->cap - 1 : 0);
    if (!o->cap) return;
    if (o->wide) ((WCHAR *)o->buf)[at] = 0; else ((char *)o->buf)[at] = 0;
}
static uint32_t fmt_ch(const void *f, uint64_t i, int wide) { return wide ? ((const WCHAR *)f)[i] : (uint8_t)((const char *)f)[i]; }

static void pad(out_t *o, int n, char c) { while (n-- > 0) out_ch(o, (uint8_t)c); }

/* One conversion, C99/Microsoft semantics: flags -+ 0#, width/precision (also '*'), length h/hh/l/ll/I/I32/I64/w/z/t/j,
 * conversions d i u o x X p c C s S Z (ANSI_STRING) wZ (UNICODE_STRING) n-less. %ws/%wc/%wZ are Microsoft's wide forms. */
static int64_t va_int(__builtin_ms_va_list *ap, int longs, int is_signed)
{
    if (longs >= 2) return __builtin_va_arg(*ap, int64_t);
    if (longs == 1) return is_signed ? (int64_t)__builtin_va_arg(*ap, int32_t) : (int64_t)__builtin_va_arg(*ap, uint32_t);   /* long is 32-bit on Win64 */
    return is_signed ? (int64_t)__builtin_va_arg(*ap, int32_t) : (int64_t)__builtin_va_arg(*ap, uint32_t);
}

static void ntdrv_vformat_core(out_t *o, const void *fmt, int fwide, __builtin_ms_va_list *ap)
{
    uint64_t i = 0;
    for (;;) {
        uint32_t c = fmt_ch(fmt, i, fwide);
        int left = 0, plus = 0, space = 0, zero = 0, alt = 0, width = 0, prec = -1, longs = 0, hs = 0, wideconv = -1;
        if (!c) break;
        ++i;
        if (c != '%') { out_ch(o, c); continue; }
        for (;;) {
            c = fmt_ch(fmt, i, fwide);
            if (c == '-') left = 1; else if (c == '+') plus = 1; else if (c == ' ') space = 1;
            else if (c == '0') zero = 1; else if (c == '#') alt = 1; else break;
            ++i;
        }
        if (c == '*') { width = __builtin_va_arg(*ap, int); if (width < 0) { left = 1; width = -width; } ++i; c = fmt_ch(fmt, i, fwide); }
        else while (c >= '0' && c <= '9') { width = width * 10 + (int)(c - '0'); ++i; c = fmt_ch(fmt, i, fwide); }
        if (c == '.') {
            ++i; c = fmt_ch(fmt, i, fwide); prec = 0;
            if (c == '*') { prec = __builtin_va_arg(*ap, int); if (prec < 0) prec = -1; ++i; c = fmt_ch(fmt, i, fwide); }
            else while (c >= '0' && c <= '9') { prec = prec * 10 + (int)(c - '0'); ++i; c = fmt_ch(fmt, i, fwide); }
        }
        for (;;) {
            if (c == 'l') { ++longs; ++i; }
            else if (c == 'h') { ++hs; ++i; }
            else if (c == 'I') {
                ++i; c = fmt_ch(fmt, i, fwide);
                if (c == '6' && fmt_ch(fmt, i + 1, fwide) == '4') { longs = 2; i += 2; }
                else if (c == '3' && fmt_ch(fmt, i + 1, fwide) == '2') { longs = 1; i += 2; }
                else longs = 2;                                    /* %I = ptrdiff/size_t width */
                c = fmt_ch(fmt, i, fwide); continue;
            }
            else if (c == 'z' || c == 't' || c == 'j') { longs = 2; ++i; }
            else if (c == 'w') { wideconv = 1; ++i; }
            else break;
            c = fmt_ch(fmt, i, fwide);
        }
        if (!c) break;
        ++i;
        switch (c) {
        case '%': out_ch(o, '%'); break;
        case 'c': case 'C': {
            uint32_t ch = (uint32_t)__builtin_va_arg(*ap, int);
            int w = wideconv == 1 || (c == 'C' ? !fwide : (longs > 0 || (fwide && c == 'c')));
            (void)w;
            if (!left) pad(o, width - 1, ' ');
            out_ch(o, ch);
            if (left) pad(o, width - 1, ' ');
            break; }
        case 's': case 'S': {
            const void *s = __builtin_va_arg(*ap, const void *);
            int w = wideconv == 1 || longs > 0 || (fwide ? c == 's' : c == 'S');
            int n = 0, k;
            if (!s) s = w ? (const void *)u"(null)" : (const void *)"(null)";
            if (w) { while (((const WCHAR *)s)[n] && (prec < 0 || n < prec)) ++n; }
            else { while (((const char *)s)[n] && (prec < 0 || n < prec)) ++n; }
            if (!left) pad(o, width - n, ' ');
            for (k = 0; k < n; ++k) out_ch(o, w ? ((const WCHAR *)s)[k] : (uint8_t)((const char *)s)[k]);
            if (left) pad(o, width - n, ' ');
            break; }
        case 'Z': {                                                    /* %Z ANSI_STRING, %wZ UNICODE_STRING */
            const void *p = __builtin_va_arg(*ap, const void *);
            int w = wideconv == 1 || longs > 0, n = 0, k;
            const ANSI_STRING *a = p; const UNICODE_STRING *u = p;
            if (p) n = w ? u->Length / 2 : a->Length;
            if (prec >= 0 && n > prec) n = prec;
            if (!left) pad(o, width - n, ' ');
            for (k = 0; k < n; ++k) out_ch(o, w ? u->Buffer[k] : (uint8_t)a->Buffer[k]);
            if (left) pad(o, width - n, ' ');
            break; }
        case 'p': longs = 2; alt = 0; zero = 1; width = width > 16 ? width : 16; c = 'X'; /* Microsoft prints 16 upper hex digits */
            __attribute__((fallthrough));
        case 'd': case 'i': case 'u': case 'x': case 'X': case 'o': {
            int is_signed = c == 'd' || c == 'i';
            int64_t v = va_int(ap, longs, is_signed);
            uint64_t uv;
            unsigned base = c == 'x' || c == 'X' ? 16 : c == 'o' ? 8 : 10;
            const char *digits = c == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
            char tmp[32]; int n = 0, neg = 0, k, total, prefixlen = 0;
            const char *prefix = "";
            if (hs == 1) { if (is_signed) v = (int16_t)v; else v = (uint16_t)v; }
            else if (hs >= 2) { if (is_signed) v = (int8_t)v; else v = (uint8_t)v; }
            if (is_signed && v < 0) { neg = 1; uv = (uint64_t)(-v); } else uv = (uint64_t)v;
            if (!is_signed && longs < 2 && hs == 0) uv &= 0xffffffffull;
            if (!uv && prec != 0) tmp[n++] = '0';
            while (uv) { tmp[n++] = digits[uv % base]; uv /= base; }
            while (n < prec) tmp[n++] = '0';
            if (neg) prefix = "-"; else if (plus && is_signed) prefix = "+"; else if (space && is_signed) prefix = " ";
            if (alt && base == 16 && v) prefix = c == 'X' ? "0X" : "0x";
            if (alt && base == 8 && tmp[n - 1] != '0') tmp[n++] = '0';
            while (prefix[prefixlen]) ++prefixlen;
            total = n + prefixlen;
            if (!left && !(zero && prec < 0)) pad(o, width - total, ' ');
            for (k = 0; k < prefixlen; ++k) out_ch(o, (uint8_t)prefix[k]);
            if (!left && zero && prec < 0) pad(o, width - total, '0');
            while (n) out_ch(o, (uint8_t)tmp[--n]);
            if (left) pad(o, width - total, ' ');
            break; }
        case 'n': { int *p = __builtin_va_arg(*ap, int *); if (p) *p = (int)o->n; break; }
        default: out_ch(o, '%'); out_ch(o, c); break;
        }
    }
}

/* Shared with DbgPrint (ntdrv_rtl.c). Returns the number of characters that would have been written. */
int ntdrv_vformat(void *buf, uint64_t cap, int outwide, const void *fmt, int fmtwide, __builtin_ms_va_list ap)
{
    out_t o = { buf, cap, 0, outwide };
    __builtin_ms_va_list ap2;
    __builtin_ms_va_copy(ap2, ap);
    ntdrv_vformat_core(&o, fmt, fmtwide, &ap2);
    __builtin_ms_va_end(ap2);
    out_term(&o);
    return (int)o.n;
}

/* Microsoft semantics: sprintf/swprintf return the count; the _sn variants return -1 when the output was truncated
 * (and leave the buffer unterminated on exactly-full, as the CRT does -- callers that need a terminator pass cap-1). */
static int sn_result(int n, uint64_t cap) { return (uint64_t)n < cap ? n : -1; }
int NTAPI ntdrv_vsprintf(char *buf, const char *fmt, __builtin_ms_va_list ap) { return ntdrv_vformat(buf, ~0ull, 0, fmt, 0, ap); }
int NTAPI ntdrv_sprintf(char *buf, const char *fmt, ...)
{ __builtin_ms_va_list ap; int r; __builtin_ms_va_start(ap, fmt); r = ntdrv_vformat(buf, ~0ull, 0, fmt, 0, ap); __builtin_ms_va_end(ap); return r; }
int NTAPI ntdrv_vsnprintf(char *buf, uint64_t cap, const char *fmt, __builtin_ms_va_list ap)
{ int n = ntdrv_vformat(buf, cap + 1, 0, fmt, 0, ap); if ((uint64_t)n == cap && cap) buf[cap - 1] = (char)0; return sn_result(n, cap + 1) < 0 ? -1 : n; }
int NTAPI ntdrv_snprintf(char *buf, uint64_t cap, const char *fmt, ...)
{ __builtin_ms_va_list ap; int r; __builtin_ms_va_start(ap, fmt); r = ntdrv_vsnprintf(buf, cap, fmt, ap); __builtin_ms_va_end(ap); return r; }
int NTAPI ntdrv_vswprintf(WCHAR *buf, const WCHAR *fmt, __builtin_ms_va_list ap) { return ntdrv_vformat(buf, ~0ull, 1, fmt, 1, ap); }
int NTAPI ntdrv_swprintf(WCHAR *buf, const WCHAR *fmt, ...)
{ __builtin_ms_va_list ap; int r; __builtin_ms_va_start(ap, fmt); r = ntdrv_vformat(buf, ~0ull, 1, fmt, 1, ap); __builtin_ms_va_end(ap); return r; }
int NTAPI ntdrv_vsnwprintf(WCHAR *buf, uint64_t cap, const WCHAR *fmt, __builtin_ms_va_list ap)
{ int n = ntdrv_vformat(buf, cap + 1, 1, fmt, 1, ap); if ((uint64_t)n == cap && cap) buf[cap - 1] = 0; return sn_result(n, cap + 1) < 0 ? -1 : n; }
int NTAPI ntdrv_snwprintf(WCHAR *buf, uint64_t cap, const WCHAR *fmt, ...)
{ __builtin_ms_va_list ap; int r; __builtin_ms_va_start(ap, fmt); r = ntdrv_vsnwprintf(buf, cap, fmt, ap); __builtin_ms_va_end(ap); return r; }

/* ================================================================ str* / wcs* */
static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }
static int upper(int c) { return c >= 'a' && c <= 'z' ? c - 32 : c; }
uint64_t NTAPI ntdrv_strlen(const char *s) { return strlen(s); }
int NTAPI ntdrv_strcmp(const char *a, const char *b) { return strcmp(a, b); }
int NTAPI ntdrv_strncmp(const char *a, const char *b, uint64_t n) { return strncmp(a, b, n); }
char *NTAPI ntdrv_strncpy(char *d, const char *s, uint64_t n) { uint64_t i = 0; for (; i < n && s[i]; ++i) d[i] = s[i]; for (; i < n; ++i) d[i] = 0; return d; }
char *NTAPI ntdrv_strcpy(char *d, const char *s) { char *r = d; while ((*d++ = *s++)) {} return r; }
char *NTAPI ntdrv_strcat(char *d, const char *s) { char *r = d; while (*d) ++d; while ((*d++ = *s++)) {} return r; }
char *NTAPI ntdrv_strchr(const char *s, int c) { for (;; ++s) { if (*s == (char)c) return (char *)s; if (!*s) return 0; } }
char *NTAPI ntdrv_strrchr(const char *s, int c) { const char *r = 0; for (;; ++s) { if (*s == (char)c) r = s; if (!*s) return (char *)r; } }
char *NTAPI ntdrv_strstr(const char *h, const char *n) { uint64_t l = strlen(n); for (; *h; ++h) if (!strncmp(h, n, l)) return (char *)h; return l ? 0 : (char *)h; }
int NTAPI ntdrv_stricmp(const char *a, const char *b) { while (*a && lower((uint8_t)*a) == lower((uint8_t)*b)) { ++a; ++b; } return lower((uint8_t)*a) - lower((uint8_t)*b); }
int NTAPI ntdrv_strnicmp(const char *a, const char *b, uint64_t n)
{ while (n && *a && lower((uint8_t)*a) == lower((uint8_t)*b)) { ++a; ++b; --n; } return n ? lower((uint8_t)*a) - lower((uint8_t)*b) : 0; }
int NTAPI ntdrv_memcmp(const void *a, const void *b, uint64_t n) { return memcmp(a, b, n); }
int NTAPI ntdrv_toupper(int c) { return upper(c); }
int NTAPI ntdrv_tolower(int c) { return lower(c); }
int NTAPI ntdrv_isdigit(int c) { return c >= '0' && c <= '9'; }
int NTAPI ntdrv_isspace(int c) { return c == ' ' || (c >= 9 && c <= 13); }
int NTAPI ntdrv_atoi(const char *s) { int neg = 0, v = 0; while (ntdrv_isspace(*s)) ++s; if (*s == '-') { neg = 1; ++s; } else if (*s == '+') ++s; while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0'); return neg ? -v : v; }
uint64_t NTAPI ntdrv_wcslen(const WCHAR *s) { uint64_t n = 0; while (s[n]) ++n; return n; }
WCHAR *NTAPI ntdrv_wcscpy(WCHAR *d, const WCHAR *s) { WCHAR *r = d; while ((*d++ = *s++)) {} return r; }
WCHAR *NTAPI ntdrv_wcsncpy(WCHAR *d, const WCHAR *s, uint64_t n) { uint64_t i = 0; for (; i < n && s[i]; ++i) d[i] = s[i]; for (; i < n; ++i) d[i] = 0; return d; }
WCHAR *NTAPI ntdrv_wcscat(WCHAR *d, const WCHAR *s) { WCHAR *r = d; while (*d) ++d; while ((*d++ = *s++)) {} return r; }
WCHAR *NTAPI ntdrv_wcsncat(WCHAR *d, const WCHAR *s, uint64_t n) { WCHAR *r = d; while (*d) ++d; while (n-- && *s) *d++ = *s++; *d = 0; return r; }
int NTAPI ntdrv_wcscmp(const WCHAR *a, const WCHAR *b) { while (*a && *a == *b) { ++a; ++b; } return (int)*a - (int)*b; }
int NTAPI ntdrv_wcsncmp(const WCHAR *a, const WCHAR *b, uint64_t n) { while (n && *a && *a == *b) { ++a; ++b; --n; } return n ? (int)*a - (int)*b : 0; }
int NTAPI ntdrv_wcsicmp(const WCHAR *a, const WCHAR *b) { while (*a && upper(*a) == upper(*b)) { ++a; ++b; } return upper(*a) - upper(*b); }
int NTAPI ntdrv_wcsnicmp(const WCHAR *a, const WCHAR *b, uint64_t n) { while (n && *a && upper(*a) == upper(*b)) { ++a; ++b; --n; } return n ? upper(*a) - upper(*b) : 0; }
WCHAR *NTAPI ntdrv_wcschr(const WCHAR *s, WCHAR c) { for (;; ++s) { if (*s == c) return (WCHAR *)s; if (!*s) return 0; } }
WCHAR *NTAPI ntdrv_wcsrchr(const WCHAR *s, WCHAR c) { const WCHAR *r = 0; for (;; ++s) { if (*s == c) r = s; if (!*s) return (WCHAR *)r; } }
WCHAR *NTAPI ntdrv_wcsstr(const WCHAR *h, const WCHAR *n) { uint64_t l = ntdrv_wcslen(n); for (; *h; ++h) if (!ntdrv_wcsncmp(h, n, l)) return (WCHAR *)h; return l ? 0 : (WCHAR *)h; }
WCHAR NTAPI ntdrv_towupper(WCHAR c) { return (WCHAR)upper(c); }
WCHAR NTAPI ntdrv_towlower(WCHAR c) { return (WCHAR)lower(c); }
WCHAR *NTAPI ntdrv_wcsupr(WCHAR *s) { WCHAR *r = s; for (; *s; ++s) *s = (WCHAR)upper(*s); return r; }
char *NTAPI ntdrv_strupr(char *s) { char *r = s; for (; *s; ++s) *s = (char)upper((uint8_t)*s); return r; }
char *NTAPI ntdrv_strlwr(char *s) { char *r = s; for (; *s; ++s) *s = (char)lower((uint8_t)*s); return r; }

/* ================================================================ Rtl code-page conversion (ANSI = Latin-1 subset) */
NTSTATUS NTAPI RtlMultiByteToUnicodeN(WCHAR *dst, uint32_t dstbytes, uint32_t *result, const char *src, uint32_t srcbytes)
{
    uint32_t n = srcbytes < dstbytes / 2 ? srcbytes : dstbytes / 2, i;
    for (i = 0; i < n; ++i) dst[i] = (uint8_t)src[i];
    if (result) *result = n * 2;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlMultiByteToUnicodeSize(uint32_t *size, const char *src, uint32_t srcbytes) { (void)src; *size = srcbytes * 2; return STATUS_SUCCESS; }
NTSTATUS NTAPI RtlUnicodeToMultiByteN(char *dst, uint32_t dstbytes, uint32_t *result, const WCHAR *src, uint32_t srcbytes)
{
    uint32_t n = srcbytes / 2 < dstbytes ? srcbytes / 2 : dstbytes, i;
    for (i = 0; i < n; ++i) dst[i] = src[i] < 0x100 ? (char)src[i] : '?';        /* the code page's default character */
    if (result) *result = n;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlUnicodeToMultiByteSize(uint32_t *size, const WCHAR *src, uint32_t srcbytes) { (void)src; *size = srcbytes / 2; return STATUS_SUCCESS; }
NTSTATUS NTAPI RtlUpcaseUnicodeToMultiByteN(char *dst, uint32_t dstbytes, uint32_t *result, const WCHAR *src, uint32_t srcbytes)
{
    uint32_t n = srcbytes / 2 < dstbytes ? srcbytes / 2 : dstbytes, i;
    for (i = 0; i < n; ++i) dst[i] = src[i] < 0x100 ? (char)upper(src[i]) : '?';
    if (result) *result = n;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlOemToUnicodeN(WCHAR *dst, uint32_t dstbytes, uint32_t *result, const char *src, uint32_t srcbytes) { return RtlMultiByteToUnicodeN(dst, dstbytes, result, src, srcbytes); }
NTSTATUS NTAPI RtlUnicodeToOemN(char *dst, uint32_t dstbytes, uint32_t *result, const WCHAR *src, uint32_t srcbytes) { return RtlUnicodeToMultiByteN(dst, dstbytes, result, src, srcbytes); }
/* Converts the character at *src, advances *src past it, returns the WCHAR (documented: single- or lead/trail byte). */
WCHAR NTAPI RtlAnsiCharToUnicodeChar(char **src) { WCHAR c = (uint8_t)**src; (*src)++; return c; }
uint32_t NTAPI RtlxAnsiStringToUnicodeSize(const ANSI_STRING *a) { return ((uint32_t)a->Length + 1) * 2; }
uint32_t NTAPI RtlxUnicodeStringToOemSize(const UNICODE_STRING *u) { return u->Length / 2 + 1; }
uint32_t NTAPI RtlxOemStringToUnicodeSize(const ANSI_STRING *a) { return ((uint32_t)a->Length + 1) * 2; }

/* ================================================================ Rtl strings */
WCHAR NTAPI RtlUpcaseUnicodeChar(WCHAR c) { return (WCHAR)upper(c); }
WCHAR NTAPI RtlDowncaseUnicodeChar(WCHAR c) { return (WCHAR)lower(c); }
NTSTATUS NTAPI RtlUpcaseUnicodeString(UNICODE_STRING *dst, const UNICODE_STRING *src, uint8_t alloc)
{
    unsigned n = src->Length / 2, i;
    if (alloc) { dst->Buffer = kmalloc(n * 2 + 2); if (!dst->Buffer) return STATUS_NO_MEMORY; dst->MaximumLength = (uint16_t)(n * 2 + 2); }
    else if (dst->MaximumLength < n * 2) return STATUS_BUFFER_OVERFLOW;
    for (i = 0; i < n; ++i) dst->Buffer[i] = (WCHAR)upper(src->Buffer[i]);
    dst->Length = (uint16_t)(n * 2);
    if (alloc) dst->Buffer[n] = 0;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlDowncaseUnicodeString(UNICODE_STRING *dst, const UNICODE_STRING *src, uint8_t alloc)
{
    unsigned n = src->Length / 2, i;
    if (alloc) { dst->Buffer = kmalloc(n * 2 + 2); if (!dst->Buffer) return STATUS_NO_MEMORY; dst->MaximumLength = (uint16_t)(n * 2 + 2); }
    else if (dst->MaximumLength < n * 2) return STATUS_BUFFER_OVERFLOW;
    for (i = 0; i < n; ++i) dst->Buffer[i] = (WCHAR)lower(src->Buffer[i]);
    dst->Length = (uint16_t)(n * 2);
    if (alloc) dst->Buffer[n] = 0;
    return STATUS_SUCCESS;
}
void NTAPI RtlUpperString(ANSI_STRING *dst, const ANSI_STRING *src)
{
    unsigned n = src->Length < dst->MaximumLength ? src->Length : dst->MaximumLength, i;
    for (i = 0; i < n; ++i) dst->Buffer[i] = (char)upper((uint8_t)src->Buffer[i]);
    dst->Length = (uint16_t)n;
}
uint8_t NTAPI RtlCreateUnicodeString(UNICODE_STRING *dst, const WCHAR *src)
{
    uint64_t n = ntdrv_wcslen(src);
    if (n * 2 + 2 > 0xffff) return 0;
    dst->Buffer = kmalloc(n * 2 + 2);
    if (!dst->Buffer) return 0;
    memcpy(dst->Buffer, src, n * 2 + 2);
    dst->Length = (uint16_t)(n * 2);
    dst->MaximumLength = (uint16_t)(n * 2 + 2);
    return 1;
}
NTSTATUS NTAPI RtlInitUnicodeStringEx(UNICODE_STRING *u, const WCHAR *s)
{
    uint64_t n = s ? ntdrv_wcslen(s) : 0;
    if (n * 2 + 2 > 0xffff) return STATUS_NAME_TOO_LONG;
    u->Buffer = (WCHAR *)s; u->Length = (uint16_t)(n * 2); u->MaximumLength = (uint16_t)(s ? n * 2 + 2 : 0);
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlInitAnsiStringEx(ANSI_STRING *a, const char *s)
{
    uint64_t n = s ? strlen(s) : 0;
    if (n + 1 > 0xffff) return STATUS_NAME_TOO_LONG;
    a->Buffer = (char *)s; a->Length = (uint16_t)n; a->MaximumLength = (uint16_t)(s ? n + 1 : 0);
    return STATUS_SUCCESS;
}
void NTAPI RtlInitString(ANSI_STRING *a, const char *s) { uint64_t n = s ? strlen(s) : 0; a->Buffer = (char *)s; a->Length = (uint16_t)n; a->MaximumLength = (uint16_t)(s ? n + 1 : 0); }
void NTAPI RtlInitEmptyUnicodeString_(UNICODE_STRING *u, WCHAR *buf, uint16_t max) { u->Buffer = buf; u->Length = 0; u->MaximumLength = max; }
LONG NTAPI RtlCompareString(const ANSI_STRING *a, const ANSI_STRING *b, uint8_t ci)
{
    unsigned n = a->Length < b->Length ? a->Length : b->Length, i;
    for (i = 0; i < n; ++i) {
        int x = (uint8_t)a->Buffer[i], y = (uint8_t)b->Buffer[i];
        if (ci) { x = upper(x); y = upper(y); }
        if (x != y) return x - y;
    }
    return (LONG)a->Length - (LONG)b->Length;
}
uint8_t NTAPI RtlEqualString(const ANSI_STRING *a, const ANSI_STRING *b, uint8_t ci) { return a->Length == b->Length && RtlCompareString(a, b, ci) == 0; }
void NTAPI RtlCopyString(ANSI_STRING *dst, const ANSI_STRING *src)
{
    unsigned n = src ? src->Length : 0;
    if (n > dst->MaximumLength) n = dst->MaximumLength;
    if (src) memcpy(dst->Buffer, src->Buffer, n);
    dst->Length = (uint16_t)n;
}
uint8_t NTAPI RtlPrefixUnicodeString(const UNICODE_STRING *pfx, const UNICODE_STRING *s, uint8_t ci)
{
    unsigned n = pfx->Length / 2, i;
    if (s->Length < pfx->Length) return 0;
    for (i = 0; i < n; ++i) {
        int x = pfx->Buffer[i], y = s->Buffer[i];
        if (ci) { x = upper(x); y = upper(y); }
        if (x != y) return 0;
    }
    return 1;
}
NTSTATUS NTAPI RtlAppendStringToString(ANSI_STRING *dst, const ANSI_STRING *src)
{
    if ((unsigned)dst->Length + src->Length > dst->MaximumLength) return STATUS_BUFFER_TOO_SMALL;
    memcpy(dst->Buffer + dst->Length, src->Buffer, src->Length);
    dst->Length = (uint16_t)(dst->Length + src->Length);
    return STATUS_SUCCESS;
}

/* RtlUnicodeStringToInteger: optional whitespace, sign, base prefix (0x/0o/0b when Base==0), digits of the base;
 * stops at the first non-digit; STATUS_INVALID_PARAMETER for an unsupported base. */
NTSTATUS NTAPI RtlUnicodeStringToInteger(const UNICODE_STRING *s, uint32_t base, uint32_t *value)
{
    unsigned n = s->Length / 2, i = 0;
    int neg = 0;
    uint32_t v = 0;
    while (i < n && (s->Buffer[i] == ' ' || (s->Buffer[i] >= 9 && s->Buffer[i] <= 13))) ++i;
    if (i < n && (s->Buffer[i] == '-' || s->Buffer[i] == '+')) { neg = s->Buffer[i] == '-'; ++i; }
    if (!base) {
        base = 10;
        if (i + 1 < n && s->Buffer[i] == '0') {
            WCHAR c = (WCHAR)lower(s->Buffer[i + 1]);
            if (c == 'x') { base = 16; i += 2; } else if (c == 'o') { base = 8; i += 2; } else if (c == 'b') { base = 2; i += 2; }
        }
    } else if (base != 2 && base != 8 && base != 10 && base != 16) return STATUS_INVALID_PARAMETER;
    for (; i < n; ++i) {
        int c = lower(s->Buffer[i]), d;
        if (c >= '0' && c <= '9') d = c - '0'; else if (c >= 'a' && c <= 'z') d = c - 'a' + 10; else break;
        if ((uint32_t)d >= base) break;
        v = v * base + (uint32_t)d;
    }
    *value = neg ? (uint32_t)(-(int32_t)v) : v;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlCharToInteger(const char *s, uint32_t base, uint32_t *value)
{
    WCHAR w[64]; UNICODE_STRING u; unsigned i = 0;
    while (s[i] && i < 63) { w[i] = (uint8_t)s[i]; ++i; }
    u.Buffer = w; u.Length = (uint16_t)(i * 2); u.MaximumLength = sizeof w;
    return RtlUnicodeStringToInteger(&u, base, value);
}
NTSTATUS NTAPI RtlInt64ToUnicodeString(uint64_t value, uint32_t base, UNICODE_STRING *dst)
{
    WCHAR tmp[72]; int n = 0, i;
    if (!base) base = 10;
    if (base != 2 && base != 8 && base != 10 && base != 16) return STATUS_INVALID_PARAMETER;
    if (!value) tmp[n++] = '0';
    while (value) { uint64_t d = value % base; tmp[n++] = (WCHAR)(d < 10 ? '0' + d : 'a' + d - 10); value /= base; }
    if ((unsigned)(n * 2) > dst->MaximumLength) return STATUS_BUFFER_OVERFLOW;
    for (i = 0; i < n; ++i) dst->Buffer[i] = tmp[n - 1 - i];
    dst->Length = (uint16_t)(n * 2);
    if ((unsigned)(n * 2 + 2) <= dst->MaximumLength) dst->Buffer[n] = 0;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlIntegerToChar(uint32_t value, uint32_t base, uint32_t len, char *out)
{
    char tmp[36]; unsigned n = 0, i;
    if (!base) base = 10;
    if (base != 2 && base != 8 && base != 10 && base != 16) return STATUS_INVALID_PARAMETER;
    if (!value) tmp[n++] = '0';
    while (value) { uint32_t d = value % base; tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); value /= base; }
    if (n > len) return STATUS_BUFFER_OVERFLOW;
    for (i = 0; i < n; ++i) out[i] = tmp[n - 1 - i];
    if (n < len) out[n] = 0;
    return STATUS_SUCCESS;
}

/* ================================================================ bitmaps */
typedef struct { uint32_t SizeOfBitMap; uint32_t _pad; uint32_t *Buffer; } RTL_BITMAP;
void NTAPI RtlInitializeBitMap(RTL_BITMAP *bm, uint32_t *buf, uint32_t bits) { bm->SizeOfBitMap = bits; bm->Buffer = buf; }
void NTAPI RtlClearAllBits(RTL_BITMAP *bm) { memset(bm->Buffer, 0, ((bm->SizeOfBitMap + 31) / 32) * 4); }
void NTAPI RtlSetAllBits(RTL_BITMAP *bm) { memset(bm->Buffer, 0xff, ((bm->SizeOfBitMap + 31) / 32) * 4); }
void NTAPI RtlSetBit(RTL_BITMAP *bm, uint32_t i) { if (i < bm->SizeOfBitMap) bm->Buffer[i / 32] |= 1u << (i % 32); }
void NTAPI RtlClearBit(RTL_BITMAP *bm, uint32_t i) { if (i < bm->SizeOfBitMap) bm->Buffer[i / 32] &= ~(1u << (i % 32)); }
uint8_t NTAPI RtlTestBit(RTL_BITMAP *bm, uint32_t i) { return i < bm->SizeOfBitMap && (bm->Buffer[i / 32] >> (i % 32)) & 1; }
uint8_t NTAPI RtlCheckBit(RTL_BITMAP *bm, uint32_t i) { return RtlTestBit(bm, i); }
void NTAPI RtlSetBits(RTL_BITMAP *bm, uint32_t start, uint32_t n) { while (n--) RtlSetBit(bm, start++); }
void NTAPI RtlClearBits(RTL_BITMAP *bm, uint32_t start, uint32_t n) { while (n--) RtlClearBit(bm, start++); }
uint32_t NTAPI RtlNumberOfSetBits(RTL_BITMAP *bm) { uint32_t i, c = 0; for (i = 0; i < bm->SizeOfBitMap; ++i) c += RtlTestBit(bm, i); return c; }
uint32_t NTAPI RtlNumberOfClearBits(RTL_BITMAP *bm) { return bm->SizeOfBitMap - RtlNumberOfSetBits(bm); }
uint8_t NTAPI RtlAreBitsClear(RTL_BITMAP *bm, uint32_t start, uint32_t n)
{ uint32_t i; if (!n || start + n > bm->SizeOfBitMap || start + n < start) return 0; for (i = 0; i < n; ++i) if (RtlTestBit(bm, start + i)) return 0; return 1; }
uint8_t NTAPI RtlAreBitsSet(RTL_BITMAP *bm, uint32_t start, uint32_t n)
{ uint32_t i; if (!n || start + n > bm->SizeOfBitMap || start + n < start) return 0; for (i = 0; i < n; ++i) if (!RtlTestBit(bm, start + i)) return 0; return 1; }
static uint32_t find_run(RTL_BITMAP *bm, uint32_t n, uint32_t hint, int want_set)
{
    uint32_t pass, start;
    if (!n || n > bm->SizeOfBitMap) return 0xffffffffu;
    if (hint >= bm->SizeOfBitMap) hint = 0;
    for (pass = 0; pass < 2; ++pass) {
        uint32_t lo = pass ? 0 : hint, hi = pass ? hint : bm->SizeOfBitMap, run = 0;
        for (start = lo; start < hi; ++start) {
            if (RtlTestBit(bm, start) == (uint8_t)want_set) { if (++run == n) return start + 1 - n; } else run = 0;
        }
        if (!hint) break;
    }
    return 0xffffffffu;
}
uint32_t NTAPI RtlFindClearBits(RTL_BITMAP *bm, uint32_t n, uint32_t hint) { return find_run(bm, n, hint, 0); }
uint32_t NTAPI RtlFindSetBits(RTL_BITMAP *bm, uint32_t n, uint32_t hint) { return find_run(bm, n, hint, 1); }
uint32_t NTAPI RtlFindClearBitsAndSet(RTL_BITMAP *bm, uint32_t n, uint32_t hint) { uint32_t p = find_run(bm, n, hint, 0); if (p != 0xffffffffu) RtlSetBits(bm, p, n); return p; }
uint32_t NTAPI RtlFindSetBitsAndClear(RTL_BITMAP *bm, uint32_t n, uint32_t hint) { uint32_t p = find_run(bm, n, hint, 1); if (p != 0xffffffffu) RtlClearBits(bm, p, n); return p; }
uint32_t NTAPI RtlFindFirstRunClear(RTL_BITMAP *bm, uint32_t *start)
{
    uint32_t i = 0, n = 0;
    while (i < bm->SizeOfBitMap && RtlTestBit(bm, i)) ++i;
    if (i >= bm->SizeOfBitMap) { *start = 0xffffffffu; return 0; }
    *start = i;
    while (i + n < bm->SizeOfBitMap && !RtlTestBit(bm, i + n)) ++n;
    return n;
}
uint32_t NTAPI RtlFindNextForwardRunClear(RTL_BITMAP *bm, uint32_t from, uint32_t *start)
{
    uint32_t i = from, n = 0;
    while (i < bm->SizeOfBitMap && RtlTestBit(bm, i)) ++i;
    if (i >= bm->SizeOfBitMap) { *start = 0xffffffffu; return 0; }
    *start = i;
    while (i + n < bm->SizeOfBitMap && !RtlTestBit(bm, i + n)) ++n;
    return n;
}
uint32_t NTAPI RtlFindLastBackwardRunClear(RTL_BITMAP *bm, uint32_t from, uint32_t *start)
{
    uint32_t i = from < bm->SizeOfBitMap ? from : bm->SizeOfBitMap - 1, n = 0;
    if (!bm->SizeOfBitMap) { *start = 0xffffffffu; return 0; }
    while (RtlTestBit(bm, i)) { if (!i) { *start = 0xffffffffu; return 0; } --i; }
    while (!RtlTestBit(bm, i - n)) { ++n; if (n > i) break; }
    *start = i + 1 - n;
    return n;
}

/* ================================================================ time */
typedef struct { int16_t Year, Month, Day, Hour, Minute, Second, Milliseconds, Weekday; } TIME_FIELDS;
static const int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
static int leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }
void NTAPI RtlTimeToTimeFields(const LARGE_INTEGER *t, TIME_FIELDS *f)
{
    uint64_t v = (uint64_t)t->QuadPart, days, secs;
    int y = 1601, m = 0;
    f->Milliseconds = (int16_t)((v / 10000) % 1000);
    secs = v / 10000000ull;
    days = secs / 86400; secs %= 86400;
    f->Hour = (int16_t)(secs / 3600); f->Minute = (int16_t)((secs / 60) % 60); f->Second = (int16_t)(secs % 60);
    f->Weekday = (int16_t)((days + 1) % 7);                    /* 1601-01-01 was a Monday */
    for (;;) { uint64_t yl = leap(y) ? 366 : 365; if (days < yl) break; days -= yl; ++y; }
    for (;;) { uint64_t ml = (uint64_t)mdays[m] + (m == 1 && leap(y)); if (days < ml) break; days -= ml; ++m; }
    f->Year = (int16_t)y; f->Month = (int16_t)(m + 1); f->Day = (int16_t)(days + 1);
}
uint8_t NTAPI RtlTimeFieldsToTime(const TIME_FIELDS *f, LARGE_INTEGER *t)
{
    int y, m; uint64_t days = 0;
    if (f->Year < 1601 || f->Month < 1 || f->Month > 12 || f->Day < 1 || f->Day > 31 || f->Hour > 23 || f->Minute > 59 || f->Second > 59 || f->Milliseconds > 999) return 0;
    for (y = 1601; y < f->Year; ++y) days += leap(y) ? 366 : 365;
    for (m = 0; m < f->Month - 1; ++m) days += (uint64_t)mdays[m] + (m == 1 && leap(f->Year));
    days += (uint64_t)f->Day - 1;
    t->QuadPart = (int64_t)(((days * 86400 + (uint64_t)f->Hour * 3600 + (uint64_t)f->Minute * 60 + f->Second) * 1000 + f->Milliseconds) * 10000);
    return 1;
}
uint8_t NTAPI RtlTimeToSecondsSince1970(const LARGE_INTEGER *t, uint32_t *secs)
{
    int64_t s = t->QuadPart / 10000000ll - 11644473600ll;
    if (s < 0 || s > 0xffffffffll) return 0;
    *secs = (uint32_t)s;
    return 1;
}
void NTAPI RtlSecondsSince1970ToTime(uint32_t secs, LARGE_INTEGER *t) { t->QuadPart = ((int64_t)secs + 11644473600ll) * 10000000ll; }

/* ================================================================ GUIDs */
static void put_hex(WCHAR *p, uint64_t v, int digits) { int i; for (i = digits - 1; i >= 0; --i) { p[i] = (WCHAR)"0123456789ABCDEF"[v & 15]; v >>= 4; } }
NTSTATUS NTAPI RtlStringFromGUID(const GUID *g, UNICODE_STRING *s)
{
    WCHAR *p = kmalloc(39 * 2);
    int i;
    if (!p) return STATUS_NO_MEMORY;
    p[0] = '{'; put_hex(p + 1, g->Data1, 8); p[9] = '-'; put_hex(p + 10, g->Data2, 4); p[14] = '-'; put_hex(p + 15, g->Data3, 4); p[19] = '-';
    put_hex(p + 20, g->Data4[0], 2); put_hex(p + 22, g->Data4[1], 2); p[24] = '-';
    for (i = 0; i < 6; ++i) put_hex(p + 25 + i * 2, g->Data4[2 + i], 2);
    p[37] = '}'; p[38] = 0;
    s->Buffer = p; s->Length = 38 * 2; s->MaximumLength = 39 * 2;
    return STATUS_SUCCESS;
}
static int hexval(WCHAR c) { c = (WCHAR)lower(c); if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; return -1; }
static int parse_hex(const WCHAR *p, int digits, uint64_t *out) { uint64_t v = 0; int i; for (i = 0; i < digits; ++i) { int d = hexval(p[i]); if (d < 0) return 0; v = v * 16 + (uint64_t)d; } *out = v; return 1; }
NTSTATUS NTAPI RtlGUIDFromString(const UNICODE_STRING *s, GUID *g)
{
    const WCHAR *p = s->Buffer; uint64_t v; int i;
    if (s->Length != 38 * 2 || p[0] != '{' || p[37] != '}' || p[9] != '-' || p[14] != '-' || p[19] != '-' || p[24] != '-') return STATUS_INVALID_PARAMETER;
    if (!parse_hex(p + 1, 8, &v)) return STATUS_INVALID_PARAMETER;
    g->Data1 = (uint32_t)v;
    if (!parse_hex(p + 10, 4, &v)) return STATUS_INVALID_PARAMETER;
    g->Data2 = (uint16_t)v;
    if (!parse_hex(p + 15, 4, &v)) return STATUS_INVALID_PARAMETER;
    g->Data3 = (uint16_t)v;
    for (i = 0; i < 2; ++i) { if (!parse_hex(p + 20 + i * 2, 2, &v)) return STATUS_INVALID_PARAMETER; g->Data4[i] = (uint8_t)v; }
    for (i = 0; i < 6; ++i) { if (!parse_hex(p + 25 + i * 2, 2, &v)) return STATUS_INVALID_PARAMETER; g->Data4[2 + i] = (uint8_t)v; }
    return STATUS_SUCCESS;
}
int ntdrv_guid_to_ascii(const GUID *g, char *out)                     /* "{...}" upper-case, 38 chars + NUL */
{
    WCHAR w[39]; int i;
    { WCHAR *p = w; p[0] = '{'; put_hex(p + 1, g->Data1, 8); p[9] = '-'; put_hex(p + 10, g->Data2, 4); p[14] = '-'; put_hex(p + 15, g->Data3, 4); p[19] = '-';
      put_hex(p + 20, g->Data4[0], 2); put_hex(p + 22, g->Data4[1], 2); p[24] = '-';
      for (i = 0; i < 6; ++i) put_hex(p + 25 + i * 2, g->Data4[2 + i], 2);
      p[37] = '}'; p[38] = 0; }
    for (i = 0; i < 39; ++i) out[i] = (char)w[i];
    return 38;
}

/* ================================================================ version verification */
/* RTL_OSVERSIONINFOEXW: dwOSVersionInfoSize(0) dwMajorVersion(4) dwMinorVersion(8) dwBuildNumber(0xc) dwPlatformId(0x10)
 * szCSDVersion(0x14, 128 WCHARs) wServicePackMajor(0x114) wServicePackMinor(0x116) wSuiteMask(0x118) wProductType(0x11a)
 * wReserved(0x11b). The condition mask packs 3 bits per type (VerSetConditionMask). */
enum { VER_MINORVERSION = 1, VER_MAJORVERSION = 2, VER_BUILDNUMBER = 4, VER_PLATFORMID = 8, VER_SERVICEPACKMINOR = 0x10,
       VER_SERVICEPACKMAJOR = 0x20, VER_SUITENAME = 0x40, VER_PRODUCT_TYPE = 0x80 };
enum { VER_EQUAL = 1, VER_GREATER, VER_GREATER_EQUAL, VER_LESS, VER_LESS_EQUAL, VER_AND, VER_OR };
#define STATUS_REVISION_MISMATCH ((int32_t)0xC0000059)
static unsigned cond_bits(uint32_t type) { unsigned i = 0; while (type > 1) { type >>= 1; ++i; } return i * 3; }
uint64_t NTAPI VerSetConditionMask(uint64_t mask, uint32_t type, uint8_t cond)
{
    if (!type) return mask;
    cond &= 7;
    if (!cond) return mask;
    return mask | ((uint64_t)cond << cond_bits(type));
}
static int cmp_cond(uint64_t have, uint64_t want, unsigned cond)
{
    switch (cond) {
    case VER_EQUAL: return have == want; case VER_GREATER: return have > want; case VER_GREATER_EQUAL: return have >= want;
    case VER_LESS: return have < want; case VER_LESS_EQUAL: return have <= want; default: return 0;
    }
}
NTSTATUS NTAPI RtlVerifyVersionInfo(const uint8_t *info, uint32_t typemask, uint64_t condmask)
{
    const uint32_t size = *(const uint32_t *)info, major = *(const uint32_t *)(info + 4), minor = *(const uint32_t *)(info + 8),
                   build = *(const uint32_t *)(info + 0xc), plat = *(const uint32_t *)(info + 0x10);
    const uint16_t spmajor = size >= 0x11c ? *(const uint16_t *)(info + 0x114) : 0, spminor = size >= 0x11c ? *(const uint16_t *)(info + 0x116) : 0,
                   suite = size >= 0x11c ? *(const uint16_t *)(info + 0x118) : 0;
    const uint8_t product = size >= 0x11c ? info[0x11a] : 0;
    unsigned c;
    if (size != 0x11c && size != 0x114) return STATUS_INVALID_PARAMETER;
    if (typemask & (VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR | VER_SUITENAME | VER_PRODUCT_TYPE) && size < 0x11c) return STATUS_INVALID_PARAMETER;
    if (typemask & VER_PRODUCT_TYPE) { c = (condmask >> cond_bits(VER_PRODUCT_TYPE)) & 7; if (!cmp_cond(1 /* VER_NT_WORKSTATION */, product, c)) return STATUS_REVISION_MISMATCH; }
    if (typemask & VER_SUITENAME) {
        c = (condmask >> cond_bits(VER_SUITENAME)) & 7;
        if (c == VER_AND) { if ((suite & 0x100) != suite) return STATUS_REVISION_MISMATCH; }                 /* VER_SUITE_SINGLEUSERTS */
        else if (c == VER_OR) { if (!(suite & 0x100)) return STATUS_REVISION_MISMATCH; }
        else return STATUS_INVALID_PARAMETER;
    }
    if (typemask & VER_PLATFORMID) { c = (condmask >> cond_bits(VER_PLATFORMID)) & 7; if (!cmp_cond(2, plat, c)) return STATUS_REVISION_MISMATCH; }
    if (typemask & (VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER | VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR)) {
        /* Windows' rule: the version fields are compared lexicographically, with the condition of the most significant
         * field requested applying to the comparison as a whole (VER_MAJORVERSION's condition governs). */
        unsigned cond = 0; int decided = 0;
        const struct { uint32_t type; uint64_t have, want; } f[5] = {
            { VER_MAJORVERSION, 10, major }, { VER_MINORVERSION, 0, minor }, { VER_SERVICEPACKMAJOR, 0, spmajor },
            { VER_SERVICEPACKMINOR, 0, spminor }, { VER_BUILDNUMBER, 22631, build } };
        unsigned i;
        for (i = 0; i < 5 && !decided; ++i) {
            if (!(typemask & f[i].type)) continue;
            if (!cond) cond = (condmask >> cond_bits(f[i].type)) & 7;
            if (!cond) return STATUS_INVALID_PARAMETER;
            if (f[i].have != f[i].want) {
                if (!cmp_cond(f[i].have, f[i].want, cond)) return STATUS_REVISION_MISMATCH;
                decided = 1;
            }
        }
        if (!decided && (cond == VER_GREATER || cond == VER_LESS)) return STATUS_REVISION_MISMATCH;
    }
    return STATUS_SUCCESS;
}

/* ================================================================ image directory / message table / stack */
/* A mapped PE32+ image (a loaded .sys, or ntoskrnl-relative addresses in a driver's own image). */
void *NTAPI RtlImageNtHeader(void *base)
{
    const uint8_t *b = base; uint32_t e_lfanew;
    if (!b || *(const uint16_t *)b != 0x5a4d) return 0;
    e_lfanew = *(const uint32_t *)(b + 0x3c);
    if (e_lfanew > 0x1000 || *(const uint32_t *)(b + e_lfanew) != 0x4550) return 0;
    return (void *)(b + e_lfanew);
}
void *NTAPI RtlImageDirectoryEntryToData(void *base, uint8_t mapped_as_image, uint16_t dir, uint32_t *size)
{
    uint8_t *nt = RtlImageNtHeader(base);
    uint32_t rva, sz;
    const uint16_t magic = nt ? *(uint16_t *)(nt + 0x18) : 0;
    if (!nt || magic != 0x20b || dir >= *(uint32_t *)(nt + 0x18 + 0x6c)) return 0;   /* PE32+ NumberOfRvaAndSizes */
    rva = *(uint32_t *)(nt + 0x18 + 0x70 + dir * 8);
    sz = *(uint32_t *)(nt + 0x18 + 0x74 + dir * 8);
    if (!rva) return 0;
    if (size) *size = sz;
    if (mapped_as_image) return (uint8_t *)base + rva;
    {   /* file layout: translate the RVA through the section table */
        uint16_t nsec = *(uint16_t *)(nt + 6), i;
        uint8_t *sec = nt + 0x18 + *(uint16_t *)(nt + 0x14);
        for (i = 0; i < nsec; ++i, sec += 40) {
            uint32_t va = *(uint32_t *)(sec + 12), vs = *(uint32_t *)(sec + 8), raw = *(uint32_t *)(sec + 20);
            if (rva >= va && rva < va + vs) return (uint8_t *)base + raw + (rva - va);
        }
        return 0;
    }
}
/* RtlFindMessage: resource directory type RT_MESSAGETABLE(11) -> any name -> language -> MESSAGE_RESOURCE_DATA.
 * Returns a pointer to the MESSAGE_RESOURCE_ENTRY {USHORT Length, Flags; UCHAR Text[]} inside the image. */
#define STATUS_MESSAGE_NOT_FOUND ((int32_t)0xC0000109)
NTSTATUS NTAPI RtlFindMessage(void *base, uint32_t type, uint32_t lang, uint32_t id, void **entry)
{
    uint32_t sz;
    uint8_t *res = RtlImageDirectoryEntryToData(base, 1, 2, &sz), *dir, *data = 0;
    uint16_t named, ids, i;
    (void)lang;
    if (!res || type != 11) return STATUS_MESSAGE_NOT_FOUND;
    /* level 1: type */
    named = *(uint16_t *)(res + 12); ids = *(uint16_t *)(res + 14); dir = 0;
    for (i = 0; i < named + ids; ++i) {
        uint32_t name = *(uint32_t *)(res + 16 + i * 8), off = *(uint32_t *)(res + 20 + i * 8);
        if (!(name & 0x80000000u) && name == type && (off & 0x80000000u)) { dir = res + (off & 0x7fffffffu); break; }
    }
    if (!dir) return STATUS_MESSAGE_NOT_FOUND;
    /* level 2: first name, level 3: first language (message tables carry one) */
    named = *(uint16_t *)(dir + 12); ids = *(uint16_t *)(dir + 14);
    if (!named + ids) return STATUS_MESSAGE_NOT_FOUND;
    { uint32_t off = *(uint32_t *)(dir + 20); if (!(off & 0x80000000u)) return STATUS_MESSAGE_NOT_FOUND; dir = res + (off & 0x7fffffffu); }
    named = *(uint16_t *)(dir + 12); ids = *(uint16_t *)(dir + 14);
    if (!named + ids) return STATUS_MESSAGE_NOT_FOUND;
    { uint32_t off = *(uint32_t *)(dir + 20); if (off & 0x80000000u) return STATUS_MESSAGE_NOT_FOUND;
      data = (uint8_t *)base + *(uint32_t *)(res + off); }
    {   /* MESSAGE_RESOURCE_DATA: NumberOfBlocks, then {LowId, HighId, OffsetToEntries} */
        uint32_t nblocks = *(uint32_t *)data, b;
        for (b = 0; b < nblocks; ++b) {
            uint32_t lo = *(uint32_t *)(data + 4 + b * 12), hi = *(uint32_t *)(data + 8 + b * 12), off = *(uint32_t *)(data + 12 + b * 12);
            if (id >= lo && id <= hi) {
                uint8_t *e = data + off; uint32_t k;
                for (k = lo; k < id; ++k) e += *(uint16_t *)e;
                *entry = e;
                return STATUS_SUCCESS;
            }
        }
    }
    return STATUS_MESSAGE_NOT_FOUND;
}
/* Frame-pointer walk bounded to the current kernel stack (a frame outside it or not moving up ends the walk). */
uint16_t NTAPI RtlCaptureStackBackTrace(uint32_t skip, uint32_t count, void **frames, uint32_t *hash)
{
    thread_t *t = thread_current();
    uint64_t lo = t ? t->stack_base : 0, hi = lo + KSTACK_BYTES, rbp, seen = 0, h = 0;
    uint16_t n = 0;
    __asm__ volatile("mov %%rbp, %0" : "=r"(rbp));
    while (rbp >= lo && rbp + 16 <= hi && n < count && lo) {
        uint64_t ret = *(uint64_t *)(rbp + 8), next = *(uint64_t *)rbp;
        if (!ret) break;
        if (seen >= skip) { frames[n++] = (void *)ret; h += (uint32_t)ret; }
        ++seen;
        if (next <= rbp) break;
        rbp = next;
    }
    if (hash) *hash = (uint32_t)h;
    return n;
}
void NTAPI RtlGetCallersAddress(void **caller, void **callers_caller)
{
    void *f[3] = { 0, 0, 0 };
    uint16_t n = RtlCaptureStackBackTrace(1, 3, f, 0);
    *caller = n > 0 ? f[0] : 0;
    *callers_caller = n > 1 ? f[1] : 0;
}

/* ================================================================ range lists */
/* RTL_RANGE (public, 0x28): Start(8) End(8) UserData(8) Owner(8) Attributes(1) Flags(1). The list entry is the public
 * range followed by the list linkage, so the pointer handed back by the iterator is the entry itself. */
typedef struct { uint64_t Start, End; void *UserData, *Owner; uint8_t Attributes, Flags; uint8_t _pad[6]; } RTL_RANGE;
typedef struct { RTL_RANGE r; LIST_ENTRY link; } range_entry_t;
typedef struct { LIST_ENTRY ListHead; uint32_t Flags, Count, Stamp; uint32_t _pad; } RTL_RANGE_LIST;
typedef struct { void *RangeListHead, *MergedHead, *Current; uint32_t Stamp; uint32_t _pad; } RTL_RANGE_LIST_ITERATOR;
#define RTL_RANGE_SHARED 1
#define RTL_RANGE_CONFLICT 2
#define RTL_RANGE_LIST_ADD_IF_CONFLICT 1
#define RTL_RANGE_LIST_ADD_SHARED 2
#define RTL_RANGE_LIST_SHARED_OK 1
#define RTL_RANGE_LIST_NULL_CONFLICT_OK 2
#define STATUS_RANGE_LIST_CONFLICT ((int32_t)0xC0000282)
#define STATUS_RANGE_NOT_FOUND ((int32_t)0xC000028C)
#define STATUS_MORE_ENTRIES_ ((int32_t)0x00000105)

void NTAPI RtlInitializeRangeList(RTL_RANGE_LIST *l) { l->ListHead.Flink = l->ListHead.Blink = &l->ListHead; l->Flags = 0; l->Count = 0; l->Stamp = 0; }
void NTAPI RtlFreeRangeList(RTL_RANGE_LIST *l)
{
    while (l->ListHead.Flink != &l->ListHead) {
        LIST_ENTRY *e = l->ListHead.Flink;
        l->ListHead.Flink = e->Flink; e->Flink->Blink = &l->ListHead;
        kfree((uint8_t *)e - __builtin_offsetof(range_entry_t, link));
    }
    l->Count = 0; l->Stamp++;
}
static int ranges_overlap(uint64_t s1, uint64_t e1, uint64_t s2, uint64_t e2) { return s1 <= e2 && s2 <= e1; }
NTSTATUS NTAPI RtlAddRange(RTL_RANGE_LIST *l, uint64_t start, uint64_t end, uint8_t attrs, uint32_t flags, void *userdata, void *owner)
{
    LIST_ENTRY *e;
    range_entry_t *n;
    int conflict = 0;
    if (start > end) return STATUS_INVALID_PARAMETER;
    for (e = l->ListHead.Flink; e != &l->ListHead; e = e->Flink) {
        range_entry_t *x = (range_entry_t *)((uint8_t *)e - __builtin_offsetof(range_entry_t, link));
        if (ranges_overlap(x->r.Start, x->r.End, start, end)) {
            if ((flags & RTL_RANGE_LIST_ADD_SHARED) && (x->r.Flags & RTL_RANGE_SHARED)) continue;
            if (!(flags & RTL_RANGE_LIST_ADD_IF_CONFLICT)) return STATUS_RANGE_LIST_CONFLICT;
            conflict = 1;
        }
    }
    n = kzalloc(sizeof *n);
    if (!n) return STATUS_INSUFFICIENT_RESOURCES;
    n->r.Start = start; n->r.End = end; n->r.UserData = userdata; n->r.Owner = owner; n->r.Attributes = attrs;
    n->r.Flags = (uint8_t)(((flags & RTL_RANGE_LIST_ADD_SHARED) ? RTL_RANGE_SHARED : 0) | (conflict ? RTL_RANGE_CONFLICT : 0));
    for (e = l->ListHead.Flink; e != &l->ListHead; e = e->Flink) {           /* keep the list sorted by Start */
        range_entry_t *x = (range_entry_t *)((uint8_t *)e - __builtin_offsetof(range_entry_t, link));
        if (x->r.Start > start) break;
    }
    n->link.Flink = e; n->link.Blink = e->Blink; e->Blink->Flink = &n->link; e->Blink = &n->link;
    l->Count++; l->Stamp++;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlDeleteRange(RTL_RANGE_LIST *l, uint64_t start, uint64_t end, void *owner)
{
    LIST_ENTRY *e;
    for (e = l->ListHead.Flink; e != &l->ListHead; e = e->Flink) {
        range_entry_t *x = (range_entry_t *)((uint8_t *)e - __builtin_offsetof(range_entry_t, link));
        if (x->r.Start == start && x->r.End == end && x->r.Owner == owner) {
            e->Blink->Flink = e->Flink; e->Flink->Blink = e->Blink;
            kfree(x); l->Count--; l->Stamp++;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_RANGE_NOT_FOUND;
}
NTSTATUS NTAPI RtlDeleteOwnersRanges(RTL_RANGE_LIST *l, void *owner)
{
    LIST_ENTRY *e = l->ListHead.Flink;
    while (e != &l->ListHead) {
        range_entry_t *x = (range_entry_t *)((uint8_t *)e - __builtin_offsetof(range_entry_t, link));
        LIST_ENTRY *next = e->Flink;
        if (x->r.Owner == owner) { e->Blink->Flink = e->Flink; e->Flink->Blink = e->Blink; kfree(x); l->Count--; l->Stamp++; }
        e = next;
    }
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlCopyRangeList(RTL_RANGE_LIST *dst, const RTL_RANGE_LIST *src)
{
    const LIST_ENTRY *e;
    if (dst->Count) return STATUS_INVALID_PARAMETER;
    for (e = src->ListHead.Flink; e != &src->ListHead; e = e->Flink) {
        const range_entry_t *x = (const range_entry_t *)((const uint8_t *)e - __builtin_offsetof(range_entry_t, link));
        range_entry_t *n = kzalloc(sizeof *n);
        if (!n) { RtlFreeRangeList(dst); return STATUS_INSUFFICIENT_RESOURCES; }
        n->r = x->r;
        n->link.Flink = &dst->ListHead; n->link.Blink = dst->ListHead.Blink; dst->ListHead.Blink->Flink = &n->link; dst->ListHead.Blink = &n->link;
        dst->Count++;
    }
    dst->Flags = src->Flags; dst->Stamp++;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlGetFirstRange(RTL_RANGE_LIST *l, RTL_RANGE_LIST_ITERATOR *it, RTL_RANGE **range)
{
    it->RangeListHead = &l->ListHead; it->MergedHead = 0; it->Stamp = l->Stamp;
    if (l->ListHead.Flink == &l->ListHead) { it->Current = 0; *range = 0; return STATUS_NO_MORE_ENTRIES; }
    it->Current = (uint8_t *)l->ListHead.Flink - __builtin_offsetof(range_entry_t, link);
    *range = it->Current;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlGetNextRange(RTL_RANGE_LIST_ITERATOR *it, RTL_RANGE **range, uint8_t forward)
{
    RTL_RANGE_LIST *l = (RTL_RANGE_LIST *)it->RangeListHead;
    range_entry_t *cur = it->Current;
    LIST_ENTRY *next;
    if (it->Stamp != l->Stamp) return STATUS_INVALID_PARAMETER;               /* list changed under the iterator */
    if (!cur) { *range = 0; return STATUS_NO_MORE_ENTRIES; }
    next = forward ? cur->link.Flink : cur->link.Blink;
    if (next == &l->ListHead) { it->Current = 0; *range = 0; return STATUS_NO_MORE_ENTRIES; }
    it->Current = (uint8_t *)next - __builtin_offsetof(range_entry_t, link);
    *range = it->Current;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlIsRangeAvailable(RTL_RANGE_LIST *l, uint64_t start, uint64_t end, uint32_t flags, uint8_t attrs_avail, void *ctx,
                                   uint8_t (NTAPI *cb)(void *, RTL_RANGE *), uint8_t *available)
{
    LIST_ENTRY *e;
    *available = 1;
    for (e = l->ListHead.Flink; e != &l->ListHead; e = e->Flink) {
        range_entry_t *x = (range_entry_t *)((uint8_t *)e - __builtin_offsetof(range_entry_t, link));
        if (!ranges_overlap(x->r.Start, x->r.End, start, end)) continue;
        if ((flags & RTL_RANGE_LIST_SHARED_OK) && (x->r.Flags & RTL_RANGE_SHARED)) continue;
        if ((flags & RTL_RANGE_LIST_NULL_CONFLICT_OK) && !x->r.Owner) continue;
        if ((x->r.Attributes & attrs_avail) == x->r.Attributes && x->r.Attributes) continue;
        if (cb && cb(ctx, &x->r)) continue;
        *available = 0;
        return STATUS_SUCCESS;
    }
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlFindRange(RTL_RANGE_LIST *l, uint64_t minimum, uint64_t maximum, uint32_t length, uint32_t alignment, uint32_t flags,
                            uint8_t attrs_avail, void *ctx, uint8_t (NTAPI *cb)(void *, RTL_RANGE *), uint64_t *start)
{
    uint64_t cand;
    if (!length || !alignment || minimum > maximum || maximum - minimum + 1 < length) return STATUS_INVALID_PARAMETER;
    /* search from the top, as Windows does */
    cand = (maximum - length + 1) / alignment * alignment;
    while (cand >= minimum) {
        uint8_t avail;
        RtlIsRangeAvailable(l, cand, cand + length - 1, flags, attrs_avail, ctx, cb, &avail);
        if (avail) { *start = cand; return STATUS_SUCCESS; }
        if (cand < alignment) break;
        cand -= alignment;
    }
    return STATUS_UNSUCCESSFUL;
}
NTSTATUS NTAPI RtlInvertRangeList(RTL_RANGE_LIST *inv, RTL_RANGE_LIST *l)
{
    LIST_ENTRY *e; uint64_t next = 0; NTSTATUS st;
    for (e = l->ListHead.Flink; e != &l->ListHead; e = e->Flink) {
        range_entry_t *x = (range_entry_t *)((uint8_t *)e - __builtin_offsetof(range_entry_t, link));
        if (x->r.Start > next) { st = RtlAddRange(inv, next, x->r.Start - 1, 0, 0, 0, 0); if (st) return st; }
        if (x->r.End + 1 > next) next = x->r.End + 1;
        if (x->r.End == ~0ull) return STATUS_SUCCESS;
    }
    return RtlAddRange(inv, next, ~0ull, 0, 0, 0, 0);
}
NTSTATUS NTAPI RtlMergeRangeLists(RTL_RANGE_LIST *merged, RTL_RANGE_LIST *a, RTL_RANGE_LIST *b, uint32_t flags)
{
    LIST_ENTRY *e; NTSTATUS st = RtlCopyRangeList(merged, a);
    if (st) return st;
    for (e = b->ListHead.Flink; e != &b->ListHead; e = e->Flink) {
        range_entry_t *x = (range_entry_t *)((uint8_t *)e - __builtin_offsetof(range_entry_t, link));
        st = RtlAddRange(merged, x->r.Start, x->r.End, x->r.Attributes, flags | ((x->r.Flags & RTL_RANGE_SHARED) ? RTL_RANGE_LIST_ADD_SHARED : 0), x->r.UserData, x->r.Owner);
        if (st) { RtlFreeRangeList(merged); return st; }
    }
    return STATUS_SUCCESS;
}

/* ================================================================ Cm / Io resource descriptor encoding */
/* CM_PARTIAL_RESOURCE_DESCRIPTOR (0x14): Type(0) ShareDisposition(1) Flags(2) u.Memory{Start(4) Length(0xc)}.
 * IO_RESOURCE_DESCRIPTOR (0x20): Option(0) Type(1) ShareDisposition(2) Spare1(3) Flags(4) Spare2(6)
 * u.Memory{Length(8) Alignment(0xc) MinimumAddress(0x10) MaximumAddress(0x18)}.
 * Large memory: CmResourceTypeMemoryLarge (7) with flags _40 (0x200: length<<8), _48 (0x400: <<16), _64 (0x800: <<32). */
#define CmResourceTypeMemory 3
#define CmResourceTypeMemoryLarge 7
#define CM_RESOURCE_MEMORY_LARGE_40 0x200
#define CM_RESOURCE_MEMORY_LARGE_48 0x400
#define CM_RESOURCE_MEMORY_LARGE_64 0x800
static inline uint32_t rd32(const void *p, unsigned off) { uint32_t v; memcpy(&v, (const uint8_t *)p + off, 4); return v; }
static inline uint64_t rd64(const void *p, unsigned off) { uint64_t v; memcpy(&v, (const uint8_t *)p + off, 8); return v; }
static inline void wr32(void *p, unsigned off, uint32_t v) { memcpy((uint8_t *)p + off, &v, 4); }
static inline void wr64(void *p, unsigned off, uint64_t v) { memcpy((uint8_t *)p + off, &v, 8); }
static uint64_t large_scale(uint16_t flags) { return flags & CM_RESOURCE_MEMORY_LARGE_40 ? 8 : flags & CM_RESOURCE_MEMORY_LARGE_48 ? 16 : flags & CM_RESOURCE_MEMORY_LARGE_64 ? 32 : 0; }
uint64_t NTAPI RtlCmDecodeMemIoResource(const uint8_t *d, uint64_t *start)
{
    uint64_t len = rd32(d, 0xc);
    if (start) *start = rd64(d, 4);
    if (d[0] == CmResourceTypeMemoryLarge) len <<= large_scale(*(const uint16_t *)(d + 2));
    return len;
}
NTSTATUS NTAPI RtlCmEncodeMemIoResource(uint8_t *d, uint8_t type, uint64_t length, uint64_t start)
{
    uint16_t flags = (uint16_t)(*(uint16_t *)(d + 2) & ~(CM_RESOURCE_MEMORY_LARGE_40 | CM_RESOURCE_MEMORY_LARGE_48 | CM_RESOURCE_MEMORY_LARGE_64));
    if (type != CmResourceTypeMemory && type != CmResourceTypeMemoryLarge) return STATUS_INVALID_PARAMETER;
    if (length <= 0xffffffffull) { d[0] = type == CmResourceTypeMemoryLarge ? CmResourceTypeMemory : type; }
    else if (!(length & 0xff) && length <= (0xffffffffull << 8)) { d[0] = CmResourceTypeMemoryLarge; flags |= CM_RESOURCE_MEMORY_LARGE_40; length >>= 8; }
    else if (!(length & 0xffff) && length <= (0xffffffffull << 16)) { d[0] = CmResourceTypeMemoryLarge; flags |= CM_RESOURCE_MEMORY_LARGE_48; length >>= 16; }
    else if (!(length & 0xffffffffull)) { d[0] = CmResourceTypeMemoryLarge; flags |= CM_RESOURCE_MEMORY_LARGE_64; length >>= 32; }
    else return STATUS_INVALID_PARAMETER;
    *(uint16_t *)(d + 2) = flags;
    wr64(d, 4, start); wr32(d, 0xc, (uint32_t)length);
    return STATUS_SUCCESS;
}
uint64_t NTAPI RtlIoDecodeMemIoResource(const uint8_t *d, uint64_t *alignment, uint64_t *minimum, uint64_t *maximum)
{
    uint64_t len = rd32(d, 8), sh = d[1] == CmResourceTypeMemoryLarge ? large_scale(*(const uint16_t *)(d + 4)) : 0;
    if (alignment) *alignment = (uint64_t)rd32(d, 0xc) << sh;
    if (minimum) *minimum = rd64(d, 0x10);
    if (maximum) *maximum = rd64(d, 0x18);
    return len << sh;
}
NTSTATUS NTAPI RtlIoEncodeMemIoResource(uint8_t *d, uint8_t type, uint64_t length, uint64_t alignment, uint64_t minimum, uint64_t maximum)
{
    uint16_t flags = (uint16_t)(*(uint16_t *)(d + 4) & ~(CM_RESOURCE_MEMORY_LARGE_40 | CM_RESOURCE_MEMORY_LARGE_48 | CM_RESOURCE_MEMORY_LARGE_64));
    unsigned sh = 0;
    if (type != CmResourceTypeMemory && type != CmResourceTypeMemoryLarge) return STATUS_INVALID_PARAMETER;
    if (length <= 0xffffffffull && alignment <= 0xffffffffull) d[1] = CmResourceTypeMemory;
    else if (!(length & 0xff) && !(alignment & 0xff) && (length >> 8) <= 0xffffffffull) { d[1] = CmResourceTypeMemoryLarge; flags |= CM_RESOURCE_MEMORY_LARGE_40; sh = 8; }
    else if (!(length & 0xffff) && !(alignment & 0xffff) && (length >> 16) <= 0xffffffffull) { d[1] = CmResourceTypeMemoryLarge; flags |= CM_RESOURCE_MEMORY_LARGE_48; sh = 16; }
    else if (!(length & 0xffffffffull) && !(alignment & 0xffffffffull)) { d[1] = CmResourceTypeMemoryLarge; flags |= CM_RESOURCE_MEMORY_LARGE_64; sh = 32; }
    else return STATUS_INVALID_PARAMETER;
    *(uint16_t *)(d + 4) = flags;
    wr32(d, 8, (uint32_t)(length >> sh)); wr32(d, 0xc, (uint32_t)(alignment >> sh)); wr64(d, 0x10, minimum); wr64(d, 0x18, maximum);
    return STATUS_SUCCESS;
}
