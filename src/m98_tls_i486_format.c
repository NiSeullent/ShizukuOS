/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_tls_i486_format.h"
#include <stdint.h>
#include <limits.h>

#define FORMAT_LIMIT 4096u
#define RESULT_LIMIT 1048576u
enum length { NORMAL, HH, H, L, LL, J, Z, T, IPTR, I32, I64 };
struct sink { char *out; size_t size, count; };

static int put(struct sink *s, unsigned char c)
{
    if (s->count >= RESULT_LIMIT) return 0;
    if (s->out && s->count < s->size - 1) s->out[s->count] = (char)c;
    ++s->count;
    return 1;
}
static int repeat(struct sink *s, unsigned n, unsigned char c)
{
    while (n--) if (!put(s, c)) return 0;
    return 1;
}
static int decimal(const char **p, unsigned *out)
{
    unsigned n = 0;
    while (**p >= '0' && **p <= '9') {
        if (n > FORMAT_LIMIT / 10 || n * 10 + (unsigned)(**p - '0') > FORMAT_LIMIT) return 0;
        n = n * 10 + (unsigned)(*(*p)++ - '0');
    }
    *out = n;
    return 1;
}
static uintmax_t unsigned_arg(va_list *ap, enum length length)
{
    switch (length) {
    case HH: return (unsigned char)va_arg(*ap, unsigned int);
    case H: return (unsigned short)va_arg(*ap, unsigned int);
    case L: return va_arg(*ap, unsigned long);
    case LL: case I64: return va_arg(*ap, unsigned long long);
    case J: return va_arg(*ap, uintmax_t);
    case Z: return va_arg(*ap, size_t);
    case T: case IPTR: return va_arg(*ap, uintptr_t);
    case I32: return va_arg(*ap, uint32_t);
    default: return va_arg(*ap, unsigned int);
    }
}
static intmax_t signed_arg(va_list *ap, enum length length)
{
    switch (length) {
    case HH: return (signed char)va_arg(*ap, int);
    case H: return (short)va_arg(*ap, int);
    case L: return va_arg(*ap, long);
    case LL: case I64: return va_arg(*ap, long long);
    case J: return va_arg(*ap, intmax_t);
    case Z: case T: case IPTR: return va_arg(*ap, ptrdiff_t);
    case I32: return va_arg(*ap, int32_t);
    default: return va_arg(*ap, int);
    }
}
static int format(struct sink *sink, const char *p, va_list *ap)
{
    unsigned format_bytes = 0;
    while (*p) {
        const char *begin = p;
        unsigned width = 0, precision = 0, left = 0, plus = 0, space = 0, alternate = 0, zero = 0, specified = 0;
        enum length length = NORMAL;
        if (*p != '%') { if (!put(sink, (unsigned char)*p++)) return -1; }
        else {
            unsigned n, padding, prefix_n = 0, digits_n = 0;
            char code, prefix[3], digits[sizeof(uintmax_t) * CHAR_BIT];
            uintmax_t value;
            ++p;
            for (;;) {
                if (*p == '-') left = 1;
                else if (*p == '+') plus = 1;
                else if (*p == ' ') space = 1;
                else if (*p == '#') alternate = 1;
                else if (*p == '0') zero = 1;
                else break;
                ++p;
                if ((unsigned)(p - begin) > FORMAT_LIMIT) return -1;
            }
            if (*p == '*') {
                int v = va_arg(*ap, int); ++p;
                if (v < -(int)FORMAT_LIMIT || v > (int)FORMAT_LIMIT) return -1;
                if (v < 0) { left = 1; v = -v; }
                width = (unsigned)v;
            } else if (!decimal(&p, &width)) return -1;
            if (*p == '.') {
                ++p; specified = 1;
                if (*p == '*') {
                    int v = va_arg(*ap, int); ++p;
                    if (v > (int)FORMAT_LIMIT) return -1;
                    if (v < 0) specified = 0;
                    else precision = (unsigned)v;
                } else if (!decimal(&p, &precision)) return -1;
            }
            if (*p == 'h') { ++p; length = H; if (*p == 'h') { ++p; length = HH; } }
            else if (*p == 'l') { ++p; length = L; if (*p == 'l') { ++p; length = LL; } }
            else if (*p == 'j') { ++p; length = J; }
            else if (*p == 'z') { ++p; length = Z; }
            else if (*p == 't') { ++p; length = T; }
            else if (*p == 'I') {
                ++p; length = IPTR;
                if (p[0] == '3' && p[1] == '2') { p += 2; length = I32; }
                else if (p[0] == '6' && p[1] == '4') { p += 2; length = I64; }
            }
            code = *p;
            if (!code) return -1;
            ++p;
            if (code == '%') {
                if (p - begin != 2 || !put(sink, '%')) return -1;
            } else if (code == 's' || code == 'c') {
                const char *text;
                char character;
                if (length != NORMAL || plus || space || alternate || zero || (code == 'c' && specified)) return -1;
                if (code == 'c') { character = (char)va_arg(*ap, int); text = &character; n = 1; }
                else {
                    text = va_arg(*ap, const char *);
                    if (!text) return -1;
                    n = 0;
                    while (!specified || n < precision) {
                        if (!text[n]) break;
                        if (n == RESULT_LIMIT) return -1;
                        ++n;
                    }
                }
                padding = width > n ? width - n : 0;
                if (!left && !repeat(sink, padding, ' ')) return -1;
                for (unsigned i = 0; i < n; ++i) if (!put(sink, (unsigned char)text[i])) return -1;
                if (left && !repeat(sink, padding, ' ')) return -1;
            } else if (code == 'd' || code == 'i' || code == 'u' || code == 'o' || code == 'x' || code == 'X' || code == 'p') {
                unsigned base = code == 'o' ? 8 : (code == 'x' || code == 'X' || code == 'p' ? 16 : 10);
                const char *alphabet = code == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
                if (code == 'p') {
                    if (length != NORMAL || specified || plus || space || alternate) return -1;
                    value = (uintptr_t)va_arg(*ap, void *);
                    prefix[prefix_n++] = '0'; prefix[prefix_n++] = 'x';
                } else if (code == 'd' || code == 'i') {
                    intmax_t signed_value = signed_arg(ap, length);
                    if (signed_value < 0) { prefix[prefix_n++] = '-'; value = (uintmax_t)0 - (uintmax_t)signed_value; }
                    else { value = (uintmax_t)signed_value; if (plus || space) prefix[prefix_n++] = plus ? '+' : ' '; }
                } else value = unsigned_arg(ap, length);
                if (value || !specified || precision) {
                    do { digits[digits_n++] = alphabet[value % base]; value /= base; } while (value);
                }
                if (alternate && code == 'o' && (!digits_n || digits[digits_n - 1] != '0') && precision <= digits_n) precision = digits_n + 1;
                if (alternate && (code == 'x' || code == 'X') && digits_n && !(digits_n == 1 && digits[0] == '0')) {
                    prefix[prefix_n++] = '0'; prefix[prefix_n++] = code;
                }
                n = precision > digits_n ? precision - digits_n : 0;
                padding = width > prefix_n + n + digits_n ? width - prefix_n - n - digits_n : 0;
                if (!left && !(zero && !specified) && !repeat(sink, padding, ' ')) return -1;
                for (unsigned i = 0; i < prefix_n; ++i) if (!put(sink, (unsigned char)prefix[i])) return -1;
                if (!left && zero && !specified && !repeat(sink, padding, '0')) return -1;
                if (!repeat(sink, n, '0')) return -1;
                while (digits_n) if (!put(sink, (unsigned char)digits[--digits_n])) return -1;
                if (left && !repeat(sink, padding, ' ')) return -1;
            } else return -1;
        }
        if ((size_t)(p - begin) > FORMAT_LIMIT - format_bytes) return -1;
        format_bytes += (unsigned)(p - begin);
    }
    return (int)sink->count;
}
int m98_tls_i486_vsnprintf(char *out, size_t size, const char *text, va_list args)
{
    va_list copy;
    struct sink probe = {0, 0, 0}, destination = {out, size, 0};
    int count, written;
    size_t length = 0;
    if (!text || (!out && size)) return -1;
    while (text[length]) if (++length > FORMAT_LIMIT) return -1;
    va_copy(copy, args); count = format(&probe, text, &copy); va_end(copy);
    if (count < 0) return -1;
    if (!size) return count;
    va_copy(copy, args); written = format(&destination, text, &copy); va_end(copy);
    if (written != count) return -1;
    out[destination.count < size ? destination.count : size - 1] = 0;
    return count;
}
int m98_tls_i486_snprintf(char *out, size_t size, const char *text, ...)
{
    va_list args;
    int result;
    va_start(args, text); result = m98_tls_i486_vsnprintf(out, size, text, args); va_end(args);
    return result;
}
