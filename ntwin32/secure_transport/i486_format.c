/* SPDX-License-Identifier: GPL-2.0-only
 * Adapt original OEM _vsnprintf to bounded C99 count/truncation semantics.
 * A private growing buffer measures the complete result; caller output is
 * committed only after a successful, terminated result. This relies on the
 * native legacy integer/string formatter, not on precompiled MinGW code.
 */
#include "i486_format.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(NTWST_FORMAT_HOST_MODEL)
extern int ntwst_test_legacy_vsnprintf(char *, size_t, const char *, va_list);
#define LEGACY_FORMAT ntwst_test_legacy_vsnprintf
#elif defined(_WIN32)
#define LEGACY_FORMAT _vsnprintf
#else
#define LEGACY_FORMAT vsnprintf
#endif

#define FORMAT_LIMIT 4096u
#define VALUE_LIMIT (1024u * 1024u)
enum length { NORMAL, SHORT, LONG, LONG_LONG, SIZE, DIFF, MAXINT };

static int bounded_size(const char *s, size_t limit, size_t *result)
{
    size_t i;
    if (!s) return -1;
    for (i = 0; i <= limit; ++i)
        if (!s[i]) { *result = i; return 0; }
    return -1;
}

static int prepare(char *result, const char *format, va_list arguments)
{
    size_t n, i = 0, at = 0;
    if (bounded_size(format, FORMAT_LIMIT, &n)) return -1;
    while (i < n) {
        size_t start, end, dummy;
        enum length length = NORMAL;
        char kind;
        int wide = 0;
        if (format[i] != '%') { result[at++] = format[i++]; continue; }
        start = i++;
        if (format[i] == '%') { result[at++] = '%'; result[at++] = '%'; ++i; continue; }
        while (format[i] && strchr("-+ #0", format[i])) ++i;
        if (format[i] == '*') {
            int width = va_arg(arguments, int);
            if (width < -4096 || width > 4096) return -1;
            ++i;
        } else {
            unsigned width = 0;
            while (format[i] >= '0' && format[i] <= '9') {
                width = width * 10 + (unsigned)(format[i++] - '0');
                if (width > FORMAT_LIMIT) return -1;
            }
        }
        if (format[i] == '.') {
            ++i;
            if (format[i] == '*') {
                int precision = va_arg(arguments, int);
                if (precision < -4096 || precision > 4096) return -1;
                ++i;
            } else {
                unsigned precision = 0;
                while (format[i] >= '0' && format[i] <= '9') {
                    precision = precision * 10 + (unsigned)(format[i++] - '0');
                    if (precision > FORMAT_LIMIT) return -1;
                }
            }
        }
        end = i;
        if (format[i] == 'h') { length = SHORT; ++i; if (format[i] == 'h') return -1; }
        else if (format[i] == 'l') { length = LONG; ++i; if (format[i] == 'l') { length = LONG_LONG; ++i; } }
        else if (format[i] == 'z') { length = SIZE; ++i; }
        else if (format[i] == 't') { length = DIFF; ++i; }
        else if (format[i] == 'j') { length = MAXINT; ++i; }
        else if (format[i] == 'I' && i + 2 < n && format[i+1] == '6' && format[i+2] == '4') {
            length = LONG_LONG; i += 3;
        }
        kind = format[i++];
        if (!kind || !strchr("diuoxXcsp", kind)) return -1;
        if (kind == 's') {
            if (length != NORMAL || bounded_size(va_arg(arguments, const char *), VALUE_LIMIT, &dummy)) return -1;
        } else if (kind == 'p') {
            if (length != NORMAL) return -1;
            (void)va_arg(arguments, void *);
        } else if (kind == 'c') {
            if (length != NORMAL) return -1;
            (void)va_arg(arguments, int);
        } else {
            int sign = kind == 'd' || kind == 'i';
            if (length == LONG_LONG) {
                if (sign) (void)va_arg(arguments, long long); else (void)va_arg(arguments, unsigned long long);
                wide = 1;
            } else if (length == MAXINT) {
                if (sign) (void)va_arg(arguments, intmax_t); else (void)va_arg(arguments, uintmax_t);
                wide = sizeof(intmax_t) > 4;
            } else if (length == SIZE) {
                if (sign) (void)va_arg(arguments, ptrdiff_t); else (void)va_arg(arguments, size_t);
                wide = sizeof(size_t) > 4;
            } else if (length == DIFF) {
                if (sign) (void)va_arg(arguments, ptrdiff_t); else (void)va_arg(arguments, uintptr_t);
                wide = sizeof(ptrdiff_t) > 4;
            } else if (length == LONG) {
                if (sign) (void)va_arg(arguments, long); else (void)va_arg(arguments, unsigned long);
            } else {
                if (sign || length == SHORT) (void)va_arg(arguments, int); else (void)va_arg(arguments, unsigned int);
            }
        }
        if (at + (end - start) + 4 >= FORMAT_LIMIT * 4) return -1;
        memcpy(result + at, format + start, end - start); at += end - start;
        if (wide) { memcpy(result + at, "I64", 3); at += 3; }
        else if (length == LONG) result[at++] = 'l';
        else if (length == SHORT) result[at++] = 'h';
        result[at++] = kind;
    }
    result[at] = 0;
    return 0;
}

int ntwst_i486_vsnprintf(char *out, size_t capacity, const char *format, va_list arguments)
{
    char normalized[FORMAT_LIMIT * 4], *temporary;
    size_t room = 128;
    va_list check;
    int size;
    if ((capacity && !out) || capacity > VALUE_LIMIT) return -1;
    va_copy(check, arguments);
    size = prepare(normalized, format, check);
    va_end(check);
    if (size) return -1;
    for (;;) {
        va_list copy;
        temporary = malloc(room);
        if (!temporary) return -1;
        memset(temporary, 0xa5, room);
        va_copy(copy, arguments);
        size = LEGACY_FORMAT(temporary, room, normalized, copy);
        va_end(copy);
        if (size >= 0 && (size_t)size < room && temporary[size] == 0) break;
        free(temporary);
        if (room == VALUE_LIMIT) return -1;
        room *= 2;
    }
    if (capacity) {
        size_t count = (size_t)size < capacity - 1 ? (size_t)size : capacity - 1;
        memcpy(out, temporary, count); out[count] = 0;
    }
    free(temporary);
    return size;
}

int ntwst_i486_snprintf(char *out, size_t capacity, const char *format, ...)
{
    int result;
    va_list arguments;
    va_start(arguments, format);
    result = ntwst_i486_vsnprintf(out, capacity, format, arguments);
    va_end(arguments);
    return result;
}
