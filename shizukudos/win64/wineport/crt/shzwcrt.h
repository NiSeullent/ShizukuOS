/* SPDX-License-Identifier: GPL-2.0-only
 * Internal header of the small C runtime linked into the Wine DLLs and Wine test programs built by wineport/build.py.
 *
 * Wine's PE DLLs are written against the Microsoft C runtime (they import ucrtbase/msvcrt). This runtime has no
 * msvcrt.dll, so the functions those DLLs use are provided here as a static library, written from the C standard and
 * the documented UCRT entry points (__stdio_common_*), on top of the Shizuku kernel32. It is compiled against Wine's
 * own msvcrt headers (include/msvcrt) so every prototype matches what the DLL sources see.
 *
 * Deliberate limits: only the "C" locale (bytes 0..255 map 1:1 to U+0000..U+00FF in narrow<->wide conversions made by
 * the CRT itself; the Win32 code-page functions are not used here), stdio is unbuffered, and every module that links
 * this library has its own copy (malloc/free all go to the process heap, so memory may still cross modules).
 */
#ifndef SHZWCRT_H
#define SHZWCRT_H
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* one common formatter behind every printf/sprintf/swprintf entry point (wcrt_printf.c) */
typedef struct shzw_sink {
    int wide;                       /* output units: 0 = char, 1 = wchar_t */
    char *a;                        /* buffer (narrow) */
    wchar_t *w;                     /* buffer (wide) */
    size_t cap;                     /* buffer capacity in units (SIZE_MAX = unbounded) */
    size_t pos;                     /* units stored so far */
    size_t total;                   /* units that would have been written */
    FILE *fp;                       /* or: file sink */
    int error;                      /* a file write failed */
} shzw_sink;

int shzw_format(shzw_sink *sink, const void *fmt, int fmt_wide, unsigned long long options, va_list *args);
int shzw_scan(const void *input, size_t len, int wide, const void *fmt, unsigned long long options, va_list *args);
int shzw_file_write(FILE *fp, const void *data, size_t bytes);       /* wcrt_stdio.c */
double shzw_strtod(const void *s, int wide, const void **end);      /* wcrt_scanf.c */
void shzw_set_errno(int e);
#endif
