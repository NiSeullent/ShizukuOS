/* SPDX-License-Identifier: GPL-2.0-only
 * Wine port glue: the few user32 text services the ported DLLs call that the Shizuku user32.dll does not export
 * (string-table resources, wsprintf, CharNext/CharPrev). They are linked statically into each module that needs them,
 * written from the documented Win32 behaviour:
 *   LoadString: RT_STRING block (id >> 4) + 1 holds 16 counted UTF-16 strings; buffer size 0 returns a read-only
 *               pointer to the resource text; the result is truncated to buffer size - 1 and always terminated.
 *   wsprintf:   the Win32 format subset (no floating point) into at most 1024 characters including the terminator.
 */
#define _USER32_                  /* these definitions are local: no dllimport on the declarations */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winuser.h"
#include <corecrt_stdio_config.h>

static const WCHAR *find_string(HINSTANCE inst, UINT id, int *len)
{
    HRSRC r = FindResourceW(inst, MAKEINTRESOURCEW((LOWORD(id) >> 4) + 1), (LPWSTR)RT_STRING);
    const WCHAR *p;
    UINT i;
    if (!r || !(p = LockResource(LoadResource(inst, r)))) return NULL;
    for (i = 0; i < (id & 0x0f); ++i) p += *p + 1;
    *len = *p;
    return p + 1;
}

INT WINAPI LoadStringW(HINSTANCE inst, UINT id, LPWSTR buffer, INT size)
{
    int len;
    const WCHAR *s;
    if (!buffer) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    s = find_string(inst, id, &len);
    if (!size) {                                        /* read-only pointer into the resource */
        *(const WCHAR **)buffer = s;
        return s ? len : 0;
    }
    if (!s) { buffer[0] = 0; return 0; }
    if (len > size - 1) len = size - 1;
    memcpy(buffer, s, len * sizeof(WCHAR));
    buffer[len] = 0;
    return len;
}

INT WINAPI LoadStringA(HINSTANCE inst, UINT id, LPSTR buffer, INT size)
{
    int len, n;
    const WCHAR *s;
    if (!buffer || size <= 0) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    s = find_string(inst, id, &len);
    if (!s || !len) { buffer[0] = 0; return 0; }
    n = WideCharToMultiByte(CP_ACP, 0, s, len, buffer, size - 1, NULL, NULL);
    if (!n && len) n = size - 1;                        /* truncated: keep what fitted */
    buffer[n] = 0;
    return n;
}

#define WSPRINTF_MAX 1024
INT WINAPI wvsprintfW(LPWSTR buffer, LPCWSTR format, va_list args)
{
    int r = __stdio_common_vswprintf(_CRT_INTERNAL_PRINTF_LEGACY_WIDE_SPECIFIERS, buffer, WSPRINTF_MAX, format, NULL, args);
    if (r < 0) { buffer[WSPRINTF_MAX - 1] = 0; return WSPRINTF_MAX - 1; }
    return r;
}
INT WINAPI wvsprintfA(LPSTR buffer, LPCSTR format, va_list args)
{
    int r = __stdio_common_vsprintf(_CRT_INTERNAL_PRINTF_LEGACY_WIDE_SPECIFIERS, buffer, WSPRINTF_MAX, format, NULL, args);
    if (r < 0) { buffer[WSPRINTF_MAX - 1] = 0; return WSPRINTF_MAX - 1; }
    return r;
}
INT WINAPIV wsprintfW(LPWSTR buffer, LPCWSTR format, ...)
{
    va_list ap;
    int r;
    va_start(ap, format);
    r = wvsprintfW(buffer, format, ap);
    va_end(ap);
    return r;
}
INT WINAPIV wsprintfA(LPSTR buffer, LPCSTR format, ...)
{
    va_list ap;
    int r;
    va_start(ap, format);
    r = wvsprintfA(buffer, format, ap);
    va_end(ap);
    return r;
}

/* The system code page is UTF-8 on Shizuku: CharNextA steps over one complete UTF-8 sequence. */
LPSTR WINAPI CharNextA(LPCSTR p)
{
    unsigned char c = (unsigned char)*p;
    int n = 1;
    if (!c) return (LPSTR)p;
    if (c >= 0xc2 && c <= 0xdf) n = 2;
    else if (c >= 0xe0 && c <= 0xef) n = 3;
    else if (c >= 0xf0 && c <= 0xf4) n = 4;
    while (--n > 0 && (((unsigned char)p[1]) & 0xc0) == 0x80) ++p;
    return (LPSTR)(p + 1);
}
LPSTR WINAPI CharPrevA(LPCSTR start, LPCSTR p)
{
    if (p <= start) return (LPSTR)start;
    --p;
    while (p > start && (((unsigned char)*p) & 0xc0) == 0x80) --p;
    return (LPSTR)p;
}
LPWSTR WINAPI CharNextW(LPCWSTR p) { return (LPWSTR)(*p ? p + 1 : p); }
LPWSTR WINAPI CharPrevW(LPCWSTR start, LPCWSTR p) { return (LPWSTR)(p > start ? p - 1 : start); }

/* callers compiled against winuser.h (dllimport declarations) reference the import slots */
void *__imp_LoadStringW = (void *)LoadStringW;
void *__imp_LoadStringA = (void *)LoadStringA;
void *__imp_wvsprintfW = (void *)wvsprintfW;
void *__imp_wvsprintfA = (void *)wvsprintfA;
void *__imp_wsprintfW = (void *)wsprintfW;
void *__imp_wsprintfA = (void *)wsprintfA;
void *__imp_CharNextA = (void *)CharNextA;
void *__imp_CharPrevA = (void *)CharPrevA;
void *__imp_CharNextW = (void *)CharNextW;
void *__imp_CharPrevW = (void *)CharPrevW;
