/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: the few national-language and string functions the DLLs ported from Wine (wineport) call that the rest
 * of kernel32 does not export. Each one is a thin layer over kernel32's own NLS (k32_nls.c), so the locale model is
 * that one (en-US and the invariant locale; the ANSI code page is UTF-8):
 *   GetDateFormatA / GetTimeFormatA / LCMapStringA  convert through the W functions (CP_ACP);
 *   GetStringTypeA / GetStringTypeExA               one type per byte of the string, as documented for the A form;
 *   ConvertDefaultLocale, IsValidLocaleName, SetThreadUILanguage (only the current UI language can be selected);
 *   lstrcpyn / lstrcat (A and W).
 */
#include "k32_winecompat.h"

K32API LCID WINAPI ConvertDefaultLocale(LCID lcid)
{
    LANGID lang = LANGIDFROMLCID(lcid);
    switch (lcid) {
    case LOCALE_INVARIANT: return lcid;
    case LOCALE_SYSTEM_DEFAULT: return GetSystemDefaultLCID();
    case LOCALE_USER_DEFAULT: case LOCALE_NEUTRAL: return GetUserDefaultLCID();
    }
    if (PRIMARYLANGID(lang) == LANG_NEUTRAL) return GetUserDefaultLCID();
    if (SUBLANGID(lang) == SUBLANG_NEUTRAL)          /* "language only": the default sublanguage of that language */
        return MAKELCID(MAKELANGID(PRIMARYLANGID(lang), SUBLANG_DEFAULT), SORTIDFROMLCID(lcid));
    return lcid;
}

K32API BOOL WINAPI IsValidLocaleName(LPCWSTR name)
{
    DWORD err = GetLastError();
    BOOL ok = name && LocaleNameToLCID(name, 0) != 0;
    SetLastError(err);                               /* a pure predicate: it does not report through the last error */
    return ok;
}

K32API LANGID WINAPI SetThreadUILanguage(LANGID id)
{
    LANGID cur = GetThreadUILanguage();
    if (!id || id == cur) return cur;
    SetLastError(ERROR_INVALID_PARAMETER);           /* no other UI language is installed */
    return 0;
}

K32API LPWSTR WINAPI lstrcpynW(LPWSTR d, LPCWSTR s, int n)
{
    LPWSTR r = d;
    if (!d || !s || n <= 0) return n == 0 ? d : NULL;
    while (--n > 0 && *s) *d++ = *s++;
    *d = 0;
    return r;
}
K32API LPSTR WINAPI lstrcpynA(LPSTR d, LPCSTR s, int n)
{
    LPSTR r = d;
    if (!d || !s || n <= 0) return n == 0 ? d : NULL;
    while (--n > 0 && *s) *d++ = *s++;
    *d = 0;
    return r;
}
K32API LPWSTR WINAPI lstrcatW(LPWSTR d, LPCWSTR s) { if (!d || !s) return NULL; lstrcpyW(d + lstrlenW(d), s); return d; }
K32API LPSTR WINAPI lstrcatA(LPSTR d, LPCSTR s) { if (!d || !s) return NULL; lstrcpyA(d + lstrlenA(d), s); return d; }

K32API BOOL WINAPI GetStringTypeA(LCID lcid, DWORD type, LPCSTR s, int n, LPWORD out)
{
    WCHAR buf[256], *w = buf;
    int i;
    BOOL r;
    (void)lcid;
    if (!s || !out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (n < 0) n = lstrlenA(s) + 1;
    if (n > 256 && !(w = HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR)))) return FALSE;
    for (i = 0; i < n; ++i) w[i] = (unsigned char)s[i];                   /* one type per byte, as documented */
    r = GetStringTypeW(type, w, n, out);
    if (w != buf) HeapFree(GetProcessHeap(), 0, w);
    return r;
}
K32API BOOL WINAPI GetStringTypeExA(LCID lcid, DWORD type, LPCSTR s, int n, LPWORD out) { return GetStringTypeA(lcid, type, s, n, out); }

static WCHAR *a_to_w(LPCSTR s, int n, int *outn)
{
    int wn;
    WCHAR *w;
    if (n < 0) n = lstrlenA(s) + 1;
    wn = MultiByteToWideChar(CP_ACP, 0, s, n, NULL, 0);
    if (!(w = HeapAlloc(GetProcessHeap(), 0, (wn + 1) * sizeof(WCHAR)))) return NULL;
    MultiByteToWideChar(CP_ACP, 0, s, n, w, wn);
    *outn = wn;
    return w;
}

K32API int WINAPI LCMapStringA(LCID lcid, DWORD flags, LPCSTR src, int n, LPSTR dst, int cap)
{
    WCHAR *w, *o;
    int wn, r, on;
    if (!src) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!(w = a_to_w(src, n, &wn))) return 0;
    if (flags & LCMAP_SORTKEY) {                     /* a sort key is bytes in both forms */
        r = LCMapStringW(lcid, flags, w, wn, (LPWSTR)dst, cap);
        HeapFree(GetProcessHeap(), 0, w);
        return r;
    }
    on = LCMapStringW(lcid, flags, w, wn, NULL, 0);
    if (!on || !(o = HeapAlloc(GetProcessHeap(), 0, on * sizeof(WCHAR)))) { HeapFree(GetProcessHeap(), 0, w); return 0; }
    on = LCMapStringW(lcid, flags, w, wn, o, on);
    r = on ? WideCharToMultiByte(CP_ACP, 0, o, on, cap ? dst : NULL, cap, NULL, NULL) : 0;
    HeapFree(GetProcessHeap(), 0, o);
    HeapFree(GetProcessHeap(), 0, w);
    return r;
}

static int format_a(BOOL date, LCID lcid, DWORD flags, const SYSTEMTIME *st, LPCSTR fmt, LPSTR out, int cap)
{
    WCHAR wfmt[128], wout[256];
    int n;
    if (fmt && !MultiByteToWideChar(CP_ACP, 0, fmt, -1, wfmt, ARRAYSIZE(wfmt))) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    n = date ? GetDateFormatW(lcid, flags, st, fmt ? wfmt : NULL, wout, ARRAYSIZE(wout))
             : GetTimeFormatW(lcid, flags, st, fmt ? wfmt : NULL, wout, ARRAYSIZE(wout));
    if (!n) return 0;
    n = WideCharToMultiByte(CP_ACP, 0, wout, -1, cap ? out : NULL, cap, NULL, NULL);
    if (!n && cap) SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return n;
}
K32API int WINAPI GetDateFormatA(LCID lcid, DWORD flags, const SYSTEMTIME *st, LPCSTR fmt, LPSTR out, int cap)
{
    return format_a(TRUE, lcid, flags, st, fmt, out, cap);
}
K32API int WINAPI GetTimeFormatA(LCID lcid, DWORD flags, const SYSTEMTIME *st, LPCSTR fmt, LPSTR out, int cap)
{
    return format_a(FALSE, lcid, flags, st, fmt, out, cap);
}
