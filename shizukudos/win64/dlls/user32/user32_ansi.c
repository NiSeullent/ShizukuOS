/* SPDX-License-Identifier: GPL-2.0-only
 * user32: the ANSI ("A") entry points that are thin conversions to the Unicode ones, and the character helpers.
 * The ANSI and OEM code pages of this system are both UTF-8 (kernel32 GetACP/GetOEMCP return 65001). Every window is
 * a Unicode window: CreateWindowExA converts its strings and creates the same window CreateWindowExW would. The
 * single-byte "OEM" buffer functions (CharToOemBuff, OemToCharBuff) keep their 1:1 length contract, so a character that
 * would need more than one UTF-8 byte becomes '?', like any unmappable character. */
#include "user32_int.h"

static WCHAR *a2w(LPCSTR s)
{
    int n;
    WCHAR *w;
    if (!s || IS_INTRESOURCE(s)) return 0;
    n = MultiByteToWideChar(CP_ACP, 0, s, -1, 0, 0);
    w = HeapAlloc(GetProcessHeap(), 0, (size_t)(n > 0 ? n : 1) * 2);
    if (!w) return 0;
    if (n <= 0 || !MultiByteToWideChar(CP_ACP, 0, s, -1, w, n)) w[0] = 0;
    return w;
}
static void wfree(WCHAR *w) { if (w) HeapFree(GetProcessHeap(), 0, w); }
static LPCWSTR name_or_atom(LPCSTR s, WCHAR *conv) { return IS_INTRESOURCE(s) ? (LPCWSTR)s : conv; }

DLLAPI HWND WINAPI CreateWindowExA(DWORD ex, LPCSTR cls, LPCSTR title, DWORD style, int x, int y, int w, int h, HWND parent, HMENU menu,
                                   HINSTANCE inst, LPVOID param)
{
    WCHAR *c = a2w(cls), *t = a2w(title);
    HWND r = CreateWindowExW(ex, name_or_atom(cls, c), title ? (t ? t : L"") : 0, style, x, y, w, h, parent, menu, inst, param);
    wfree(c);
    wfree(t);
    return r;
}

DLLAPI BOOL WINAPI UnregisterClassA(LPCSTR name, HINSTANCE inst)
{
    WCHAR *c = a2w(name);
    const BOOL r = UnregisterClassW(name_or_atom(name, c), inst);
    wfree(c);
    return r;
}

DLLAPI ATOM WINAPI RegisterClassExA(const WNDCLASSEXA *wc)
{
    WNDCLASSEXW w;
    WCHAR *n, *m;
    ATOM a;
    if (!wc || wc->cbSize != sizeof *wc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    memcpy(&w, wc, sizeof w);
    w.cbSize = sizeof w;
    n = a2w(wc->lpszClassName);
    m = a2w(wc->lpszMenuName);
    w.lpszClassName = name_or_atom(wc->lpszClassName, n);
    w.lpszMenuName = name_or_atom(wc->lpszMenuName, m);
    a = RegisterClassExW(&w);
    wfree(n);
    wfree(m);
    return a;
}

DLLAPI ATOM WINAPI RegisterClassA(const WNDCLASSA *wc)
{
    WNDCLASSEXA ex;
    if (!wc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    memset(&ex, 0, sizeof ex);
    ex.cbSize = sizeof ex;
    ex.style = wc->style; ex.lpfnWndProc = wc->lpfnWndProc; ex.cbClsExtra = wc->cbClsExtra; ex.cbWndExtra = wc->cbWndExtra;
    ex.hInstance = wc->hInstance; ex.hIcon = wc->hIcon; ex.hCursor = wc->hCursor; ex.hbrBackground = wc->hbrBackground;
    ex.lpszMenuName = wc->lpszMenuName; ex.lpszClassName = wc->lpszClassName;
    return RegisterClassExA(&ex);
}

DLLAPI HCURSOR WINAPI LoadCursorA(HINSTANCE inst, LPCSTR name) { WCHAR *n = a2w(name); HCURSOR r = LoadCursorW(inst, name_or_atom(name, n)); wfree(n); return r; }
DLLAPI HICON WINAPI LoadIconA(HINSTANCE inst, LPCSTR name) { WCHAR *n = a2w(name); HICON r = LoadIconW(inst, name_or_atom(name, n)); wfree(n); return r; }
DLLAPI HANDLE WINAPI LoadImageA(HINSTANCE inst, LPCSTR name, UINT type, int cx, int cy, UINT flags)
{
    WCHAR *n = a2w(name);
    HANDLE r = LoadImageW(inst, name_or_atom(name, n), type, cx, cy, flags);
    wfree(n);
    return r;
}
DLLAPI UINT WINAPI RegisterWindowMessageA(LPCSTR name) { WCHAR *n = a2w(name); UINT r = n ? RegisterWindowMessageW(n) : 0; wfree(n); if (!name) SetLastError(ERROR_INVALID_PARAMETER); return r; }
DLLAPI HWND WINAPI FindWindowA(LPCSTR cls, LPCSTR title)
{
    WCHAR *c = a2w(cls), *t = a2w(title);
    HWND r = FindWindowW(cls ? name_or_atom(cls, c) : 0, t);
    wfree(c);
    wfree(t);
    return r;
}
DLLAPI BOOL WINAPI SetWindowTextA(HWND hwnd, LPCSTR text) { WCHAR *t = a2w(text); const BOOL r = SetWindowTextW(hwnd, t ? t : L""); wfree(t); return r; }
DLLAPI int WINAPI GetWindowTextA(HWND hwnd, LPSTR buf, int cap)
{
    WCHAR w[1024];
    int n;
    if (!buf || cap <= 0) return 0;
    n = GetWindowTextW(hwnd, w, 1024);
    n = n > 0 ? WideCharToMultiByte(CP_ACP, 0, w, n, buf, cap - 1, 0, 0) : 0;
    buf[n] = 0;
    return n;
}
DLLAPI int WINAPI GetClassNameA(HWND hwnd, LPSTR buf, int cap)
{
    WCHAR w[256];
    int n;
    if (!buf || cap <= 0) return 0;
    n = GetClassNameW(hwnd, w, 256);
    n = n > 0 ? WideCharToMultiByte(CP_ACP, 0, w, n, buf, cap - 1, 0, 0) : 0;
    buf[n] = 0;
    return n;
}

/* ---------------------------------------------------------------- characters */
static WCHAR wup(WCHAR c) { CharUpperBuffW(&c, 1); return c; }
static WCHAR wlow(WCHAR c) { CharLowerBuffW(&c, 1); return c; }

DLLAPI BOOL WINAPI IsCharUpperW(WCHAR c) { return wlow(c) != c; }
DLLAPI BOOL WINAPI IsCharLowerW(WCHAR c) { return wup(c) != c; }
DLLAPI BOOL WINAPI IsCharAlphaW(WCHAR c) { return wup(c) != wlow(c) || c == 0xaa || c == 0xba || c == 0xdf; }   /* cased letters, ª º ß */
DLLAPI BOOL WINAPI IsCharAlphaNumericW(WCHAR c) { return IsCharAlphaW(c) || (c >= '0' && c <= '9'); }
DLLAPI BOOL WINAPI IsCharUpperA(CHAR c) { return c >= 'A' && c <= 'Z'; }
DLLAPI BOOL WINAPI IsCharLowerA(CHAR c) { return c >= 'a' && c <= 'z'; }
DLLAPI BOOL WINAPI IsCharAlphaA(CHAR c) { return (c | 0x20) >= 'a' && (c | 0x20) <= 'z'; }
DLLAPI BOOL WINAPI IsCharAlphaNumericA(CHAR c) { return IsCharAlphaA(c) || (c >= '0' && c <= '9'); }

/* UTF-8 is the ANSI code page: a character is a lead byte plus its continuation bytes */
static int u8len(unsigned char c) { return c < 0x80 ? 1 : (c & 0xe0) == 0xc0 ? 2 : (c & 0xf0) == 0xe0 ? 3 : (c & 0xf8) == 0xf0 ? 4 : 1; }

DLLAPI LPSTR WINAPI CharUpperA(LPSTR s)
{
    LPSTR p;
    if (IS_INTRESOURCE(s)) { const char c = (char)(uintptr_t)s; return (LPSTR)(uintptr_t)(unsigned char)(c >= 'a' && c <= 'z' ? c - 32 : c); }
    for (p = s; *p; ++p) if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 32);   /* ASCII: other letters need more bytes */
    return s;
}
DLLAPI LPSTR WINAPI CharLowerA(LPSTR s)
{
    LPSTR p;
    if (IS_INTRESOURCE(s)) { const char c = (char)(uintptr_t)s; return (LPSTR)(uintptr_t)(unsigned char)(c >= 'A' && c <= 'Z' ? c + 32 : c); }
    for (p = s; *p; ++p) if (*p >= 'A' && *p <= 'Z') *p = (char)(*p + 32);
    return s;
}
DLLAPI DWORD WINAPI CharUpperBuffA(LPSTR s, DWORD n) { DWORD i; if (!s) return 0; for (i = 0; i < n; ++i) if (s[i] >= 'a' && s[i] <= 'z') s[i] = (char)(s[i] - 32); return n; }
DLLAPI DWORD WINAPI CharLowerBuffA(LPSTR s, DWORD n) { DWORD i; if (!s) return 0; for (i = 0; i < n; ++i) if (s[i] >= 'A' && s[i] <= 'Z') s[i] = (char)(s[i] + 32); return n; }

/* surrogate pairs count as one character */
DLLAPI LPWSTR WINAPI CharNextW(LPCWSTR s)
{
    if (!*s) return (LPWSTR)s;
    if (s[0] >= 0xd800 && s[0] < 0xdc00 && s[1] >= 0xdc00 && s[1] < 0xe000) return (LPWSTR)(s + 2);
    return (LPWSTR)(s + 1);
}
DLLAPI LPWSTR WINAPI CharPrevW(LPCWSTR start, LPCWSTR s)
{
    if (s <= start) return (LPWSTR)start;
    if (s - start >= 2 && s[-1] >= 0xdc00 && s[-1] < 0xe000 && s[-2] >= 0xd800 && s[-2] < 0xdc00) return (LPWSTR)(s - 2);
    return (LPWSTR)(s - 1);
}
DLLAPI LPSTR WINAPI CharNextA(LPCSTR s)
{
    int n, i;
    if (!*s) return (LPSTR)s;
    n = u8len((unsigned char)*s);
    for (i = 1; i < n && s[i]; ++i) { }
    return (LPSTR)(s + i);
}
DLLAPI LPSTR WINAPI CharPrevA(LPCSTR start, LPCSTR s)
{
    if (s <= start) return (LPSTR)start;
    --s;
    while (s > start && ((unsigned char)*s & 0xc0) == 0x80) --s;
    return (LPSTR)s;
}

/* ---- OEM conversions (the OEM code page is UTF-8, see above) ---- */
DLLAPI BOOL WINAPI CharToOemBuffW(LPCWSTR src, LPSTR dst, DWORD n)
{
    DWORD i;
    if (!src || !dst) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < n; ++i) dst[i] = src[i] < 0x80 ? (char)src[i] : '?';
    return TRUE;
}
DLLAPI BOOL WINAPI CharToOemW(LPCWSTR src, LPSTR dst)
{
    int n;
    if (!src || !dst) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    n = WideCharToMultiByte(CP_OEMCP, 0, src, -1, dst, 0x7fffffff, 0, 0);
    return n > 0;
}
DLLAPI BOOL WINAPI CharToOemA(LPCSTR src, LPSTR dst) { if (!src || !dst) return FALSE; if (src != dst) { while ((*dst++ = *src++)) { } } return TRUE; }
DLLAPI BOOL WINAPI CharToOemBuffA(LPCSTR src, LPSTR dst, DWORD n) { if (!src || !dst) return FALSE; if (src != dst) memmove(dst, src, n); return TRUE; }
DLLAPI BOOL WINAPI OemToCharA(LPCSTR src, LPSTR dst) { return CharToOemA(src, dst); }       /* the same code page */
DLLAPI BOOL WINAPI OemToCharBuffA(LPCSTR src, LPSTR dst, DWORD n) { return CharToOemBuffA(src, dst, n); }
DLLAPI BOOL WINAPI OemToCharW(LPCSTR src, LPWSTR dst)
{
    if (!src || !dst) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return MultiByteToWideChar(CP_OEMCP, 0, src, -1, dst, 0x7fffffff) > 0;
}
DLLAPI BOOL WINAPI OemToCharBuffW(LPCSTR src, LPWSTR dst, DWORD n)
{
    DWORD i;
    if (!src || !dst) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < n; ++i) dst[i] = (unsigned char)src[i] < 0x80 ? (WCHAR)(unsigned char)src[i] : '?';
    return TRUE;
}
