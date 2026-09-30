/* SPDX-License-Identifier: GPL-2.0-only
 * user32: the clipboard, over the kernel's single system-wide clipboard (kernel64/gfx_clip.c, NtUserClipboard).
 *
 * HGLOBAL formats are copied into the kernel when set (the system owns the handle afterwards, so it is freed) and copied
 * out into a fresh HGLOBAL when read; that copy stays valid until the clipboard is closed (and is freed then). CF_BITMAP
 * (an HBITMAP, meaningless in another process) is stored as CF_DIB bytes and rebuilt on request. The text formats are
 * synthesised from each other the way Windows does it: CF_UNICODETEXT <-> CF_TEXT (ANSI code page) <-> CF_OEMTEXT, with
 * CF_LOCALE reporting en-US; CF_DIB <-> CF_BITMAP likewise. Delayed rendering (SetClipboardData with a NULL handle) asks
 * the owner with WM_RENDERFORMAT when the data is wanted; owners in another process cannot be asked (SendMessage does not
 * cross processes here) and their delayed formats read as unavailable.
 */
#include "user32_int.h"

static int32_t clip(shz_clip_t *c)
{
    const int32_t st = NtUserClipboard(c);
    if (st < 0) u32_err(st);
    return st;
}

static int32_t clip_op(uint32_t op, uint32_t format, HWND hwnd, shz_clip_t *out)
{
    memset(out, 0, sizeof *out);
    out->op = op;
    out->format = format;
    out->hwnd = H2U(hwnd);
    return NtUserClipboard(out);
}

/* HGLOBAL access that works whether kernel32 hands out fixed pointers or movable handles */
typedef LPVOID (WINAPI *glock_t)(HGLOBAL);
typedef BOOL (WINAPI *gunlock_t)(HGLOBAL);
typedef SIZE_T (WINAPI *gsize_t)(HGLOBAL);
static glock_t p_lock;
static gunlock_t p_unlock;
static gsize_t p_size;
static int g_resolved;

static void resolve(void)
{
    HMODULE k;
    if (g_resolved) return;
    k = GetModuleHandleW(L"kernel32.dll");
    if (k) {
        p_lock = (glock_t)(void *)GetProcAddress(k, "GlobalLock");
        p_unlock = (gunlock_t)(void *)GetProcAddress(k, "GlobalUnlock");
        p_size = (gsize_t)(void *)GetProcAddress(k, "GlobalSize");
    }
    g_resolved = 1;
}
static void *glock(HGLOBAL h) { resolve(); return p_lock ? p_lock(h) : (void *)h; }
static void gunlock(HGLOBAL h) { resolve(); if (p_unlock) p_unlock(h); }
static SIZE_T gsize(HGLOBAL h) { resolve(); return p_size ? p_size(h) : HeapSize(GetProcessHeap(), 0, h); }

/* ---- the copies GetClipboardData handed out, freed at CloseClipboard ---- */
#define OUT_MAX 32
static struct { UINT fmt; HANDLE h; int gdi; } g_out[OUT_MAX];
static int g_nout;

static void out_free_all(void)
{
    int i;
    for (i = 0; i < g_nout; ++i) {
        if (g_out[i].gdi) DeleteObject((HGDIOBJ)g_out[i].h); else GlobalFree(g_out[i].h);
    }
    g_nout = 0;
}

static HANDLE out_find(UINT fmt)
{
    int i;
    for (i = 0; i < g_nout; ++i) if (g_out[i].fmt == fmt) return g_out[i].h;
    return 0;
}

static HANDLE out_keep(UINT fmt, HANDLE h, int gdi)
{
    if (!h) return 0;
    if (g_nout < OUT_MAX) { g_out[g_nout].fmt = fmt; g_out[g_nout].h = h; g_out[g_nout].gdi = gdi; ++g_nout; }
    return h;
}

/* ---------------------------------------------------------------- open/close/empty */
DLLAPI BOOL WINAPI OpenClipboard(HWND hwnd)
{
    shz_clip_t c;
    int32_t st;
    U32_NEED_GFX(FALSE);
    st = clip_op(SHZ_CB_OPEN, 0, hwnd, &c);
    if (st < 0) { if ((uint32_t)st == 0xC0000022u) SetLastError(ERROR_ACCESS_DENIED); else u32_err(st); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI CloseClipboard(void)
{
    shz_clip_t c;
    int32_t st;
    U32_NEED_GFX(FALSE);
    st = clip_op(SHZ_CB_CLOSE, 0, 0, &c);
    out_free_all();
    if (st < 0) { SetLastError(ERROR_CLIPBOARD_NOT_OPEN); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI EmptyClipboard(void)
{
    shz_clip_t c;
    int32_t st;
    U32_NEED_GFX(FALSE);
    st = clip_op(SHZ_CB_EMPTY, 0, 0, &c);
    if (st < 0) { SetLastError(ERROR_CLIPBOARD_NOT_OPEN); return FALSE; }
    out_free_all();
    if (c.out1 && IsWindow(U2H(c.out1))) {                              /* the previous owner loses the clipboard */
        DWORD pid = 0;
        GetWindowThreadProcessId(U2H(c.out1), &pid);
        if (pid == GetCurrentProcessId()) SendMessageW(U2H(c.out1), WM_DESTROYCLIPBOARD, 0, 0);
    }
    return TRUE;
}

DLLAPI HWND WINAPI GetClipboardOwner(void) { shz_clip_t c; if (!u32_display(0) || clip_op(SHZ_CB_INFO, 0, 0, &c) < 0) return 0; return U2H(c.out1); }
DLLAPI HWND WINAPI GetOpenClipboardWindow(void) { shz_clip_t c; if (!u32_display(0) || clip_op(SHZ_CB_INFO, 0, 0, &c) < 0) return 0; return U2H(c.out2); }
DLLAPI DWORD WINAPI GetClipboardSequenceNumber(void) { shz_clip_t c; if (!u32_display(0) || clip_op(SHZ_CB_INFO, 0, 0, &c) < 0) return 0; return (DWORD)c.out0; }

/* ---------------------------------------------------------------- set */
static int32_t put_bytes(UINT fmt, const void *p, SIZE_T n)
{
    shz_clip_t c;
    memset(&c, 0, sizeof c);
    c.op = SHZ_CB_SET;
    c.format = fmt;
    c.buf = (uint64_t)(uintptr_t)p;
    c.size = n;
    return clip(&c);
}

/* an HBITMAP as a packed CF_DIB (BITMAPINFOHEADER + 32 bpp bottom-up rows) */
static void *bitmap_to_dib(HBITMAP hb, SIZE_T *n)
{
    BITMAP bm;
    BITMAPINFOHEADER *h;
    HDC dc;
    uint8_t *p;
    int ok;
    if (GetObjectW(hb, sizeof bm, &bm) != (int)sizeof bm || bm.bmWidth <= 0 || bm.bmHeight <= 0) return 0;
    *n = sizeof *h + (SIZE_T)bm.bmWidth * (SIZE_T)bm.bmHeight * 4;
    p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *n);
    if (!p) return 0;
    h = (BITMAPINFOHEADER *)p;
    h->biSize = sizeof *h;
    h->biWidth = bm.bmWidth;
    h->biHeight = bm.bmHeight;
    h->biPlanes = 1;
    h->biBitCount = 32;
    h->biCompression = BI_RGB;
    h->biSizeImage = (DWORD)(*n - sizeof *h);
    dc = CreateCompatibleDC(0);
    ok = dc && GetDIBits(dc, hb, 0, (UINT)bm.bmHeight, p + sizeof *h, (BITMAPINFO *)h, DIB_RGB_COLORS) == bm.bmHeight;
    if (dc) DeleteDC(dc);
    if (!ok) { HeapFree(GetProcessHeap(), 0, p); return 0; }
    return p;
}

DLLAPI HANDLE WINAPI SetClipboardData(UINT fmt, HANDLE h)
{
    int32_t st;
    U32_NEED_GFX(0);
    if (!fmt) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!h) {                                                           /* delayed rendering: NULL is returned either way */
        put_bytes(fmt, 0, 0);
        return 0;
    }
    if (fmt == CF_BITMAP) {
        SIZE_T n = 0;
        void *dib = bitmap_to_dib((HBITMAP)h, &n);
        if (!dib) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
        st = put_bytes(CF_DIB, dib, n);
        HeapFree(GetProcessHeap(), 0, dib);
        if (st < 0) return 0;
        DeleteObject((HGDIOBJ)h);                                       /* the system owns it now */
        return h;
    }
    if (fmt == CF_PALETTE || fmt == CF_ENHMETAFILE || fmt == CF_METAFILEPICT || fmt == CF_OWNERDISPLAY) {
        SetLastError(ERROR_NOT_SUPPORTED);                              /* GDI objects that have no byte form here */
        return 0;
    }
    {
        const SIZE_T n = gsize(h);
        void *p = glock(h);
        if (!p || !n) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
        st = put_bytes(fmt, p, n);
        gunlock(h);
        if (st < 0) return 0;
        GlobalFree(h);                                                  /* the system owns it now */
    }
    return h;
}

/* ---------------------------------------------------------------- get */
/* the bytes of a real (not synthesised) format: HeapAlloc'ed, *n bytes; renders delayed formats of this process */
static void *get_bytes(UINT fmt, SIZE_T *n)
{
    shz_clip_t c;
    void *p;
    int tries;
    for (tries = 0; tries < 2; ++tries) {
        if (clip_op(SHZ_CB_GET, fmt, 0, &c) < 0) return 0;
        if (c.out1 && tries == 0) {                                     /* delayed: ask the owner to render it */
            shz_clip_t i;
            DWORD pid = 0;
            if (clip_op(SHZ_CB_INFO, 0, 0, &i) < 0 || !i.out1) return 0;
            GetWindowThreadProcessId(U2H(i.out1), &pid);
            if (pid != GetCurrentProcessId()) return 0;
            SendMessageW(U2H(i.out1), WM_RENDERFORMAT, fmt, 0);
            continue;
        }
        if (c.out1 || !c.out0) return 0;
        p = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)c.out0);
        if (!p) return 0;
        c.op = SHZ_CB_GET;
        c.format = fmt;
        c.buf = (uint64_t)(uintptr_t)p;
        c.size = c.out0;
        if (NtUserClipboard(&c) < 0 || c.out0 > c.size) { HeapFree(GetProcessHeap(), 0, p); continue; }   /* changed meanwhile */
        *n = (SIZE_T)c.out0;
        return p;
    }
    return 0;
}

static int has_real(UINT fmt) { shz_clip_t c; return clip_op(SHZ_CB_GET, fmt, 0, &c) >= 0; }

static HGLOBAL to_hglobal(const void *p, SIZE_T n)
{
    HGLOBAL g = GlobalAlloc(GMEM_FIXED, n ? n : 1);
    void *d;
    if (!g) return 0;
    d = glock(g);
    if (n) memcpy(d, p, n);
    gunlock(g);
    return g;
}

/* text conversions between the three text formats */
static HGLOBAL convert_text(UINT want, UINT have, const void *p, SIZE_T n)
{
    if (have == CF_UNICODETEXT) {
        const WCHAR *w = p;
        const int wl = (int)(n / 2);
        const UINT cp = want == CF_OEMTEXT ? CP_OEMCP : CP_ACP;
        int need = WideCharToMultiByte(cp, 0, w, wl, 0, 0, 0, 0);
        HGLOBAL g;
        char *d;
        if (need <= 0) return 0;
        g = GlobalAlloc(GMEM_FIXED, (SIZE_T)need + 1);
        if (!g) return 0;
        d = glock(g);
        WideCharToMultiByte(cp, 0, w, wl, d, need, 0, 0);
        d[need] = 0;
        gunlock(g);
        return g;
    } else {
        const UINT cp = have == CF_OEMTEXT ? CP_OEMCP : CP_ACP;
        if (want == CF_UNICODETEXT) {
            int need = MultiByteToWideChar(cp, 0, p, (int)n, 0, 0);
            HGLOBAL g;
            WCHAR *d;
            if (need <= 0) return 0;
            g = GlobalAlloc(GMEM_FIXED, ((SIZE_T)need + 1) * 2);
            if (!g) return 0;
            d = glock(g);
            MultiByteToWideChar(cp, 0, p, (int)n, d, need);
            d[need] = 0;
            gunlock(g);
            return g;
        } else {                                                        /* ANSI <-> OEM through UTF-16 */
            int wn = MultiByteToWideChar(cp, 0, p, (int)n, 0, 0);
            WCHAR *tmp;
            HGLOBAL g;
            if (wn <= 0) return 0;
            tmp = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)wn * 2);
            if (!tmp) return 0;
            MultiByteToWideChar(cp, 0, p, (int)n, tmp, wn);
            g = convert_text(want, CF_UNICODETEXT, tmp, (SIZE_T)wn * 2);
            HeapFree(GetProcessHeap(), 0, tmp);
            return g;
        }
    }
}

static HBITMAP dib_to_bitmap(const void *p, SIZE_T n)
{
    const BITMAPINFOHEADER *h = p;
    const uint8_t *bits;
    HDC dc;
    HBITMAP hb;
    size_t pal = 0;
    if (n < sizeof *h || h->biSize < sizeof *h) return 0;
    if (h->biBitCount <= 8) pal = (h->biClrUsed ? h->biClrUsed : (1u << h->biBitCount)) * 4;
    else if (h->biCompression == BI_BITFIELDS) pal = 12;
    bits = (const uint8_t *)p + h->biSize + pal;
    if ((SIZE_T)(bits - (const uint8_t *)p) > n) return 0;
    dc = GetDC(0);
    hb = CreateCompatibleBitmap(dc, h->biWidth, h->biHeight < 0 ? -h->biHeight : h->biHeight);
    if (hb && !SetDIBits(dc, hb, 0, (UINT)(h->biHeight < 0 ? -h->biHeight : h->biHeight), bits, (const BITMAPINFO *)p, DIB_RGB_COLORS)) {
        DeleteObject(hb);
        hb = 0;
    }
    ReleaseDC(0, dc);
    return hb;
}

DLLAPI HANDLE WINAPI GetClipboardData(UINT fmt)
{
    HANDLE h;
    void *p;
    SIZE_T n = 0;
    U32_NEED_GFX(0);
    if ((h = out_find(fmt)) != 0) return h;
    if (fmt == CF_BITMAP) {
        p = get_bytes(CF_DIB, &n);
        if (!p) { SetLastError(ERROR_CLIPBOARD_NOT_OPEN); return 0; }
        h = dib_to_bitmap(p, n);
        HeapFree(GetProcessHeap(), 0, p);
        return out_keep(fmt, h, 1);
    }
    p = get_bytes(fmt, &n);
    if (p) {
        h = to_hglobal(p, n);
        HeapFree(GetProcessHeap(), 0, p);
        return out_keep(fmt, h, 0);
    }
    if (fmt == CF_UNICODETEXT || fmt == CF_TEXT || fmt == CF_OEMTEXT) {    /* synthesise from another text format */
        static const UINT order[3] = { CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT };
        int i;
        for (i = 0; i < 3; ++i) {
            if (order[i] == fmt || !(p = get_bytes(order[i], &n))) continue;
            {
                SIZE_T len = n;                                         /* up to the terminator */
                if (order[i] == CF_UNICODETEXT) { const WCHAR *w = p; SIZE_T k; for (k = 0; k < n / 2; ++k) if (!w[k]) break; len = k * 2; }
                else { const char *a = p; SIZE_T k; for (k = 0; k < n; ++k) if (!a[k]) break; len = k; }
                h = convert_text(fmt, order[i], p, len);
            }
            HeapFree(GetProcessHeap(), 0, p);
            return out_keep(fmt, h, 0);
        }
    }
    if (fmt == CF_LOCALE && (has_real(CF_UNICODETEXT) || has_real(CF_TEXT) || has_real(CF_OEMTEXT))) {
        const LCID lcid = 0x0409;
        return out_keep(fmt, to_hglobal(&lcid, sizeof lcid), 0);
    }
    SetLastError(ERROR_CLIPBOARD_NOT_OPEN);
    return 0;
}

/* ---------------------------------------------------------------- queries */
static int synthesisable(UINT fmt)
{
    switch (fmt) {
    case CF_TEXT: case CF_OEMTEXT: case CF_UNICODETEXT: case CF_LOCALE:
        return has_real(CF_UNICODETEXT) || has_real(CF_TEXT) || has_real(CF_OEMTEXT);
    case CF_BITMAP: return has_real(CF_DIB);
    default: return 0;
    }
}

DLLAPI BOOL WINAPI IsClipboardFormatAvailable(UINT fmt)
{
    if (!u32_display(0) || !fmt) return FALSE;
    return has_real(fmt) || synthesisable(fmt);
}

/* the real formats in the order they were set, then the synthesised ones */
static int list_formats(UINT *out, int max)
{
    static const UINT synth[5] = { CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT, CF_LOCALE, CF_BITMAP };
    shz_clip_t c;
    UINT f = 0;
    int n = 0, i, k;
    for (;;) {
        if (clip_op(SHZ_CB_ENUM, f, 0, &c) < 0 || !c.out0 || n >= max) break;
        f = (UINT)c.out0;
        out[n++] = f;
    }
    for (i = 0; i < 5 && n < max; ++i) {
        int dup = 0;
        for (k = 0; k < n; ++k) if (out[k] == synth[i]) dup = 1;
        if (!dup && synthesisable(synth[i])) out[n++] = synth[i];
    }
    return n;
}

DLLAPI int WINAPI CountClipboardFormats(void)
{
    UINT f[64];
    if (!u32_display(0)) return 0;
    return list_formats(f, 64);
}

DLLAPI UINT WINAPI EnumClipboardFormats(UINT fmt)
{
    UINT f[64];
    int n, i;
    U32_NEED_GFX(0);
    n = list_formats(f, 64);
    SetLastError(ERROR_SUCCESS);
    if (!fmt) return n ? f[0] : 0;
    for (i = 0; i < n; ++i) if (f[i] == fmt) return i + 1 < n ? f[i + 1] : 0;
    return 0;
}

DLLAPI int WINAPI GetPriorityClipboardFormat(UINT *list, int n)
{
    int i;
    if (!CountClipboardFormats()) return 0;
    for (i = 0; i < n; ++i) if (IsClipboardFormatAvailable(list[i])) return (int)list[i];
    return -1;
}

DLLAPI BOOL WINAPI GetUpdatedClipboardFormats(PUINT out, UINT max, PUINT n)
{
    UINT f[64];
    int k;
    if (!n) { SetLastError(ERROR_NOACCESS); return FALSE; }
    k = u32_display(0) ? list_formats(f, 64) : 0;
    *n = (UINT)k;
    if ((UINT)k > max) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (k && out) memcpy(out, f, (size_t)k * sizeof(UINT));
    return TRUE;
}

DLLAPI UINT WINAPI RegisterClipboardFormatW(LPCWSTR name) { return RegisterWindowMessageW(name); }   /* the same atom table */

DLLAPI UINT WINAPI RegisterClipboardFormatA(LPCSTR name)
{
    WCHAR w[256];
    if (!name || !MultiByteToWideChar(CP_ACP, 0, name, -1, w, 256)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return RegisterWindowMessageW(w);
}

DLLAPI int WINAPI GetClipboardFormatNameW(UINT fmt, LPWSTR buf, int cap)
{
    shz_atom_t a;
    if (!buf || cap <= 0 || fmt < 0xC000) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    U32_NEED_GFX(0);
    memset(&a, 0, sizeof a);
    a.op = SHZ_ATOM_GETNAME;
    a.atom = fmt;
    a.name = (uint64_t)(uintptr_t)buf;
    a.name_len = (uint32_t)cap;
    if (NtUserAtom(&a) < 0) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return (int)a.name_len;
}

DLLAPI int WINAPI GetClipboardFormatNameA(UINT fmt, LPSTR buf, int cap)
{
    WCHAR w[256];
    int n;
    if (!buf || cap <= 0) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    n = GetClipboardFormatNameW(fmt, w, 256);
    if (n <= 0) return 0;
    n = WideCharToMultiByte(CP_ACP, 0, w, n, buf, cap - 1, 0, 0);
    buf[n] = 0;
    return n;
}

DLLAPI BOOL WINAPI AddClipboardFormatListener(HWND hwnd)
{
    shz_clip_t c;
    U32_NEED_GFX(FALSE);
    {
        const int32_t st = clip_op(SHZ_CB_LISTEN, 1, hwnd, &c);
        if (st < 0) { u32_err(st); return FALSE; }
    }
    return TRUE;
}

DLLAPI BOOL WINAPI RemoveClipboardFormatListener(HWND hwnd)
{
    shz_clip_t c;
    U32_NEED_GFX(FALSE);
    if (clip_op(SHZ_CB_LISTEN, 0, hwnd, &c) < 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}

