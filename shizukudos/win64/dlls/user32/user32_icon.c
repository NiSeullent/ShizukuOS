/* SPDX-License-Identifier: GPL-2.0-only
 * user32: icons and cursors. An icon or cursor is a user-mode object of this process holding a top-down image of straight
 * 0xAARRGGBB pixels and a hot spot; handles are (generation << 12 | 0x800 | slot), a range no window handle can take
 * (window handles carry slot + 1 <= 255 in their low 12 bits).
 *
 * Built-in system images (shared, never freed, LR_SHARED semantics): cursors IDC_ARROW, IDC_IBEAM, IDC_WAIT, IDC_CROSS,
 * IDC_UPARROW, IDC_SIZENWSE, IDC_SIZENESW, IDC_SIZEWE, IDC_SIZENS, IDC_SIZEALL (= IDC_SIZE), IDC_NO, IDC_HAND,
 * IDC_APPSTARTING, IDC_HELP and icons IDI_APPLICATION (= IDI_WINLOGO), IDI_HAND, IDI_QUESTION, IDI_EXCLAMATION,
 * IDI_ASTERISK, each 32x32 with alpha 0 or 255, drawn from code and glyphs of the built-in font (our own artwork). Any other system identifier, and any
 * resource of a module, fails with ERROR_RESOURCE_NAME_NOT_FOUND: there is no resource loader.
 * CreateIconIndirect accepts a 32 bpp colour bitmap (its alpha channel is used when it is not all zero, otherwise the AND
 * mask decides transparency, as on Windows) or a colour-less (monochrome-style, double height) mask given as a 32 bpp bitmap
 * whose white pixels are the "1" bits. There is no pointing device yet, so no cursor is ever shown on screen; SetCursor only
 * records the thread's current cursor. */
#include "user32_int.h"
#include "../../../supervisor/src/font8x8_basic.h"
#include "shzpointer.h"

BOOL WINAPI ShzGdiDrawArgb(HDC hdc, int x, int y, int w, int h, const uint32_t *argb, int sw, int sh, int mode);

#define IC 32
#define NICONS 128
typedef struct { int used, is_cursor, shared, hot_x, hot_y, w, h; unsigned gen; uintptr_t sys_id; uint32_t *argb; } uicon_t;
static uicon_t g_icons[NICONS];
static unsigned g_icon_gen;
static CRITICAL_SECTION g_icon_lock;
static volatile LONG g_icon_lock_init;

static void icon_lock(void)
{
    if (g_icon_lock_init != 2) {
        if (InterlockedCompareExchange(&g_icon_lock_init, 1, 0) == 0) { InitializeCriticalSection(&g_icon_lock); g_icon_lock_init = 2; }
        else while (g_icon_lock_init != 2) Sleep(0);
    }
    EnterCriticalSection(&g_icon_lock);
}
static void icon_unlock(void) { LeaveCriticalSection(&g_icon_lock); }

#define BLACK 0xff000000u
#define WHITE 0xffffffffu

static void px(uint32_t *a, int x, int y, uint32_t c) { if (x >= 0 && y >= 0 && x < IC && y < IC) a[y * IC + x] = c; }

static void disc(uint32_t *a, int cx, int cy, int r, uint32_t c)
{
    int x, y;
    for (y = cy - r; y <= cy + r; ++y)
        for (x = cx - r; x <= cx + r; ++x)
            if ((x - cx) * (x - cx) + (y - cy) * (y - cy) <= r * r) px(a, x, y, c);
}

/* a glyph of the built-in font at 2x (16x16 pixels) with its top-left corner at (x,y) */
static void glyph2(uint32_t *a, int x, int y, char ch, uint32_t c)
{
    int row, col;
    for (row = 0; row < 16; ++row)
        for (col = 0; col < 16; ++col)
            if ((font8x8_basic[(int)ch & 0x7f][row / 2] >> (col / 2)) & 1) px(a, x + col, y + row, c);
}

static void icon_round(uint32_t *a, uint32_t fill, char mark)
{
    disc(a, 16, 16, 15, BLACK);
    disc(a, 16, 16, 13, fill);
    glyph2(a, 8, 8, mark, WHITE);
}

static void icon_triangle(uint32_t *a, uint32_t fill, char mark)
{
    int y, x;
    for (y = 2; y < 30; ++y) {
        const int half = (y - 2) * 15 / 27;
        for (x = 16 - half - 1; x <= 16 + half + 1; ++x) px(a, x, y, BLACK);
    }
    for (y = 5; y < 28; ++y) {
        const int half = (y - 2) * 15 / 27 - 2;
        for (x = 16 - half; x <= 16 + half; ++x) px(a, x, y, fill);
    }
    glyph2(a, 8, 11, mark, BLACK);
}

static void icon_app(uint32_t *a)
{
    int x, y;
    for (y = 4; y < 28; ++y)
        for (x = 3; x < 29; ++x) px(a, x, y, BLACK);
    for (y = 5; y < 27; ++y)
        for (x = 4; x < 28; ++x) px(a, x, y, y < 9 ? 0xff000080u : 0xffffffffu);
    for (x = 6; x < 26; ++x) px(a, x, 12, 0xff808080u);
    for (x = 6; x < 20; ++x) px(a, x, 16, 0xff808080u);
}

#define arrow shz_arrow_art

static void from_art(uint32_t *a, const char *const *art, int rows, int ox, int oy)
{
    int x, y;
    for (y = 0; y < rows; ++y)
        for (x = 0; art[y][x]; ++x) {
            const char c = art[y][x];
            if (c == 'X') px(a, ox + x, oy + y, BLACK); else if (c == '.') px(a, ox + x, oy + y, WHITE);
        }
}

static const char *const hand[21] = {
    "     XX          ", "    X..X         ", "    X..X         ", "    X..X         ", "    X..X         ", "    X..XXX       ",
    "    X..X..XXX    ", "    X..X..X..XX  ", " XX X..X..X..X.X ", "X..XX........X..X", "X...X...........X", " X..............X",
    "  X.............X", "  X............X ", "   X...........X ", "   X..........X  ", "    X.........X  ", "    X.........X  ",
    "     X.......X   ", "     X.......X   ", "     XXXXXXXXX   " };

static void bar(uint32_t *a, int x0, int y0, int x1, int y1)          /* axis-aligned black bar with a one-pixel white outline */
{
    int x, y;
    for (y = y0 - 1; y <= y1 + 1; ++y)
        for (x = x0 - 1; x <= x1 + 1; ++x)
            if (x >= 0 && y >= 0 && x < IC && y < IC && a[y * IC + x] != BLACK) px(a, x, y, WHITE);
    for (y = y0; y <= y1; ++y)
        for (x = x0; x <= x1; ++x) px(a, x, y, BLACK);
}

static void hourglass(uint32_t *a, int ox, int oy, int size)          /* size x size hourglass, top-left (ox,oy) */
{
    int i, x;
    const int c = ox + size / 2, half_n = size / 2;
    for (i = 0; i < size; ++i) {
        const int half = i < half_n ? half_n - i : i - half_n + 1;
        for (x = c - half - 1; x <= c + half; ++x) px(a, x, oy + i, BLACK);
        for (x = c - half + 1; x <= c + half - 2; ++x) px(a, x, oy + i, WHITE);
    }
}

static void diagonal(uint32_t *a, int flip)                           /* the IDC_SIZENWSE / IDC_SIZENESW double arrow */
{
    int t;
#define DX(x) (flip ? 31 - (x) : (x))
    for (t = 6; t <= 25; ++t) bar(a, DX(t), t, DX(t), t);
    bar(a, flip ? DX(12) : 6, 6, flip ? DX(6) : 12, 6);
    bar(a, DX(6), 6, DX(6), 12);
    bar(a, flip ? DX(25) : 19, 25, flip ? DX(19) : 25, 25);
    bar(a, DX(25), 19, DX(25), 25);
#undef DX
}

/* Draws system image `id` into a 32x32 buffer; returns 0 for identifiers that do not exist here. */
static int build_system(uint32_t *a, int cursor, uintptr_t id, int *hx, int *hy)
{
    int i, x, y;
    memset(a, 0, IC * IC * 4);
    *hx = *hy = cursor ? 15 : 16;
    if (!cursor) {
        switch (id) {
        case 32512: case 32517: icon_app(a); return 1;              /* IDI_APPLICATION, IDI_WINLOGO */
        case 32513: icon_round(a, 0xffc00000u, 'X'); return 1;      /* IDI_HAND / IDI_ERROR */
        case 32514: icon_round(a, 0xff0000c0u, '?'); return 1;      /* IDI_QUESTION */
        case 32515: icon_triangle(a, 0xffffff00u, '!'); return 1;   /* IDI_EXCLAMATION / IDI_WARNING */
        case 32516: icon_round(a, 0xff0000c0u, 'i'); return 1;      /* IDI_ASTERISK / IDI_INFORMATION */
        default: return 0;
        }
    }
    switch (id) {
    case 32512: from_art(a, arrow, 19, 0, 0); *hx = *hy = 0; return 1;                     /* IDC_ARROW */
    case 32513: bar(a, 15, 4, 15, 27); bar(a, 11, 4, 19, 4); bar(a, 11, 27, 19, 27); return 1; /* IDC_IBEAM */
    case 32514: hourglass(a, 4, 4, 24); return 1;                                           /* IDC_WAIT */
    case 32515: bar(a, 15, 4, 15, 27); bar(a, 4, 15, 27, 15); return 1;                   /* IDC_CROSS */
    case 32516:                                                                             /* IDC_UPARROW */
        bar(a, 15, 4, 15, 27);
        for (i = 1; i <= 6; ++i) bar(a, 15 - i, 4 + i, 15 + i, 4 + i);
        *hy = 4;
        return 1;
    case 32642: diagonal(a, 0); return 1;                                                   /* IDC_SIZENWSE */
    case 32643: diagonal(a, 1); return 1;                                                   /* IDC_SIZENESW */
    case 32640: case 32646: case 32644: case 32645:                                         /* IDC_SIZE(ALL), SIZEWE, SIZENS */
        if (id != 32645) {
            bar(a, 4, 15, 27, 15);
            for (i = 1; i <= 4; ++i) { bar(a, 4 + i, 15 - i, 4 + i, 15 + i); bar(a, 27 - i, 15 - i, 27 - i, 15 + i); }
        }
        if (id != 32644) {
            bar(a, 15, 4, 15, 27);
            for (i = 1; i <= 4; ++i) { bar(a, 15 - i, 4 + i, 15 + i, 4 + i); bar(a, 15 - i, 27 - i, 15 + i, 27 - i); }
        }
        return 1;
    case 32648:                                                                             /* IDC_NO: circle with a slash */
        disc(a, 15, 15, 12, BLACK);
        disc(a, 15, 15, 9, 0);
        for (y = 0; y < IC; ++y)
            for (x = 0; x < IC; ++x) {
                const int dx = x - 15, dy = y - 15;
                if (dx * dx + dy * dy <= 100 && (dx - dy) * (dx - dy) <= 4) px(a, x, y, BLACK);
            }
        return 1;
    case 32649: from_art(a, hand, 21, 0, 0); *hx = 5; *hy = 0; return 1;                   /* IDC_HAND */
    case 32650: from_art(a, arrow, 19, 0, 0); hourglass(a, 14, 14, 14); *hx = *hy = 0; return 1; /* IDC_APPSTARTING */
    case 32651: from_art(a, arrow, 19, 0, 0); glyph2(a, 14, 6, '?', BLACK); *hx = *hy = 0; return 1; /* IDC_HELP */
    default: return 0;
    }
}

static HANDLE handle_of(int slot) { return (HANDLE)(uintptr_t)(((uintptr_t)g_icons[slot].gen << 12) | 0x800u | (unsigned)slot); }

static uicon_t *icon_of(HANDLE h)
{
    const uintptr_t v = (uintptr_t)h;
    const unsigned slot = (unsigned)(v & 0x7ff);
    if ((v & 0x800) == 0 || slot >= NICONS || !g_icons[slot].used || (v >> 12) != g_icons[slot].gen) return 0;
    return &g_icons[slot];
}

/* Allocates a slot owning `argb` (heap memory of w*h pixels). Called with the lock held. */
static HANDLE icon_new(uint32_t *argb, int w, int h, int cursor, int hx, int hy, int shared, uintptr_t sys_id)
{
    int slot;
    for (slot = 0; slot < NICONS; ++slot)
        if (!g_icons[slot].used) {
            uicon_t *ic = &g_icons[slot];
            if (++g_icon_gen > 0xfffff) g_icon_gen = 1;
            ic->used = 1; ic->is_cursor = cursor; ic->shared = shared; ic->hot_x = hx; ic->hot_y = hy;
            ic->w = w; ic->h = h; ic->gen = g_icon_gen; ic->sys_id = sys_id; ic->argb = argb;
            return handle_of(slot);
        }
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return 0;
}

static HANDLE load_system(LPCWSTR name, int cursor)
{
    const uintptr_t id = (uintptr_t)name;
    uint32_t *a;
    int slot, hx, hy;
    HANDLE h;
    if (id >= 0x10000) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }     /* named resources: no resource loader */
    icon_lock();
    for (slot = 0; slot < NICONS; ++slot)
        if (g_icons[slot].used && g_icons[slot].shared && g_icons[slot].sys_id == id && g_icons[slot].is_cursor == cursor) {
            h = handle_of(slot);
            icon_unlock();
            return h;
        }
    a = HeapAlloc(GetProcessHeap(), 0, IC * IC * 4);
    if (!a) { icon_unlock(); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    if (!build_system(a, cursor, id, &hx, &hy)) {
        HeapFree(GetProcessHeap(), 0, a);
        icon_unlock();
        SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
        return 0;
    }
    h = icon_new(a, IC, IC, cursor, hx, hy, 1, id);
    if (!h) HeapFree(GetProcessHeap(), 0, a);
    icon_unlock();
    return h;
}

/* Resources of a module are real, per-call objects; the system images (hinst NULL) are shared. LoadIcon/LoadCursor load
 * the SM_CXICON/SM_CXCURSOR size from a module (user32_res.c). */
DLLAPI HICON WINAPI LoadIconW(HINSTANCE inst, LPCWSTR name)
{
    if (inst) return u32_icon_from_resource(inst, name, 0, 0, 0);
    return (HICON)load_system(name, 0);
}

DLLAPI HCURSOR WINAPI LoadCursorW(HINSTANCE inst, LPCWSTR name)
{
    if (inst) return (HCURSOR)u32_icon_from_resource(inst, name, 1, 0, 0);
    return (HCURSOR)load_system(name, 1);
}

HICON u32_icon_from_file(LPCWSTR path, int cursor, int cx, int cy);
HBITMAP u32_bitmap_from_file(LPCWSTR path);
HBITMAP WINAPI LoadBitmapW(HINSTANCE inst, LPCWSTR name);

/* System images (hinst NULL): the built-in 32x32 ones, whatever size is asked (DrawIconEx scales). Module resources and
 * .ico/.cur/.bmp files (LR_LOADFROMFILE) at the requested size (LR_DEFAULTSIZE / 0: the system metric). */
DLLAPI HANDLE WINAPI LoadImageW(HINSTANCE inst, LPCWSTR name, UINT type, int cx, int cy, UINT flags)
{
    if (type != IMAGE_ICON && type != IMAGE_CURSOR && type != IMAGE_BITMAP) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & LR_LOADFROMFILE) {
        if (!name || IS_INTRESOURCE(name)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
        if (type == IMAGE_BITMAP) return u32_bitmap_from_file(name);
        return u32_icon_from_file(name, type == IMAGE_CURSOR, cx, cy);
    }
    if (type == IMAGE_BITMAP) return LoadBitmapW(inst, name);
    if (!inst) return load_system(name, type == IMAGE_CURSOR);
    if (!cx && !(flags & LR_DEFAULTSIZE)) cx = 0;
    return u32_icon_from_resource(inst, name, type == IMAGE_CURSOR, cx, cy);
}

HICON u32_icon_create_argb(uint32_t *argb, int w, int h, int cursor, int hx, int hy)
{
    HANDLE r;
    icon_lock();
    r = icon_new(argb, w, h, cursor, hx, hy, 0, 0);
    icon_unlock();
    if (!r) HeapFree(GetProcessHeap(), 0, argb);
    return (HICON)r;
}

/* Converts a bitmap to straight ARGB pixels via GetDIBits (32 bpp, top-down). */
static uint32_t *bitmap_pixels(HBITMAP hb, int *w, int *h)
{
    BITMAP bm;
    BITMAPINFO bi;
    uint32_t *p;
    HDC dc;
    int ok;
    if (!hb || GetObjectW(hb, sizeof bm, &bm) != (int)sizeof bm || bm.bmWidth <= 0 || bm.bmHeight <= 0 || bm.bmWidth > 1024 || bm.bmHeight > 2048) return 0;
    p = HeapAlloc(GetProcessHeap(), 0, (size_t)bm.bmWidth * (size_t)bm.bmHeight * 4);
    if (!p) return 0;
    memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = bm.bmWidth;
    bi.bmiHeader.biHeight = -bm.bmHeight;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    dc = CreateCompatibleDC(0);
    ok = dc && GetDIBits(dc, hb, 0, (UINT)bm.bmHeight, p, &bi, DIB_RGB_COLORS) == bm.bmHeight;
    if (dc) DeleteDC(dc);
    if (!ok) { HeapFree(GetProcessHeap(), 0, p); return 0; }
    *w = bm.bmWidth;
    *h = bm.bmHeight;
    return p;
}

DLLAPI HICON WINAPI CreateIconIndirect(PICONINFO ii)
{
    uint32_t *color = 0, *mask = 0;
    int cw = 0, ch = 0, mw = 0, mh = 0, w, h, i, any_alpha = 0;
    HANDLE r;
    if (!ii || !ii->hbmMask) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    mask = bitmap_pixels(ii->hbmMask, &mw, &mh);
    if (!mask) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (ii->hbmColor) {
        color = bitmap_pixels(ii->hbmColor, &cw, &ch);
        if (!color || mw != cw || mh < ch) {
            if (color) HeapFree(GetProcessHeap(), 0, color);
            HeapFree(GetProcessHeap(), 0, mask);
            SetLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        w = cw; h = ch;
        for (i = 0; i < w * h; ++i) any_alpha |= (int)(color[i] >> 24);
        for (i = 0; i < w * h; ++i) {
            const int and_bit = (mask[i] & 0x00ffffffu) != 0;               /* AND-mask 1 = transparent */
            if (!any_alpha) color[i] = and_bit ? (color[i] & 0x00ffffffu) : (color[i] | 0xff000000u);
        }
        HeapFree(GetProcessHeap(), 0, mask);
    } else {                                                                 /* monochrome: AND mask over XOR mask */
        if (mh < 2 || (mh & 1)) { HeapFree(GetProcessHeap(), 0, mask); SetLastError(ERROR_INVALID_PARAMETER); return 0; }
        w = mw; h = mh / 2;
        color = mask;
        for (i = 0; i < w * h; ++i) {
            const int and_bit = (mask[i] & 0x00ffffffu) != 0, xor_bit = (mask[w * h + i] & 0x00ffffffu) != 0;
            /* AND 0: opaque, XOR picks white/black; AND 1 with XOR 0: transparent; AND 1 with XOR 1 (screen inversion) is
               not representable in ARGB and is drawn transparent */
            color[i] = and_bit ? 0 : (xor_bit ? WHITE : BLACK);
        }
    }
    icon_lock();
    r = icon_new(color, w, h, !ii->fIcon, ii->fIcon ? w / 2 : (int)ii->xHotspot, ii->fIcon ? h / 2 : (int)ii->yHotspot, 0, 0);
    icon_unlock();
    if (!r) HeapFree(GetProcessHeap(), 0, color);
    return (HICON)r;
}

DLLAPI HICON WINAPI CreateIcon(HINSTANCE inst, int w, int h, BYTE planes, BYTE bpp, const BYTE *andbits, const BYTE *xorbits)
{
    /* only 1 bpp monochrome icons (planes 1, bpp 1): WORD-aligned AND and XOR masks */
    const int stride = ((w + 15) / 16) * 2;
    uint32_t *a;
    int x, y;
    HANDLE r;
    (void)inst;
    if (w <= 0 || h <= 0 || w > 256 || h > 256 || planes != 1 || bpp != 1 || !andbits || !xorbits) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    a = HeapAlloc(GetProcessHeap(), 0, (size_t)w * (size_t)h * 4);
    if (!a) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    for (y = 0; y < h; ++y)
        for (x = 0; x < w; ++x) {
            const int an = (andbits[y * stride + x / 8] >> (7 - (x & 7))) & 1, xo = (xorbits[y * stride + x / 8] >> (7 - (x & 7))) & 1;
            a[y * w + x] = an ? 0 : (xo ? WHITE : BLACK);
        }
    icon_lock();
    r = icon_new(a, w, h, 0, w / 2, h / 2, 0, 0);
    icon_unlock();
    if (!r) HeapFree(GetProcessHeap(), 0, a);
    return (HICON)r;
}

/* A copy is always a new, non-shared object, also for system images. */
DLLAPI HICON WINAPI CopyIcon(HICON h)
{
    uicon_t *ic;
    uint32_t *a;
    HANDLE r = 0;
    icon_lock();
    ic = icon_of(h);
    if (!ic) { icon_unlock(); SetLastError(ERROR_INVALID_CURSOR_HANDLE); return 0; }
    a = HeapAlloc(GetProcessHeap(), 0, (size_t)ic->w * (size_t)ic->h * 4);
    if (a) {
        memcpy(a, ic->argb, (size_t)ic->w * (size_t)ic->h * 4);
        r = icon_new(a, ic->w, ic->h, ic->is_cursor, ic->hot_x, ic->hot_y, 0, 0);
        if (!r) HeapFree(GetProcessHeap(), 0, a);
    } else SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    icon_unlock();
    return (HICON)r;
}

/* Returns new 32 bpp bitmaps: the colour image (with its alpha) and the AND mask (white = transparent, black = opaque; a 32 bpp
 * bitmap, not a 1 bpp one, because gdi32 has only 32 bpp bitmaps). The caller owns both. */
DLLAPI BOOL WINAPI GetIconInfo(HICON h, PICONINFO ii)
{
    uicon_t *ic;
    uint32_t *copy;
    int i, w, hh;
    BOOL ok = FALSE;
    if (!ii) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    icon_lock();
    ic = icon_of(h);
    if (!ic) { icon_unlock(); SetLastError(ERROR_INVALID_CURSOR_HANDLE); return FALSE; }
    w = ic->w; hh = ic->h;
    copy = HeapAlloc(GetProcessHeap(), 0, (size_t)w * (size_t)hh * 4);
    if (copy) memcpy(copy, ic->argb, (size_t)w * (size_t)hh * 4);
    ii->fIcon = !ic->is_cursor;
    ii->xHotspot = (DWORD)ic->hot_x;
    ii->yHotspot = (DWORD)ic->hot_y;
    icon_unlock();
    if (!copy) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    ii->hbmColor = CreateBitmap(w, hh, 1, 32, copy);
    for (i = 0; i < w * hh; ++i) copy[i] = (copy[i] >> 24) >= 128 ? 0 : 0x00ffffffu;
    ii->hbmMask = CreateBitmap(w, hh, 1, 32, copy);
    HeapFree(GetProcessHeap(), 0, copy);
    ok = ii->hbmColor && ii->hbmMask;
    if (!ok) {
        if (ii->hbmColor) DeleteObject(ii->hbmColor);
        if (ii->hbmMask) DeleteObject(ii->hbmMask);
        ii->hbmColor = ii->hbmMask = 0;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }
    return ok;
}

static BOOL destroy(HANDLE h)
{
    uicon_t *ic;
    uint32_t *a = 0;
    icon_lock();
    ic = icon_of(h);
    if (!ic) { icon_unlock(); SetLastError(ERROR_INVALID_CURSOR_HANDLE); return FALSE; }
    if (!ic->shared) {                                           /* shared system images stay valid, as on Windows */
        a = ic->argb;
        memset(ic, 0, sizeof *ic);
    }
    icon_unlock();
    if (a) HeapFree(GetProcessHeap(), 0, a);
    return TRUE;
}

DLLAPI BOOL WINAPI DestroyIcon(HICON h) { return destroy(h); }
DLLAPI BOOL WINAPI DestroyCursor(HCURSOR h) { return destroy(h); }

DLLAPI HANDLE WINAPI CopyImage(HANDLE h, UINT type, int cx, int cy, UINT flags)
{
    (void)cx; (void)cy; (void)flags;
    if (type == IMAGE_ICON || type == IMAGE_CURSOR) return CopyIcon((HICON)h);   /* no resizing: DrawIconEx scales */
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
}

DLLAPI BOOL WINAPI DrawIconEx(HDC hdc, int x, int y, HICON h, int cx, int cy, UINT step, HBRUSH bg, UINT flags)
{
    uicon_t *ic;
    uint32_t *copy;
    int w, hh, mode;
    BOOL ok;
    (void)step;
    icon_lock();
    ic = icon_of(h);
    if (!ic) { icon_unlock(); SetLastError(ERROR_INVALID_CURSOR_HANDLE); return FALSE; }
    w = ic->w; hh = ic->h;
    copy = HeapAlloc(GetProcessHeap(), 0, (size_t)w * (size_t)hh * 4);
    if (copy) memcpy(copy, ic->argb, (size_t)w * (size_t)hh * 4);
    icon_unlock();
    if (!copy) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    if (!cx) cx = (flags & DI_DEFAULTSIZE) ? GetSystemMetrics(ic->is_cursor ? SM_CXCURSOR : SM_CXICON) : w;
    if (!cy) cy = (flags & DI_DEFAULTSIZE) ? GetSystemMetrics(ic->is_cursor ? SM_CYCURSOR : SM_CYICON) : hh;
    if (bg) { RECT r; r.left = x; r.top = y; r.right = x + cx; r.bottom = y + cy; FillRect(hdc, &r, bg); }
    mode = (int)(flags & DI_NORMAL);
    ok = mode ? ShzGdiDrawArgb(hdc, x, y, cx, cy, copy, w, hh, mode) : TRUE;
    HeapFree(GetProcessHeap(), 0, copy);
    return ok;
}

DLLAPI BOOL WINAPI DrawIcon(HDC hdc, int x, int y, HICON h) { return DrawIconEx(hdc, x, y, h, 0, 0, 0, 0, DI_NORMAL | DI_DEFAULTSIZE); }

/* ---------------------------------------------------------------- the thread's cursor (per thread, as the per-queue state
 * of Windows). The kernel draws it while the pointer is over a window of this thread (user32_input.c pushes it). */
int u32_icon_argb32(HICON h, uint32_t *out, int *w, int *hh, int *hx, int *hy)
{
    uicon_t *ic;
    int x, y, ow, oh;
    icon_lock();
    ic = icon_of(h);
    if (!ic) { icon_unlock(); return 0; }
    ow = ic->w > 32 ? 32 : ic->w;
    oh = ic->h > 32 ? 32 : ic->h;
    for (y = 0; y < oh; ++y)
        for (x = 0; x < ow; ++x)
            out[y * ow + x] = ic->argb[(size_t)(y * ic->h / oh) * (size_t)ic->w + (size_t)(x * ic->w / ow)];
    *w = ow;
    *hh = oh;
    *hx = ic->hot_x * ow / ic->w;
    *hy = ic->hot_y * oh / ic->h;
    icon_unlock();
    return 1;
}

DLLAPI HCURSOR WINAPI SetCursor(HCURSOR h)
{
    u32_thread_t *t = u32_ts();
    HCURSOR old;
    if (h && !icon_of(h)) { SetLastError(ERROR_INVALID_CURSOR_HANDLE); return 0; }
    if (!t) return 0;
    old = t->cursor;
    t->cursor = h;
    if (old != h || !t->cursor_init) u32_cursor_push();
    return old;
}

DLLAPI HCURSOR WINAPI GetCursor(void) { u32_thread_t *t = u32_ts(); return t ? t->cursor : 0; }

DLLAPI int WINAPI ShowCursor(BOOL show) { return u32_cursor_count(show ? 1 : -1); }

int u32_icon_count(void)
{
    int i, n = 0;
    icon_lock();
    for (i = 0; i < NICONS; ++i) n += g_icons[i].used && !g_icons[i].shared;
    icon_unlock();
    return n;
}
