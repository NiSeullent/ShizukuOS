/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS shell wallpaper provider. See wallpaper.h. Original ShizukuOS code. */
#ifdef SHZ_THEME_NATIVE
#include <windows.h>
#endif
#include "wallpaper.h"

static uint32_t rd16(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return rd16(p) | (rd16(p + 2) << 16); }

int ShzBmpParseHeader(const uint8_t *h, size_t n, uint64_t fsize, SHZ_BMP_INFO *o)
{
    uint32_t hs, w, bpp, comp, off; int32_t sw, sh; uint64_t stride, need;
    if (!h || !o) return SHZ_WPE_NULL;
    if (n < 26) return SHZ_WPE_SHORT;
    if (h[0] != 'B' || h[1] != 'M') return SHZ_WPE_MAGIC;
    hs = rd32(h + 14);
    if (hs < 40 || hs > 124 || n < 14u + hs) return SHZ_WPE_HEADER;      /* OS/2 core header rejected */
    sw = (int32_t)rd32(h + 18); sh = (int32_t)rd32(h + 22);
    if (rd16(h + 26) != 1) return SHZ_WPE_HEADER;
    bpp = rd16(h + 28); comp = rd32(h + 30);
    if (comp != 0 || (bpp != 24 && bpp != 32)) return SHZ_WPE_FORMAT;    /* BI_RGB only; no BITFIELDS/RLE/indexed */
    if (sw <= 0 || sh == 0 || sh == (int32_t)0x80000000) return SHZ_WPE_SIZE;
    w = (uint32_t)sw;
    o->bottom_up = sh > 0;
    o->height = (uint32_t)(sh > 0 ? sh : -sh);
    if (w > SHZ_WP_MAX_W || o->height > SHZ_WP_MAX_H) return SHZ_WPE_SIZE;
    off = rd32(h + 10);
    stride = (((uint64_t)w * bpp + 31u) / 32u) * 4u;
    need = (uint64_t)off + stride * o->height;
    if (off < 14u + hs || need > fsize || fsize > SHZ_WP_MAX_FILE) return fsize > SHZ_WP_MAX_FILE ? SHZ_WPE_SIZE : SHZ_WPE_TRUNC;
    o->width = w; o->bpp = bpp; o->stride = (uint32_t)stride; o->data_off = off;
    return SHZ_WPE_OK;
}

void ShzBmpConvertRow(const SHZ_BMP_INFO *bi, const uint8_t *s, uint8_t *d)
{
    uint32_t x, step = bi->bpp / 8;
    for (x = 0; x < bi->width; ++x, s += step, d += 4) { d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = 0; }
}

int ShzWallpaperLayout(int style, int32_t sw, int32_t sh, int32_t dw, int32_t dh, SHZ_WP_RECT *s, SHZ_WP_RECT *d)
{
    int64_t a, b;
    if (!s || !d || sw <= 0 || sh <= 0 || dw <= 0 || dh <= 0) return 0;
    s->x = 0; s->y = 0; s->w = sw; s->h = sh; d->x = 0; d->y = 0; d->w = dw; d->h = dh;
    switch (style) {
    case 2: /* stretch (enum order fill|fit|stretch|tile|center) */
    case 3: return 1;                       /* tile: whole bitmap, painter repeats */
    case 0: /* fill: cover, crop source to destination aspect */
        a = (int64_t)sw * dh; b = (int64_t)dw * sh;
        if (a > b) { s->w = (int32_t)(((int64_t)dw * sh + dh - 1) / dh); if (s->w > sw) s->w = sw; if (s->w < 1) s->w = 1; s->x = (sw - s->w) / 2; }
        else if (a < b) { s->h = (int32_t)(((int64_t)dh * sw + dw - 1) / dw); if (s->h > sh) s->h = sh; if (s->h < 1) s->h = 1; s->y = (sh - s->h) / 2; }
        return 1;
    case 1: /* fit: contain, centered */
        a = (int64_t)sw * dh; b = (int64_t)dw * sh;
        if (a > b) { d->h = (int32_t)(((int64_t)sh * dw) / sw); if (d->h < 1) d->h = 1; d->y = (dh - d->h) / 2; }
        else if (a < b) { d->w = (int32_t)(((int64_t)sw * dh) / sh); if (d->w < 1) d->w = 1; d->x = (dw - d->w) / 2; }
        return 1;
    case 4: /* center 1:1, clipped */
        d->w = s->w = sw < dw ? sw : dw; d->h = s->h = sh < dh ? sh : dh;
        s->x = (sw - s->w) / 2; s->y = (sh - s->h) / 2; d->x = (dw - d->w) / 2; d->y = (dh - d->h) / 2;
        return 1;
    }
    return 0;
}

/* Preflight for tile style: 1 iff ceil(dw/w)*ceil(dh/h) (64-bit) is within the draw bound; 0 otherwise. Callers must
 * check this BEFORE drawing so an over-limit tiling never leaves a partial picture. (Not declared in wallpaper.h.) */
#define SHZ_WP_MAX_TILES 4096u
int ShzWallpaperTilesOk(int32_t dw, int32_t dh, uint32_t w, uint32_t h)
{
    uint64_t nx, ny;
    if (dw <= 0 || dh <= 0 || !w || !h) return 0;
    nx = ((uint64_t)dw + w - 1) / w; ny = ((uint64_t)dh + h - 1) / h;
    return nx * ny <= SHZ_WP_MAX_TILES;
}

#ifdef SHZ_THEME_NATIVE
static uint8_t g_pix[SHZ_WP_MAX_W * SHZ_WP_MAX_H * 4u];     /* single UI thread; bounded static, top-down B,G,R,0 */
static uint8_t g_row[SHZ_WP_MAX_W * 4u + 4u];
static SHZ_WP_STATUS g_st;
static int g_style;

const SHZ_WP_STATUS *ShzWallpaperStatus(void) { return &g_st; }

void ShzWallpaperRelease(void)
{
    g_st.image_ready = 0; g_st.generation = 0; g_st.width = g_st.height = 0;
    ShzThemeSetWallpaperReady(0);
}

static int fail(int e, uint32_t w32) { ShzWallpaperRelease(); g_st.err = e; g_st.win32 = w32; return e; }

int ShzWallpaperPrepare(const SHZ_THEME *t, int id, uint32_t gen, SHZ_WP_STATUS *out)
{
    HANDLE h = INVALID_HANDLE_VALUE; uint8_t hdr[SHZ_WP_HDR_MAX]; SHZ_BMP_INFO bi; LARGE_INTEGER sz;
    DWORD got = 0, y, e; int rc = SHZ_WPE_OK;
    ShzWallpaperRelease();                                   /* never keep the previous selection's picture */
    if (!t) rc = fail(SHZ_WPE_NULL, 0);
    else if (gen == 0 || gen != ShzThemeGeneration() || id != ShzThemeCurrentId() || t != ShzThemeCurrent()) rc = fail(SHZ_WPE_NULL, 0);   /* caller must pass the published theme, id and generation */
    else if (t->wallpaper_mode != SHZ_WP_IMAGE) rc = fail(SHZ_WPE_NOT_IMAGE_MODE, 0);
    else {
        { void *vh = 0; uint64_t fs = 0; e = ShzThemeWallpaperOpen(id, t->wallpaper_image, SHZ_WP_MAX_FILE, &vh, &fs); h = e ? INVALID_HANDLE_VALUE : (HANDLE)vh; sz.QuadPart = (LONGLONG)fs; }
        if (e) rc = fail(SHZ_WPE_IO, e);
        else if (!ReadFile(h, hdr, sizeof hdr < (DWORD)sz.QuadPart ? sizeof hdr : (DWORD)sz.QuadPart, &got, 0) || got < 26) rc = fail(SHZ_WPE_IO, GetLastError());
        else if ((rc = ShzBmpParseHeader(hdr, got, (uint64_t)sz.QuadPart, &bi)) != SHZ_WPE_OK) rc = fail(rc, 0);
        else if (SetFilePointer(h, (LONG)bi.data_off, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) rc = fail(SHZ_WPE_IO, GetLastError());
        else {
            for (y = 0; y < bi.height && rc == SHZ_WPE_OK; ++y) {
                uint32_t dy = bi.bottom_up ? bi.height - 1 - y : y, k = 0; unsigned guard = 0;
                while (k < bi.stride && guard++ < 64) {
                    got = 0;
                    if (!ReadFile(h, g_row + k, bi.stride - k, &got, 0) || !got || got > bi.stride - k) { rc = fail(SHZ_WPE_TRUNC, GetLastError()); break; }
                    k += got;
                }
                if (rc == SHZ_WPE_OK && k != bi.stride) rc = fail(SHZ_WPE_TRUNC, 0);
                if (rc == SHZ_WPE_OK) ShzBmpConvertRow(&bi, g_row, g_pix + (size_t)dy * bi.width * 4u);
            }
            if (rc == SHZ_WPE_OK) {
                g_st.err = 0; g_st.win32 = 0; g_st.generation = gen; g_st.width = bi.width; g_st.height = bi.height;
                g_style = t->wallpaper_style; g_st.image_ready = 1;
                ShzThemeSetWallpaperReady(gen);              /* capability only after real decode, bound to this generation */
            }
        }
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    if (out) *out = g_st;
    return rc;
}

int ShzWallpaperPaint(HDC dc, const RECT *a)
{
    BITMAPINFO bmi; int dw, dh, ok = 1;
    if (!dc || !a || !g_st.image_ready || g_st.generation != ShzThemeGeneration()) return 0;   /* stale => caller fallback */
    dw = a->right - a->left; dh = a->bottom - a->top;
    if (dw <= 0 || dh <= 0) return 0;
    ZeroMemory(&bmi, sizeof bmi);
    bmi.bmiHeader.biSize = sizeof bmi.bmiHeader; bmi.bmiHeader.biWidth = (LONG)g_st.width;
    bmi.bmiHeader.biHeight = -(LONG)g_st.height; bmi.bmiHeader.biPlanes = 1; bmi.bmiHeader.biBitCount = 32;
    if (g_style == 3) {
        int x, y, n = 0;
        if (!ShzWallpaperTilesOk(dw, dh, g_st.width, g_st.height)) return 0;   /* before any draw: caller fallback */
        for (y = 0; y < dh && ok && n < 4096; y += (int)g_st.height)
            for (x = 0; x < dw && n < 4096; x += (int)g_st.width, ++n) {
                int cw = dw - x < (int)g_st.width ? dw - x : (int)g_st.width, ch = dh - y < (int)g_st.height ? dh - y : (int)g_st.height;
                if (StretchDIBits(dc, a->left + x, a->top + y, cw, ch, 0, 0, cw, ch, g_pix, &bmi, DIB_RGB_COLORS, SRCCOPY) <= 0) { ok = 0; break; }
            }
        return ok;
    } else {
        SHZ_WP_RECT s, d;
        if (!ShzWallpaperLayout(g_style, (int32_t)g_st.width, (int32_t)g_st.height, dw, dh, &s, &d)) return 0;
        if (d.w < dw || d.h < dh) { HBRUSH b = CreateSolidBrush(ShzThemeCR(ShzThemeCurrent() ? ShzThemeCurrent()->wallpaper_color : 0)); if (b) { FillRect(dc, a, b); DeleteObject(b); } }
        if (!SetStretchBltMode(dc, COLORONCOLOR)) return 0;
        return StretchDIBits(dc, a->left + d.x, a->top + d.y, d.w, d.h, s.x, s.y, s.w, s.h, g_pix, &bmi, DIB_RGB_COLORS, SRCCOPY) > 0;
    }
}
#endif
