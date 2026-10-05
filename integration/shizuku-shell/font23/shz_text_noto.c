/* SPDX-License-Identifier: GPL-2.0-only
 * ShzTextMeasureW/ShzTextDrawW (API of integration/shizuku-font/shz_text.h, unchanged) over noto_provider.
 * Proposed replacement body for the protected shz_text.c; NOT yet wired into build.py. Not for GDI32/USER32
 * (they must call noto_provider directly). Fails explicitly when the Noto files are absent: no VGA/bitmap fallback. */
#include <limits.h>
#include "noto_win32.h"

BOOL ShzTextMeasureW(LPCWSTR text, int length, int scale, SIZE *extent);
BOOL ShzTextDrawW(HDC dc, int x, int y, LPCWSTR text, int length, COLORREF foreground, int scale);

static NotoProvider *g_provider;     /* process-wide wrapper-owned context; provider itself is serialized (BUSY) */
static volatile LONG g_init;

static NotoProvider *provider(void)
{
    if (!g_provider && !InterlockedExchange(&g_init, 1)) {
        NotoProvider *p = NULL;
        if (noto_win32_open_default(&p) == NOTO_OK) g_provider = p;
        InterlockedExchange(&g_init, 0);
    }
    return g_provider;
}

static BOOL bound(LPCWSTR text, int *length)
{
    int n = 0;
    if (!text || *length < -1) return FALSE;
    if (*length == -1) { while (text[n]) { if (n == NOTO_MAX_TEXT) return FALSE; ++n; } *length = n; }
    return *length <= NOTO_MAX_TEXT;
}

BOOL ShzTextMeasureW(LPCWSTR text, int length, int scale, SIZE *extent)
{
    NotoProvider *p; NotoExtent e;
    if (!extent || !bound(text, &length)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!(p = provider())) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }   /* font unavailable */
    if (noto_measure(p, (const uint16_t *)text, (size_t)length, scale, &e) != NOTO_OK) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    extent->cx = e.cx; extent->cy = e.cy;
    return TRUE;
}

typedef struct { HDC dc; COLORREF fg; } DrawCtx;

/* Composite against the ACTUAL destination: GetPixel==CLR_INVALID (outside DC clip) => skip, no SetPixel. */
static int span(void *c, int x, int y, const uint8_t *cov, int n)
{
    DrawCtx *d = c; int i, fr = GetRValue(d->fg), fg = GetGValue(d->fg), fb = GetBValue(d->fg);
    for (i = 0; i < n; ++i) {
        unsigned a = cov[i]; COLORREF bg;
        if (!a) continue;
        bg = GetPixel(d->dc, x + i, y);
        if (bg == CLR_INVALID) continue;
        if (a != 255)
            bg = RGB((GetRValue(bg) * (255 - a) + fr * a + 127) / 255, (GetGValue(bg) * (255 - a) + fg * a + 127) / 255,
                     (GetBValue(bg) * (255 - a) + fb * a + 127) / 255);
        else bg = d->fg;
        SetPixel(d->dc, x + i, y, bg);
    }
    return 0;
}

BOOL ShzTextDrawW(HDC dc, int x, int y, LPCWSTR text, int length, COLORREF foreground, int scale)
{
    NotoProvider *p; DrawCtx d; NotoPen pen = {0, 0}; NotoStatus st; int tries = 0;
    if (!dc || !bound(text, &length)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!length) return TRUE;
    if (!(p = provider())) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
    d.dc = dc; d.fg = foreground & 0xFFFFFF;
    do st = noto_draw(p, (const uint16_t *)text, (size_t)length, scale, x, y, NULL, span, &d, &pen);
    while (st == NOTO_E_BUSY && ++tries < 3 && (Sleep(1), 1));
    if (st != NOTO_OK) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}
