/* SPDX-License-Identifier: GPL-2.0-only
 * Successor of font23/shz_text_noto.c (that draft is preserved unchanged as history).
 * ShzTextMeasureW/ShzTextDrawW (API of shz_text.h) over noto_provider (Noto Sans + Noto Sans KR, FreeType).
 * Differences from the draft: once-init state machine (no start-up race, failure remembered, memory barrier before
 * publication), wrapper-owned lock serializing whole measure/draw (no Sleep/BUSY retry), px adapters, provider shutdown, shz_text.h is included (not redeclared), missing glyphs are
 * reported (ShzTextMeasureExW) instead of silently drawn. Not for GDI32/USER32 (they call noto_provider directly).
 * Fails explicitly when the font files are absent: no VGA/bitmap fallback and no fake "ready". */
#include <limits.h>
#include "noto_win32.h"
#include "noto_asset_pins.h"   /* compiled SHA-256 pins from the root NAS font-package manifest */
#include <string.h>
#include "shz_text_diag.h"

enum { ST_NEW = 0, ST_INIT = 1, ST_READY = 2, ST_FAILED = 3, ST_STOPPED = 4 };
static volatile LONG g_state = ST_NEW;
static NotoProvider *g_provider;      /* written once before ST_READY is published */
static DWORD g_fail_win32;            /* written once before ST_FAILED is published */
static int g_fail_noto;
static CRITICAL_SECTION g_lock;       /* wrapper-owned: serializes whole measure/draw; initialised once by the single
                                       * initialiser BEFORE ST_READY is published (never inside DllMain) */

static DWORD map_status(NotoStatus st)
{
    switch (st) {
    case NOTO_E_UNAVAILABLE: return ERROR_FILE_NOT_FOUND;  /* font asset file absent */
    case NOTO_E_HASH:   return ERROR_CRC;                  /* bytes differ from the compiled SHA-256 pin */
    case NOTO_E_COVERAGE: return ERROR_NOT_SUPPORTED;      /* family ok, required glyph coverage missing */
    case NOTO_E_FONT:   return ERROR_INVALID_DATA;         /* unreadable/over budget/bad font data */
    case NOTO_E_NOMEM:  return ERROR_NOT_ENOUGH_MEMORY;
    case NOTO_E_BUSY:   return ERROR_BUSY;
    case NOTO_E_PARAM:
    case NOTO_E_RANGE:  return ERROR_INVALID_PARAMETER;
    default:            return ERROR_INVALID_DATA;         /* family/FreeType/bitmap failure */
    }
}

BOOL ShzTextFontInit(DWORD *win32, int *noto_status)
{
    int waited = 0;
    for (;;) {
        LONG s = InterlockedCompareExchange(&g_state, ST_INIT, ST_NEW);   /* full barrier */
        if (s == ST_NEW) {                                                /* we are the single initialiser */
            NotoProvider *p = NULL;
            static uint8_t pin_l[NOTO_SHA256_LEN], pin_k[NOTO_SHA256_LEN];
            NotoWin32Assets as;
            NotoStatus st = noto_pin_from_hex(NOTO_PIN_LATIN_HEX, pin_l);
            if (st == NOTO_OK) st = noto_pin_from_hex(NOTO_PIN_KR_HEX, pin_k);
            memset(&as, 0, sizeof as);
            as.latin_path = NOTO_PIN_LATIN_PATH; as.latin_face = NOTO_PIN_LATIN_FACE; as.latin_sha256 = pin_l;
            as.kr_path = NOTO_PIN_KR_PATH;       as.kr_face = NOTO_PIN_KR_FACE;       as.kr_sha256 = pin_k;
            if (st == NOTO_OK) st = noto_win32_open(&as, &p);
            if (st == NOTO_OK && p) {
                InitializeCriticalSection(&g_lock);
                g_provider = p;
                MemoryBarrier();
                InterlockedExchange(&g_state, ST_READY);
            } else {
                g_fail_noto = (int)(st == NOTO_OK ? NOTO_E_FREETYPE : st);
                g_fail_win32 = map_status((NotoStatus)g_fail_noto);
                MemoryBarrier();
                InterlockedExchange(&g_state, ST_FAILED);
            }
            continue;
        }
        if (s == ST_READY) {
            if (win32) *win32 = 0;
            if (noto_status) *noto_status = NOTO_OK;
            return TRUE;
        }
        if (s == ST_FAILED) {
            SetLastError(g_fail_win32);
            if (win32) *win32 = g_fail_win32;
            if (noto_status) *noto_status = g_fail_noto;
            return FALSE;
        }
        if (s == ST_STOPPED) {
            SetLastError(ERROR_INVALID_STATE);
            if (win32) *win32 = ERROR_INVALID_STATE;
            if (noto_status) *noto_status = NOTO_E_UNAVAILABLE;
            return FALSE;
        }
        if (waited >= 5000) {                                             /* initialiser still running: do not remember */
            SetLastError(ERROR_BUSY);
            if (win32) *win32 = ERROR_BUSY;
            if (noto_status) *noto_status = NOTO_E_BUSY;
            return FALSE;
        }
        Sleep(1); ++waited;
    }
}

static BOOL bound(LPCWSTR text, int *length)
{
    int n = 0;
    if (!text || *length < -1) return FALSE;
    if (*length == -1) { while (text[n]) { if (n == NOTO_MAX_TEXT) return FALSE; ++n; } *length = n; }
    return *length <= NOTO_MAX_TEXT;
}

/* Enter the wrapper lock after a successful init; NULL = unavailable (init failed or provider shut down).
 * On success the caller owns g_lock and must LeaveCriticalSection. */
static NotoProvider *enter(void)
{
    if (!ShzTextFontInit(NULL, NULL)) return NULL;                         /* SetLastError already done */
    EnterCriticalSection(&g_lock);
    if (!g_provider) { LeaveCriticalSection(&g_lock); SetLastError(ERROR_INVALID_STATE); return NULL; }
    return g_provider;
}

BOOL ShzTextMeasurePxExW(LPCWSTR text, int length, int px, SIZE *extent, unsigned *missing, int *ascent)
{
    NotoProvider *p; NotoExtent e; NotoStatus st;
    if (missing) *missing = 0;
    if (ascent) *ascent = 0;
    if (!extent || px < NOTO_MIN_PIXELS || px > NOTO_MAX_PIXELS || !bound(text, &length)) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    if (!(p = enter())) return FALSE;
    st = noto_measure_px(p, (const uint16_t *)text, (size_t)length, px, &e);
    LeaveCriticalSection(&g_lock);
    if (st != NOTO_OK) { SetLastError(map_status(st)); return FALSE; }
    extent->cx = e.cx; extent->cy = e.cy;
    if (missing) *missing = e.missing;
    if (ascent) *ascent = e.ascent;
    return TRUE;
}

BOOL ShzTextMeasureExW(LPCWSTR text, int length, int scale, SIZE *extent, unsigned *missing, int *ascent)
{
    if (scale < 1 || scale > NOTO_MAX_SCALE) { if (missing) *missing = 0; if (ascent) *ascent = 0; SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return ShzTextMeasurePxExW(text, length, scale * NOTO_BASE_PIXELS, extent, missing, ascent);
}

BOOL ShzTextMeasureW(LPCWSTR text, int length, int scale, SIZE *extent)
{
    return ShzTextMeasureExW(text, length, scale, extent, NULL, NULL);
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

BOOL ShzTextDrawPxW(HDC dc, int x, int y, LPCWSTR text, int length, COLORREF foreground, int px)
{
    NotoProvider *p; DrawCtx d; NotoPen pen; NotoStatus st;
    memset(&pen, 0, sizeof pen);
    if (!dc || px < NOTO_MIN_PIXELS || px > NOTO_MAX_PIXELS || !bound(text, &length)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!length) return TRUE;
    d.dc = dc; d.fg = foreground & 0xFFFFFF;
    if (!(p = enter())) return FALSE;
    st = noto_draw_px(p, (const uint16_t *)text, (size_t)length, px, x, y, NULL, span, &d, &pen);
    LeaveCriticalSection(&g_lock);
    if (st != NOTO_OK) { SetLastError(st == NOTO_E_ABORT ? ERROR_INVALID_PARAMETER : map_status(st)); return FALSE; }
    return TRUE;
}

BOOL ShzTextDrawW(HDC dc, int x, int y, LPCWSTR text, int length, COLORREF foreground, int scale)
{
    if (scale < 1 || scale > NOTO_MAX_SCALE) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return ShzTextDrawPxW(dc, x, y, text, length, foreground, scale * NOTO_BASE_PIXELS);
}

/* Owner-side teardown (call only at shell exit, not from DllMain). Destroys the provider under the wrapper lock;
 * later calls fail with ERROR_INVALID_STATE. NOTO_E_BUSY cannot happen while we hold the lock. */
BOOL ShzTextFontShutdown(void)
{
    NotoStatus st;
    if (g_state != ST_READY) return TRUE;
    EnterCriticalSection(&g_lock);
    st = g_provider ? noto_destroy(g_provider) : NOTO_OK;
    if (st == NOTO_OK) {
        g_provider = NULL;
        InterlockedExchange(&g_state, ST_STOPPED);    /* never report ready after the faces are destroyed */
    }
    LeaveCriticalSection(&g_lock);
    if (st != NOTO_OK) { SetLastError(map_status(st)); return FALSE; }
    return TRUE;
}
