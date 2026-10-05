/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32 text. The system font is Noto Sans (regular, weight 400) with Noto Sans KR for Hangul, realised by the ONE shared
 * NotoProvider (integration/shizuku-font, FreeType) that also answers every metric, so measuring and drawing cannot
 * disagree. gdi_noto.c holds the portable provider adapter (host-tested); this file maps it onto GDI objects.
 *
 * Contract:
 *  - The provider is opened lazily from the pinned assets C:\SHZ\FONTS\NotoSans.ttf / NotoSansKR.otf (noto_asset_pins.h,
 *    compiled root pins; the SHA-256 of both files is verified by the loader). If they are absent or do
 *    not match, every text call FAILS with a specific last error (ERROR_FILE_NOT_FOUND / ERROR_FILE_CORRUPT ...). There is no
 *    fallback bitmap or substitute font. The provider is never created in or destroyed from DllMain (pinned-resident for the life of
 *    the process, see "Provider lifetime"); the coarse GDI lock serialises every provider call and no callback outlives its call.
 *  - Requested vs actual: the requested face name is only a request. GetTextFaceW reports the family actually realised from
 *    the font file ("Noto Sans"); Hangul falls back to the Noto Sans KR face inside the same realisation. Only weight 400
 *    upright exists: a bold/italic request is realised regular and TEXTMETRIC reports tmWeight 400 / tmItalic 0.
 *  - Height: lfHeight < 0 is the em height in pixels, > 0 the cell height (ascent+descent), 0 a cell height of 16; the
 *    result must be 1..128 pixels, otherwise text calls fail with ERROR_INVALID_PARAMETER.
 *  - ExtTextOutW: ETO_OPAQUE, ETO_CLIPPED, dx (per UTF-16 code unit, pixels), TA_LEFT/CENTER/RIGHT, TA_TOP/BASELINE/BOTTOM,
 *    TA_UPDATECP, OPAQUE/TRANSPARENT background, underline and strike-out (drawn as bars) are honoured with 8 bit coverage
 *    blended into the destination RGB (alpha byte preserved) inside the DC clip. Refused with ERROR_NOT_SUPPORTED, never
 *    ignored: ETO_GLYPH_INDEX, ETO_RTLREADING, ETO_NUMERICSLOCAL/LATIN, ETO_IGNORELANGUAGE, ETO_PDY, TA_RTLREADING, non-zero
 *    escapement/orientation. Inside a path bracket the text adds the pixel runs whose coverage is >= 128 (a bitmap threshold,
 *    NOT an outline). GetFontData, GetGlyphIndicesW, GetOutlineTextMetrics and AddFontMemResourceEx are refused: this
 *    rasteriser exposes no TrueType tables, glyph indices (the realisation is a two-face composite) or outlines. */
#include "gdi_internal.h"
#include "gdi_noto.h"
#define _INC_WINDOWS 1                                             /* noto_win32.h wants <windows.h>; nt.h already provides the types */
#include "noto_win32.h"
_Static_assert(sizeof(WCHAR) == 2, "NotoWin32Assets path type must be UTF-16");
#include "noto_asset_pins.h"

#ifndef ETO_GLYPH_INDEX
#define ETO_GLYPH_INDEX 0x0010
#endif
#ifndef ETO_RTLREADING
#define ETO_RTLREADING 0x0080
#endif
#ifndef ETO_NUMERICSLOCAL
#define ETO_NUMERICSLOCAL 0x0400
#endif
#ifndef ETO_NUMERICSLATIN
#define ETO_NUMERICSLATIN 0x0800
#endif
#ifndef ETO_IGNORELANGUAGE
#define ETO_IGNORELANGUAGE 0x1000
#endif
#ifndef ETO_PDY
#define ETO_PDY 0x2000
#endif
#ifndef TA_RTLREADING
#define TA_RTLREADING 0x100
#endif
#define ETO_UNSUPPORTED (ETO_GLYPH_INDEX | ETO_RTLREADING | ETO_NUMERICSLOCAL | ETO_NUMERICSLATIN | ETO_IGNORELANGUAGE | ETO_PDY)
#define GDI_DEFAULT_LF_HEIGHT (-12)
#define GDI_TEXT_COORD (1 << 23)
#define GDI_CHAR_RANGE 0x10000u

_Static_assert(sizeof(RECT) == sizeof(NotoRect) && offsetof(RECT, left) == offsetof(NotoRect, left) &&
               offsetof(RECT, top) == offsetof(NotoRect, top) && offsetof(RECT, right) == offsetof(NotoRect, right) &&
               offsetof(RECT, bottom) == offsetof(NotoRect, bottom), "RECT must alias NotoRect");

/* ------------------------------------------------------------------ provider ownership (all under g_gdi_lock) */
static GdiNoto g_noto;
static int g_noto_ready;
static void *noto_mem_alloc(void *ctx, size_t n) { (void)ctx; return gdi_alloc(n); }
static void noto_mem_free(void *ctx, void *p) { (void)ctx; gdi_free(p); }
static const NotoConfig g_noto_cfg = { noto_mem_alloc, noto_mem_free, 0, 0 };
static uint64_t noto_now_ms(void) { return (uint64_t)GetTickCount64(); }

static NotoStatus noto_open_pinned(void *ctx, NotoProvider **out)
{
    uint8_t lpin[NOTO_SHA256_LEN], kpin[NOTO_SHA256_LEN];
    NotoWin32Assets a;
    NotoStatus st;
    (void)ctx;
    if ((st = noto_pin_from_hex(NOTO_PIN_LATIN_HEX, lpin)) != NOTO_OK) return st;
    if ((st = noto_pin_from_hex(NOTO_PIN_KR_HEX, kpin)) != NOTO_OK) return st;
    memset(&a, 0, sizeof a);
    a.latin_path = NOTO_PIN_LATIN_PATH; a.latin_face = NOTO_PIN_LATIN_FACE; a.latin_sha256 = lpin;
    a.kr_path = NOTO_PIN_KR_PATH; a.kr_face = NOTO_PIN_KR_FACE; a.kr_sha256 = kpin;
    a.cfg = &g_noto_cfg;
    return noto_win32_open(&a, out);
}

static DWORD noto_error(NotoStatus st)
{
    switch (st) {
    case NOTO_E_UNAVAILABLE: return ERROR_FILE_NOT_FOUND;
    case NOTO_E_HASH: case NOTO_E_COVERAGE: case NOTO_E_FONT: case NOTO_E_FAMILY: case NOTO_E_FREETYPE: case NOTO_E_BITMAP:
        return ERROR_FILE_CORRUPT;
    case NOTO_E_NOMEM: return ERROR_NOT_ENOUGH_MEMORY;
    case NOTO_E_BUSY: return ERROR_BUSY;
    case NOTO_E_PARAM: case NOTO_E_RANGE: return ERROR_INVALID_PARAMETER;
    default: return ERROR_GEN_FAILURE;
    }
}

static NotoProvider *provider(void)
{
    NotoStatus st;
    NotoProvider *p;
    if (!g_noto_ready) { gdi_noto_init(&g_noto, noto_open_pinned, 0, noto_now_ms); g_noto_ready = 1; }
    p = gdi_noto_get(&g_noto, &st);
    if (!p) SetLastError(noto_error(st));
    return p;
}

/* Provider lifetime: PINNED-RESIDENT. The provider is opened on first use under the GDI lock and then stays alive until
 * the process exits (the OS reclaims the heap and file buffers). It is deliberately never destroyed from DllMain/the loader
 * lock, and no teardown entry point is exported because nothing in the tree could call it safely while other threads
 * draw. A FreeLibrary of gdi32 therefore leaks the provider (about 3 MiB plus the FreeType heap); gdi32 is never unloaded
 * in practice. gdi_noto_release (host-tested) exists for an owner that can quiesce all users. */

/* ------------------------------------------------------------------ font realisation */
typedef struct { NotoProvider *p; int px; GdiNotoTM tm; } fontctx_t;

int gdi_font_scale(dc_t *dc)
{
    font_t *f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
    return f ? f->scale : 1;
}

static int font_ctx(dc_t *dc, fontctx_t *fc)
{
    font_t *f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
    NotoStatus st;
    memset(fc, 0, sizeof *fc);
    fc->p = provider();
    if (!fc->p) return 0;
    if (f && f->px_state == 1) fc->px = f->px;
    else if (f && f->px_state == 2) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    else {
        st = gdi_noto_resolve_px(fc->p, f ? f->lf.lfHeight : GDI_DEFAULT_LF_HEIGHT, &fc->px);
        if (st == NOTO_E_RANGE && f) f->px_state = 2;
        if (st != NOTO_OK) { SetLastError(noto_error(st)); return 0; }
        if (f) { f->px = fc->px; f->px_state = 1; }
    }
    if ((st = gdi_noto_text_metrics(fc->p, fc->px, &fc->tm)) != NOTO_OK) { SetLastError(noto_error(st)); return 0; }
    return 1;
}

/* the family actually realised (from the font file), widened; returns the length including the terminator */
static int actual_face(NotoProvider *p, WCHAR *w, int cap)
{
    const char *fam = noto_family(p, 0);
    int i = 0;
    if (!fam) return 0;
    while (fam[i] && i < cap - 1) { w[i] = (unsigned char)fam[i]; ++i; }
    w[i] = 0;
    return i + 1;
}

static int face_equal(const WCHAR *a, const WCHAR *b)
{
    int i;
    for (i = 0; a[i] && b[i]; ++i)
        if ((a[i] | 0x20) != (b[i] | 0x20)) return 0;
    return a[i] == b[i];
}

/* ------------------------------------------------------------------ drawing */
typedef struct { dc_t *dc; } path_ctx_t;
static int path_run(void *vctx, int x, int y, int n)
{
    path_ctx_t *c = vctx;
    return !gdi_path_rect_dev(c->dc, x, y, x + n, y + 1, 1);
}

static void bars(int px, int baseline, int *ul_top, int *st_top, int *thick)
{
    int t = (px + 8) / 16;
    if (t < 1) t = 1;
    *thick = t;
    *ul_top = baseline + t;
    *st_top = baseline - (px * 4) / 10 - t / 2;
}

static void dev_rect(const dc_t *dc, const RECT *rc, RECT *dev)
{
    dev->left = dc_lx(dc, rc->left); dev->right = dc_lx(dc, rc->right);
    dev->top = dc_ly(dc, rc->top); dev->bottom = dc_ly(dc, rc->bottom);
}

static BOOL text_out(dc_t *dc, int x, int y, UINT options, const RECT *rc, const WCHAR *s, UINT n, const INT *dx)
{
    gctx_t g;
    fontctx_t fc;
    font_t *f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
    const UINT align = dc->textalign;
    const int updatecp = (align & TA_UPDATECP) != 0;
    int64_t width = 0, ax, ay, tx64, ty64;
    int tx, ty, i, ul_top, st_top, thick, have_clip = 0, ok = 0;
    rlist_t clipped;
    NotoStatus st;
    if (options & ~(UINT)(ETO_OPAQUE | ETO_CLIPPED | ETO_UNSUPPORTED)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if ((options & ETO_UNSUPPORTED) || (align & TA_RTLREADING) || (f && (f->lf.lfEscapement || f->lf.lfOrientation))) {
        SetLastError(ERROR_NOT_SUPPORTED);                          /* refused, never silently ignored */
        return FALSE;
    }
    if (n > NOTO_MAX_TEXT) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (updatecp) { x = dc->pos.x; y = dc->pos.y; }
    memset(&fc, 0, sizeof fc);
    if (n && !font_ctx(dc, &fc)) return FALSE;
    if (n) {
        if (dx) {
            for (i = 0; i < (int)n; ++i) {
                if (dx[i] < 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
                width += dx[i];
            }
        } else {
            int cx, cy;
            st = gdi_noto_extent(fc.p, (const uint16_t *)s, n, fc.px, &cx, &cy, 0);
            if (st != NOTO_OK) { SetLastError(noto_error(st)); return FALSE; }
            width = cx;
        }
    }
    ax = x;
    if ((align & 6) == TA_CENTER) ax -= width / 2;
    else if ((align & 6) == TA_RIGHT) ax -= width;
    ay = y;
    if ((align & TA_BASELINE) == TA_BASELINE) ay -= fc.tm.ascent;
    else if (align & TA_BOTTOM) ay -= fc.tm.height;
    tx64 = ax + dc_ox(dc);
    ty64 = ay + dc_oy(dc);
    if (n && (tx64 < -GDI_TEXT_COORD || tx64 > GDI_TEXT_COORD || ty64 < -GDI_TEXT_COORD || ty64 > GDI_TEXT_COORD ||
              width > GDI_TEXT_COORD)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    tx = (int)tx64;
    ty = (int)ty64;
    bars(fc.px, ty + fc.tm.ascent, &ul_top, &st_top, &thick);
    if (gdi_path_recording(dc)) {
        path_ctx_t pc;
        pc.dc = dc;
        if (n) {
            st = gdi_noto_runs(fc.p, (const uint16_t *)s, n, fc.px, tx, ty, dx, path_run, &pc);
            if (st != NOTO_OK) { SetLastError(st == NOTO_E_ABORT ? ERROR_NOT_ENOUGH_MEMORY : noto_error(st)); return FALSE; }
            if (f && f->lf.lfUnderline && !gdi_path_rect_dev(dc, tx, ul_top, tx + (int)width, ul_top + thick, 1)) return FALSE;
            if (f && f->lf.lfStrikeOut && !gdi_path_rect_dev(dc, tx, st_top, tx + (int)width, st_top + thick, 1)) return FALSE;
        }
        if (updatecp) dc->pos.x = (int)(ax + width);
        return TRUE;
    }
    if (!gctx_begin(&g, dc)) return TRUE;
    rl_init(&clipped);
    if ((options & ETO_CLIPPED) && rc) {                            /* the clip of this call only: the DC's own lists stay untouched */
        RECT dev;
        rlist_t only;
        dev_rect(dc, rc, &dev);
        rl_init(&only);
        if (!rc_is_empty(&dev) && !rl_add_rect(&only, &dev)) { rl_free(&only); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        if (!rl_intersect(&clipped, g.clip, &only)) { rl_free(&only); rl_free(&clipped); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        rl_free(&only);
        have_clip = 1;
        g.clip = &clipped;
    }
    if ((options & ETO_OPAQUE) && rc) {
        RECT dev;
        int yy;
        dev_rect(dc, rc, &dev);
        for (yy = dev.top; yy < dev.bottom; ++yy) gctx_span_rop2(&g, dev.left, dev.right, yy, colorref_to_pixel(dc->bk_color), R2_COPYPEN);
    }
    if (n) {
        const uint32_t fg = colorref_to_pixel(dc->text);
        GdiNotoSurface surf;
        GdiNotoDirty d;
        if (dc->bkmode == OPAQUE) {
            int yy;
            for (yy = ty; yy < ty + fc.tm.height; ++yy) gctx_span_rop2(&g, tx, tx + (int)width, yy, colorref_to_pixel(dc->bk_color), R2_COPYPEN);
        }
        surf.bits = g.bm->bits; surf.w = g.bm->w; surf.h = g.bm->h; surf.topdown = g.bm->topdown;
        memset(&d, 0, sizeof d);
        st = gdi_noto_draw(fc.p, &surf, (const NotoRect *)g.clip->r, g.clip->n, (const uint16_t *)s, n, fc.px, tx, ty, dx, fg, &d);
        if (d.valid) {                                              /* merge the blended area into the call's dirty rectangle */
            if (!g.has_dirty) { g.dirty.left = d.r.left; g.dirty.top = d.r.top; g.dirty.right = d.r.right; g.dirty.bottom = d.r.bottom; g.has_dirty = 1; }
            else {
                if (d.r.left < g.dirty.left) g.dirty.left = d.r.left;
                if (d.r.top < g.dirty.top) g.dirty.top = d.r.top;
                if (d.r.right > g.dirty.right) g.dirty.right = d.r.right;
                if (d.r.bottom > g.dirty.bottom) g.dirty.bottom = d.r.bottom;
            }
        }
        if (st != NOTO_OK) { SetLastError(noto_error(st)); goto done; }
        if (f && f->lf.lfUnderline)
            for (i = 0; i < thick; ++i) gctx_span_rop2(&g, tx, tx + (int)width, ul_top + i, fg, R2_COPYPEN);
        if (f && f->lf.lfStrikeOut)
            for (i = 0; i < thick; ++i) gctx_span_rop2(&g, tx, tx + (int)width, st_top + i, fg, R2_COPYPEN);
    }
    if (updatecp) dc->pos.x = (int)(ax + width);
    ok = 1;
done:
    if (have_clip) rl_free(&clipped);
    gctx_end(&g);                                                   /* whatever was drawn is presented, also after a failure */
    return ok ? TRUE : FALSE;
}

DLLAPI BOOL WINAPI ExtTextOutW(HDC hdc, int x, int y, UINT options, const RECT *rc, LPCWSTR s, UINT n, const INT *dx)
{
    dc_t *dc;
    BOOL ok;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (n && !s) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    ok = text_out(dc, x, y, options, rc, s, n, dx);
    RET(ok);
}

DLLAPI BOOL WINAPI TextOutW(HDC hdc, int x, int y, LPCWSTR s, int n)
{
    if (n < 0) return FALSE;
    return ExtTextOutW(hdc, x, y, 0, 0, s, (UINT)n, 0);
}

/* ------------------------------------------------------------------ measuring (the same provider as the drawing) */
DLLAPI BOOL WINAPI GetTextExtentPoint32W(HDC hdc, LPCWSTR s, int n, LPSIZE sz)
{
    dc_t *dc;
    fontctx_t fc;
    int cx = 0, cy;
    NotoStatus st;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !sz || n < 0 || n > NOTO_MAX_TEXT || (n && !s)) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    if (!font_ctx(dc, &fc)) RET(FALSE);
    cy = fc.tm.height;
    if (n && (st = gdi_noto_extent(fc.p, (const uint16_t *)s, (size_t)n, fc.px, &cx, &cy, 0)) != NOTO_OK) {
        SetLastError(noto_error(st));
        RET(FALSE);
    }
    sz->cx = cx;
    sz->cy = cy;
    RET(TRUE);
}

DLLAPI BOOL WINAPI GetTextExtentExPointW(HDC hdc, LPCWSTR s, int n, int maxw, LPINT fit, LPINT dx, LPSIZE sz)
{
    dc_t *dc;
    fontctx_t fc;
    int cx = 0, cy, nfit = 0;
    NotoStatus st;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !sz || n < 0 || n > NOTO_MAX_TEXT || (n && !s)) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    if (!font_ctx(dc, &fc)) RET(FALSE);
    cy = fc.tm.height;
    st = gdi_noto_extent_ex(fc.p, (const uint16_t *)s, (size_t)n, fc.px, maxw, &nfit, dx, &cx, &cy);
    if (st != NOTO_OK) { SetLastError(noto_error(st)); RET(FALSE); }
    if (fit) *fit = nfit;
    sz->cx = cx;
    sz->cy = cy;
    RET(TRUE);
}

DLLAPI BOOL WINAPI GetTextMetricsW(HDC hdc, LPTEXTMETRICW tm)
{
    dc_t *dc;
    font_t *f;
    fontctx_t fc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !tm) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    if (!font_ctx(dc, &fc)) RET(FALSE);
    f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
    memset(tm, 0, sizeof *tm);
    tm->tmHeight = fc.tm.height;
    tm->tmAscent = fc.tm.ascent;
    tm->tmDescent = fc.tm.descent;
    tm->tmInternalLeading = fc.tm.internal_leading;
    tm->tmExternalLeading = 0;
    tm->tmAveCharWidth = fc.tm.avg_width;
    tm->tmMaxCharWidth = fc.tm.max_width;                          /* widest of printable ASCII and U+AC00 */
    tm->tmWeight = FW_NORMAL;                                      /* the ACTUAL weight: only regular exists */
    tm->tmDigitizedAspectX = 96;
    tm->tmDigitizedAspectY = 96;
    tm->tmFirstChar = 0x20;
    tm->tmLastChar = 0xffff;
    tm->tmDefaultChar = 0xfffd;
    tm->tmBreakChar = ' ';
    tm->tmItalic = 0;                                              /* not synthesised */
    tm->tmUnderlined = f ? f->lf.lfUnderline : 0;                  /* drawn as a bar */
    tm->tmStruckOut = f ? f->lf.lfStrikeOut : 0;
    tm->tmPitchAndFamily = 1 /* TMPF_FIXED_PITCH: variable pitch */ | FF_SWISS;
    tm->tmCharSet = ANSI_CHARSET;
    RET(TRUE);
}

/* GetTextFace* report the family ACTUALLY realised, not the requested name; 0 + last error when no font can be realised */
DLLAPI int WINAPI GetTextFaceW(HDC hdc, int count, LPWSTR buf)
{
    dc_t *dc;
    NotoProvider *p;
    WCHAR face[LF_FACESIZE];
    int n;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    p = provider();
    if (!p) RET(0);
    n = actual_face(p, face, LF_FACESIZE);
    if (n <= 0) { SetLastError(ERROR_FILE_CORRUPT); RET(0); }
    if (!buf) RET(n);
    if (count < n) n = count;
    if (n > 0) { memcpy(buf, face, (size_t)n * sizeof(WCHAR)); buf[n - 1] = 0; }
    RET(n);
}

DLLAPI int WINAPI GetTextFaceA(HDC hdc, int count, LPSTR buf)
{
    WCHAR w[LF_FACESIZE];
    int n, i;
    n = GetTextFaceW(hdc, LF_FACESIZE, w);
    if (n <= 0) return 0;
    if (!buf) return n;
    if (count < n) n = count;
    for (i = 0; i < n; ++i) buf[i] = (char)w[i];
    if (n > 0) buf[n - 1] = 0;
    return n;
}

static int char_arg(UINT first, UINT last, uint32_t *code, UINT i)
{
    (void)first; (void)last;
    if (i > 0x10ffffu) return 0;
    *code = (i >= 0xd800u && i <= 0xdfffu) ? 0xfffdu : i;           /* an unpaired surrogate unit measures as U+FFFD */
    return 1;
}

DLLAPI BOOL WINAPI GetCharWidthW(HDC hdc, UINT first, UINT last, LPINT out)
{
    dc_t *dc;
    UINT i;
    fontctx_t fc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !out || last < first || last - first >= GDI_CHAR_RANGE) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    if (!font_ctx(dc, &fc)) RET(FALSE);
    for (i = first; i <= last; ++i) {
        uint32_t code;
        NotoStatus st;
        if (!char_arg(first, last, &code, i)) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
        if ((st = gdi_noto_char_width(fc.p, code, fc.px, &out[i - first])) != NOTO_OK) { SetLastError(noto_error(st)); RET(FALSE); }
        if (i == 0xffffffffu) break;
    }
    RET(TRUE);
}

DLLAPI BOOL WINAPI GetCharWidth32W(HDC hdc, UINT first, UINT last, LPINT out)
{
    return GetCharWidthW(hdc, first, last, out);
}

DLLAPI BOOL WINAPI GetCharABCWidthsW(HDC hdc, UINT first, UINT last, LPABC abc)
{
    dc_t *dc;
    UINT i;
    fontctx_t fc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!abc || last < first || last - first >= GDI_CHAR_RANGE) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    if (!font_ctx(dc, &fc)) RET(FALSE);
    for (i = first; i <= last; ++i) {
        uint32_t code;
        GdiNotoABC v;
        NotoStatus st;
        if (!char_arg(first, last, &code, i)) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
        if ((st = gdi_noto_abc(fc.p, code, fc.px, &v)) != NOTO_OK) { SetLastError(noto_error(st)); RET(FALSE); }
        abc[i - first].abcA = v.a;
        abc[i - first].abcB = (UINT)v.b;
        abc[i - first].abcC = v.c;
        if (i == 0xffffffffu) break;
    }
    RET(TRUE);
}

/* ------------------------------------------------------------------ enumeration: the one family that is realised */
DLLAPI int WINAPI EnumFontFamiliesExW(HDC hdc, LPLOGFONTW lf, FONTENUMPROCW proc, LPARAM lparam, DWORD flags)
{
    ENUMLOGFONTEXW e;
    NEWTEXTMETRICEXW tm;
    dc_t *dc;
    NotoProvider *p;
    GdiNotoTM m;
    WCHAR face[LF_FACESIZE];
    NotoStatus st;
    (void)flags;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !proc) { GDI_LEAVE(); SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    p = provider();
    if (!p || actual_face(p, face, LF_FACESIZE) <= 0 || (st = gdi_noto_text_metrics(p, 16, &m)) != NOTO_OK) {
        GDI_LEAVE();
        return 0;                                                  /* last error was set by provider() */
    }
    if (lf && lf->lfCharSet != DEFAULT_CHARSET && lf->lfCharSet != ANSI_CHARSET && lf->lfCharSet != HANGEUL_CHARSET) { GDI_LEAVE(); return 1; }
    if (lf && lf->lfFaceName[0] && !face_equal(lf->lfFaceName, face)) { GDI_LEAVE(); return 1; }
    memset(&e, 0, sizeof e);
    memset(&tm, 0, sizeof tm);
    e.elfLogFont.lfHeight = -16;
    e.elfLogFont.lfWeight = FW_NORMAL;
    e.elfLogFont.lfCharSet = ANSI_CHARSET;
    e.elfLogFont.lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
    memcpy(e.elfLogFont.lfFaceName, face, sizeof face);
    memcpy(e.elfFullName, face, sizeof face);
    tm.ntmTm.tmHeight = m.height;
    tm.ntmTm.tmAscent = m.ascent;
    tm.ntmTm.tmDescent = m.descent;
    tm.ntmTm.tmInternalLeading = m.internal_leading;
    tm.ntmTm.tmAveCharWidth = m.avg_width;
    tm.ntmTm.tmMaxCharWidth = m.max_width;
    tm.ntmTm.tmWeight = FW_NORMAL;
    tm.ntmTm.tmFirstChar = 0x20;
    tm.ntmTm.tmLastChar = 0xffff;
    tm.ntmTm.tmDefaultChar = 0xfffd;
    tm.ntmTm.tmBreakChar = ' ';
    tm.ntmTm.tmPitchAndFamily = 1 | FF_SWISS;
    tm.ntmTm.tmCharSet = ANSI_CHARSET;
    GDI_LEAVE();                                                   /* the callback may call back into GDI */
    return proc(&e.elfLogFont, (const TEXTMETRICW *)&tm, 0, lparam);   /* font type 0: neither raster nor claimed TrueType */
}

DLLAPI int WINAPI EnumFontFamiliesExA(HDC hdc, LPLOGFONTA lf, FONTENUMPROCA proc, LPARAM lparam, DWORD flags)
{
    ENUMLOGFONTEXA e;
    NEWTEXTMETRICEXA tm;
    dc_t *dc;
    NotoProvider *p;
    GdiNotoTM m;
    WCHAR face[LF_FACESIZE];
    NotoStatus st;
    int i;
    (void)flags;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !proc) { GDI_LEAVE(); SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    p = provider();
    if (!p || actual_face(p, face, LF_FACESIZE) <= 0 || (st = gdi_noto_text_metrics(p, 16, &m)) != NOTO_OK) {
        GDI_LEAVE();
        return 0;
    }
    if (lf && lf->lfCharSet != DEFAULT_CHARSET && lf->lfCharSet != ANSI_CHARSET && lf->lfCharSet != HANGEUL_CHARSET) { GDI_LEAVE(); return 1; }
    if (lf && lf->lfFaceName[0]) {
        WCHAR req[LF_FACESIZE];
        for (i = 0; i < LF_FACESIZE - 1 && lf->lfFaceName[i]; ++i) req[i] = (unsigned char)lf->lfFaceName[i];
        req[i] = 0;
        if (!face_equal(req, face)) { GDI_LEAVE(); return 1; }
    }
    memset(&e, 0, sizeof e);
    memset(&tm, 0, sizeof tm);
    e.elfLogFont.lfHeight = -16;
    e.elfLogFont.lfWeight = FW_NORMAL;
    e.elfLogFont.lfCharSet = ANSI_CHARSET;
    e.elfLogFont.lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
    for (i = 0; face[i]; ++i) { e.elfLogFont.lfFaceName[i] = (CHAR)face[i]; e.elfFullName[i] = (BYTE)face[i]; }
    tm.ntmTm.tmHeight = m.height;
    tm.ntmTm.tmAscent = m.ascent;
    tm.ntmTm.tmDescent = m.descent;
    tm.ntmTm.tmInternalLeading = m.internal_leading;
    tm.ntmTm.tmAveCharWidth = m.avg_width;
    tm.ntmTm.tmMaxCharWidth = m.max_width;
    tm.ntmTm.tmWeight = FW_NORMAL;
    tm.ntmTm.tmFirstChar = 0x20;
    tm.ntmTm.tmLastChar = 0xff;                                    /* the ANSI view cannot name more */
    tm.ntmTm.tmDefaultChar = '?';
    tm.ntmTm.tmBreakChar = ' ';
    tm.ntmTm.tmPitchAndFamily = 1 | FF_SWISS;
    tm.ntmTm.tmCharSet = ANSI_CHARSET;
    GDI_LEAVE();
    return proc(&e.elfLogFont, (const TEXTMETRICA *)&tm, 0, lparam);
}

/* ------------------------------------------------------------------ explicitly unsupported advanced operations */
DLLAPI DWORD WINAPI GetFontData(HDC hdc, DWORD table, DWORD offset, LPVOID buf, DWORD size)
{
    (void)table; (void)offset; (void)buf; (void)size;
    if (!gdi_dc_get(hdc)) { SetLastError(ERROR_INVALID_HANDLE); return GDI_ERROR; }
    SetLastError(ERROR_NOT_SUPPORTED);                             /* the provider exposes no TrueType/OpenType tables */
    return GDI_ERROR;
}

DLLAPI DWORD WINAPI GetGlyphIndicesW(HDC hdc, LPCWSTR s, int n, LPWORD out, DWORD flags)
{
    (void)flags;
    if (!gdi_dc_get(hdc)) { SetLastError(ERROR_INVALID_HANDLE); return GDI_ERROR; }
    if (n < 0 || (n && (!s || !out))) { SetLastError(ERROR_INVALID_PARAMETER); return GDI_ERROR; }
    SetLastError(ERROR_NOT_SUPPORTED);                             /* glyph indices are per face; the realisation is a two-face composite */
    return GDI_ERROR;
}

DLLAPI UINT WINAPI GetOutlineTextMetricsW(HDC hdc, UINT size, LPOUTLINETEXTMETRICW otm)
{
    (void)size; (void)otm;
    SetLastError(gdi_dc_get(hdc) ? ERROR_NOT_SUPPORTED : ERROR_INVALID_HANDLE);   /* no outline metrics are exposed */
    return 0;
}

DLLAPI HANDLE WINAPI AddFontMemResourceEx(PVOID data, DWORD size, PVOID reserved, DWORD *count)
{
    (void)size; (void)reserved;
    if (!data || !count) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    *count = 0;
    SetLastError(ERROR_NOT_SUPPORTED);                             /* the system font set is fixed: pinned Noto assets only */
    return 0;
}

DLLAPI BOOL WINAPI RemoveFontMemResourceEx(HANDLE h)
{
    (void)h;
    SetLastError(ERROR_INVALID_HANDLE);                            /* AddFontMemResourceEx never returned one */
    return FALSE;
}

/* The charset / code page / font-signature bit correspondence of Windows (bit i of fsCsb[0] is entry i). */
static const struct { BYTE charset; UINT acp; } g_tci[32] = {
    { ANSI_CHARSET, 1252 }, { EASTEUROPE_CHARSET, 1250 }, { RUSSIAN_CHARSET, 1251 }, { GREEK_CHARSET, 1253 },
    { TURKISH_CHARSET, 1254 }, { HEBREW_CHARSET, 1255 }, { ARABIC_CHARSET, 1256 }, { BALTIC_CHARSET, 1257 },
    { VIETNAMESE_CHARSET, 1258 }, { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 },
    { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 },
    { THAI_CHARSET, 874 }, { SHIFTJIS_CHARSET, 932 }, { GB2312_CHARSET, 936 }, { HANGEUL_CHARSET, 949 },
    { CHINESEBIG5_CHARSET, 950 }, { JOHAB_CHARSET, 1361 }, { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 },
    { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 },
    { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 }, { DEFAULT_CHARSET, 0 }, { SYMBOL_CHARSET, 42 /* CP_SYMBOL */ } };

DLLAPI BOOL WINAPI TranslateCharsetInfo(DWORD *src, LPCHARSETINFO cs, DWORD flags)
{
    unsigned i = 0;
    if (!cs) return FALSE;
    switch (flags) {
    case TCI_SRCFONTSIG:
        if (!src) return FALSE;
        while (i < 32 && !((*src >> i) & 1)) ++i;
        break;
    case TCI_SRCCODEPAGE:
        while (i < 32 && (UINT)(ULONG_PTR)src != g_tci[i].acp) ++i;
        break;
    case TCI_SRCCHARSET:
        while (i < 32 && (UINT)(ULONG_PTR)src != g_tci[i].charset) ++i;
        break;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (i >= 32 || g_tci[i].charset == DEFAULT_CHARSET) return FALSE;
    memset(cs, 0, sizeof *cs);
    cs->ciCharset = g_tci[i].charset;
    cs->ciACP = g_tci[i].acp;
    cs->fs.fsCsb[0] = 1u << i;
    return TRUE;
}
