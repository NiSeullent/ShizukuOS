/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32 text. THE ONLY FONT THAT EXISTS is the built-in bitmap font of gdi_font.c: a 16-pixel cell (13 above the
 * baseline, 3 below) whose ASCII half is the public-domain 8x8 IBM VGA font with every row doubled (8 wide, unchanged
 * from the original ASCII-only gdi32) and whose non-ASCII glyphs are GNU Unifont 18.0.01 bitmaps (GPL-2.0-or-later with
 * the font embedding exception / OFL-1.1, fonts/LICENSE-unifont-18.0.01.txt): Latin-1, Hangul Jamo and compatibility
 * Jamo, all 11172 modern Hangul syllables (16 wide), CJK punctuation and fullwidth forms. Any other code point draws a
 * hollow notdef box (16 wide for East Asian wide code points, else 8) and GetGlyphIndices reports it as missing; a UTF-16
 * surrogate pair is one wide box (the low surrogate has no width). Every measuring call below adds the same per-unit
 * advances text_out draws with, so measurement equals rendering.
 *
 * CreateFont* always succeeds and always selects this font; the requested height only picks an integer scale of 1..4
 * (height 16 = 1, 32 = 2, ...), weight >= 600 is faked by a one-pixel smear, italic and rotation are ignored,
 * underline/strike-out are drawn as lines. There is no kerning, shaping or subpixel ClearType. Selected font qualities
 * render grayscale coverage; inside a path bracket, text adds its bitmap outline (one rectangle per run of set pixels)
 * instead of drawing (paths carry no coverage, so path text is the 1-bit glyph even when TextOut antialiases).
 * Antialiasing is grayscale coverage composited over the real destination pixels; see font_aa. ETO_GLYPH_INDEX strings are glyph indices as GetGlyphIndicesW returns them.
 *
 * Font queries answer for this font: it is a raster font, so it has no TrueType tables (GetFontData fails with GDI_ERROR)
 * and no outline metrics (GetOutlineTextMetrics returns 0, as Windows does for raster fonts). GetCharABCWidths reports its
 * real metrics (no overhang: A = C = 0) although Windows refuses the call for raster fonts. Fonts cannot be added from
 * memory (AddFontMemResourceEx fails: there is no TrueType rasteriser to use them with). */
#include "gdi_internal.h"
#include "gdi_font.h"

#define CELL_W GDI_FONT_NARROW
#define CELL_H GDI_FONT_CELL_H
#define ASCENT GDI_FONT_ASCENT

int gdi_font_scale(dc_t *dc)
{
    font_t *f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
    return f ? f->scale : 1;
}

static int font_bold(dc_t *dc)
{
    font_t *f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
    return f && f->lf.lfWeight >= 600;
}

/* the glyph text_out draws for s[i]: a character, or with ETO_GLYPH_INDEX a glyph index (unknown index -> notdef box) */
static void text_glyph(UINT options, WCHAR c, gdi_glyph_t *g)
{
    if (!(options & ETO_GLYPH_INDEX)) gdi_font_glyph(c, g);
    else if (!gdi_font_glyph_by_index(c, g)) gdi_font_glyph_by_index(0, g);
}

/* total unscaled-advance width of the string, times scale: exactly what text_out advances by when dx is absent */
static int text_width(UINT options, const WCHAR *s, int n, int scale)
{
    gdi_glyph_t g;
    int i, w = 0;
    for (i = 0; i < n; ++i) { text_glyph(options, s[i], &g); w += g.width * scale; }
    return w;
}

static int glyph_on(const gdi_glyph_t *g, int row, int col, int scale, int bold)
{
    const uint32_t bits = gdi_font_row(g, row / scale);
    return ((bits >> (col / scale)) & 1) || (bold && col > 0 && ((bits >> ((col - 1) / scale)) & 1));
}

/* Antialiasing policy, from LOGFONT lfQuality (grayscale only; CLEARTYPE_* get grayscale, never subpixel colour):
 * NONANTIALIASED_QUALITY: every glyph 1-bit. ANTIALIASED_QUALITY / CLEARTYPE_QUALITY / CLEARTYPE_NATURAL_QUALITY: every
 * glyph, ASCII included, is coverage-rendered (gdi_font_coverage). DEFAULT/DRAFT/PROOF: the Unifont glyphs (Hangul, Latin-1,
 * CJK punctuation, notdef box) are coverage-rendered while the ASCII VGA bitmap face keeps its exact 1-bit pixels. */
enum { AA_NONE, AA_NONASCII, AA_ALL };
static int font_aa(dc_t *dc)
{
    font_t *f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
    const int q = f ? f->lf.lfQuality : DEFAULT_QUALITY;
    if (q == NONANTIALIASED_QUALITY) return AA_NONE;
    if (q == ANTIALIASED_QUALITY || q == CLEARTYPE_QUALITY || q == CLEARTYPE_NATURAL_QUALITY) return AA_ALL;
    return AA_NONASCII;
}

/* composite fg over the destination pixel with coverage a, inside the effective clip (as gctx_pixel clips) */
static void blend_px(gctx_t *g, int x, int y, uint32_t fg, unsigned a)
{
    int i;
    if (!a) return;
    for (i = 0; i < g->clip->n; ++i) {
        const RECT *c = &g->clip->r[i];
        uint32_t *px;
        if (x < c->left || x >= c->right || y < c->top || y >= c->bottom) continue;
        px = bm_px(g->bm, x, y);
        *px = gdi_font_blend(*px, fg, a);
        if (!g->has_dirty) { g->dirty.left = x; g->dirty.top = y; g->dirty.right = x + 1; g->dirty.bottom = y + 1; g->has_dirty = 1; }
        else {
            if (x < g->dirty.left) g->dirty.left = x;
            if (y < g->dirty.top) g->dirty.top = y;
            if (x + 1 > g->dirty.right) g->dirty.right = x + 1;
            if (y + 1 > g->dirty.bottom) g->dirty.bottom = y + 1;
        }
        return;
    }
}

static void draw_glyph(gctx_t *g, int x, int y, const gdi_glyph_t *gl, int scale, uint32_t fg, uint32_t bg, int opaque, int bold, int aa)
{
    int row, col;
    if (aa == AA_ALL || (aa == AA_NONASCII && gl->kind != GDI_GLYPH_ASCII)) {
        for (row = 0; row < CELL_H * scale; ++row)
            for (col = 0; col < gl->width * scale; ++col) {
                const unsigned a = gdi_font_coverage(gl, scale, 1, bold, col, row);
                if (opaque) gctx_pixel(g, x + col, y + row, gdi_font_blend(bg, fg, a), R2_COPYPEN);
                else blend_px(g, x + col, y + row, fg, a);
            }
        return;
    }
    for (row = 0; row < CELL_H * scale; ++row)
        for (col = 0; col < gl->width * scale; ++col) {
            if (glyph_on(gl, row, col, scale, bold)) gctx_pixel(g, x + col, y + row, fg, R2_COPYPEN);
            else if (opaque) gctx_pixel(g, x + col, y + row, bg, R2_COPYPEN);
        }
}

/* the pixels draw_glyph would set, as path rectangles (device coordinates). ASCII rows are doubled font8x8 rows, so they
 * are emitted two cell rows at a time exactly as before; Unifont glyphs one cell row at a time. */
static BOOL glyph_path(dc_t *dc, int x, int y, const gdi_glyph_t *gl, int scale, int bold)
{
    const int step = gl->kind == GDI_GLYPH_ASCII ? 2 : 1;
    int fr, c, c0;
    for (fr = 0; fr < CELL_H; fr += step) {
        const int t = y + fr * scale, b = t + step * scale, r0 = fr * scale;
        for (c = 0; c < gl->width * scale;) {
            if (!glyph_on(gl, r0, c, scale, bold)) { ++c; continue; }
            c0 = c;
            while (c < gl->width * scale && glyph_on(gl, r0, c, scale, bold)) ++c;
            if (!gdi_path_rect_dev(dc, x + c0, t, x + c, b, 1)) return FALSE;
        }
    }
    return TRUE;
}

static BOOL text_out(dc_t *dc, int x, int y, UINT options, const RECT *rc, const WCHAR *s, UINT n, const INT *dx)
{
    gctx_t g;
    gdi_glyph_t gl;
    const int scale = gdi_font_scale(dc), ch = CELL_H * scale;
    int width = 0, x0, y0, tx, i, ty;
    UINT align = dc->textalign;
    const int updatecp = (align & TA_UPDATECP) != 0;
    rlist_t saved;
    int had_user = 0;
    if (updatecp) { x = dc->pos.x; y = dc->pos.y; }
    if (dx) for (i = 0; i < (int)n; ++i) width += dx[i];
    else width = text_width(options, s, (int)n, scale);
    if (gdi_path_recording(dc)) {
        font_t *f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
        const int bold = font_bold(dc);
        if ((align & 6) == TA_CENTER) x -= width / 2;
        else if ((align & 6) == TA_RIGHT) x -= width;
        if ((align & TA_BASELINE) == TA_BASELINE) y -= ASCENT * scale;
        else if (align & TA_BOTTOM) y -= ch;
        tx = dc_lx(dc, x);
        ty = dc_ly(dc, y);
        for (i = 0; i < (int)n; ++i) {
            text_glyph(options, s[i], &gl);
            if (!glyph_path(dc, tx, ty, &gl, scale, bold)) return FALSE;
            tx += dx ? dx[i] : gl.width * scale;
        }
        if (f && f->lf.lfUnderline && !gdi_path_rect_dev(dc, dc_lx(dc, x), ty + (ASCENT + 1) * scale, dc_lx(dc, x) + width, ty + (ASCENT + 2) * scale, 1)) return FALSE;
        if (f && f->lf.lfStrikeOut && !gdi_path_rect_dev(dc, dc_lx(dc, x), ty + 8 * scale, dc_lx(dc, x) + width, ty + 9 * scale, 1)) return FALSE;
        if (updatecp) dc->pos.x = x + width;
        return TRUE;
    }
    if (!gctx_begin(&g, dc)) return TRUE;
    if ((align & 6) == TA_CENTER) x -= width / 2;
    else if ((align & 6) == TA_RIGHT) x -= width;
    if ((align & TA_BASELINE) == TA_BASELINE) y -= ASCENT * scale;
    else if (align & TA_BOTTOM) y -= ch;
    x0 = dc_lx(dc, x);
    y0 = dc_ly(dc, y);
    tx = x0;
    ty = y0;
    if (options & ETO_CLIPPED && rc) {                              /* temporarily intersect the clip with the rectangle */
        RECT dev;
        rlist_t only, out;
        dev.left = dc_lx(dc, rc->left); dev.right = dc_lx(dc, rc->right); dev.top = dc_ly(dc, rc->top); dev.bottom = dc_ly(dc, rc->bottom);
        rl_init(&only); rl_init(&out);
        rl_add_rect(&only, &dev);
        rl_intersect(&out, g.clip, &only);
        saved = dc->eff;
        had_user = 1;
        dc->eff = out;
        g.clip = &dc->eff;
        rl_free(&only);
    }
    if ((options & ETO_OPAQUE) && rc) {
        RECT dev;
        int yy;
        dev.left = dc_lx(dc, rc->left); dev.right = dc_lx(dc, rc->right); dev.top = dc_ly(dc, rc->top); dev.bottom = dc_ly(dc, rc->bottom);
        for (yy = dev.top; yy < dev.bottom; ++yy) gctx_span_rop2(&g, dev.left, dev.right, yy, colorref_to_pixel(dc->bk_color), R2_COPYPEN);
    }
    {
        const uint32_t fg = colorref_to_pixel(dc->text), bg = colorref_to_pixel(dc->bk_color);
        const int opaque = dc->bkmode == OPAQUE, bold = font_bold(dc), aa = font_aa(dc);
        font_t *f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
        for (i = 0; i < (int)n; ++i) {
            text_glyph(options, s[i], &gl);
            draw_glyph(&g, tx, ty, &gl, scale, fg, bg, opaque, bold, aa);
            tx += dx ? dx[i] : gl.width * scale;
        }
        if (f && f->lf.lfUnderline)
            for (i = 0; i < scale; ++i) gctx_span_rop2(&g, x0, x0 + width, ty + (ASCENT + 1) * scale + i, fg, R2_COPYPEN);
        if (f && f->lf.lfStrikeOut)
            for (i = 0; i < scale; ++i) gctx_span_rop2(&g, x0, x0 + width, ty + 8 * scale + i, fg, R2_COPYPEN);
    }
    if (had_user) { rl_free(&dc->eff); dc->eff = saved; }
    if (updatecp) dc->pos.x = x + width;
    gctx_end(&g);
    return TRUE;
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

DLLAPI BOOL WINAPI GetTextExtentPoint32W(HDC hdc, LPCWSTR s, int n, LPSIZE sz)
{
    dc_t *dc;
    int scale;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !sz || n < 0 || (n && !s)) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    scale = gdi_font_scale(dc);
    sz->cx = text_width(0, s, n, scale);
    sz->cy = CELL_H * scale;
    RET(TRUE);
}

DLLAPI BOOL WINAPI GetTextExtentExPointW(HDC hdc, LPCWSTR s, int n, int maxw, LPINT fit, LPINT dx, LPSIZE sz)
{
    dc_t *dc;
    int scale, i, total = 0, nfit = 0;
    gdi_glyph_t gl;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !sz || n < 0 || (n && !s)) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    scale = gdi_font_scale(dc);
    for (i = 0; i < n; ++i) {
        gdi_font_glyph(s[i], &gl);
        total += gl.width * scale;
        if (dx) dx[i] = total;
        if (maxw < 0 || total <= maxw) nfit = i + 1;
    }
    if (fit) *fit = nfit;
    sz->cx = total;
    sz->cy = CELL_H * scale;
    RET(TRUE);
}

DLLAPI BOOL WINAPI GetTextMetricsW(HDC hdc, LPTEXTMETRICW tm)
{
    dc_t *dc;
    font_t *f;
    int s;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !tm) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
    s = f ? f->scale : 1;
    memset(tm, 0, sizeof *tm);
    tm->tmHeight = CELL_H * s;
    tm->tmAscent = ASCENT * s;
    tm->tmDescent = (CELL_H - ASCENT) * s;
    tm->tmAveCharWidth = CELL_W * s;
    tm->tmMaxCharWidth = GDI_FONT_WIDE * s;                        /* Hangul syllables and other full-width glyphs */
    tm->tmWeight = f && f->lf.lfWeight ? f->lf.lfWeight : FW_NORMAL;
    tm->tmDigitizedAspectX = 96;
    tm->tmDigitizedAspectY = 96;
    tm->tmFirstChar = 0x20;
    tm->tmLastChar = 0xffe6;                                       /* last glyph of gdi_font_data.c (fullwidth signs) */
    tm->tmDefaultChar = '?';                                       /* the substitute in Unicode->ANSI conversion */
    tm->tmBreakChar = ' ';
    tm->tmItalic = f ? f->lf.lfItalic : 0;
    tm->tmUnderlined = f ? f->lf.lfUnderline : 0;
    tm->tmStruckOut = f ? f->lf.lfStrikeOut : 0;
    tm->tmPitchAndFamily = FF_MODERN;                              /* fixed pitch: TMPF_FIXED_PITCH (the "variable" bit) is clear */
    tm->tmCharSet = ANSI_CHARSET;
    RET(TRUE);
}

static const WCHAR face_name[] = { 'S', 'h', 'i', 'z', 'u', 'k', 'u', ' ', 'F', 'i', 'x', 'e', 'd', ' ', '8', 'x', '1', '6', 0 };

DLLAPI int WINAPI GetTextFaceW(HDC hdc, int count, LPWSTR buf)
{
    dc_t *dc;
    int n = (int)(sizeof face_name / sizeof face_name[0]);
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    if (!buf) RET(n);
    if (count < n) n = count;
    if (n > 0) { memcpy(buf, face_name, (size_t)n * sizeof(WCHAR)); buf[n - 1] = 0; }
    RET(n);
}

DLLAPI int WINAPI GetTextFaceA(HDC hdc, int count, LPSTR buf)
{
    int n = (int)(sizeof face_name / sizeof face_name[0]), i;
    if (!gdi_dc_get(hdc)) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    if (!buf) return n;
    if (count < n) n = count;
    for (i = 0; i < n; ++i) buf[i] = (char)face_name[i];
    if (n > 0) buf[n - 1] = 0;
    return n;
}

DLLAPI BOOL WINAPI GetCharWidthW(HDC hdc, UINT first, UINT last, LPINT out)
{
    dc_t *dc;
    UINT i;
    int scale;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !out || last < first) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    scale = gdi_font_scale(dc);
    for (i = first; i <= last; ++i) out[i - first] = gdi_font_advance(i) * scale;
    RET(TRUE);
}

DLLAPI BOOL WINAPI GetCharWidth32W(HDC hdc, UINT first, UINT last, LPINT out)
{
    return GetCharWidthW(hdc, first, last, out);
}

/* Unicode ranges / code pages the glyph set really covers (OS/2 ulUnicodeRange / ulCodePageRange bit numbers). */
static void font_signature(FONTSIGNATURE *fs)
{
    fs->fsUsb[0] = 1u << 0 | 1u << 1 | 1u << 28 | 1u << 31;     /* Basic Latin, Latin-1 Sup., Hangul Jamo, Gen. Punctuation */
    fs->fsUsb[1] = 1u << (37 - 32) | 1u << (42 - 32) | 1u << (45 - 32) | 1u << (47 - 32) |   /* Arrows, Encl. Alnum, Box, Geom. */
                   1u << (48 - 32) | 1u << (52 - 32) | 1u << (56 - 32);   /* CJK Symbols, Enclosed CJK, Hangul Syllables */
    fs->fsUsb[2] = 1u << (68 - 64);                                 /* Halfwidth and Fullwidth Forms */
    fs->fsUsb[3] = 0;
    fs->fsCsb[0] = 1u << 0 | 1u << 19;                             /* Latin 1 (1252), Korean Wansung (949) */
    fs->fsCsb[1] = 0;
}

/* The one font family that exists, offered to EnumFontFamiliesEx callers if the requested charset/face admits it
 * (ANSI_CHARSET, HANGEUL_CHARSET, or DEFAULT_CHARSET which reports it once as ANSI). */
DLLAPI int WINAPI EnumFontFamiliesExW(HDC hdc, LPLOGFONTW lf, FONTENUMPROCW proc, LPARAM lparam, DWORD flags)
{
    ENUMLOGFONTEXW e;
    NEWTEXTMETRICEXW tm;
    dc_t *dc;
    unsigned i;
    BYTE cs;
    (void)flags;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    GDI_LEAVE();
    if (!dc || !proc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (lf && lf->lfCharSet != DEFAULT_CHARSET && lf->lfCharSet != ANSI_CHARSET && lf->lfCharSet != HANGEUL_CHARSET) return 1;
    cs = lf && lf->lfCharSet == HANGEUL_CHARSET ? HANGEUL_CHARSET : ANSI_CHARSET;
    if (lf && lf->lfFaceName[0]) {
        for (i = 0; face_name[i]; ++i)
            if ((lf->lfFaceName[i] | 0x20) != (face_name[i] | 0x20)) return 1;
        if (lf->lfFaceName[i]) return 1;
    }
    memset(&e, 0, sizeof e);
    memset(&tm, 0, sizeof tm);
    e.elfLogFont.lfHeight = CELL_H;
    e.elfLogFont.lfWidth = CELL_W;
    e.elfLogFont.lfWeight = FW_NORMAL;
    e.elfLogFont.lfCharSet = cs;
    e.elfLogFont.lfPitchAndFamily = FF_MODERN;
    memcpy(e.elfLogFont.lfFaceName, face_name, sizeof face_name);
    memcpy(e.elfFullName, face_name, sizeof face_name);
    tm.ntmTm.tmHeight = CELL_H;
    tm.ntmTm.tmAscent = ASCENT;
    tm.ntmTm.tmDescent = CELL_H - ASCENT;
    tm.ntmTm.tmAveCharWidth = CELL_W;
    tm.ntmTm.tmMaxCharWidth = GDI_FONT_WIDE;
    tm.ntmTm.tmWeight = FW_NORMAL;
    tm.ntmTm.tmFirstChar = 0x20;
    tm.ntmTm.tmLastChar = 0xffe6;
    tm.ntmTm.tmDefaultChar = '?';
    tm.ntmTm.tmBreakChar = ' ';
    tm.ntmTm.tmPitchAndFamily = FF_MODERN;
    tm.ntmTm.tmCharSet = cs;
    font_signature(&tm.ntmFontSig);
    return proc(&e.elfLogFont, (const TEXTMETRICW *)&tm, RASTER_FONTTYPE, lparam);
}

/* the ANSI view of the same enumeration: the face name is ASCII, so the conversion is a narrowing copy */
DLLAPI int WINAPI EnumFontFamiliesExA(HDC hdc, LPLOGFONTA lf, FONTENUMPROCA proc, LPARAM lparam, DWORD flags)
{
    ENUMLOGFONTEXA e;
    NEWTEXTMETRICEXA tm;
    unsigned i;
    BYTE cs;
    (void)flags;
    if (!gdi_dc_get(hdc) || !proc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (lf && lf->lfCharSet != DEFAULT_CHARSET && lf->lfCharSet != ANSI_CHARSET && lf->lfCharSet != HANGEUL_CHARSET) return 1;
    cs = lf && lf->lfCharSet == HANGEUL_CHARSET ? HANGEUL_CHARSET : ANSI_CHARSET;
    if (lf && lf->lfFaceName[0]) {
        for (i = 0; face_name[i]; ++i)
            if ((lf->lfFaceName[i] | 0x20) != (char)(face_name[i] | 0x20)) return 1;
        if (lf->lfFaceName[i]) return 1;
    }
    memset(&e, 0, sizeof e);
    memset(&tm, 0, sizeof tm);
    e.elfLogFont.lfHeight = CELL_H;
    e.elfLogFont.lfWidth = CELL_W;
    e.elfLogFont.lfWeight = FW_NORMAL;
    e.elfLogFont.lfCharSet = cs;
    e.elfLogFont.lfPitchAndFamily = FF_MODERN;
    for (i = 0; face_name[i]; ++i) { e.elfLogFont.lfFaceName[i] = (CHAR)face_name[i]; e.elfFullName[i] = (BYTE)face_name[i]; }
    tm.ntmTm.tmHeight = CELL_H;
    tm.ntmTm.tmAscent = ASCENT;
    tm.ntmTm.tmDescent = CELL_H - ASCENT;
    tm.ntmTm.tmAveCharWidth = CELL_W;
    tm.ntmTm.tmMaxCharWidth = GDI_FONT_WIDE;
    tm.ntmTm.tmWeight = FW_NORMAL;
    tm.ntmTm.tmFirstChar = 0x20;
    tm.ntmTm.tmLastChar = 0xff;                                  /* the ANSI view ends at 0xff */
    tm.ntmTm.tmDefaultChar = '?';
    tm.ntmTm.tmBreakChar = ' ';
    tm.ntmTm.tmPitchAndFamily = FF_MODERN;
    tm.ntmTm.tmCharSet = cs;
    font_signature(&tm.ntmFontSig);
    return proc(&e.elfLogFont, (const TEXTMETRICA *)&tm, RASTER_FONTTYPE, lparam);
}

DLLAPI BOOL WINAPI GetCharABCWidthsW(HDC hdc, UINT first, UINT last, LPABC abc)
{
    dc_t *dc;
    UINT i;
    int scale;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!abc || last < first) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    scale = gdi_font_scale(dc);
    for (i = first; i <= last; ++i) {                              /* every glyph fills its cell: no overhang either side */
        abc[i - first].abcA = 0;
        abc[i - first].abcB = (UINT)(gdi_font_advance(i) * scale);
        abc[i - first].abcC = 0;
    }
    RET(TRUE);
}

DLLAPI DWORD WINAPI GetFontData(HDC hdc, DWORD table, DWORD offset, LPVOID buf, DWORD size)
{
    (void)table; (void)offset; (void)buf; (void)size;
    if (!gdi_dc_get(hdc)) { SetLastError(ERROR_INVALID_HANDLE); return GDI_ERROR; }
    SetLastError(ERROR_CAN_NOT_COMPLETE);                          /* a raster font has no TrueType tables */
    return GDI_ERROR;
}

/* glyph index = character code for ASCII 0x20..0x7e, 0x100 + ordinal for Unifont glyphs (gdi_font.h); a character the
 * font lacks maps to the notdef box (0 narrow / 1 wide), or 0xffff with GGI_MARK_NONEXISTING_GLYPHS */
DLLAPI DWORD WINAPI GetGlyphIndicesW(HDC hdc, LPCWSTR s, int n, LPWORD out, DWORD flags)
{
    gdi_glyph_t g;
    int i;
    if (!gdi_dc_get(hdc)) { SetLastError(ERROR_INVALID_HANDLE); return GDI_ERROR; }
    if (n < 0 || (n && (!s || !out))) { SetLastError(ERROR_INVALID_PARAMETER); return GDI_ERROR; }
    for (i = 0; i < n; ++i)
        if (gdi_font_has_glyph(s[i])) out[i] = (WORD)gdi_font_glyph(s[i], &g);
        else if (flags & GGI_MARK_NONEXISTING_GLYPHS) out[i] = 0xffff;
        else out[i] = (WORD)gdi_font_glyph(s[i] < 0x80 ? 0x80 : s[i], &g);   /* ASCII controls: the narrow notdef box */
    return (DWORD)n;
}

DLLAPI UINT WINAPI GetOutlineTextMetricsW(HDC hdc, UINT size, LPOUTLINETEXTMETRICW otm)
{
    (void)size; (void)otm;
    if (!gdi_dc_get(hdc)) SetLastError(ERROR_INVALID_HANDLE);
    return 0;                                                      /* raster font: no outline metrics */
}

DLLAPI HANDLE WINAPI AddFontMemResourceEx(PVOID data, DWORD size, PVOID reserved, DWORD *count)
{
    (void)size; (void)reserved;
    if (!data || !count) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    *count = 0;
    SetLastError(ERROR_NOT_SUPPORTED);                             /* no TrueType/OpenType rasteriser */
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
