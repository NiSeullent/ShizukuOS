/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32 text. THE ONLY FONT THAT EXISTS is the built-in fixed-pitch bitmap font: the public-domain 8x8 IBM VGA font
 * (shizukudos/supervisor/src/font8x8_basic.h, ASCII 0..127) with every row doubled to give an 8x16 cell (13 above the
 * baseline, 3 below). CreateFont* always succeeds and always selects this font; the requested height only picks an
 * integer scale of 1..4 (height 16 = 1, 32 = 2, ...), weight >= 600 is faked by a one-pixel smear, italic and rotation
 * are ignored, underline/strike-out are drawn as lines. Characters above 0x7f draw as '?'. No kerning, no Unicode, no
 * ClearType: a glyph is either on or off. Inside a path bracket, text adds the exact outline of its pixels (one rectangle
 * per run of set pixels in each glyph row) instead of drawing.
 *
 * Font queries answer for this font: it is a raster font, so it has no TrueType tables (GetFontData fails with GDI_ERROR)
 * and no outline metrics (GetOutlineTextMetrics returns 0, as Windows does for raster fonts). GetCharABCWidths reports its
 * real metrics (no overhang: A = C = 0) although Windows refuses the call for raster fonts. Fonts cannot be added from
 * memory (AddFontMemResourceEx fails: there is no TrueType rasteriser to use them with). */
#include "gdi_internal.h"
#include "../../../supervisor/src/font8x8_basic.h"

#define CELL_W 8
#define CELL_H 16
#define ASCENT 13

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

static void draw_glyph(gctx_t *g, int x, int y, unsigned ch, int scale, uint32_t fg, uint32_t bg, int opaque, int bold)
{
    int row, col;
    if (ch >= 0x80) ch = '?';
    if (ch < 0x20) ch = 0x20;
    for (row = 0; row < CELL_H * scale; ++row) {
        const uint8_t bits = font8x8_basic[ch][(row / scale) >> 1];
        for (col = 0; col < CELL_W * scale; ++col) {
            const int on = ((bits >> (col / scale)) & 1) || (bold && col > 0 && ((bits >> ((col - 1) / scale)) & 1));
            if (on) gctx_pixel(g, x + col, y + row, fg, R2_COPYPEN);
            else if (opaque) gctx_pixel(g, x + col, y + row, bg, R2_COPYPEN);
        }
    }
}

/* the pixels draw_glyph would set, as path rectangles (device coordinates) */
static BOOL glyph_path(dc_t *dc, int x, int y, unsigned ch, int scale, int bold)
{
    int fr, c, c0;
    if (ch >= 0x80) ch = '?';
    if (ch < 0x20) ch = 0x20;
    for (fr = 0; fr < CELL_H / 2; ++fr) {                          /* each font row covers two cell rows */
        const uint8_t bits = font8x8_basic[ch][fr];
        const int t = y + fr * 2 * scale, b = t + 2 * scale;
        for (c = 0; c < CELL_W * scale;) {
            #define ON(cc) (((bits >> ((cc) / scale)) & 1) || (bold && (cc) > 0 && ((bits >> (((cc) - 1) / scale)) & 1)))
            if (!ON(c)) { ++c; continue; }
            c0 = c;
            while (c < CELL_W * scale && ON(c)) ++c;
            #undef ON
            if (!gdi_path_rect_dev(dc, x + c0, t, x + c, b, 1)) return FALSE;
        }
    }
    return TRUE;
}

static BOOL text_out(dc_t *dc, int x, int y, UINT options, const RECT *rc, const WCHAR *s, UINT n, const INT *dx)
{
    gctx_t g;
    const int scale = gdi_font_scale(dc), cw = CELL_W * scale, ch = CELL_H * scale;
    int width = 0, x0, y0, tx, i, ty;
    UINT align = dc->textalign;
    const int updatecp = (align & TA_UPDATECP) != 0;
    rlist_t saved;
    int had_user = 0;
    if (updatecp) { x = dc->pos.x; y = dc->pos.y; }
    if (gdi_path_recording(dc)) {
        font_t *f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
        const int bold = font_bold(dc);
        for (i = 0; i < (int)n; ++i) width += dx ? dx[i] : cw;
        if ((align & 6) == TA_CENTER) x -= width / 2;
        else if ((align & 6) == TA_RIGHT) x -= width;
        if ((align & TA_BASELINE) == TA_BASELINE) y -= ASCENT * scale;
        else if (align & TA_BOTTOM) y -= ch;
        tx = dc_lx(dc, x);
        ty = dc_ly(dc, y);
        for (i = 0; i < (int)n; ++i) {
            if (!glyph_path(dc, tx, ty, s[i], scale, bold)) return FALSE;
            tx += dx ? dx[i] : cw;
        }
        if (f && f->lf.lfUnderline && !gdi_path_rect_dev(dc, dc_lx(dc, x), ty + (ASCENT + 1) * scale, dc_lx(dc, x) + width, ty + (ASCENT + 2) * scale, 1)) return FALSE;
        if (f && f->lf.lfStrikeOut && !gdi_path_rect_dev(dc, dc_lx(dc, x), ty + 8 * scale, dc_lx(dc, x) + width, ty + 9 * scale, 1)) return FALSE;
        if (updatecp) dc->pos.x = x + width;
        return TRUE;
    }
    if (!gctx_begin(&g, dc)) return TRUE;
    for (i = 0; i < (int)n; ++i) width += dx ? dx[i] : cw;
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
        const int opaque = dc->bkmode == OPAQUE, bold = font_bold(dc);
        font_t *f = gdi_obj_get((HGDIOBJ)dc->font, OBJ_FONT, 0);
        for (i = 0; i < (int)n; ++i) {
            draw_glyph(&g, tx, ty, s[i], scale, fg, bg, opaque, bold);
            tx += dx ? dx[i] : cw;
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
    sz->cx = n * CELL_W * scale;
    sz->cy = CELL_H * scale;
    RET(TRUE);
}

DLLAPI BOOL WINAPI GetTextExtentExPointW(HDC hdc, LPCWSTR s, int n, int maxw, LPINT fit, LPINT dx, LPSIZE sz)
{
    dc_t *dc;
    int scale, i, cw;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !sz || n < 0 || (n && !s)) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    scale = gdi_font_scale(dc);
    cw = CELL_W * scale;
    if (fit) *fit = maxw < 0 ? n : (maxw / cw < n ? maxw / cw : n);
    if (dx) for (i = 0; i < n; ++i) dx[i] = (i + 1) * cw;
    sz->cx = n * cw;
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
    tm->tmMaxCharWidth = CELL_W * s;
    tm->tmWeight = f && f->lf.lfWeight ? f->lf.lfWeight : FW_NORMAL;
    tm->tmDigitizedAspectX = 96;
    tm->tmDigitizedAspectY = 96;
    tm->tmFirstChar = 0x20;
    tm->tmLastChar = 0x7e;
    tm->tmDefaultChar = '?';
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
    for (i = first; i <= last; ++i) out[i - first] = CELL_W * scale;
    RET(TRUE);
}

DLLAPI BOOL WINAPI GetCharWidth32W(HDC hdc, UINT first, UINT last, LPINT out)
{
    return GetCharWidthW(hdc, first, last, out);
}

/* The one font family that exists, offered to EnumFontFamiliesEx callers if the requested charset/face admits it. */
DLLAPI int WINAPI EnumFontFamiliesExW(HDC hdc, LPLOGFONTW lf, FONTENUMPROCW proc, LPARAM lparam, DWORD flags)
{
    ENUMLOGFONTEXW e;
    NEWTEXTMETRICEXW tm;
    dc_t *dc;
    unsigned i;
    (void)flags;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    GDI_LEAVE();
    if (!dc || !proc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (lf && lf->lfCharSet != DEFAULT_CHARSET && lf->lfCharSet != ANSI_CHARSET) return 1;
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
    e.elfLogFont.lfCharSet = ANSI_CHARSET;
    e.elfLogFont.lfPitchAndFamily = FF_MODERN;
    memcpy(e.elfLogFont.lfFaceName, face_name, sizeof face_name);
    memcpy(e.elfFullName, face_name, sizeof face_name);
    tm.ntmTm.tmHeight = CELL_H;
    tm.ntmTm.tmAscent = ASCENT;
    tm.ntmTm.tmDescent = CELL_H - ASCENT;
    tm.ntmTm.tmAveCharWidth = CELL_W;
    tm.ntmTm.tmMaxCharWidth = CELL_W;
    tm.ntmTm.tmWeight = FW_NORMAL;
    tm.ntmTm.tmFirstChar = 0x20;
    tm.ntmTm.tmLastChar = 0x7e;
    tm.ntmTm.tmDefaultChar = '?';
    tm.ntmTm.tmBreakChar = ' ';
    tm.ntmTm.tmPitchAndFamily = FF_MODERN;
    tm.ntmTm.tmCharSet = ANSI_CHARSET;
    return proc(&e.elfLogFont, (const TEXTMETRICW *)&tm, RASTER_FONTTYPE, lparam);
}

/* the ANSI view of the same enumeration: the face name is ASCII, so the conversion is a narrowing copy */
DLLAPI int WINAPI EnumFontFamiliesExA(HDC hdc, LPLOGFONTA lf, FONTENUMPROCA proc, LPARAM lparam, DWORD flags)
{
    ENUMLOGFONTEXA e;
    NEWTEXTMETRICEXA tm;
    unsigned i;
    (void)flags;
    if (!gdi_dc_get(hdc) || !proc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (lf && lf->lfCharSet != DEFAULT_CHARSET && lf->lfCharSet != ANSI_CHARSET) return 1;
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
    e.elfLogFont.lfCharSet = ANSI_CHARSET;
    e.elfLogFont.lfPitchAndFamily = FF_MODERN;
    for (i = 0; face_name[i]; ++i) { e.elfLogFont.lfFaceName[i] = (CHAR)face_name[i]; e.elfFullName[i] = (BYTE)face_name[i]; }
    tm.ntmTm.tmHeight = CELL_H;
    tm.ntmTm.tmAscent = ASCENT;
    tm.ntmTm.tmDescent = CELL_H - ASCENT;
    tm.ntmTm.tmAveCharWidth = CELL_W;
    tm.ntmTm.tmMaxCharWidth = CELL_W;
    tm.ntmTm.tmWeight = FW_NORMAL;
    tm.ntmTm.tmFirstChar = 0x20;
    tm.ntmTm.tmLastChar = 0x7e;
    tm.ntmTm.tmDefaultChar = '?';
    tm.ntmTm.tmBreakChar = ' ';
    tm.ntmTm.tmPitchAndFamily = FF_MODERN;
    tm.ntmTm.tmCharSet = ANSI_CHARSET;
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
        abc[i - first].abcB = (UINT)(CELL_W * scale);
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

/* glyph index = character code for the glyphs the font has (0x20..0x7e) */
DLLAPI DWORD WINAPI GetGlyphIndicesW(HDC hdc, LPCWSTR s, int n, LPWORD out, DWORD flags)
{
    int i;
    if (!gdi_dc_get(hdc)) { SetLastError(ERROR_INVALID_HANDLE); return GDI_ERROR; }
    if (n < 0 || (n && (!s || !out))) { SetLastError(ERROR_INVALID_PARAMETER); return GDI_ERROR; }
    for (i = 0; i < n; ++i)
        out[i] = s[i] >= 0x20 && s[i] <= 0x7e ? s[i] : (flags & GGI_MARK_NONEXISTING_GLYPHS) ? 0xffff : '?';
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
