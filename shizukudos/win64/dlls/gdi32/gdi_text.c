/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32 text. THE ONLY FONT THAT EXISTS is the built-in fixed-pitch bitmap font: the public-domain 8x8 IBM VGA font
 * (shizukudos/supervisor/src/font8x8_basic.h, ASCII 0..127) with every row doubled to give an 8x16 cell (13 above the
 * baseline, 3 below). CreateFont* always succeeds and always selects this font; the requested height only picks an
 * integer scale of 1..4 (height 16 = 1, 32 = 2, ...), weight >= 600 is faked by a one-pixel smear, italic and rotation
 * are ignored, underline/strike-out are drawn as lines. Characters above 0x7f draw as '?'. No kerning, no Unicode, no
 * ClearType: a glyph is either on or off. */
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

static BOOL text_out(dc_t *dc, int x, int y, UINT options, const RECT *rc, const WCHAR *s, UINT n, const INT *dx)
{
    gctx_t g;
    const int scale = gdi_font_scale(dc), cw = CELL_W * scale, ch = CELL_H * scale;
    int width = 0, x0, y0, tx, i, ty;
    UINT align = dc->textalign;
    const int updatecp = (align & TA_UPDATECP) != 0;
    rlist_t saved;
    int had_user = 0;
    if (!gctx_begin(&g, dc)) return TRUE;
    if (updatecp) { x = dc->pos.x; y = dc->pos.y; }
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
