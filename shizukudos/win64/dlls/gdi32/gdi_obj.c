/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32: handle table, stock objects, pens, brushes, fonts, bitmaps, DIB sections, device contexts and DC state.
 * See gdi_internal.h for the architecture (user-mode GDI drawing into bitmaps; windows present to the kernel). */
#include "gdi_internal.h"
#include "gdi_render_trace.h"
#include "gdi_dib_layout.h"

CRITICAL_SECTION g_gdi_lock;
HGDIOBJ g_stock[32];

typedef struct { uint8_t type, stock, gen, pad; int32_t pad2; void *p; } gobj_t;
static gobj_t g_objs[GDI_MAX_OBJECTS];

/* ---------------------------------------------------------------- memory */
void *gdi_alloc(size_t n) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n ? n : 1); }
void gdi_free(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }

uint32_t *gdi_alloc_pixels(uint64_t n, int *big)
{
    if (n * 4 >= 0x10000) {
        *big = 1;
        return VirtualAlloc(0, (SIZE_T)(n * 4), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    *big = 0;
    return gdi_alloc((size_t)(n * 4));
}
void gdi_free_pixels(uint32_t *p, uint64_t n, int big)
{
    (void)n;
    if (!p) return;
    if (big) VirtualFree(p, 0, MEM_RELEASE); else gdi_free(p);
}

/* ---------------------------------------------------------------- handle table */
static unsigned g_nobjs, g_peak_objs;                          /* live non-stock objects (GetGuiResources) */

HGDIOBJ gdi_obj_new(int type, void *p, int stock)
{
    unsigned i;
    for (i = 1; i < GDI_MAX_OBJECTS; ++i)
        if (!g_objs[i].type) {
            gobj_t *o = &g_objs[i];
            if (!stock && ++g_nobjs > g_peak_objs) g_peak_objs = g_nobjs;
            o->gen = (uint8_t)(o->gen + 1);
            o->type = (uint8_t)type;
            o->stock = (uint8_t)stock;
            o->p = p;
            return (HGDIOBJ)(uintptr_t)(((uint32_t)type << 24) | ((uint32_t)o->gen << 16) | i);
        }
    return 0;
}

static gobj_t *obj_slot(HGDIOBJ h)
{
    const uint64_t v = (uint64_t)(uintptr_t)h;
    const unsigned i = (unsigned)(v & 0xffff);
    gobj_t *o;
    if ((v >> 32) || !i || i >= GDI_MAX_OBJECTS) return 0;
    o = &g_objs[i];
    if (!o->type || (uint32_t)v != (((uint32_t)o->type << 24) | ((uint32_t)o->gen << 16) | i)) return 0;
    return o;
}

void *gdi_obj_get(HGDIOBJ h, int type, int *type_out)
{
    gobj_t *o = obj_slot(h);
    if (!o) return 0;
    if (type_out) *type_out = o->type;
    if (type && o->type != type && !(type == OBJ_DC && (o->type == OBJ_MEMDC || o->type == OBJ_ENHMETADC)) &&
        !(type == OBJ_PEN && o->type == OBJ_EXTPEN))
        return 0;
    return o->p;
}
int gdi_obj_type(HGDIOBJ h) { gobj_t *o = obj_slot(h); return o ? o->type : 0; }
void gdi_obj_free(HGDIOBJ h) { gobj_t *o = obj_slot(h); if (o) { if (!o->stock && g_nobjs) --g_nobjs; o->type = 0; o->p = 0; o->stock = 0; } }

/* Private exports for user32 (not Windows APIs). */
DLLAPI DWORD WINAPI ShzGdiObjectCount(DWORD *peak)
{
    DWORD n;
    GDI_ENTER();
    n = g_nobjs;
    if (peak) *peak = g_peak_objs;
    GDI_LEAVE();
    return n;
}
static int obj_is_stock(HGDIOBJ h) { gobj_t *o = obj_slot(h); return o && o->stock; }

/* A window backing is being freed (the window is gone): DCs that still point at it must not touch it again. */
void gdi_forget_backing(backing_t *b)
{
    unsigned i;
    for (i = 1; i < GDI_MAX_OBJECTS; ++i)
        if ((g_objs[i].type == OBJ_DC || g_objs[i].type == OBJ_MEMDC) && g_objs[i].p) {
            dc_t *dc = g_objs[i].p;
            if (!dc->memdc && dc->bk == b) { dc->bk = 0; dc->wcx = dc->wcy = 0; dc->eff_valid = 0; }
        }
}

/* ---------------------------------------------------------------- pens, brushes, fonts */
static HPEN make_pen(int style, int width, COLORREF c, int ext)
{
    pen_t *p = gdi_alloc(sizeof *p);
    HGDIOBJ h;
    if (!p) return 0;
    p->lp.lopnStyle = (UINT)style;
    p->lp.lopnWidth.x = width;
    p->lp.lopnColor = c;
    p->ext = ext;
    h = gdi_obj_new(ext ? OBJ_EXTPEN : OBJ_PEN, p, 0);
    if (!h) gdi_free(p);
    return (HPEN)h;
}

DLLAPI HPEN WINAPI CreatePen(int style, int width, COLORREF color)
{
    HPEN h;
    if ((style & 0xf) > PS_INSIDEFRAME) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    GDI_ENTER();
    h = make_pen(style & 0xf, width, color, 0);
    RET(h);
}

DLLAPI HPEN WINAPI CreatePenIndirect(const LOGPEN *lp)
{
    HPEN h;
    if (!lp) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    GDI_ENTER();
    h = make_pen((int)lp->lopnStyle & 0xf, lp->lopnWidth.x, lp->lopnColor, 0);
    RET(h);
}

DLLAPI HPEN WINAPI ExtCreatePen(DWORD style, DWORD width, const LOGBRUSH *lb, DWORD cstyle, const DWORD *dash)
{
    HPEN h;
    (void)cstyle; (void)dash;
    if (!lb || (style & PS_STYLE_MASK) == PS_USERSTYLE || (style & PS_STYLE_MASK) == PS_ALTERNATE) {
        SetLastError(ERROR_NOT_SUPPORTED);                    /* user-defined dash arrays are not implemented */
        return 0;
    }
    if (lb->lbStyle != BS_SOLID) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }
    GDI_ENTER();
    h = make_pen((int)(style & PS_STYLE_MASK), (style & PS_TYPE_MASK) == PS_COSMETIC ? 1 : (int)width, lb->lbColor, 1);
    if (h) { pen_t *p = gdi_obj_get(h, 0, 0); p->ext_style = style; }
    RET(h);
}

static HBRUSH make_brush(int style, COLORREF c, int hatch, HBITMAP pattern)
{
    brush_t *b = gdi_alloc(sizeof *b);
    HGDIOBJ h;
    if (!b) return 0;
    b->lb.lbStyle = (UINT)style;
    b->lb.lbColor = c;
    b->lb.lbHatch = (ULONG_PTR)hatch;
    b->pattern = pattern;
    h = gdi_obj_new(OBJ_BRUSH, b, 0);
    if (!h) gdi_free(b);
    return (HBRUSH)h;
}

DLLAPI HBRUSH WINAPI CreateSolidBrush(COLORREF color)
{
    HBRUSH h;
    GDI_ENTER();
    h = make_brush(BS_SOLID, color, 0, 0);
    RET(h);
}

DLLAPI HBRUSH WINAPI CreateBrushIndirect(const LOGBRUSH *lb)
{
    HBRUSH h;
    if (!lb) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (lb->lbStyle != BS_SOLID && lb->lbStyle != BS_NULL && lb->lbStyle != BS_HATCHED) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return 0;
    }
    GDI_ENTER();
    h = make_brush((int)lb->lbStyle, lb->lbColor, (int)lb->lbHatch, 0);
    RET(h);
}

DLLAPI HBRUSH WINAPI CreateHatchBrush(int hatch, COLORREF color)
{
    HBRUSH h;
    if (hatch < HS_HORIZONTAL || hatch > HS_DIAGCROSS) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    GDI_ENTER();
    h = make_brush(BS_HATCHED, color, hatch, 0);
    RET(h);
}

/* Creates a stock-style solid brush that DeleteObject never frees (user32's system colour brushes). */
DLLAPI HBRUSH WINAPI ShzGdiCreateStockSolidBrush(COLORREF color)
{
    HBRUSH h;
    GDI_ENTER();
    h = make_brush(BS_SOLID, color, 0, 0);
    if (h) { gobj_t *o = obj_slot(h); o->stock = 1; }
    RET(h);
}

DLLAPI HFONT WINAPI CreateFontIndirectW(const LOGFONTW *lf)
{
    font_t *f;
    HGDIOBJ h;
    int hgt;
    if (!lf) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    f = gdi_alloc(sizeof *f);
    if (!f) return 0;
    f->lf = *lf;
    hgt = lf->lfHeight < 0 ? -lf->lfHeight : lf->lfHeight;
    f->scale = hgt == 0 ? 1 : (hgt + 8) / 16;                /* integer scaling of the one 8x16 font */
    if (f->scale < 1) f->scale = 1;
    if (f->scale > 4) f->scale = 4;
    GDI_ENTER();
    h = gdi_obj_new(OBJ_FONT, f, 0);
    if (!h) gdi_free(f);
    RET((HFONT)h);
}

DLLAPI HFONT WINAPI CreateFontIndirectA(const LOGFONTA *la)
{
    LOGFONTW lw;
    unsigned i;
    if (!la) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    memcpy(&lw, la, offsetof(LOGFONTW, lfFaceName));
    for (i = 0; i < LF_FACESIZE; ++i) lw.lfFaceName[i] = (unsigned char)la->lfFaceName[i];
    return CreateFontIndirectW(&lw);
}

static void fill_logfont(LOGFONTW *lf, int h, int w, int esc, int orient, int weight, DWORD it, DWORD ul, DWORD so, DWORD cs,
                         DWORD op, DWORD cp, DWORD q, DWORD pf)
{
    memset(lf, 0, sizeof *lf);
    lf->lfHeight = h; lf->lfWidth = w; lf->lfEscapement = esc; lf->lfOrientation = orient; lf->lfWeight = weight;
    lf->lfItalic = (BYTE)it; lf->lfUnderline = (BYTE)ul; lf->lfStrikeOut = (BYTE)so; lf->lfCharSet = (BYTE)cs;
    lf->lfOutPrecision = (BYTE)op; lf->lfClipPrecision = (BYTE)cp; lf->lfQuality = (BYTE)q; lf->lfPitchAndFamily = (BYTE)pf;
}

DLLAPI HFONT WINAPI CreateFontW(int h, int w, int esc, int orient, int weight, DWORD it, DWORD ul, DWORD so, DWORD cs,
                                DWORD op, DWORD cp, DWORD q, DWORD pf, LPCWSTR face)
{
    LOGFONTW lf;
    unsigned i;
    fill_logfont(&lf, h, w, esc, orient, weight, it, ul, so, cs, op, cp, q, pf);
    for (i = 0; face && face[i] && i < LF_FACESIZE - 1; ++i) lf.lfFaceName[i] = face[i];
    return CreateFontIndirectW(&lf);
}

DLLAPI HFONT WINAPI CreateFontA(int h, int w, int esc, int orient, int weight, DWORD it, DWORD ul, DWORD so, DWORD cs,
                                DWORD op, DWORD cp, DWORD q, DWORD pf, LPCSTR face)
{
    LOGFONTW lf;
    unsigned i;
    fill_logfont(&lf, h, w, esc, orient, weight, it, ul, so, cs, op, cp, q, pf);
    for (i = 0; face && face[i] && i < LF_FACESIZE - 1; ++i) lf.lfFaceName[i] = (unsigned char)face[i];
    return CreateFontIndirectW(&lf);
}

/* ---------------------------------------------------------------- stock objects */
static void make_stock(void)
{
    static const struct { int idx; int brush; COLORREF c; } brushes[] = {
        { WHITE_BRUSH, 1, 0xffffff }, { LTGRAY_BRUSH, 1, 0xc0c0c0 }, { GRAY_BRUSH, 1, 0x808080 }, { DKGRAY_BRUSH, 1, 0x404040 },
        { BLACK_BRUSH, 1, 0x000000 } };
    unsigned i;
    for (i = 0; i < sizeof brushes / sizeof brushes[0]; ++i) {
        HBRUSH b = make_brush(BS_SOLID, brushes[i].c, 0, 0);
        if (b) { obj_slot(b)->stock = 1; g_stock[brushes[i].idx] = b; }
    }
    {
        HBRUSH b = make_brush(BS_NULL, 0, 0, 0);
        if (b) { obj_slot(b)->stock = 1; g_stock[NULL_BRUSH] = b; }
        b = make_brush(BS_SOLID, 0xffffff, 0, 0);
        if (b) { obj_slot(b)->stock = 1; g_stock[DC_BRUSH] = b; }
    }
    {
        HPEN p = make_pen(PS_SOLID, 1, 0xffffff, 0);
        if (p) { obj_slot(p)->stock = 1; g_stock[WHITE_PEN] = p; }
        p = make_pen(PS_SOLID, 1, 0, 0);
        if (p) { obj_slot(p)->stock = 1; g_stock[BLACK_PEN] = p; }
        p = make_pen(PS_NULL, 0, 0, 0);
        if (p) { obj_slot(p)->stock = 1; g_stock[NULL_PEN] = p; }
        p = make_pen(PS_SOLID, 1, 0, 0);
        if (p) { obj_slot(p)->stock = 1; g_stock[DC_PEN] = p; }
    }
    {
        static const int fonts[] = { OEM_FIXED_FONT, ANSI_FIXED_FONT, ANSI_VAR_FONT, SYSTEM_FONT, DEVICE_DEFAULT_FONT,
                                     SYSTEM_FIXED_FONT, DEFAULT_GUI_FONT };
        LOGFONTW lf;
        for (i = 0; i < sizeof fonts / sizeof fonts[0]; ++i) {
            HFONT f;
            fill_logfont(&lf, 16, 8, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN);
            memcpy(lf.lfFaceName, L"Shizuku Fixed 8x16", sizeof L"Shizuku Fixed 8x16");
            f = CreateFontIndirectW(&lf);
            if (f) { obj_slot(f)->stock = 1; g_stock[fonts[i]] = f; }
        }
    }
}

DLLAPI HGDIOBJ WINAPI GetStockObject(int i)
{
    if (i < 0 || i >= 32 || !g_stock[i]) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return g_stock[i];
}

/* ---------------------------------------------------------------- bitmaps */
static bitmap_t *bitmap_create(int w, int h, int topdown)
{
    bitmap_t *b;
    if (w <= 0 || h <= 0 || (uint64_t)w * (uint64_t)h * 4 > (256u << 20)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    b = gdi_alloc(sizeof *b);
    if (!b) return 0;
    b->w = w;
    b->h = h;
    b->topdown = topdown;
    b->bits = gdi_alloc_pixels((uint64_t)w * (uint64_t)h, &b->big);
    if (!b->bits) { gdi_free(b); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    return b;
}
static BOOL bitmap_destroy(bitmap_t *b)
{
    if (b->section_view) {
        /* The section handle belongs to the caller. The bitmap owns only this
         * view, which may start before the pixel pointer at an interior offset. */
        if (!UnmapViewOfFile(b->section_view)) return FALSE;
    } else gdi_free_pixels(b->bits, (uint64_t)b->w * (uint64_t)b->h, b->big);
    gdi_free(b);
    return TRUE;
}

DLLAPI HBITMAP WINAPI CreateBitmap(int w, int h, UINT planes, UINT bpp, const VOID *bits)
{
    bitmap_t *b;
    HGDIOBJ hb;
    int y;
    if (planes != 1 || (bpp != 32 && bpp != 0)) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }     /* only 32 bpp exists */
    GDI_ENTER();
    b = bitmap_create(w, h, 1);
    if (!b) RET(0);
    if (bits)
        for (y = 0; y < h; ++y) memcpy(b->bits + (size_t)y * (size_t)w, (const uint8_t *)bits + (size_t)y * (size_t)w * 4, (size_t)w * 4);
    hb = gdi_obj_new(OBJ_BITMAP, b, 0);
    if (!hb) bitmap_destroy(b);
    RET((HBITMAP)hb);
}

DLLAPI HBITMAP WINAPI CreateCompatibleBitmap(HDC hdc, int w, int h)
{
    bitmap_t *b;
    HGDIOBJ hb;
    (void)hdc;
    GDI_ENTER();
    b = bitmap_create(w, h, 1);
    if (!b) RET(0);
    hb = gdi_obj_new(OBJ_BITMAP, b, 0);
    if (!hb) bitmap_destroy(b);
    RET((HBITMAP)hb);
}

DLLAPI HBITMAP WINAPI CreateDIBSection(HDC hdc, const BITMAPINFO *bmi, UINT usage, VOID **ppv, HANDLE section, DWORD offset)
{
    bitmap_t *b;
    HGDIOBJ hb;
    shz_dib_layout_t layout;
    DWORD masks[3] = {0, 0, 0};
    (void)hdc;
    if (ppv) *ppv = NULL;
    if (!ppv || !bmi || bmi->bmiHeader.biSize < sizeof(BITMAPINFOHEADER) || usage != DIB_RGB_COLORS) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (bmi->bmiHeader.biBitCount != 32 || bmi->bmiHeader.biPlanes != 1 ||
        (bmi->bmiHeader.biCompression != BI_RGB && bmi->bmiHeader.biCompression != BI_BITFIELDS)) {
        SetLastError(ERROR_NOT_SUPPORTED);                                                      /* 32 bpp RGB only */
        return 0;
    }
    if (bmi->bmiHeader.biCompression == BI_BITFIELDS) {
        /* V4/V5 masks occupy the same offset as the three masks following a
         * BITMAPINFOHEADER; they are part of the extended header itself. */
        const DWORD *m = (const DWORD *)((const uint8_t *)bmi + sizeof(BITMAPINFOHEADER));
        if (m[0] != 0x00ff0000 || m[1] != 0x0000ff00 || m[2] != 0x000000ff) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }
        memcpy(masks, m, sizeof masks);
    }
    if (!shz_dib_layout(bmi->bmiHeader.biWidth, bmi->bmiHeader.biHeight, section != NULL, offset, &layout)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    GDI_ENTER();
    if (section) {
        b = gdi_alloc(sizeof *b);
        if (!b) RET(0);
        /* Original mapping/lifetime adaptation after reviewing Wine11
         * win32u/dib.c and ReactOS9dc3ca win32ss/gdi/ntgdi/dibobj.c.
         * The real section provider enforces size, handle and write access. */
        b->section_view = MapViewOfFile(section, FILE_MAP_WRITE, 0, layout.map_offset, (SIZE_T)layout.view_bytes);
        if (!b->section_view) { gdi_free(b); RET(0); }
        b->w = layout.width; b->h = layout.height; b->topdown = layout.topdown;
        b->bits = (uint32_t *)((uint8_t *)b->section_view + layout.delta);
        b->section = section;
        b->section_offset = offset;
    } else b = bitmap_create(layout.width, layout.height, layout.topdown);
    if (!b) RET(0);
    b->is_dib = 1;
    b->bih = bmi->bmiHeader;
    b->bih.biSizeImage = (DWORD)layout.pixel_bytes;
    memcpy(b->masks, masks, sizeof masks);
    hb = gdi_obj_new(OBJ_BITMAP, b, 0);
    if (!hb) { bitmap_destroy(b); RET(0); }
    if (ppv) *ppv = b->bits;
    gdi_render_trace_dib(b,(HBITMAP)hb);
    RET((HBITMAP)hb);
}

/* ---------------------------------------------------------------- device contexts */
dc_t *gdi_dc_get(HDC h)
{
    dc_t *dc = gdi_obj_get((HGDIOBJ)h, OBJ_DC, 0);
    if (dc && dc->info_only) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    return dc;
}

void gdi_dc_defaults(dc_t *dc)
{
    dc->pen = g_stock[BLACK_PEN];
    dc->brush = g_stock[WHITE_BRUSH];
    dc->font = g_stock[SYSTEM_FONT];
    dc->text = 0;
    dc->bk_color = 0xffffff;
    dc->bkmode = OPAQUE;
    dc->rop2 = R2_COPYPEN;
    dc->polyfill = ALTERNATE;
    dc->stretchmode = BLACKONWHITE;
    dc->mapmode = MM_TEXT;
    dc->textalign = TA_LEFT | TA_TOP | TA_NOUPDATECP;
    dc->gfxmode = GM_COMPATIBLE;
    dc->dcpen = 0;
    dc->dcbrush = 0xffffff;
    dc->xf.eM11 = dc->xf.eM22 = 1.0f;
    dc->xf.eM12 = dc->xf.eM21 = dc->xf.eDx = dc->xf.eDy = 0.0f;
    dc->xf_dx = dc->xf_dy = 0;
    dc->arcdir = AD_COUNTERCLOCKWISE;
    dc->miter = 10.0f;
}

static bitmap_t *g_default_bitmap;
static HBITMAP g_default_hbitmap;

DLLAPI HDC WINAPI CreateCompatibleDC(HDC hdc)
{
    dc_t *dc;
    HGDIOBJ h;
    (void)hdc;
    GDI_ENTER();
    dc = gdi_alloc(sizeof *dc);
    if (!dc) RET(0);
    dc->memdc = 1;
    gdi_dc_defaults(dc);
    dc->hbmp = g_default_hbitmap;
    if (g_default_bitmap) ++g_default_bitmap->sel;
    h = gdi_obj_new(OBJ_MEMDC, dc, 0);
    if (!h) { gdi_free(dc); RET(0); }
    RET((HDC)h);
}

static void dc_release_rlists(dc_t *dc)
{
    rl_free(&dc->sysclip);
    rl_free(&dc->userclip);
    rl_free(&dc->eff);
}

DLLAPI BOOL WINAPI DeleteDC(HDC h)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_obj_get((HGDIOBJ)h, OBJ_DC, 0);   /* information contexts allow this query/lifecycle operation */
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (dc->hwnd) {                                                 /* window DC: push what was drawn */
        gdi_window_dc_flush(dc);
    }
    if (dc->memdc && dc->hbmp) {
        bitmap_t *b = gdi_obj_get((HGDIOBJ)dc->hbmp, OBJ_BITMAP, 0);
        if (b && b->sel) --b->sel;
    }
    while (dc->saved) {
        dc_t *s = dc->saved;
        dc->saved = s->saved;
        dc_release_rlists(s);
        gdi_path_free(s->path);
        gdi_free(s);
    }
    dc_release_rlists(dc);
    gdi_path_free(dc->path);
    if (dc->emf) gdi_emf_dc_free(dc);                               /* a metafile DC deleted without CloseEnhMetaFile */
    gdi_obj_free((HGDIOBJ)h);
    gdi_free(dc);
    RET(TRUE);
}

static int dc_save_copy(dc_t *dc)
{
    dc_t *s = gdi_alloc(sizeof *s);
    if (!s) return 0;
    *s = *dc;
    memset(&s->sysclip, 0, sizeof s->sysclip);
    memset(&s->eff, 0, sizeof s->eff);
    memset(&s->userclip, 0, sizeof s->userclip);
    rl_copy(&s->userclip, &dc->userclip);
    s->path = gdi_path_copy(dc->path);                              /* SaveDC keeps the path too */
    s->saved = dc->saved;
    dc->saved = s;
    return 1;
}

/* Puts the attributes recorded in `snap` back into `dc`; the window binding and the BeginPaint clip are not part of them. */
static void dc_restore_from(dc_t *dc, dc_t *snap)
{
    if (dc->memdc && snap->hbmp != dc->hbmp) {
        bitmap_t *cur = gdi_obj_get((HGDIOBJ)dc->hbmp, OBJ_BITMAP, 0), *old = gdi_obj_get((HGDIOBJ)snap->hbmp, OBJ_BITMAP, 0);
        if (cur && cur->sel) --cur->sel;
        if (old) { ++old->sel; dc->hbmp = snap->hbmp; }
    }
    dc->pen = snap->pen; dc->brush = snap->brush; dc->font = snap->font;
    dc->text = snap->text; dc->bk_color = snap->bk_color; dc->bkmode = snap->bkmode; dc->rop2 = snap->rop2;
    dc->polyfill = snap->polyfill; dc->stretchmode = snap->stretchmode; dc->mapmode = snap->mapmode;
    dc->textalign = snap->textalign; dc->gfxmode = snap->gfxmode; dc->pos = snap->pos;
    dc->win_org = snap->win_org; dc->vp_org = snap->vp_org; dc->brush_org = snap->brush_org;
    dc->dcpen = snap->dcpen; dc->dcbrush = snap->dcbrush;
    dc->xf = snap->xf; dc->xf_dx = snap->xf_dx; dc->xf_dy = snap->xf_dy;
    dc->arcdir = snap->arcdir; dc->miter = snap->miter;
    gdi_path_free(dc->path);
    dc->path = snap->path; dc->path_open = snap->path_open;
    snap->path = 0;
    rl_free(&dc->userclip);
    dc->userclip = snap->userclip;
    dc->has_userclip = snap->has_userclip;
    memset(&snap->userclip, 0, sizeof snap->userclip);
    rl_free(&dc->eff);
    dc->eff_valid = 0;
}

DLLAPI int WINAPI SaveDC(HDC h)
{
    dc_t *dc, *s;
    int n = 0;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    if (!dc_save_copy(dc)) RET(0);
    for (s = dc->saved; s; s = s->saved) ++n;
    RET(n);
}

DLLAPI BOOL WINAPI RestoreDC(HDC h, int level)
{
    dc_t *dc, *s;
    int depth = 0, drop;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    for (s = dc->saved; s; s = s->saved) ++depth;
    if (level < 0) level = depth + level + 1;
    if (level < 1 || level > depth) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    for (drop = depth - level + 1; drop > 0; --drop) {
        dc_t *top = dc->saved;
        dc->saved = top->saved;
        if (drop == 1) dc_restore_from(dc, top);
        dc_release_rlists(top);
        gdi_path_free(top->path);
        gdi_free(top);
    }
    RET(TRUE);
}

DLLAPI HGDIOBJ WINAPI SelectObject(HDC hdc, HGDIOBJ obj)
{
    dc_t *dc;
    int type = 0;
    void *p;
    HGDIOBJ prev = 0;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    p = gdi_obj_get(obj, 0, &type);
    if (!dc || !p) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    switch (type) {
    case OBJ_PEN: case OBJ_EXTPEN: prev = dc->pen; dc->pen = (HPEN)obj; break;
    case OBJ_BRUSH: prev = dc->brush; dc->brush = (HBRUSH)obj; break;
    case OBJ_FONT: prev = dc->font; dc->font = (HFONT)obj; break;
    case OBJ_BITMAP: {
        bitmap_t *b = p, *old;
        if (!dc->memdc || dc->emf) { SetLastError(ERROR_INVALID_PARAMETER); RET(0); }   /* not into window or metafile DCs */
        if (b->sel && (HBITMAP)obj != dc->hbmp) { SetLastError(ERROR_INVALID_PARAMETER); RET(0); }   /* already in another DC */
        old = gdi_obj_get((HGDIOBJ)dc->hbmp, OBJ_BITMAP, 0);
        prev = (HGDIOBJ)dc->hbmp;
        if ((HBITMAP)obj != dc->hbmp) {
            if (old && old->sel) --old->sel;
            ++b->sel;
            dc->hbmp = (HBITMAP)obj;
            dc->eff_valid = 0;
        }
        break;
    }
    case OBJ_REGION: {
        extern int gdi_dc_select_region(dc_t *dc, rgn_t *r);
        RET((HGDIOBJ)(uintptr_t)gdi_dc_select_region(dc, p));
    }
    default: SetLastError(ERROR_INVALID_PARAMETER); RET(0);
    }
    RET(prev);
}

DLLAPI HGDIOBJ WINAPI GetCurrentObject(HDC hdc, UINT type)
{
    dc_t *dc;
    HGDIOBJ r = 0;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    switch (type) {
    case OBJ_PEN: case OBJ_EXTPEN: r = dc->pen; break;
    case OBJ_BRUSH: r = dc->brush; break;
    case OBJ_FONT: r = dc->font; break;
    case OBJ_BITMAP: r = (HGDIOBJ)dc->hbmp; break;
    default: SetLastError(ERROR_INVALID_PARAMETER);
    }
    RET(r);
}

DLLAPI BOOL WINAPI DeleteObject(HGDIOBJ h)
{
    int type = 0;
    void *p;
    GDI_ENTER();
    p = gdi_obj_get(h, 0, &type);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (obj_is_stock(h)) RET(TRUE);                                   /* stock objects are never deleted */
    switch (type) {
    case OBJ_BITMAP: {
        bitmap_t *b = p;
        if (b->sel) RET(FALSE);                                       /* still selected into a DC */
        if (!bitmap_destroy(b)) RET(FALSE);
        break;
    }
    case OBJ_REGION: { rgn_t *r = p; rl_free(&r->rl); gdi_free(r); break; }
    case OBJ_BRUSH: case OBJ_PEN: case OBJ_EXTPEN: case OBJ_FONT: gdi_free(p); break;
    default: SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE);
    }
    gdi_obj_free(h);
    RET(TRUE);
}

DLLAPI DWORD WINAPI GetObjectType(HGDIOBJ h)
{
    DWORD t;
    GDI_ENTER();
    t = (DWORD)gdi_obj_type(h);
    RET(t);
}

DLLAPI int WINAPI GetObjectW(HANDLE h, int cb, LPVOID buf)
{
    int type = 0;
    void *p;
    int n = 0;
    GDI_ENTER();
    p = gdi_obj_get((HGDIOBJ)h, 0, &type);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    switch (type) {
    case OBJ_PEN: n = sizeof(LOGPEN); if (buf && cb >= n) memcpy(buf, &((pen_t *)p)->lp, (size_t)n); else if (buf) n = 0; break;
    case OBJ_BRUSH: n = sizeof(LOGBRUSH); if (buf && cb >= n) memcpy(buf, &((brush_t *)p)->lb, (size_t)n); else if (buf) n = 0; break;
    case OBJ_FONT: n = sizeof(LOGFONTW); if (buf && cb >= n) memcpy(buf, &((font_t *)p)->lf, (size_t)n); else if (buf) n = 0; break;
    case OBJ_BITMAP: {
        bitmap_t *b = p;
        DIBSECTION ds;
        memset(&ds, 0, sizeof ds);
        ds.dsBm.bmWidth = b->w; ds.dsBm.bmHeight = b->h; ds.dsBm.bmWidthBytes = b->w * 4; ds.dsBm.bmPlanes = 1;
        ds.dsBm.bmBitsPixel = 32; ds.dsBm.bmBits = b->is_dib ? b->bits : 0;
        if (b->is_dib && cb >= (int)sizeof ds) {
            ds.dsBmih = b->bih;
            memcpy(ds.dsBitfields, b->masks, sizeof b->masks);
            ds.dshSection = b->section;
            ds.dsOffset = b->section_offset;
            n = sizeof ds;
            if (buf) memcpy(buf, &ds, sizeof ds);
        } else {
            n = sizeof(BITMAP);
            if (buf && cb >= n) memcpy(buf, &ds.dsBm, sizeof(BITMAP)); else if (buf) n = 0;
        }
        break;
    }
    default: SetLastError(ERROR_INVALID_PARAMETER);
    }
    RET(n);
}

/* ---------------------------------------------------------------- DC attributes */
enum { A_TEXT, A_BK, A_BKMODE, A_ROP2, A_STRETCH, A_TEXTALIGN };
static int64_t dc_attr(HDC h, int which, int have_new, int64_t nv, int64_t err)
{
    dc_t *dc;
    int64_t old;
    int *pi = 0;
    COLORREF *pc = 0;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(err); }
    switch (which) {
    case A_TEXT: pc = &dc->text; break;
    case A_BK: pc = &dc->bk_color; break;
    case A_BKMODE: pi = &dc->bkmode; break;
    case A_ROP2: pi = &dc->rop2; break;
    case A_STRETCH: pi = &dc->stretchmode; break;
    default: pi = &dc->textalign; break;
    }
    old = pc ? (int64_t)*pc : (int64_t)*pi;
    if (have_new) { if (pc) *pc = (COLORREF)nv; else *pi = (int)nv; }
    RET(old);
}

DLLAPI COLORREF WINAPI SetTextColor(HDC h, COLORREF c) { return (COLORREF)dc_attr(h, A_TEXT, 1, (int64_t)c, (int64_t)CLR_INVALID); }
DLLAPI COLORREF WINAPI GetTextColor(HDC h) { return (COLORREF)dc_attr(h, A_TEXT, 0, 0, (int64_t)CLR_INVALID); }
DLLAPI COLORREF WINAPI SetBkColor(HDC h, COLORREF c) { return (COLORREF)dc_attr(h, A_BK, 1, (int64_t)c, (int64_t)CLR_INVALID); }
DLLAPI COLORREF WINAPI GetBkColor(HDC h) { return (COLORREF)dc_attr(h, A_BK, 0, 0, (int64_t)CLR_INVALID); }
DLLAPI int WINAPI SetBkMode(HDC h, int m) { return (int)dc_attr(h, A_BKMODE, 1, m, 0); }
DLLAPI int WINAPI GetBkMode(HDC h) { return (int)dc_attr(h, A_BKMODE, 0, 0, 0); }
DLLAPI int WINAPI SetROP2(HDC h, int m) { return (int)dc_attr(h, A_ROP2, 1, m, 0); }
DLLAPI int WINAPI GetROP2(HDC h) { return (int)dc_attr(h, A_ROP2, 0, 0, 0); }
DLLAPI int WINAPI SetStretchBltMode(HDC h, int m) { return (int)dc_attr(h, A_STRETCH, 1, m, 0); }
DLLAPI int WINAPI GetStretchBltMode(HDC h) { return (int)dc_attr(h, A_STRETCH, 0, 0, 0); }
DLLAPI UINT WINAPI SetTextAlign(HDC h, UINT m) { return (UINT)dc_attr(h, A_TEXTALIGN, 1, (int64_t)m, (int64_t)GDI_ERROR); }
DLLAPI UINT WINAPI GetTextAlign(HDC h) { return (UINT)dc_attr(h, A_TEXTALIGN, 0, 0, (int64_t)GDI_ERROR); }

DLLAPI int WINAPI SetPolyFillMode(HDC h, int mode)
{
    dc_t *dc;
    int old;
    if (mode != ALTERNATE && mode != WINDING) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    old = dc->polyfill;
    dc->polyfill = mode;
    RET(old);
}

DLLAPI int WINAPI GetPolyFillMode(HDC h)
{
    dc_t *dc;
    int v;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    v = dc ? dc->polyfill : 0;
    RET(v);
}

DLLAPI int WINAPI SetGraphicsMode(HDC h, int mode)
{
    dc_t *dc;
    int old;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    if (mode != GM_COMPATIBLE && mode != GM_ADVANCED) { SetLastError(ERROR_INVALID_PARAMETER); RET(0); }
    if (mode == GM_COMPATIBLE && (dc->xf_dx || dc->xf_dy || dc->xf.eDx != 0.0f || dc->xf.eDy != 0.0f)) {
        SetLastError(ERROR_CAN_NOT_COMPLETE);                         /* only with the identity world transform, as on Windows */
        RET(0);
    }
    old = dc->gfxmode;
    dc->gfxmode = mode;
    RET(old);
}

DLLAPI int WINAPI SetMapMode(HDC h, int mode)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    if (mode != MM_TEXT) { SetLastError(ERROR_NOT_SUPPORTED); RET(0); }              /* only MM_TEXT */
    RET(MM_TEXT);
}

DLLAPI int WINAPI GetMapMode(HDC h)
{
    dc_t *dc;
    int m;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    m = dc ? MM_TEXT : 0;
    RET(m);
}

DLLAPI BOOL WINAPI SetViewportOrgEx(HDC h, int x, int y, LPPOINT old)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (old) *old = dc->vp_org;
    dc->vp_org.x = x; dc->vp_org.y = y;
    RET(TRUE);
}
DLLAPI BOOL WINAPI GetViewportOrgEx(HDC h, LPPOINT p)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc || !p) RET(FALSE);
    *p = dc->vp_org;
    RET(TRUE);
}
DLLAPI BOOL WINAPI OffsetViewportOrgEx(HDC h, int dx, int dy, LPPOINT old)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (old) *old = dc->vp_org;
    dc->vp_org.x += dx; dc->vp_org.y += dy;
    RET(TRUE);
}
DLLAPI BOOL WINAPI SetWindowOrgEx(HDC h, int x, int y, LPPOINT old)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (old) *old = dc->win_org;
    dc->win_org.x = x; dc->win_org.y = y;
    RET(TRUE);
}
DLLAPI BOOL WINAPI GetWindowOrgEx(HDC h, LPPOINT p)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc || !p) RET(FALSE);
    *p = dc->win_org;
    RET(TRUE);
}
DLLAPI BOOL WINAPI SetBrushOrgEx(HDC h, int x, int y, LPPOINT old)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (old) *old = dc->brush_org;
    dc->brush_org.x = x; dc->brush_org.y = y;
    RET(TRUE);
}
DLLAPI BOOL WINAPI GetBrushOrgEx(HDC h, LPPOINT p)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc || !p) RET(FALSE);
    *p = dc->brush_org;
    RET(TRUE);
}

DLLAPI COLORREF WINAPI SetDCPenColor(HDC h, COLORREF c)
{
    dc_t *dc;
    COLORREF old;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(CLR_INVALID); }
    old = dc->dcpen;
    dc->dcpen = c;
    RET(old);
}
DLLAPI COLORREF WINAPI GetDCPenColor(HDC h)
{
    dc_t *dc;
    COLORREF c;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    c = dc ? dc->dcpen : CLR_INVALID;
    RET(c);
}
DLLAPI COLORREF WINAPI SetDCBrushColor(HDC h, COLORREF c)
{
    dc_t *dc;
    COLORREF old;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(CLR_INVALID); }
    old = dc->dcbrush;
    dc->dcbrush = c;
    RET(old);
}
DLLAPI COLORREF WINAPI GetDCBrushColor(HDC h)
{
    dc_t *dc;
    COLORREF c;
    GDI_ENTER();
    dc = gdi_dc_get(h);
    c = dc ? dc->dcbrush : CLR_INVALID;
    RET(c);
}

/* The screen size (the display mode the kernel reports; it depends on the display backend). Without a display device the
 * nominal 1024x768 of the Bochs VBE mode stands in for it, so that memory-DC programs still get consistent answers. */
static void screen_size(int *w, int *h)
{
    static int sw, sh;
    if (!sw) {
        shz_display_info_t info;
        memset(&info, 0, sizeof info);
        info.size = sizeof info;
        if (NtUserQueryDisplay(&info, SHZ_DISP_QUERY) >= 0 && info.width && info.height) { sw = (int)info.width; sh = (int)info.height; }
        else { sw = 1024; sh = 768; }
    }
    *w = sw;
    *h = sh;
}

DLLAPI int WINAPI GetDeviceCaps(HDC h, int index)
{
    dc_t *dc;
    int w, hh, v = 0, sw, sh;
    GDI_ENTER();
    dc = gdi_obj_get((HGDIOBJ)h, OBJ_DC, 0);   /* information contexts allow this query/lifecycle operation */
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    screen_size(&sw, &sh);
    w = sw;
    hh = sh;
    if (dc->memdc) {
        bitmap_t *b = gdi_obj_get((HGDIOBJ)dc->hbmp, OBJ_BITMAP, 0);
        w = b ? b->w : 1;
        hh = b ? b->h : 1;
    } else if (dc->wcx) {
        w = dc->wcx; hh = dc->wcy;
    }
    switch (index) {
    case DRIVERVERSION: v = 0x0400; break;
    case TECHNOLOGY: v = DT_RASDISPLAY; break;
    case HORZSIZE: v = sw * 254 / 960; break;                      /* the screen at 96 dpi, in millimetres */
    case VERTSIZE: v = sh * 254 / 960; break;
    case HORZRES: v = w; break;
    case VERTRES: v = hh; break;
    case BITSPIXEL: v = 32; break;
    case PLANES: v = 1; break;
    case NUMBRUSHES: v = -1; break;
    case NUMPENS: v = -1; break;
    case NUMFONTS: v = 1; break;
    case NUMCOLORS: v = -1; break;
    case CLIPCAPS: v = CP_RECTANGLE; break;
    case RASTERCAPS: v = RC_BITBLT | RC_BITMAP64 | RC_DI_BITMAP | RC_DIBTODEV | RC_STRETCHBLT | RC_STRETCHDIB; break;
    case ASPECTX: case ASPECTY: v = 36; break;
    case ASPECTXY: v = 51; break;
    case LOGPIXELSX: case LOGPIXELSY: v = 96; break;
    case VREFRESH: v = 1; break;                                    /* "the hardware's default refresh rate": the Bochs VBE has none to report */
    case SIZEPALETTE: case NUMRESERVED: v = 0; break;
    case COLORRES: v = 24; break;
    case PHYSICALWIDTH: v = w; break;
    case PHYSICALHEIGHT: v = hh; break;
    case SHADEBLENDCAPS: v = SB_CONST_ALPHA | SB_PIXEL_ALPHA | SB_PREMULT_ALPHA; break;   /* GdiAlphaBlend */
    case DESKTOPHORZRES: v = sw; break;
    case DESKTOPVERTRES: v = sh; break;
    default: v = 0;
    }
    RET(v);
}

DLLAPI BOOL WINAPI GdiFlush(void)
{
    extern void gdi_flush_all_locked(void);
    GDI_ENTER();
    gdi_flush_all_locked();
    RET(TRUE);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        bitmap_t *b;
        HGDIOBJ hb;
        InitializeCriticalSection(&g_gdi_lock);
        make_stock();
        b = bitmap_create(1, 1, 1);                                /* the 1x1 bitmap every new memory DC starts with */
        if (b) {
            hb = gdi_obj_new(OBJ_BITMAP, b, 1);
            g_default_bitmap = b;
            g_default_hbitmap = (HBITMAP)hb;
            b->bits[0] = 0xffffff;
        }
    }
    return TRUE;
}

/* The pixels a DC draws into (UpdateLayeredWindow's source): the selected bitmap of a memory DC or a window DC's backing.
 * The pointer stays valid while the bitmap stays selected; callers hold no GDI lock while they read it. */
DLLAPI BOOL WINAPI ShzGdiDCBitmap(HDC hdc, const uint32_t **bits, int *w, int *h, int *topdown)
{
    dc_t *dc;
    bitmap_t *b;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    b = dc ? gdi_dc_target(dc) : 0;
    if (!b || !b->bits) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (dc->hwnd) gdi_window_dc_flush(dc);
    *bits = b->bits;
    *w = b->w;
    *h = b->h;
    *topdown = b->topdown;
    RET(TRUE);
}

DLLAPI HWND WINAPI ShzGdiDCWindow(HDC hdc)
{
    dc_t *dc;
    HWND h;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    h = dc ? dc->hwnd : 0;
    RET(h);
}

/* GetWindowDC: logical (0,0) is the window's top-left corner while the DC keeps drawing into the client backing. */
DLLAPI BOOL WINAPI ShzGdiSetDeviceOrigin(HDC hdc, int x, int y)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || dc->memdc) RET(FALSE);
    dc->dev_org.x = x;
    dc->dev_org.y = y;
    dc->eff_valid = 0;
    RET(TRUE);
}
