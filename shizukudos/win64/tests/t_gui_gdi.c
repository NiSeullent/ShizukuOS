/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32 self-test on memory DCs: needs no display, so it runs (and must pass) in the plain standalone runner too.
 * Expected values are written down here from the documented Win32 behaviour, not read back from the implementation. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

#define W 64
#define H 48

static HDC g_dc;
static HBITMAP g_bmp;
static unsigned *g_bits;

static int setup(void)
{
    BITMAPINFO bi;
    memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = W;
    bi.bmiHeader.biHeight = H;                       /* bottom-up */
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    g_dc = CreateCompatibleDC(0);
    g_bmp = CreateDIBSection(g_dc, &bi, DIB_RGB_COLORS, (void **)&g_bits, 0, 0);
    if (!g_dc || !g_bmp || !g_bits) return 0;
    SelectObject(g_dc, g_bmp);
    return 1;
}

static void clear(COLORREF c)
{
    HBRUSH b = CreateSolidBrush(c), old = SelectObject(g_dc, b);
    PatBlt(g_dc, 0, 0, W, H, PATCOPY);
    SelectObject(g_dc, old);
    DeleteObject(b);
}

/* memory layout of a bottom-up 32 bpp DIB: scan line y (from the top) is row H-1-y */
static unsigned raw(int x, int y) { return g_bits[(H - 1 - y) * W + x] & 0xffffff; }
static COLORREF rgb_of(unsigned p) { return RGB((p >> 16) & 255, (p >> 8) & 255, p & 255); }

static int region_is(int l, int t, int r, int b, COLORREF c)
{
    int x, y;
    for (y = t; y < b; ++y)
        for (x = l; x < r; ++x)
            if (GetPixel(g_dc, x, y) != c) return 0;
    return 1;
}

static void test_basic(void)
{
    clear(RGB(10, 20, 30));
    CHECK(GetPixel(g_dc, 5, 5) == RGB(10, 20, 30), "PatBlt(PATCOPY) fills with the brush colour");
    CHECK(rgb_of(raw(5, 5)) == RGB(10, 20, 30) && raw(5, 5) == 0x0a141e, "DIB section bits hold 0x00RRGGBB, bottom-up rows");
    CHECK(SetPixel(g_dc, 3, 4, RGB(255, 0, 0)) == RGB(255, 0, 0) && GetPixel(g_dc, 3, 4) == RGB(255, 0, 0) && raw(3, 4) == 0xff0000,
          "SetPixel/GetPixel and the raw pixel agree");
    CHECK(GetPixel(g_dc, -1, 0) == CLR_INVALID && GetPixel(g_dc, W, 0) == CLR_INVALID, "GetPixel outside the bitmap is CLR_INVALID");
}

static void test_shapes(void)
{
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(0, 0, 255)), op;
    HBRUSH br = CreateSolidBrush(RGB(255, 255, 0)), ob;
    POINT tri[3] = { { 30, 30 }, { 50, 30 }, { 40, 44 } };
    clear(RGB(255, 255, 255));
    op = SelectObject(g_dc, pen);
    ob = SelectObject(g_dc, br);
    Rectangle(g_dc, 10, 5, 20, 15);
    CHECK(GetPixel(g_dc, 10, 5) == RGB(0, 0, 255) && GetPixel(g_dc, 19, 5) == RGB(0, 0, 255) && GetPixel(g_dc, 10, 14) == RGB(0, 0, 255) &&
          GetPixel(g_dc, 19, 14) == RGB(0, 0, 255), "Rectangle: the pen outlines l..r-1, t..b-1");
    CHECK(GetPixel(g_dc, 20, 5) == RGB(255, 255, 255) && GetPixel(g_dc, 10, 15) == RGB(255, 255, 255), "Rectangle excludes the right and bottom edge");
    CHECK(region_is(11, 6, 19, 14, RGB(255, 255, 0)), "Rectangle: interior is the brush colour");
    MoveToEx(g_dc, 2, 30, 0);
    LineTo(g_dc, 12, 30);
    CHECK(region_is(2, 30, 12, 31, RGB(0, 0, 255)) && GetPixel(g_dc, 12, 30) == RGB(255, 255, 255), "LineTo draws up to but excluding the end point");
    MoveToEx(g_dc, 40, 2, 0);
    LineTo(g_dc, 50, 12);
    CHECK(GetPixel(g_dc, 40, 2) == RGB(0, 0, 255) && GetPixel(g_dc, 45, 7) == RGB(0, 0, 255) && GetPixel(g_dc, 49, 11) == RGB(0, 0, 255) &&
          GetPixel(g_dc, 50, 12) == RGB(255, 255, 255), "diagonal LineTo hits (40,2), (45,7), (49,11), not (50,12)");
    Polygon(g_dc, tri, 3);
    CHECK(GetPixel(g_dc, 40, 34) == RGB(255, 255, 0) && GetPixel(g_dc, 30, 40) == RGB(255, 255, 255) && GetPixel(g_dc, 40, 31) == RGB(255, 255, 0),
          "Polygon fills the interior with the brush and not the outside");
    Ellipse(g_dc, 2, 33, 22, 47);
    CHECK(GetPixel(g_dc, 12, 40) == RGB(255, 255, 0) && GetPixel(g_dc, 2, 33) == RGB(255, 255, 255) && GetPixel(g_dc, 12, 33) == RGB(0, 0, 255),
          "Ellipse: centre filled, bounding-box corner untouched, top of the outline drawn");
    SelectObject(g_dc, GetStockObject(NULL_PEN));
    Rectangle(g_dc, 50, 20, 60, 28);
    CHECK(region_is(50, 20, 60, 28, RGB(255, 255, 0)), "Rectangle with NULL_PEN fills [l,r) x [t,b)");
    SelectObject(g_dc, op);
    SelectObject(g_dc, ob);
    DeleteObject(pen);
    DeleteObject(br);
}

static void test_rop_and_blit(void)
{
    HDC src = CreateCompatibleDC(0);
    HBITMAP sb = CreateCompatibleBitmap(g_dc, 8, 8), old;
    HBRUSH red = CreateSolidBrush(RGB(200, 0, 0)), ob;
    int ok;
    clear(RGB(0, 0, 0));
    old = SelectObject(src, sb);
    ob = SelectObject(src, red);
    PatBlt(src, 0, 0, 8, 8, PATCOPY);
    SelectObject(src, ob);
    ok = BitBlt(g_dc, 10, 10, 8, 8, src, 0, 0, SRCCOPY);
    CHECK(ok && region_is(10, 10, 18, 18, RGB(200, 0, 0)) && GetPixel(g_dc, 18, 10) == RGB(0, 0, 0) && GetPixel(g_dc, 9, 10) == RGB(0, 0, 0),
          "BitBlt SRCCOPY copies exactly the rectangle");
    BitBlt(g_dc, 10, 10, 8, 8, src, 0, 0, SRCINVERT);
    CHECK(region_is(10, 10, 18, 18, RGB(0, 0, 0)), "SRCINVERT applied twice restores the destination");
    BitBlt(g_dc, 10, 10, 8, 8, src, 0, 0, NOTSRCCOPY);
    CHECK(GetPixel(g_dc, 12, 12) == RGB(55, 255, 255), "NOTSRCCOPY inverts the source");
    PatBlt(g_dc, 10, 10, 8, 8, DSTINVERT);
    CHECK(GetPixel(g_dc, 12, 12) == RGB(200, 0, 0), "DSTINVERT inverts the destination");
    PatBlt(g_dc, 10, 10, 8, 8, BLACKNESS);
    CHECK(region_is(10, 10, 18, 18, RGB(0, 0, 0)), "BLACKNESS");
    PatBlt(g_dc, 10, 10, 8, 8, WHITENESS);
    CHECK(region_is(10, 10, 18, 18, RGB(255, 255, 255)), "WHITENESS");
    /* stretch 8x8 red -> 16x16 at (20,20) */
    clear(RGB(0, 0, 0));
    ok = StretchBlt(g_dc, 20, 20, 16, 16, src, 0, 0, 8, 8, SRCCOPY);
    CHECK(ok && region_is(20, 20, 36, 36, RGB(200, 0, 0)) && GetPixel(g_dc, 36, 20) == RGB(0, 0, 0), "StretchBlt 2x covers the destination rectangle");
    /* scroll inside one bitmap: overlapping BitBlt must behave like memmove */
    clear(RGB(0, 0, 0));
    SetPixel(g_dc, 0, 0, RGB(1, 2, 3));
    SetPixel(g_dc, 1, 0, RGB(4, 5, 6));
    BitBlt(g_dc, 1, 0, 8, 1, g_dc, 0, 0, SRCCOPY);
    CHECK(GetPixel(g_dc, 1, 0) == RGB(1, 2, 3) && GetPixel(g_dc, 2, 0) == RGB(4, 5, 6), "overlapping BitBlt within one bitmap copies from a snapshot");
    SelectObject(src, old);
    CHECK(DeleteObject(sb) == TRUE, "a bitmap can be deleted once deselected");
    DeleteObject(red);
    DeleteDC(src);
}

static void test_rop2(void)
{
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(255, 255, 255)), op;
    clear(RGB(0, 0, 255));
    op = SelectObject(g_dc, pen);
    SetROP2(g_dc, R2_XORPEN);
    MoveToEx(g_dc, 0, 5, 0);
    LineTo(g_dc, 10, 5);
    CHECK(GetPixel(g_dc, 3, 5) == RGB(255, 255, 0), "R2_XORPEN: white pen over blue gives yellow");
    LineTo(g_dc, 0, 5);
    SetROP2(g_dc, R2_COPYPEN);
    SelectObject(g_dc, op);
    DeleteObject(pen);
}

static void test_clip_and_regions(void)
{
    HRGN a = CreateRectRgn(10, 10, 30, 30), b = CreateRectRgn(20, 20, 40, 40), c = CreateRectRgn(0, 0, 1, 1), box;
    RECT rc;
    HBRUSH br = CreateSolidBrush(RGB(9, 9, 9)), ob;
    CHECK(CombineRgn(c, a, b, RGN_AND) == SIMPLEREGION && GetRgnBox(c, &rc) == SIMPLEREGION && rc.left == 20 && rc.top == 20 &&
          rc.right == 30 && rc.bottom == 30, "CombineRgn(RGN_AND) is the overlap");
    CHECK(CombineRgn(c, a, b, RGN_OR) == COMPLEXREGION && GetRgnBox(c, &rc) && rc.left == 10 && rc.top == 10 && rc.right == 40 && rc.bottom == 40 &&
          PtInRegion(c, 15, 15) && PtInRegion(c, 35, 35) && !PtInRegion(c, 35, 15), "CombineRgn(RGN_OR) is the union");
    CHECK(CombineRgn(c, a, b, RGN_DIFF) == COMPLEXREGION && PtInRegion(c, 12, 12) && !PtInRegion(c, 25, 25) && !PtInRegion(c, 35, 35),
          "CombineRgn(RGN_DIFF) removes the overlap");
    box = CreateRectRgn(10, 10, 30, 30);
    CHECK(EqualRgn(a, box), "EqualRgn on identical regions");
    clear(RGB(255, 255, 255));
    SelectClipRgn(g_dc, b);
    ob = SelectObject(g_dc, br);
    PatBlt(g_dc, 0, 0, W, H, PATCOPY);
    CHECK(GetPixel(g_dc, 25, 25) == RGB(9, 9, 9) && raw(15, 15) == 0xffffff && raw(45, 25) == 0xffffff && raw(39, 39) == 0x090909,
          "SelectClipRgn restricts drawing to the region");
    SelectClipRgn(g_dc, 0);
    clear(RGB(255, 255, 255));
    IntersectClipRect(g_dc, 5, 5, 15, 15);
    ExcludeClipRect(g_dc, 8, 8, 12, 12);
    PatBlt(g_dc, 0, 0, W, H, PATCOPY);
    CHECK(raw(6, 6) == 0x090909 && raw(10, 10) == 0xffffff && raw(20, 20) == 0xffffff && raw(14, 14) == 0x090909,
          "IntersectClipRect + ExcludeClipRect leave a frame");
    GetClipBox(g_dc, &rc);
    CHECK(rc.left == 5 && rc.top == 5 && rc.right == 15 && rc.bottom == 15, "GetClipBox reports the clip bounds");
    SelectClipRgn(g_dc, 0);
    SelectObject(g_dc, ob);
    DeleteObject(br);
    DeleteObject(a); DeleteObject(b); DeleteObject(c); DeleteObject(box);
}

/* 'H' from the public-domain 8x8 font: rows 0x33,0x33,0x33,0x3F,0x33,0x33,0x33,0x00, bit 0 = leftmost pixel, each row doubled to 16 */
static void test_text(void)
{
    static const unsigned char H8[8] = { 0x33, 0x33, 0x33, 0x3f, 0x33, 0x33, 0x33, 0x00 };
    SIZE sz;
    TEXTMETRICW tm;
    int x, y, wrong = 0;
    clear(RGB(255, 255, 255));
    SetTextColor(g_dc, RGB(0, 0, 0));
    SetBkMode(g_dc, TRANSPARENT);
    TextOutW(g_dc, 8, 8, L"H", 1);
    for (y = 0; y < 16; ++y)
        for (x = 0; x < 8; ++x) {
            const int on = (H8[y >> 1] >> x) & 1;
            if ((GetPixel(g_dc, 8 + x, 8 + y) == RGB(0, 0, 0)) != on) ++wrong;
        }
    CHECK(wrong == 0, "TextOutW('H') draws exactly the 8x16 glyph (8x8 font rows doubled)");
    CHECK(GetPixel(g_dc, 7, 8) == RGB(255, 255, 255) && GetPixel(g_dc, 16, 8) == RGB(255, 255, 255), "transparent text leaves the neighbouring pixels alone");
    GetTextExtentPoint32W(g_dc, L"Hello", 5, &sz);
    CHECK(sz.cx == 40 && sz.cy == 16, "GetTextExtentPoint32W: 8x16 cells");
    GetTextMetricsW(g_dc, &tm);
    CHECK(tm.tmHeight == 16 && tm.tmAscent == 13 && tm.tmDescent == 3 && tm.tmAveCharWidth == 8, "GetTextMetrics: 16 high, ascent 13, width 8");
    clear(RGB(255, 255, 255));
    SetBkMode(g_dc, OPAQUE);
    SetBkColor(g_dc, RGB(0, 128, 0));
    TextOutW(g_dc, 0, 0, L" ", 1);
    CHECK(region_is(0, 0, 8, 16, RGB(0, 128, 0)), "opaque text paints the background cell");
    {
        HFONT f = CreateFontW(32, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, 0, L"Arial"), of;
        of = SelectObject(g_dc, f);
        GetTextExtentPoint32W(g_dc, L"AB", 2, &sz);
        CHECK(sz.cx == 32 && sz.cy == 32, "a 32 pixel font is the built-in font at scale 2");
        SelectObject(g_dc, of);
        DeleteObject(f);
    }
}

static void test_dib(void)
{
    /* 2x2 24 bpp bottom-up DIB: bottom row red, green; top row blue, white (BGR bytes, rows padded to 4) */
    static const unsigned char rows24[16] = { 0, 0, 255, 0, 255, 0, 0, 0, 255, 0, 0, 255, 255, 255, 0, 0 };
    struct { BITMAPINFOHEADER h; RGBQUAD pal[2]; } b8;
    BITMAPINFO bi24;
    static const unsigned char rows8[8] = { 0, 1, 0, 0, 1, 0, 0, 0 };
    int n;
    clear(RGB(0, 0, 0));
    memset(&bi24, 0, sizeof bi24);
    bi24.bmiHeader.biSize = sizeof bi24.bmiHeader;
    bi24.bmiHeader.biWidth = 2;
    bi24.bmiHeader.biHeight = 2;
    bi24.bmiHeader.biPlanes = 1;
    bi24.bmiHeader.biBitCount = 24;
    n = SetDIBitsToDevice(g_dc, 10, 10, 2, 2, 0, 0, 0, 2, rows24, &bi24, DIB_RGB_COLORS);
    CHECK(n == 2, "SetDIBitsToDevice returns the number of scan lines");
    CHECK(GetPixel(g_dc, 10, 11) == RGB(255, 0, 0) && GetPixel(g_dc, 11, 11) == RGB(0, 255, 0) && GetPixel(g_dc, 10, 10) == RGB(0, 0, 255) &&
          GetPixel(g_dc, 11, 10) == RGB(255, 255, 255), "24 bpp bottom-up DIB lands the right way up");
    memset(&b8, 0, sizeof b8);
    b8.h.biSize = sizeof b8.h;
    b8.h.biWidth = 2;
    b8.h.biHeight = -2;                                  /* top-down */
    b8.h.biPlanes = 1;
    b8.h.biBitCount = 8;
    b8.h.biClrUsed = 2;
    b8.pal[0].rgbRed = 10; b8.pal[0].rgbGreen = 20; b8.pal[0].rgbBlue = 30;
    b8.pal[1].rgbRed = 200; b8.pal[1].rgbGreen = 100; b8.pal[1].rgbBlue = 50;
    n = StretchDIBits(g_dc, 20, 20, 4, 4, 0, 0, 2, 2, rows8, (BITMAPINFO *)&b8, DIB_RGB_COLORS, SRCCOPY);
    CHECK(n == 2 && GetPixel(g_dc, 20, 20) == RGB(10, 20, 30) && GetPixel(g_dc, 22, 20) == RGB(200, 100, 50) && GetPixel(g_dc, 20, 22) == RGB(200, 100, 50) &&
          GetPixel(g_dc, 23, 23) == RGB(10, 20, 30), "StretchDIBits 8 bpp palettised top-down, 2x");
    {
        unsigned out[4];
        BITMAPINFO q;
        memset(&q, 0, sizeof q);
        q.bmiHeader.biSize = sizeof q.bmiHeader;
        q.bmiHeader.biWidth = W;
        q.bmiHeader.biHeight = -H;
        q.bmiHeader.biPlanes = 1;
        q.bmiHeader.biBitCount = 32;
        q.bmiHeader.biCompression = BI_RGB;
        {
            unsigned *all = HeapAlloc(GetProcessHeap(), 0, W * H * 4);
            n = GetDIBits(g_dc, g_bmp, 0, H, all, &q, DIB_RGB_COLORS);
            out[0] = all[11 * W + 10] & 0xffffff;
            out[1] = all[20 * W + 22] & 0xffffff;
            HeapFree(GetProcessHeap(), 0, all);
        }
        CHECK(n == H && out[0] == 0xff0000 && out[1] == 0xc86432, "GetDIBits returns the bitmap top-down as 32 bpp");
    }
}

static void test_objects(void)
{
    HPEN p = CreatePen(PS_SOLID, 3, RGB(1, 2, 3)), p2;
    HBRUSH b = CreateSolidBrush(RGB(4, 5, 6)), b2;
    LOGPEN lp;
    LOGBRUSH lb;
    BITMAP bm;
    int lvl;
    CHECK(GetObjectType(p) == OBJ_PEN && GetObjectType(b) == OBJ_BRUSH && GetObjectType(g_bmp) == OBJ_BITMAP && GetObjectType(g_dc) == OBJ_MEMDC,
          "GetObjectType");
    CHECK(GetObjectW(p, sizeof lp, &lp) == sizeof lp && lp.lopnWidth.x == 3 && lp.lopnColor == RGB(1, 2, 3) && lp.lopnStyle == PS_SOLID, "GetObject(HPEN)");
    CHECK(GetObjectW(b, sizeof lb, &lb) == sizeof lb && lb.lbColor == RGB(4, 5, 6) && lb.lbStyle == BS_SOLID, "GetObject(HBRUSH)");
    CHECK(GetObjectW(g_bmp, sizeof bm, &bm) == sizeof bm && bm.bmWidth == W && bm.bmHeight == H && bm.bmBitsPixel == 32 && bm.bmBits == g_bits,
          "GetObject(HBITMAP) of a DIB section exposes the bits pointer");
    p2 = SelectObject(g_dc, p);
    b2 = SelectObject(g_dc, b);
    lvl = SaveDC(g_dc);
    SelectObject(g_dc, GetStockObject(WHITE_PEN));
    SelectObject(g_dc, GetStockObject(BLACK_BRUSH));
    SetTextColor(g_dc, RGB(9, 9, 9));
    CHECK(RestoreDC(g_dc, lvl) && GetCurrentObject(g_dc, OBJ_PEN) == p && GetCurrentObject(g_dc, OBJ_BRUSH) == b && GetTextColor(g_dc) != RGB(9, 9, 9),
          "SaveDC/RestoreDC restore the selected objects and attributes");
    SelectObject(g_dc, p2);
    SelectObject(g_dc, b2);
    CHECK(DeleteObject(GetStockObject(BLACK_BRUSH)) == TRUE && GetObjectType(GetStockObject(BLACK_BRUSH)) == OBJ_BRUSH, "stock objects survive DeleteObject");
    CHECK(DeleteObject(g_bmp) == FALSE, "a bitmap selected into a DC cannot be deleted");
    DeleteObject(p);
    DeleteObject(b);
    CHECK(GetObjectType(p) == 0, "a deleted handle is invalid");
    CHECK(GetDeviceCaps(g_dc, HORZRES) == W && GetDeviceCaps(g_dc, BITSPIXEL) == 32 && GetDeviceCaps(g_dc, LOGPIXELSX) == 96, "GetDeviceCaps on a memory DC");
}

static void test_alpha(void)
{
    HDC src = CreateCompatibleDC(0);
    HBITMAP sb = CreateCompatibleBitmap(g_dc, 4, 4), old;
    HBRUSH red = CreateSolidBrush(RGB(255, 0, 0)), ob;
    BLENDFUNCTION bf = { AC_SRC_OVER, 0, 128, 0 };
    COLORREF c;
    old = SelectObject(src, sb);
    ob = SelectObject(src, red);
    PatBlt(src, 0, 0, 4, 4, PATCOPY);
    SelectObject(src, ob);
    clear(RGB(255, 255, 255));
    GdiAlphaBlend(g_dc, 10, 10, 4, 4, src, 0, 0, 4, 4, bf);
    c = GetPixel(g_dc, 11, 11);
    CHECK(GetRValue(c) == 255 && GetGValue(c) >= 126 && GetGValue(c) <= 128 && GetBValue(c) >= 126 && GetBValue(c) <= 128, "GdiAlphaBlend 50% red over white");
    SelectObject(src, old);
    DeleteObject(sb);
    DeleteObject(red);
    DeleteDC(src);
}

int main(void)
{
    if (!setup()) { printf("FAIL: cannot create the memory DC and DIB section\n"); return 1; }
    test_basic();
    test_shapes();
    test_rop_and_blit();
    test_rop2();
    test_clip_and_regions();
    test_text();
    test_dib();
    test_alpha();
    test_objects();
    SelectObject(g_dc, GetStockObject(BLACK_PEN));
    printf("%s: gdi32 memory-DC tests\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
