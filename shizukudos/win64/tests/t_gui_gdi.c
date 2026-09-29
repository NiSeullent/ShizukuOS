/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32 self-test on memory DCs (plus user32's icons and cursors, which draw through gdi32): needs no display, so it runs
 * (and must pass) in the plain standalone runner too.
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

/* user32 icons: the built-in IDI_APPLICATION image is a black-framed box at [3,29)x[4,28) with a navy title band (rows 5-8
 * inside the frame), a white body and grey "text" lines on rows 12 and 16; everything outside the frame is transparent. */
static void test_icons(void)
{
    HICON app = LoadIconW(0, MAKEINTRESOURCEW(32512)), app2 = LoadIconW(0, MAKEINTRESOURCEW(32512)), mine, copy;
    HCURSOR arrow = LoadCursorW(0, MAKEINTRESOURCEW(32512)), hand = LoadCursorW(0, MAKEINTRESOURCEW(32649));
    ICONINFO ii;
    BITMAPINFO bi;
    unsigned *bits = 0;
    HBITMAP color, mask;
    BITMAP bm;
    int x, y, ok;
    CHECK(app && app == app2 && arrow && hand && arrow != hand && (HANDLE)app != (HANDLE)arrow, "system icons and cursors load, shared (same handle twice)");
    SetLastError(0);
    CHECK(!LoadCursorW(0, MAKEINTRESOURCEW(12345)) && GetLastError() == ERROR_RESOURCE_NAME_NOT_FOUND, "an unknown system cursor fails with ERROR_RESOURCE_NAME_NOT_FOUND");
    SetLastError(0);
    CHECK(!LoadIconW(GetModuleHandleW(0), MAKEINTRESOURCEW(1)) &&
          (GetLastError() == ERROR_RESOURCE_DATA_NOT_FOUND || GetLastError() == ERROR_RESOURCE_NAME_NOT_FOUND),
          "LoadIconW from a module that has no such icon resource fails (T_GUI_SYS loads real ones)");
    CHECK(!IsWindow((HWND)app), "an icon handle is not a window handle");

    clear(RGB(0, 255, 0));
    CHECK(DrawIconEx(g_dc, 0, 0, app, 0, 0, 0, 0, DI_NORMAL), "DrawIconEx(DI_NORMAL) at natural size");
    CHECK(GetPixel(g_dc, 3, 4) == RGB(0, 0, 0) && GetPixel(g_dc, 28, 27) == RGB(0, 0, 0), "frame corners are black");
    CHECK(GetPixel(g_dc, 10, 6) == RGB(0, 0, 128) && GetPixel(g_dc, 10, 20) == RGB(255, 255, 255) && GetPixel(g_dc, 10, 12) == RGB(128, 128, 128), "title band, body and text line");
    CHECK(GetPixel(g_dc, 1, 1) == RGB(0, 255, 0) && GetPixel(g_dc, 30, 30) == RGB(0, 255, 0) && GetPixel(g_dc, 40, 10) == RGB(0, 255, 0), "transparent pixels keep the background");
    clear(RGB(0, 255, 0));
    DrawIconEx(g_dc, 0, 0, app, 64, 64, 0, 0, DI_NORMAL);
    CHECK(GetPixel(g_dc, 6, 8) == RGB(0, 0, 0) && GetPixel(g_dc, 5, 8) == RGB(0, 255, 0) && GetPixel(g_dc, 20, 12) == RGB(0, 0, 128), "scaled 2x: every source pixel becomes a 2x2 block");
    clear(RGB(0, 255, 0));
    DrawIconEx(g_dc, 0, 0, app, 0, 0, 0, 0, DI_MASK);
    CHECK(GetPixel(g_dc, 10, 20) == RGB(0, 0, 0) && GetPixel(g_dc, 1, 1) == RGB(0, 255, 0), "DI_MASK blackens the opaque area only");
    {
        HBRUSH red = CreateSolidBrush(RGB(255, 0, 0));
        clear(RGB(0, 255, 0));
        DrawIconEx(g_dc, 0, 0, app, 0, 0, 0, red, DI_NORMAL);
        CHECK(GetPixel(g_dc, 1, 1) == RGB(255, 0, 0) && GetPixel(g_dc, 31, 31) == RGB(255, 0, 0) && GetPixel(g_dc, 32, 32) == RGB(0, 255, 0), "hbrFlickerFreeDraw fills the icon rectangle first");
        DeleteObject(red);
    }

    memset(&bi, 0, sizeof bi);                                                  /* a 4x4 icon from a 32 bpp alpha bitmap */
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = 4;
    bi.bmiHeader.biHeight = -4;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    color = CreateDIBSection(g_dc, &bi, DIB_RGB_COLORS, (void **)&bits, 0, 0);
    for (y = 0; y < 4; ++y)
        for (x = 0; x < 4; ++x) bits[y * 4 + x] = x == 0 ? 0 : x == 1 ? 0xff0000ffu : x == 2 ? 0x80ff0000u : 0xffffffffu;
    mask = CreateCompatibleBitmap(g_dc, 4, 4);
    memset(&ii, 0, sizeof ii);
    ii.fIcon = TRUE;
    ii.hbmColor = color;
    ii.hbmMask = mask;
    mine = CreateIconIndirect(&ii);
    CHECK(mine != 0, "CreateIconIndirect from a 32 bpp bitmap with alpha");
    clear(RGB(255, 255, 255));
    DrawIconEx(g_dc, 8, 8, mine, 0, 0, 0, 0, DI_NORMAL);
    {
        const COLORREF half = GetPixel(g_dc, 10, 8);
        CHECK(GetPixel(g_dc, 8, 8) == RGB(255, 255, 255) && GetPixel(g_dc, 9, 8) == RGB(0, 0, 255) && GetPixel(g_dc, 11, 11) == RGB(255, 255, 255), "alpha 0 keeps, alpha 255 replaces");
        CHECK(GetRValue(half) == 255 && GetGValue(half) >= 126 && GetGValue(half) <= 128 && GetBValue(half) == GetGValue(half), "alpha 128 red over white blends to (255,127,127)");
    }
    memset(&ii, 0, sizeof ii);
    ok = GetIconInfo(mine, &ii);
    CHECK(ok && ii.fIcon && ii.xHotspot == 2 && ii.yHotspot == 2 && ii.hbmColor && ii.hbmMask, "GetIconInfo: icon, hot spot at the centre, two new bitmaps");
    CHECK(ok && GetObjectW(ii.hbmColor, sizeof bm, &bm) == sizeof bm && bm.bmWidth == 4 && bm.bmHeight == 4, "the colour bitmap is 4x4");
    if (ok) { DeleteObject(ii.hbmColor); DeleteObject(ii.hbmMask); }
    copy = CopyIcon(mine);
    CHECK(copy && copy != mine, "CopyIcon makes a new handle");
    CHECK(DestroyIcon(mine) && !DestroyIcon(mine) && GetLastError() == ERROR_INVALID_CURSOR_HANDLE, "DestroyIcon frees; a second call fails");
    clear(RGB(255, 255, 255));
    CHECK(DrawIconEx(g_dc, 0, 0, copy, 0, 0, 0, 0, DI_NORMAL) && GetPixel(g_dc, 1, 0) == RGB(0, 0, 255), "the copy survives the original");
    DestroyIcon(copy);
    DeleteObject(color);
    DeleteObject(mask);
    CHECK(DestroyIcon(app) && LoadIconW(0, MAKEINTRESOURCEW(32512)) == app, "shared system icons survive DestroyIcon");

    CHECK(GetCursor() == 0 && SetCursor(arrow) == 0 && GetCursor() == arrow && SetCursor(hand) == arrow, "SetCursor/GetCursor keep the thread's cursor");
    SetCursor(0);
}


/* ---------------------------------------------------------------- paths (documented Win32 behaviour: device coordinates,
 * nothing drawn while recording, FillPath/StrokePath/SelectClipPath consume the path, polygon interiors exclude the
 * right and bottom edges) */
static int count_colour(int l, int t, int r, int b, COLORREF c)
{
    int x, y, n = 0;
    for (y = t; y < b; ++y)
        for (x = l; x < r; ++x) n += GetPixel(g_dc, x, y) == c;
    return n;
}

static void test_paths(void)
{
    HBRUSH red = CreateSolidBrush(RGB(255, 0, 0)), ob;
    HPEN black = CreatePen(PS_SOLID, 1, RGB(0, 0, 0)), wide = CreatePen(PS_SOLID, 6, RGB(0, 0, 0)), op;
    POINT pts[8], sq[4] = { { 20, 20 }, { 40, 20 }, { 40, 40 }, { 20, 40 } };
    BYTE ty[8];
    HRGN rg;
    RECT rc;
    int n, x, y, wrong;
    clear(RGB(255, 255, 255));
    ob = SelectObject(g_dc, red);
    op = SelectObject(g_dc, black);
    SetPolyFillMode(g_dc, ALTERNATE);

    CHECK(!FillPath(g_dc) && GetLastError() == ERROR_CAN_NOT_COMPLETE, "FillPath without a path fails");
    CHECK(BeginPath(g_dc), "BeginPath");
    MoveToEx(g_dc, 10, 10, 0);
    LineTo(g_dc, 30, 10);
    LineTo(g_dc, 30, 30);
    LineTo(g_dc, 10, 30);
    CHECK(CloseFigure(g_dc), "CloseFigure");
    CHECK(GetPath(g_dc, 0, 0, 0) == -1, "GetPath refuses an open path");
    CHECK(EndPath(g_dc), "EndPath");
    CHECK(raw(10, 10) == 0xffffff && raw(20, 10) == 0xffffff, "nothing is drawn while a path is recorded");
    n = GetPath(g_dc, 0, 0, 0);
    CHECK(n == 4 && GetPath(g_dc, pts, ty, 8) == 4 && ty[0] == PT_MOVETO && ty[1] == PT_LINETO && ty[2] == PT_LINETO &&
          ty[3] == (PT_LINETO | PT_CLOSEFIGURE) && pts[0].x == 10 && pts[0].y == 10 && pts[2].x == 30 && pts[2].y == 30,
          "GetPath: MOVETO, LINETO x3 with CLOSEFIGURE, the recorded points");
    CHECK(FillPath(g_dc), "FillPath");
    CHECK(count_colour(10, 10, 30, 30, RGB(255, 0, 0)) == 400 && raw(30, 20) == 0xffffff && raw(20, 30) == 0xffffff && raw(9, 20) == 0xffffff,
          "FillPath fills [10,30)x[10,30) exactly (right and bottom edges excluded)");
    CHECK(!FillPath(g_dc) && GetLastError() == ERROR_CAN_NOT_COMPLETE, "FillPath consumed the path");

    clear(RGB(255, 255, 255));
    BeginPath(g_dc);
    Rectangle(g_dc, 5, 5, 20, 15);
    EndPath(g_dc);
    CHECK(StrokePath(g_dc), "StrokePath");
    CHECK(GetPixel(g_dc, 5, 5) == 0 && GetPixel(g_dc, 19, 5) == 0 && GetPixel(g_dc, 5, 14) == 0 && GetPixel(g_dc, 19, 14) == 0 &&
          GetPixel(g_dc, 12, 5) == 0 && GetPixel(g_dc, 12, 14) == 0 && raw(10, 10) == 0xffffff && raw(20, 10) == 0xffffff && raw(12, 15) == 0xffffff,
          "Rectangle(5,5,20,15) as a path strokes the same outline Rectangle draws");

    clear(RGB(255, 255, 255));
    BeginPath(g_dc);
    Polygon(g_dc, sq, 4);
    EndPath(g_dc);
    CHECK(SelectClipPath(g_dc, RGN_COPY), "SelectClipPath(RGN_COPY)");
    PatBlt(g_dc, 0, 0, W, H, PATCOPY);
    CHECK(count_colour(0, 0, W, H, RGB(255, 0, 0)) == 400 && raw(20, 20) == 0xff0000 && raw(39, 39) == 0xff0000 && raw(40, 30) == 0xffffff,
          "the clip path admits exactly the polygon's interior");
    SelectClipRgn(g_dc, 0);

    BeginPath(g_dc);
    Rectangle(g_dc, 2, 3, 12, 9);
    EndPath(g_dc);
    rg = PathToRegion(g_dc);
    CHECK(rg && GetRgnBox(rg, &rc) == SIMPLEREGION && rc.left == 2 && rc.top == 3 && rc.right == 11 && rc.bottom == 8,
          "PathToRegion of Rectangle(2,3,12,9): the 9x5 interior of the GM_COMPATIBLE path");
    DeleteObject(rg);

    clear(RGB(255, 255, 255));
    pts[0].x = 0; pts[0].y = 40; pts[1].x = 10; pts[1].y = 40; pts[2].x = 20; pts[2].y = 40; pts[3].x = 30; pts[3].y = 40;
    CHECK(PolyBezier(g_dc, pts, 4) && count_colour(0, 40, 31, 41, 0) == 31 && raw(31, 40) == 0xffffff,
          "PolyBezier with collinear control points draws the straight segment, both ends included");
    CHECK(!PolyBezier(g_dc, pts, 3) && GetLastError() == ERROR_INVALID_PARAMETER, "PolyBezier needs 3n+1 points");

    BeginPath(g_dc);
    MoveToEx(g_dc, 10, 10, 0);
    pts[0].x = 40; pts[0].y = 0; pts[1].x = 40; pts[1].y = 40; pts[2].x = 10; pts[2].y = 30;
    PolyBezierTo(g_dc, pts, 3);
    EndPath(g_dc);
    n = GetPath(g_dc, 0, 0, 0);
    CHECK(n == 4 && GetPath(g_dc, pts, ty, 8) == 4 && ty[1] == PT_BEZIERTO && ty[3] == PT_BEZIERTO, "PolyBezierTo records PT_BEZIERTO points");
    CHECK(FlattenPath(g_dc), "FlattenPath");
    {
        POINT *fp = HeapAlloc(GetProcessHeap(), 0, 512 * sizeof(POINT));
        BYTE *ft = HeapAlloc(GetProcessHeap(), 0, 512);
        int i, only_lines = 1, steps_ok = 1;
        n = GetPath(g_dc, 0, 0, 0);
        GetPath(g_dc, fp, ft, 512);
        for (i = 1; i < n; ++i) {
            if ((ft[i] & ~PT_CLOSEFIGURE) != PT_LINETO) only_lines = 0;
            if (fp[i].x - fp[i - 1].x > 3 || fp[i - 1].x - fp[i].x > 3 || fp[i].y - fp[i - 1].y > 3 || fp[i - 1].y - fp[i].y > 3) steps_ok = 0;
        }
        CHECK(n > 8 && ft[0] == PT_MOVETO && only_lines && steps_ok && fp[n - 1].x == 10 && fp[n - 1].y == 30,
              "FlattenPath: the curve becomes short line segments ending on its end point");
        HeapFree(GetProcessHeap(), 0, fp);
        HeapFree(GetProcessHeap(), 0, ft);
    }
    AbortPath(g_dc);

    clear(RGB(255, 255, 255));
    SelectObject(g_dc, wide);
    BeginPath(g_dc);
    MoveToEx(g_dc, 10, 24, 0);
    LineTo(g_dc, 50, 24);
    EndPath(g_dc);
    CHECK(WidenPath(g_dc), "WidenPath with a 6 pixel pen");
    SetPolyFillMode(g_dc, WINDING);
    FillPath(g_dc);
    CHECK(raw(30, 21) == 0xff0000 && raw(30, 26) == 0xff0000 && raw(30, 20) == 0xffffff && raw(30, 27) == 0xffffff &&
          raw(8, 24) == 0xff0000 && raw(52, 24) == 0xff0000 && raw(5, 24) == 0xffffff && raw(55, 24) == 0xffffff,
          "the widened line is 6 pixels thick with round caps of radius 3");
    clear(RGB(255, 255, 255));
    BeginPath(g_dc);
    MoveToEx(g_dc, 10, 10, 0);
    LineTo(g_dc, 40, 10);
    LineTo(g_dc, 40, 40);
    EndPath(g_dc);
    WidenPath(g_dc);
    FillPath(g_dc);
    CHECK(raw(41, 8) == 0xff0000 && raw(43, 7) == 0xffffff && raw(37, 13) == 0xff0000 && raw(42, 30) == 0xff0000 && raw(20, 12) == 0xff0000 &&
          raw(30, 20) == 0xffffff && raw(20, 14) == 0xffffff, "a widened corner: round outer join, both legs, nothing inside the L");
    SetPolyFillMode(g_dc, ALTERNATE);
    SelectObject(g_dc, black);

    /* text in a path is the exact pixel outline of the glyphs */
    clear(RGB(255, 255, 255));
    SetBkMode(g_dc, TRANSPARENT);
    SetTextColor(g_dc, RGB(255, 0, 0));
    BeginPath(g_dc);
    TextOutW(g_dc, 0, 0, L"Hg", 2);
    EndPath(g_dc);
    FillPath(g_dc);
    TextOutW(g_dc, 0, 24, L"Hg", 2);
    wrong = 0;
    for (y = 0; y < 16; ++y)
        for (x = 0; x < 16; ++x) wrong += raw(x, y) != raw(x, 24 + y);
    CHECK(wrong == 0 && count_colour(0, 0, 16, 16, RGB(255, 0, 0)) > 20, "FillPath of text equals TextOut pixel for pixel");

    SelectObject(g_dc, ob);
    SelectObject(g_dc, op);
    DeleteObject(red);
    DeleteObject(black);
    DeleteObject(wide);
}

/* ---------------------------------------------------------------- world transform: translations only */
static void test_xform(void)
{
    XFORM x = { 1.0f, 0.0f, 0.0f, 1.0f, 5.0f, 7.0f }, s2 = { 2.0f, 0.0f, 0.0f, 2.0f, 0.0f, 0.0f }, t, r;
    POINT pt;
    clear(RGB(255, 255, 255));
    CHECK(!SetWorldTransform(g_dc, &x), "SetWorldTransform needs GM_ADVANCED");
    CHECK(SetGraphicsMode(g_dc, GM_ADVANCED) == GM_COMPATIBLE, "SetGraphicsMode(GM_ADVANCED) returns the old mode");
    CHECK(SetWorldTransform(g_dc, &x), "a translation is accepted");
    SetPixel(g_dc, 0, 0, RGB(0, 0, 255));
    CHECK(raw(5, 7) == 0x0000ff && raw(0, 0) == 0xffffff, "drawing at (0,0) lands at the translated (5,7)");
    SetLastError(0);
    CHECK(!SetWorldTransform(g_dc, &s2) && GetLastError() == ERROR_NOT_SUPPORTED, "a scaling transform is refused (ERROR_NOT_SUPPORTED)");
    CHECK(GetWorldTransform(g_dc, &t) && t.eDx == 5.0f && t.eDy == 7.0f && t.eM11 == 1.0f, "a refused transform leaves the old one");
    CHECK(SetGraphicsMode(g_dc, GM_COMPATIBLE) == 0, "GM_COMPATIBLE needs the identity transform");
    x.eDx = 2.0f; x.eDy = 1.0f;
    CHECK(ModifyWorldTransform(g_dc, &x, MWT_LEFTMULTIPLY) && GetWorldTransform(g_dc, &t) && t.eDx == 7.0f && t.eDy == 8.0f,
          "MWT_LEFTMULTIPLY composes translations");
    GetCurrentPositionEx(g_dc, &pt);
    CHECK(ModifyWorldTransform(g_dc, 0, MWT_IDENTITY) && GetWorldTransform(g_dc, &t) && t.eDx == 0.0f && t.eM22 == 1.0f, "MWT_IDENTITY");
    CHECK(SetGraphicsMode(g_dc, GM_COMPATIBLE) == GM_ADVANCED, "back to GM_COMPATIBLE");
    x.eDx = 1.0f; x.eDy = 1.0f;
    CHECK(CombineTransform(&r, &s2, &x) && r.eM11 == 2.0f && r.eDx == 1.0f && r.eDy == 1.0f, "CombineTransform: scale then translate");
}

/* ---------------------------------------------------------------- enhanced metafiles */
static int g_emf_types[16], g_emf_n;
static char g_emf_comment[8];
static int CALLBACK emf_collect(HDC hdc, HANDLETABLE *ht, const ENHMETARECORD *rec, int n, LPARAM p)
{
    (void)hdc; (void)ht; (void)n; (void)p;
    if (g_emf_n < 16) g_emf_types[g_emf_n++] = (int)rec->iType;
    if (rec->iType == EMR_GDICOMMENT && ((const EMRGDICOMMENT *)rec)->cbData == 4) memcpy(g_emf_comment, ((const EMRGDICOMMENT *)rec)->Data, 4);
    return 1;
}

static void test_emf(void)
{
    static const WCHAR desc[] = L"Shizuku\0test\0";
    HDC m = CreateEnhMetaFileW(0, 0, 0, desc);
    HBRUSH red = CreateSolidBrush(RGB(255, 0, 0)), blue = CreateSolidBrush(RGB(0, 0, 255)), ob;
    HENHMETAFILE h, h2;
    ENHMETAHEADER hd;
    RECT rc;
    UINT size;
    BYTE *bits;
    CHECK(m && GetObjectType(m) == OBJ_ENHMETADC, "CreateEnhMetaFileW gives an OBJ_ENHMETADC");
    ob = SelectObject(m, red);
    PatBlt(m, 10, 10, 10, 10, PATCOPY);
    CHECK(GdiComment(m, 4, (const BYTE *)"abcd"), "GdiComment on a metafile DC");
    SelectObject(m, blue);
    PatBlt(m, 30, 5, 10, 10, PATCOPY);
    SelectObject(m, ob);
    h = CloseEnhMetaFile(m);
    CHECK(h && GetObjectType(h) == OBJ_ENHMETAFILE, "CloseEnhMetaFile gives an OBJ_ENHMETAFILE");
    CHECK(GetEnhMetaFileHeader(h, sizeof hd, &hd) && hd.dSignature == ENHMETA_SIGNATURE && hd.nRecords == 5 && hd.rclBounds.left == 10 &&
          hd.rclBounds.top == 5 && hd.rclBounds.right == 39 && hd.rclBounds.bottom == 19 && hd.nDescription == 14,
          "header: signature, 5 records, inclusive bounds (10,5)-(39,19), the description");
    g_emf_n = 0;
    CHECK(EnumEnhMetaFile(0, h, emf_collect, 0, 0) && g_emf_n == 5 && g_emf_types[0] == EMR_HEADER && g_emf_types[1] == EMR_STRETCHDIBITS &&
          g_emf_types[2] == EMR_GDICOMMENT && g_emf_types[3] == EMR_STRETCHDIBITS && g_emf_types[4] == EMR_EOF && !memcmp(g_emf_comment, "abcd", 4),
          "records in drawing order: picture, comment, picture");
    size = GetEnhMetaFileBits(h, 0, 0);
    bits = HeapAlloc(GetProcessHeap(), 0, size);
    CHECK(size == hd.nBytes && GetEnhMetaFileBits(h, size, bits) == size, "GetEnhMetaFileBits returns nBytes");
    h2 = SetEnhMetaFileBits(size, bits);
    CHECK(h2 != 0, "SetEnhMetaFileBits accepts its own bytes");
    bits[0] = 7;
    CHECK(SetEnhMetaFileBits(size, bits) == 0, "SetEnhMetaFileBits rejects a damaged header");
    HeapFree(GetProcessHeap(), 0, bits);

    clear(RGB(0, 255, 0));
    rc.left = 10; rc.top = 5; rc.right = 40; rc.bottom = 20;
    CHECK(PlayEnhMetaFile(g_dc, h2, &rc), "PlayEnhMetaFile 1:1");
    CHECK(raw(15, 15) == 0xff0000 && raw(35, 10) == 0x0000ff && raw(25, 10) == 0x00ff00 && raw(10, 10) == 0xff0000 && raw(9, 10) == 0x00ff00,
          "1:1 playback puts the pictures back where they were drawn");
    clear(RGB(0, 255, 0));
    rc.left = 0; rc.top = 0; rc.right = 60; rc.bottom = 30;
    PlayEnhMetaFile(g_dc, h, &rc);
    CHECK(raw(10, 20) == 0xff0000 && raw(50, 10) == 0x0000ff && raw(30, 10) == 0x00ff00, "playback into a twice as large rectangle scales");
    {
        DWORD rec[4] = { EMR_LINETO, 16, 1, 1 };
        SetLastError(0);
        CHECK(!PlayEnhMetaFileRecord(g_dc, 0, (const ENHMETARECORD *)rec, 1) && GetLastError() == ERROR_NOT_SUPPORTED,
              "a vector record is reported as not played");
    }
    CHECK(DeleteEnhMetaFile(h) && DeleteEnhMetaFile(h2) && !DeleteEnhMetaFile(h), "DeleteEnhMetaFile");
    m = CreateEnhMetaFileW(0, 0, 0, 0);
    CHECK(m && DeleteDC(m), "a metafile DC can be deleted without closing it");
    DeleteObject(red);
    DeleteObject(blue);
}

/* ---------------------------------------------------------------- pixel formats, printing, font queries */
static int CALLBACK enum_a(const LOGFONTA *lf, const TEXTMETRICA *tm, DWORD type, LPARAM p)
{
    (void)tm;
    if (!strcmp(lf->lfFaceName, "Shizuku Fixed 8x16") && type == RASTER_FONTTYPE) ++*(int *)p;
    return 1;
}

static void test_misc(void)
{
    PIXELFORMATDESCRIPTOR pfd;
    CHARSETINFO cs;
    WORD gi[3];
    ABC abc[2];
    LOGFONTA lf;
    DWORD fs = 1u << 17;
    int found = 0;
    memset(&pfd, 0, sizeof pfd);
    pfd.nSize = sizeof pfd;
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_BITMAP | PFD_SUPPORT_GDI;
    pfd.cColorBits = 32;
    CHECK(DescribePixelFormat(g_dc, 1, sizeof pfd, &pfd) == 1 && (pfd.dwFlags & PFD_SUPPORT_GDI) && !(pfd.dwFlags & PFD_SUPPORT_OPENGL) &&
          pfd.cColorBits == 32, "one GDI-only pixel format (no OpenGL)");
    CHECK(ChoosePixelFormat(g_dc, &pfd) == 1 && SetPixelFormat(g_dc, 1, &pfd) && GetPixelFormat(g_dc) == 1 && SwapBuffers(g_dc) &&
          !SetPixelFormat(g_dc, 2, &pfd), "Choose/Set/GetPixelFormat and SwapBuffers");
    CHECK(StartDocW(g_dc, 0) <= 0 && StartPage(g_dc) <= 0 && EndDoc(g_dc) <= 0, "a memory DC is no printer: StartDoc/StartPage/EndDoc fail");
    {
        int q = QUERYESCSUPPORT;
        CHECK(ExtEscape(g_dc, QUERYESCSUPPORT, sizeof q, (LPCSTR)&q, 0, 0) == 0 && CancelDC(g_dc), "no escapes; CancelDC succeeds");
    }
    CHECK(TranslateCharsetInfo((DWORD *)(ULONG_PTR)932, &cs, TCI_SRCCODEPAGE) && cs.ciCharset == SHIFTJIS_CHARSET && cs.fs.fsCsb[0] == (1u << 17),
          "TranslateCharsetInfo: code page 932 is SHIFTJIS_CHARSET, signature bit 17");
    CHECK(TranslateCharsetInfo(&fs, &cs, TCI_SRCFONTSIG) && cs.ciACP == 932 &&
          TranslateCharsetInfo((DWORD *)(ULONG_PTR)ANSI_CHARSET, &cs, TCI_SRCCHARSET) && cs.ciACP == 1252, "TranslateCharsetInfo by signature and charset");
    CHECK(GetGlyphIndicesW(g_dc, L"A~\x01", 3, gi, GGI_MARK_NONEXISTING_GLYPHS) == 3 && gi[0] == 'A' && gi[1] == '~' && gi[2] == 0xffff,
          "GetGlyphIndicesW marks glyphs the font lacks");
    CHECK(GetCharABCWidthsW(g_dc, 'A', 'B', abc) && abc[0].abcA == 0 && abc[0].abcB == 8 && abc[1].abcC == 0, "GetCharABCWidthsW: 8 pixel cells");
    CHECK(GetFontData(g_dc, 0, 0, 0, 0) == GDI_ERROR && GetOutlineTextMetricsW(g_dc, 0, 0) == 0, "a raster font has no TrueType data");
    memset(&lf, 0, sizeof lf);
    lf.lfCharSet = DEFAULT_CHARSET;
    EnumFontFamiliesExA(g_dc, &lf, enum_a, (LPARAM)&found, 0);
    CHECK(found == 1, "EnumFontFamiliesExA offers the built-in font");
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
    test_icons();
    test_paths();
    test_xform();
    test_emf();
    test_misc();
    SelectObject(g_dc, GetStockObject(BLACK_PEN));
    printf("%s: gdi32 memory-DC tests\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
