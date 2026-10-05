/* SPDX-License-Identifier: GPL-2.0-only
 * Guest font probe: real gdi32 memory DC + 32 bpp DIB section, DEFAULT_GUI_FONT, user32 DrawTextW.
 * Idioms (DIB setup, CHECK, shzcrt.h printf/main) follow shizukudos/win64/tests/t_gui_gdi.c.
 * Nothing is mocked: every value is read back from the running gdi32/user32. Not built or run by its author. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

#define W 200
#define H 64
#define SENT 0x00123456u            /* sentinel pixel: dark blue-grey, never a gray text value */
static int bad;
#define CHECK(c, n) do { if (c) printf("ok: %s\n", n); else { printf("bad: %s (line %d)\n", n, __LINE__); ++bad; } } while (0)

static unsigned *bits;              /* top-down 32 bpp: row y starts at bits[y * W] */

static void fill(unsigned v) { int i; for (i = 0; i < W * H; ++i) bits[i] = v; }
static int is_gray(unsigned p) { unsigned r = (p >> 16) & 255, g = (p >> 8) & 255, b = p & 255; return r == g && g == b && r > 0 && r < 255; }
static int count_gray(int l, int t, int r, int b)
{
    int x, y, n = 0;
    for (y = t; y < b; ++y) for (x = l; x < r; ++x) n += is_gray(bits[y * W + x] & 0xffffff);
    return n;
}
static int count_changed(int l, int t, int r, int b)
{
    int x, y, n = 0;
    for (y = t; y < b; ++y) for (x = l; x < r; ++x) n += (bits[y * W + x] & 0xffffff) != SENT;
    return n;
}
static int count_unchanged_outside(const RECT *in)
{
    int x, y, n = 0;
    for (y = 0; y < H; ++y) for (x = 0; x < W; ++x)
        if (!(x >= in->left && x < in->right && y >= in->top && y < in->bottom)) n += (bits[y * W + x] & 0xffffff) == SENT;
    return n;
}

int main(void)
{
    static const WCHAR ascii[] = L"Hello Noto 123", hangul[] = L"\xD55C\xAE00 \xC124\xC815", mixed[] = L"Noto \xD55C\xAE00 shell";
    BITMAPINFO bi;
    HDC dc = CreateCompatibleDC(0);
    HBITMAP dib = 0, oldbmp = 0;
    HGDIOBJ gui = GetStockObject(DEFAULT_GUI_FONT), oldfont = 0;
    WCHAR face[LF_FACESIZE + 1];
    SIZE si = {0, 0}, sw = {0, 0}, sh = {0, 0};
    RECT rc, clip;
    HRGN rgn;
    int n, area, x, y;

    memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = W;
    bi.bmiHeader.biHeight = -H;                          /* top-down */
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    if (dc) dib = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, (void **)&bits, 0, 0);
    if (!dc || !dib || !bits || !gui) { printf("FONT-PROBE FAIL: cannot create DC/DIB/DEFAULT_GUI_FONT\n"); bad = 1; goto done; }
    oldbmp = SelectObject(dc, dib);
    oldfont = SelectObject(dc, gui);
    CHECK(oldfont != 0, "SelectObject(DEFAULT_GUI_FONT) succeeds");

    memset(face, 0, sizeof face);
    n = GetTextFaceW(dc, LF_FACESIZE, face);
    CHECK(n > 0 && !lstrcmpW(face, L"Noto Sans"), "GetTextFaceW is exactly Noto Sans");
    if (n > 0) printf("face: len %d first %04x\n", n, (unsigned)face[0]);

    CHECK(GetTextExtentPoint32W(dc, L"iii", 3, &si) && GetTextExtentPoint32W(dc, L"WWW", 3, &sw) && si.cx > 0 && si.cx < sw.cx,
          "proportional widths: iii < WWW");
    printf("extent iii=%ld WWW=%ld\n", (long)si.cx, (long)sw.cx);
    CHECK(GetTextExtentPoint32W(dc, hangul, 5, &sh) && sh.cx > 0 && sh.cy > 0, "Hangul extent is positive");

    /* TextOutW: ASCII and Hangul must produce real 8-bit gray (anti-aliased) pixels, with the surround untouched */
    fill(0x00ffffffu);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(0, 0, 0));
    CHECK(TextOutW(dc, 4, 2, ascii, 14), "TextOutW ASCII");
    CHECK(count_gray(0, 0, W, 28) >= 8, "ASCII text has 8-bit gray intermediate pixels");
    CHECK(count_gray(0, 28, W, H) == 0, "no pixels touched below the ASCII line");
    CHECK(TextOutW(dc, 4, 32, hangul, 5), "TextOutW Hangul");
    CHECK(count_gray(0, 32, W, H) >= 8, "Hangul text has 8-bit gray intermediate pixels");

    /* USER32 DrawTextW CALCRECT must equal the measured extent */
    memset(&rc, 0, sizeof rc);
    rc.right = W;
    n = DrawTextW(dc, mixed, -1, &rc, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
    CHECK(GetTextExtentPoint32W(dc, mixed, lstrlenW(mixed), &si) && n > 0 && rc.right - rc.left == si.cx && rc.bottom - rc.top >= si.cy - 1 &&
          rc.right > rc.left, "DrawTextW CALCRECT width equals GetTextExtentPoint32W width");
    printf("calcrect %ld x %ld extent %ld x %ld\n", (long)(rc.right - rc.left), (long)(rc.bottom - rc.top), (long)si.cx, (long)si.cy);

    /* real clipped draw: DrawTextW into a rect narrower than the text (no DT_NOCLIP) */
    fill(SENT);
    clip.left = 20; clip.top = 10; clip.right = 20 + (rc.right - rc.left) / 2; clip.bottom = 10 + (rc.bottom - rc.top);
    if (clip.right > W) clip.right = W;
    CHECK(clip.right > clip.left && clip.bottom > clip.top && clip.bottom <= H, "bounded measured draw rectangle");
    if (clip.right <= clip.left || clip.bottom <= clip.top || clip.bottom > H) goto done;
    for (y = clip.top; y < clip.bottom; ++y) for (x = clip.left; x < clip.right; ++x) bits[y * W + x] = 0x00ffffffu;
    n = DrawTextW(dc, mixed, -1, &clip, DT_SINGLELINE | DT_NOPREFIX | DT_LEFT | DT_TOP);
    area = (W * H) - (clip.right - clip.left) * (clip.bottom - clip.top);
    CHECK(n > 0 && count_gray(clip.left, clip.top, clip.right, clip.bottom) >= 8, "DrawTextW gray intermediate pixels inside the clip rectangle");
    CHECK(count_unchanged_outside(&clip) == area, "DrawTextW leaves every pixel outside the rectangle unchanged");

    /* real clip region on the DC around a wider draw */
    fill(SENT);
    clip.left = 30; clip.top = 8; clip.right = 70; clip.bottom = 8 + 20;
    rgn = CreateRectRgn(clip.left, clip.top, clip.right, clip.bottom);
    CHECK(rgn && SelectClipRgn(dc, rgn) != ERROR, "SelectClipRgn");
    TextOutW(dc, 10, 8, mixed, lstrlenW(mixed));
    SelectClipRgn(dc, 0);
    if (rgn) DeleteObject(rgn);
    area = (W * H) - (clip.right - clip.left) * (clip.bottom - clip.top);
    CHECK(count_changed(clip.left, clip.top, clip.right, clip.bottom) > 0 && count_unchanged_outside(&clip) == area,
          "TextOutW under SelectClipRgn changes only pixels inside the region");

done:
    if (oldfont) SelectObject(dc, oldfont);
    if (oldbmp) SelectObject(dc, oldbmp);
    if (dib) DeleteObject(dib);
    if (dc) DeleteDC(dc);
    if (bad) printf("FONT-PROBE FAIL: %d check(s) failed\n", bad);
    else printf("FONT-PROBE PASS\n");
    ExitProcess(bad ? 1 : 0);
    return bad ? 1 : 0;
}
