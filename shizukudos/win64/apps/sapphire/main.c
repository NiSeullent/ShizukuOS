/* SPDX-License-Identifier: GPL-2.0-only
 * Sapphire: ShizukuOS photo viewer, basic image editor and paint surface (native Win64 GUI application).
 *
 * Viewing is the default and holds only the file's pixels. The image lives in ONE 32 bpp top-down GDI DIB section
 * (CreateDIBSection) selected into a memory DC; GDI drawing tools write into it directly. The editing state (single-level
 * undo snapshot, pen) is allocated lazily at the first modification. Formats: BMP (8/24/32 bpp uncompressed) and PNG
 * (vendored LodePNG decoder). Everything else is refused with a reason, never approximated. Saving writes BMP24 only
 * (this build has no PNG encoder); it never overwrites a PNG source.
 *
 * Keys: Ctrl+L type a path, Enter opens. P pen, L line, R rectangle, E ellipse, F filled rectangle; 1-8 colour;
 * [ and ] pen width; I invert, G grayscale, H/V flip; arrows pan; Ctrl+Z undo/redo swap; Ctrl+S save BMP; Ctrl+D discard
 * edits; Esc leaves path entry.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"
#include "sapphire_img.h"

#define PATH_CAP 260
#define STATUS_H 20
enum tool { T_PEN, T_LINE, T_RECT, T_ELLIPSE, T_FILL };

static HINSTANCE g_inst;
static HWND g_wnd;
static WCHAR g_path[PATH_CAP], g_input[PATH_CAP];
static WCHAR g_status[200] = L"Ctrl+L: type an image path (BMP or PNG), Enter to open.";
static int g_input_mode;
/* owned image: the DIB section, its memory DC and the originally selected bitmap are released together */
static HBITMAP g_dib;
static HDC g_mem;
static HGDIOBJ g_mem_old;
static uint32_t *g_bits;
static int g_w, g_h;
static int g_is_bmp_source;
/* lazy editing state */
static uint32_t *g_undo;
static int g_dirty, g_tool = T_PEN, g_penw = 2, g_color;
static int g_sx, g_sy;
static int g_drag, g_x0, g_y0, g_x1, g_y1;
static const COLORREF g_palette[8] = {RGB(0, 0, 0), RGB(255, 255, 255), RGB(220, 30, 30), RGB(30, 160, 40),
                                      RGB(30, 70, 220), RGB(240, 220, 30), RGB(160, 40, 200), RGB(120, 120, 120)};

static void say(const char *fmt, ...)
{
    char tmp[200];
    va_list ap;
    int i;
    va_start(ap, fmt); shz_vsnprintf(tmp, sizeof tmp, fmt, ap); va_end(ap);
    for (i = 0; tmp[i] && i < 199; ++i) g_status[i] = (WCHAR)(unsigned char)tmp[i];
    g_status[i] = 0;
    if (g_wnd) InvalidateRect(g_wnd, 0, FALSE);
}

static void narrow(char *dst, unsigned cap, const WCHAR *src)
{
    unsigned i = 0;
    while (src[i] && i + 1 < cap) { dst[i] = src[i] < 128 ? (char)src[i] : '?'; ++i; }
    dst[i] = 0;
}

static void release_image(void)
{
    if (g_mem && g_mem_old) SelectObject(g_mem, g_mem_old);
    if (g_dib) DeleteObject(g_dib);          /* frees the pixel memory g_bits points into */
    if (g_mem) DeleteDC(g_mem);
    g_dib = 0; g_mem = 0; g_mem_old = 0; g_bits = 0; g_w = g_h = 0;
    if (g_undo) { sap_free(g_undo); g_undo = 0; }
    g_dirty = 0; g_sx = g_sy = 0; g_drag = 0;
}

/* Reads a whole file with an explicit size cap; on failure *err holds the Win32 error or 0 for "too large". */
static uint8_t *read_file(const WCHAR *path, size_t *len, DWORD *err)
{
    LARGE_INTEGER size;
    uint8_t *buf;
    DWORD off = 0, got;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    *err = 0;
    if (f == INVALID_HANDLE_VALUE) { *err = GetLastError(); return 0; }
    if (!GetFileSizeEx(f, &size)) { *err = GetLastError(); CloseHandle(f); return 0; }
    if (size.QuadPart <= 0 || size.QuadPart > (LONGLONG)SAP_MAX_FILE * 4) { CloseHandle(f); *err = size.QuadPart <= 0 ? ERROR_FILE_INVALID : 0; return 0; }
    buf = (uint8_t *)sap_alloc((size_t)size.QuadPart);
    if (!buf) { CloseHandle(f); *err = ERROR_NOT_ENOUGH_MEMORY; return 0; }
    while (off < (DWORD)size.QuadPart) {
        if (!ReadFile(f, buf + off, (DWORD)size.QuadPart - off, &got, 0) || !got) {
            *err = GetLastError(); if (!*err) *err = ERROR_HANDLE_EOF;
            CloseHandle(f); sap_free(buf); return 0;
        }
        off += got;
    }
    CloseHandle(f);
    *len = (size_t)size.QuadPart;
    return buf;
}

static int ends_bmp(const WCHAR *p)
{
    size_t n = 0;
    while (p[n]) ++n;
    return n > 4 && p[n - 4] == '.' && (p[n - 3] | 32) == 'b' && (p[n - 2] | 32) == 'm' && (p[n - 1] | 32) == 'p';
}

static int open_image_internal(const WCHAR *path, int discard)
{
    size_t len = 0;
    DWORD err;
    uint8_t *file;
    sap_info info;
    enum sap_status st;
    BITMAPINFO bi;
    HDC wdc, mem;
    HBITMAP dib;
    HGDIOBJ old_bitmap;
    void *bits = 0;
    char shown[PATH_CAP];
    narrow(shown, sizeof shown, path);
    if (g_dirty && !discard) {
        say("Unsaved edits: Ctrl+S saves a BMP, Ctrl+D discards them.");
        printf("SAPPHIRE REFUSED op=open path=%s reason=unsaved-edits\n", shown);
        return 0;
    }
    file = read_file(path, &len, &err);
    if (!file) {
        if (err) say("Cannot read %s (error %lu).", shown, (unsigned long)err);
        else say("File is larger than the %u MiB limit.", (unsigned)(SAP_MAX_FILE >> 20));
        printf("SAPPHIRE ERROR op=read path=%s error=%lu\n", shown, (unsigned long)err);
        return 0;
    }
    st = sap_probe(file, len, &info);            /* every dimension is validated before the pixel allocation below */
    if (st != SAP_OK) {
        say("%s: %s.", shown, sap_status_text(st));
        printf("SAPPHIRE REFUSED op=probe path=%s reason=%s\n", shown, sap_status_text(st));
        sap_free(file); return 0;
    }
    memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader; bi.bmiHeader.biWidth = (LONG)info.width;
    bi.bmiHeader.biHeight = -(LONG)info.height; bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    wdc = GetDC(g_wnd);
    dib = CreateDIBSection(wdc, &bi, DIB_RGB_COLORS, &bits, 0, 0);
    mem = dib ? CreateCompatibleDC(wdc) : 0;
    if (wdc) ReleaseDC(g_wnd, wdc);
    if (!dib || !bits || !mem) {
        err = GetLastError();
        if (mem) DeleteDC(mem);
        if (dib) DeleteObject(dib);
        sap_free(file);
        say("Cannot allocate a %ux%u bitmap (error %lu).", info.width, info.height, (unsigned long)err);
        printf("SAPPHIRE ERROR op=dib w=%u h=%u error=%lu\n", info.width, info.height, (unsigned long)err);
        return 0;
    }
    st = sap_decode(file, len, &info, (uint32_t *)bits, (size_t)info.width * info.height);
    sap_free(file);
    if (st != SAP_OK) {
        DeleteDC(mem); DeleteObject(dib);
        say("%s: %s.", shown, sap_status_text(st));
        printf("SAPPHIRE ERROR op=decode path=%s reason=%s\n", shown, sap_status_text(st));
        return 0;
    }
    old_bitmap = SelectObject(mem, dib);
    if (!old_bitmap || old_bitmap == HGDI_ERROR) {
        err = GetLastError();
        DeleteDC(mem); DeleteObject(dib);
        say("Cannot select the new bitmap (error %lu).", (unsigned long)err);
        printf("SAPPHIRE ERROR op=select-dib error=%lu\n", (unsigned long)err);
        return 0;
    }
    release_image();                              /* only a usable replacement ends the old image's lifetime */
    g_dib = dib; g_mem = mem; g_bits = (uint32_t *)bits; g_w = (int)info.width; g_h = (int)info.height;
    g_mem_old = old_bitmap;
    memcpy(g_path, path, sizeof g_path);
    g_is_bmp_source = info.kind == SAP_BMP;
    say("%s  %dx%d  %s", shown, g_w, g_h, info.kind == SAP_PNG ? "PNG" : "BMP");
    printf("SAPPHIRE OPENED path=%s format=%s width=%d height=%d\n", shown, info.kind == SAP_PNG ? "png" : "bmp", g_w, g_h);
    InvalidateRect(g_wnd, 0, TRUE);
    return 1;
}

static int open_image(const WCHAR *path) { return open_image_internal(path, 0); }

static void discard_edits(void)
{
    WCHAR path[PATH_CAP];
    if (!g_dirty || !g_path[0]) return;
    memcpy(path, g_path, sizeof path);
    /* Failed reads/decodes retain the old DIB, undo buffer and dirty flag. */
    open_image_internal(path, 1);
}

/* Lazy edit state: the snapshot is created at the first modification and is then reused for the single undo level. */
static int edit_begin(void)
{
    if (!g_bits) return 0;
    if (!g_undo) {
        g_undo = (uint32_t *)sap_alloc((size_t)g_w * g_h * 4);
        if (!g_undo) { say("Not enough memory to start editing."); return 0; }
    }
    GdiFlush();
    memcpy(g_undo, g_bits, (size_t)g_w * g_h * 4);
    g_dirty = 1;
    return 1;
}

static void filter(int kind)
{
    size_t n = (size_t)g_w * g_h, i;
    int x, y;
    if (!edit_begin()) return;
    for (i = 0; kind == 'I' && i < n; ++i) g_bits[i] ^= 0x00ffffffu;
    for (i = 0; kind == 'G' && i < n; ++i) {
        uint32_t c = g_bits[i], v = (((c >> 16) & 255) * 77 + ((c >> 8) & 255) * 150 + (c & 255) * 29) >> 8;
        g_bits[i] = v << 16 | v << 8 | v;
    }
    if (kind == 'H') for (y = 0; y < g_h; ++y) for (x = 0; x < g_w / 2; ++x) {
        uint32_t *a = g_bits + (size_t)y * g_w + x, *b = g_bits + (size_t)y * g_w + (g_w - 1 - x), t = *a; *a = *b; *b = t;
    }
    if (kind == 'V') for (y = 0; y < g_h / 2; ++y) for (x = 0; x < g_w; ++x) {
        uint32_t *a = g_bits + (size_t)y * g_w + x, *b = g_bits + (size_t)(g_h - 1 - y) * g_w + x, t = *a; *a = *b; *b = t;
    }
    say("Edited (%c). Ctrl+Z undoes.", kind);
    InvalidateRect(g_wnd, 0, FALSE);
}

static void undo(void)
{
    size_t n = (size_t)g_w * g_h, i;
    if (!g_undo) { say("Nothing to undo."); return; }
    GdiFlush();
    for (i = 0; i < n; ++i) { uint32_t t = g_bits[i]; g_bits[i] = g_undo[i]; g_undo[i] = t; }
    g_dirty = 1;
    say("Swapped with the previous state.");
    InvalidateRect(g_wnd, 0, FALSE);
}

static void origin(const RECT *c, int *ox, int *oy)
{
    int cw = c->right, ch = c->bottom - STATUS_H;
    if (g_sx > g_w - cw) g_sx = g_w - cw;
    if (g_sy > g_h - ch) g_sy = g_h - ch;
    if (g_sx < 0) g_sx = 0;
    if (g_sy < 0) g_sy = 0;
    *ox = g_w <= cw ? (cw - g_w) / 2 : -g_sx;
    *oy = g_h <= ch ? (ch - g_h) / 2 : -g_sy;
}

static void to_image(int mx, int my, int *ix, int *iy)
{
    RECT c; int ox, oy;
    GetClientRect(g_wnd, &c); origin(&c, &ox, &oy);
    *ix = mx - ox; *iy = my - oy;
}

static void draw_shape(int tool, int x0, int y0, int x1, int y1)
{
    HPEN pen = CreatePen(PS_SOLID, g_penw, g_palette[g_color]);
    HBRUSH fill = CreateSolidBrush(g_palette[g_color]);
    HGDIOBJ op, ob;
    if (!pen || !fill) { if (pen) DeleteObject(pen); if (fill) DeleteObject(fill); say("GDI object creation failed (%lu).", (unsigned long)GetLastError()); return; }
    op = SelectObject(g_mem, pen);
    ob = SelectObject(g_mem, tool == T_FILL ? (HGDIOBJ)fill : GetStockObject(NULL_BRUSH));
    if (tool == T_LINE || tool == T_PEN) { MoveToEx(g_mem, x0, y0, 0); LineTo(g_mem, x1, y1); }
    else if (tool == T_ELLIPSE) Ellipse(g_mem, x0, y0, x1 + 1, y1 + 1);
    else Rectangle(g_mem, x0 < x1 ? x0 : x1, y0 < y1 ? y0 : y1, (x0 < x1 ? x1 : x0) + 1, (y0 < y1 ? y1 : y0) + 1);
    SelectObject(g_mem, ob); SelectObject(g_mem, op);    /* never leave our objects selected before deleting them */
    DeleteObject(pen); DeleteObject(fill);
}

static HANDLE create_owned_temp(const WCHAR *out, WCHAR *tmp)
{
    static DWORD sequence;
    static const WCHAR hex[] = L"0123456789ABCDEF";
    size_t n = 0;
    DWORD pid = GetCurrentProcessId();
    unsigned attempt, j;
    while (out[n]) ++n;
    if (n + 23 > PATH_CAP) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return INVALID_HANDLE_VALUE; }
    memcpy(tmp, out, n * sizeof(WCHAR));
    tmp[n] = '.'; tmp[n + 1] = 'S';
    for (j = 0; j < 8; ++j) tmp[n + 2 + j] = hex[(pid >> (28u - j * 4u)) & 15u];
    tmp[n + 18] = '.'; tmp[n + 19] = 'T'; tmp[n + 20] = 'M'; tmp[n + 21] = 'P'; tmp[n + 22] = 0;
    for (attempt = 0; attempt < 32; ++attempt) {
        DWORD seq = ++sequence, error;
        HANDLE file;
        for (j = 0; j < 8; ++j) tmp[n + 10 + j] = hex[(seq >> (28u - j * 4u)) & 15u];
        file = CreateFileW(tmp, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
        if (file != INVALID_HANDLE_VALUE) return file;
        error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) return INVALID_HANDLE_VALUE;
    }
    SetLastError(ERROR_FILE_EXISTS);
    return INVALID_HANDLE_VALUE;
}

static int finish_temp(HANDLE file, DWORD *error)
{
    BOOL flushed = FlushFileBuffers(file), closed;
    DWORD flush_error = flushed ? 0 : GetLastError();
    closed = CloseHandle(file); /* Always close, including after a failed flush. */
    *error = !flushed ? flush_error : (closed ? 0 : GetLastError());
    return flushed && closed;
}

static int save_bmp(void)
{
    WCHAR out[PATH_CAP], tmp[PATH_CAP];
    char shown[PATH_CAP];
    uint8_t *buf = 0, *back;
    size_t blen = 0, rlen = 0, n = 0, dot = 0, i;
    DWORD off = 0, wrote, err;
    HANDLE f;
    enum sap_status st;
    if (!g_bits) { say("No image to save."); return 0; }
    while (g_path[n]) ++n;
    if (g_is_bmp_source) { memcpy(out, g_path, (n + 1) * sizeof(WCHAR)); }
    else {
        for (i = 0; i < n; ++i) { if (g_path[i] == '\\') dot = 0; else if (g_path[i] == '.') dot = i; }
        if (!dot) dot = n;
        if (dot + 5 > PATH_CAP) { say("Path too long for the .BMP name."); return 0; }
        memcpy(out, g_path, dot * sizeof(WCHAR));
        out[dot] = '.'; out[dot + 1] = 'B'; out[dot + 2] = 'M'; out[dot + 3] = 'P'; out[dot + 4] = 0;
    }
    narrow(shown, sizeof shown, out);
    GdiFlush();
    st = sap_encode_bmp24(g_bits, (uint32_t)g_w, (uint32_t)g_h, &buf, &blen);
    if (st != SAP_OK) { say("Cannot encode: %s.", sap_status_text(st)); return 0; }
    f = create_owned_temp(out, tmp);
    if (f == INVALID_HANDLE_VALUE) { err = GetLastError(); sap_free(buf); say("Cannot create temporary file (error %lu).", (unsigned long)err); return 0; }
    while (off < blen) {
        if (!WriteFile(f, buf + off, (DWORD)(blen - off), &wrote, 0) || !wrote) {
            err = GetLastError(); CloseHandle(f); DeleteFileW(tmp); sap_free(buf);
            say("Write failed (error %lu); original untouched.", (unsigned long)err); return 0;
        }
        off += wrote;
    }
    if (!finish_temp(f, &err)) {
        DeleteFileW(tmp); sap_free(buf); say("Flush/close failed (error %lu).", (unsigned long)err); return 0;
    }
    back = read_file(tmp, &rlen, &err);           /* read-back verification before the destination is replaced */
    if (!back || rlen != blen || memcmp(back, buf, blen)) {
        if (back) sap_free(back);
        DeleteFileW(tmp); sap_free(buf); say("Read-back verification failed; original untouched."); return 0;
    }
    sap_free(back); sap_free(buf);
    if (!MoveFileExW(tmp, out, MOVEFILE_REPLACE_EXISTING)) {
        err = GetLastError(); DeleteFileW(tmp); say("Cannot replace %s (error %lu).", shown, (unsigned long)err); return 0;
    }
    memcpy(g_path, out, sizeof g_path); g_is_bmp_source = 1; g_dirty = 0;
    say("Saved %s (%lu bytes, verified).", shown, (unsigned long)blen);
    printf("SAPPHIRE SAVED path=%s bytes=%lu verified=1\n", shown, (unsigned long)blen);
    return 1;
}

static void paint(HWND hwnd)
{
    PAINTSTRUCT ps;
    RECT c, bar;
    int ox = 0, oy = 0, len = 0;
    HDC dc = BeginPaint(hwnd, &ps);
    GetClientRect(hwnd, &c);
    if (g_mem) {
        int cw = c.right, ch = c.bottom - STATUS_H, sx = g_w <= cw ? 0 : g_sx, sy = g_h <= ch ? 0 : g_sy;
        RECT area = {0, 0, c.right, c.bottom - STATUS_H};
        origin(&c, &ox, &oy);
        FillRect(dc, &area, (HBRUSH)GetStockObject(GRAY_BRUSH));
        BitBlt(dc, ox < 0 ? 0 : ox, oy < 0 ? 0 : oy, g_w < cw ? g_w : cw, g_h < ch ? g_h : ch, g_mem, sx, sy, SRCCOPY);
    } else {
        RECT area = {0, 0, c.right, c.bottom - STATUS_H};
        FillRect(dc, &area, (HBRUSH)GetStockObject(GRAY_BRUSH));
    }
    bar.left = 0; bar.top = c.bottom - STATUS_H; bar.right = c.right; bar.bottom = c.bottom;
    FillRect(dc, &bar, (HBRUSH)(COLOR_BTNFACE + 1));
    SetBkMode(dc, TRANSPARENT);
    if (g_input_mode) {
        WCHAR line[PATH_CAP + 8];
        int i = 0, j = 0;
        line[i++] = 'P'; line[i++] = 'a'; line[i++] = 't'; line[i++] = 'h'; line[i++] = ':'; line[i++] = ' ';
        while (g_input[j] && i < PATH_CAP + 6) line[i++] = g_input[j++];
        line[i++] = '_'; line[i] = 0;
        TextOutW(dc, 4, bar.top + 2, line, i);
    } else {
        while (g_status[len]) ++len;
        TextOutW(dc, 4, bar.top + 2, g_status, len);
    }
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_PAINT: paint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_KEYDOWN: {
        int ctrl = GetKeyState(VK_CONTROL) < 0;
        if (g_input_mode) {
            if (wp == VK_ESCAPE) { g_input_mode = 0; say("Path entry cancelled."); }
            else if (wp == VK_RETURN) { g_input_mode = 0; open_image(g_input); }
            InvalidateRect(hwnd, 0, FALSE);
            return 0;
        }
        if (ctrl && wp == 'L') { g_input_mode = 1; g_input[0] = 0; InvalidateRect(hwnd, 0, FALSE); }
        else if (ctrl && wp == 'S') save_bmp();
        else if (ctrl && wp == 'Z') undo();
        else if (ctrl && wp == 'D') discard_edits();
        else if (!g_bits) say("Open an image first (Ctrl+L).");
        else if (wp == 'P') g_tool = T_PEN;
        else if (wp == 'L') g_tool = T_LINE;
        else if (wp == 'R') g_tool = T_RECT;
        else if (wp == 'E') g_tool = T_ELLIPSE;
        else if (wp == 'F') g_tool = T_FILL;
        else if (wp >= '1' && wp <= '8') g_color = (int)(wp - '1');
        else if (wp == VK_OEM_4 && g_penw > 1) --g_penw;
        else if (wp == VK_OEM_6 && g_penw < 32) ++g_penw;
        else if (wp == 'I' || wp == 'G' || wp == 'H' || wp == 'V') filter((int)wp);
        else if (wp == VK_LEFT) { g_sx -= 32; InvalidateRect(hwnd, 0, FALSE); }
        else if (wp == VK_RIGHT) { g_sx += 32; InvalidateRect(hwnd, 0, FALSE); }
        else if (wp == VK_UP) { g_sy -= 32; InvalidateRect(hwnd, 0, FALSE); }
        else if (wp == VK_DOWN) { g_sy += 32; InvalidateRect(hwnd, 0, FALSE); }
        return 0;
    }
    case WM_CHAR:
        if (g_input_mode) {
            size_t n = 0;
            while (g_input[n]) ++n;
            if (wp == 8) { if (n) g_input[n - 1] = 0; }
            else if (wp >= 32 && wp < 127 && n + 1 < PATH_CAP) { g_input[n] = (WCHAR)wp; g_input[n + 1] = 0; }
            InvalidateRect(hwnd, 0, FALSE);
        }
        return 0;
    case WM_LBUTTONDOWN:
        if (g_bits && !g_input_mode && edit_begin()) {
            int ix, iy;
            to_image((short)LOWORD(lp), (short)HIWORD(lp), &ix, &iy);
            g_drag = 1; g_x0 = g_x1 = ix; g_y0 = g_y1 = iy;
            SetCapture(hwnd);
            if (g_tool == T_PEN) draw_shape(T_PEN, ix, iy, ix, iy + 0);
            InvalidateRect(hwnd, 0, FALSE);
        }
        return 0;
    case WM_MOUSEMOVE:
        if (g_drag && g_tool == T_PEN) {
            int ix, iy;
            to_image((short)LOWORD(lp), (short)HIWORD(lp), &ix, &iy);
            draw_shape(T_PEN, g_x1, g_y1, ix, iy); g_x1 = ix; g_y1 = iy;
            InvalidateRect(hwnd, 0, FALSE);
        }
        return 0;
    case WM_LBUTTONUP:
        if (g_drag) {
            int ix, iy;
            to_image((short)LOWORD(lp), (short)HIWORD(lp), &ix, &iy);
            if (g_tool != T_PEN) draw_shape(g_tool, g_x0, g_y0, ix, iy);
            g_drag = 0; ReleaseCapture();
            say("Drew (tool %c, colour %d, width %d). Ctrl+S saves a BMP.", "PLREF"[g_tool], g_color + 1, g_penw);
            InvalidateRect(hwnd, 0, FALSE);
        }
        return 0;
    case WM_CLOSE:
        if (g_dirty) { say("Unsaved edits: Ctrl+S saves, Ctrl+D discards, then close again."); return 0; }
        DestroyWindow(hwnd); return 0;
    case WM_DESTROY: release_image(); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static int first_arg(WCHAR *dst)
{
    const WCHAR *p = GetCommandLineW();
    int q = 0, n = 0;
    dst[0] = 0;
    if (!p) return 0;
    while (*p == ' ' || *p == '\t') ++p;
    for (; *p && (q || (*p != ' ' && *p != '\t')); ++p) if (*p == '"') q = !q;
    if (q) return -1;
    while (*p == ' ' || *p == '\t') ++p;
    if (!*p) return 0;
    q = *p == '"';
    if (q) ++p;
    while (*p && (q ? *p != '"' : (*p != ' ' && *p != '\t'))) {
        if (*p == '"' || n + 1 >= PATH_CAP) { dst[0] = 0; return -1; }
        dst[n++] = *p++;
    }
    if (q && *p++ != '"') { dst[0] = 0; return -1; }
    if (q && *p && *p != ' ' && *p != '\t') { dst[0] = 0; return -1; }
    dst[n] = 0;
    return n ? 1 : 0;
}

int main(void)
{
    WNDCLASSEXW wc;
    MSG m;
    int r, code = 0;
    WCHAR arg[PATH_CAP];
    if (first_arg(arg) < 0) { printf("SAPPHIRE REFUSED op=argument reason=malformed-or-too-long\n"); return 2; }
    g_inst = GetModuleHandleW(0);
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc; wc.style = CS_HREDRAW | CS_VREDRAW; wc.lpfnWndProc = proc; wc.hInstance = g_inst;
    wc.lpszClassName = L"SapphireWindow"; wc.hCursor = LoadCursorW(0, (LPCWSTR)IDC_ARROW);
    if (!RegisterClassExW(&wc)) { printf("SAPPHIRE ERROR op=register error=%lu\n", (unsigned long)GetLastError()); return 1; }
    g_wnd = CreateWindowExW(0, wc.lpszClassName, L"Sapphire", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 30, 640, 480, 0, 0, g_inst, 0);
    if (!g_wnd) { printf("SAPPHIRE ERROR op=window error=%lu\n", (unsigned long)GetLastError()); return 1; }
    SetFocus(g_wnd);
    if (arg[0]) open_image(arg);
    UpdateWindow(g_wnd);
    printf("SAPPHIRE READY\n");
    while ((r = GetMessageW(&m, 0, 0, 0)) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
    if (r < 0) code = 1;
    release_image();
    UnregisterClassW(wc.lpszClassName, g_inst);
    return code;
}
