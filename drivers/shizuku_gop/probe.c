/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded native Win98 GDI diagnostic, no CRT and no physical/firmware access.
 * The report identifies the primary enumerated adapter and tests GDI surfaces;
 * backend installation and physical presentation need separate guest evidence.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0400
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <stdint.h>

#define WIDTH 160
#define HEIGHT 96
#define MAX_LOG 4096u
typedef struct legacy_display_device {
    DWORD cb;
    char name[32];
    char description[128];
    DWORD flags;
    char reserved[256];
} legacy_display_device;
typedef BOOL (WINAPI *enum_display_fn)(LPCSTR, DWORD, legacy_display_device *, DWORD);
typedef struct dib {
    HDC dc;
    HBITMAP bitmap;
    HGDIOBJ old_bitmap;
    uint32_t *pixels;
} dib;
static HANDLE logfile;
static DWORD log_bytes;
static int failed, io_failed, closing, image_ready;
static dib source, copy;

static void zero(void *data, DWORD n)
{
    unsigned char *p = data;
    while(n--) *p++ = 0;
}
static void text(const char *value)
{
    DWORD n = 0, written = 0;
    while(value[n] && n < 1024) n++;
    if(value[n] || n > MAX_LOG - log_bytes) { io_failed = 1; return; }
    if(!WriteFile(logfile, value, n, &written, NULL) || written != n) io_failed = 1;
    log_bytes += n;
}
static void number(const char *name, DWORD value)
{
    char buf[11]; DWORD n = 0, i;
    text(name);
    do { buf[n++] = (char)('0' + value % 10); value /= 10; } while(value);
    for(i = 0; i < n / 2; i++) { char c = buf[i]; buf[i] = buf[n - i - 1]; buf[n - i - 1] = c; }
    buf[n] = 0; text(buf); text("\r\n");
}
static void hex(const char *name, DWORD value)
{
    static const char digits[] = "0123456789abcdef";
    char buf[9]; DWORD i;
    for(i = 0; i < 8; i++) buf[i] = digits[(value >> (28 - 4 * i)) & 15];
    buf[8] = 0; text(name); text(buf); text("\r\n");
}
static void bounded_string(const char *name, const char *value, DWORD limit)
{
    static const char digits[] = "0123456789abcdef";
    DWORD i;
    text(name);
    for(i = 0; i < limit && value[i]; i++) {
        unsigned char c = (unsigned char)value[i];
        char out[5];
        if(c >= 32 && c < 127 && c != '\\') { out[0] = (char)c; out[1] = 0; }
        else { out[0] = '\\'; out[1] = 'x'; out[2] = digits[c >> 4]; out[3] = digits[c & 15]; out[4] = 0; }
        text(out);
    }
    text("\r\n");
}
static void fail(const char *stage)
{
    DWORD error = GetLastError();
    failed = 1; text("FAIL_STAGE="); text(stage); text("\r\n"); number("LAST_ERROR=", error);
}
static int adapter(void)
{
    union { FARPROC raw; enum_display_fn enumerate; } proc;
    DWORD i;
    proc.raw = GetProcAddress(GetModuleHandleA("USER32.DLL"), "EnumDisplayDevicesA");
    if(!proc.raw) { text("ADAPTER_STATUS=ENUM_UNAVAILABLE\r\n"); return 0; }
    for(i = 0; i < 8; i++) {
        legacy_display_device device;
        zero(&device, sizeof(device));
        /* Microsoft's Win98 KB197671 uses the original 168-byte structure.
         * The larger allocation also safely accommodates later fields. */
        device.cb = 168;
        if(!proc.enumerate(NULL, i, &device, 0)) {
            zero(&device, sizeof(device)); device.cb = sizeof(device);
            if(!proc.enumerate(NULL, i, &device, 0)) break;
        }
        if((device.flags & 5) == 5 && !(device.flags & 8)) {
            text("ADAPTER_STATUS=PRIMARY_ENUMERATED\r\n");
            bounded_string("ADAPTER_NAME=", device.name, sizeof(device.name));
            bounded_string("ADAPTER_DESCRIPTION_BYTES=", device.description, sizeof(device.description));
            hex("ADAPTER_FLAGS=", device.flags);
            return 1;
        }
    }
    text("ADAPTER_STATUS=PRIMARY_NOT_FOUND\r\n"); return 0;
}
static int create_dib(HDC screen, dib *b)
{
    BITMAPINFO info;
    zero(&info, sizeof(info));
    b->dc = CreateCompatibleDC(screen);
    if(!b->dc) return 0;
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = WIDTH; info.bmiHeader.biHeight = -HEIGHT;
    info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    b->bitmap = CreateDIBSection(b->dc, &info, DIB_RGB_COLORS, (void **)&b->pixels, NULL, 0);
    if(!b->bitmap || !b->pixels) return 0;
    b->old_bitmap = SelectObject(b->dc, b->bitmap);
    if(!b->old_bitmap || b->old_bitmap == HGDI_ERROR) { b->old_bitmap = NULL; return 0; }
    zero(b->pixels, WIDTH * HEIGHT * 4); return 1;
}
static int release_dib(dib *b)
{
    int ok = 1;
    if(b->old_bitmap) {
        HGDIOBJ restored = SelectObject(b->dc, b->old_bitmap);
        if(!restored || restored == HGDI_ERROR) ok = 0;
    }
    b->old_bitmap = NULL;
    if(b->bitmap && !DeleteObject(b->bitmap)) ok = 0;
    if(b->dc && !DeleteDC(b->dc)) ok = 0;
    b->dc = NULL; b->bitmap = NULL; b->pixels = NULL;
    return ok;
}
static uint32_t expected_pixel(DWORD x, DWORD y)
{
    return x >= 16 && x < 72 && y >= 12 && y < 52 ? 0x00d04030u : 0x001060a0u;
}
static DWORD pixel_hash(const uint32_t *pixels, int expected)
{
    DWORD x, y, channel, hash = 2166136261u;
    for(y = 0; y < HEIGHT; y++) for(x = 0; x < WIDTH; x++) {
        uint32_t value = expected ? expected_pixel(x, y) : pixels[y * WIDTH + x];
        for(channel = 0; channel < 3; channel++) { hash ^= (value >> (channel * 8)) & 255; hash *= 16777619u; }
    }
    return hash;
}
static int exact_pixels(const uint32_t *pixels)
{
    DWORD x, y;
    for(y = 0; y < HEIGHT; y++) for(x = 0; x < WIDTH; x++)
        if((pixels[y * WIDTH + x] & 0x00ffffffu) != expected_pixel(x, y)) return 0;
    return 1;
}
static int fill_pattern(void)
{
    HBRUSH background = CreateSolidBrush(RGB(16, 96, 160));
    HBRUSH rectangle = CreateSolidBrush(RGB(208, 64, 48));
    HGDIOBJ old = NULL, selected;
    int ok = 0;
    if(!background || !rectangle) goto end;
    old = SelectObject(source.dc, background);
    if(!old || old == HGDI_ERROR) { old = NULL; goto end; }
    if(!PatBlt(source.dc, 0, 0, WIDTH, HEIGHT, PATCOPY)) goto end;
    selected = SelectObject(source.dc, rectangle);
    if(!selected || selected == HGDI_ERROR) goto end;
    if(!PatBlt(source.dc, 16, 12, 56, 40, PATCOPY) || !GdiFlush()) goto end;
    ok = exact_pixels(source.pixels);
end:
    if(old) {
        selected = SelectObject(source.dc, old);
        if(!selected || selected == HGDI_ERROR) ok = 0;
    }
    if(background && !DeleteObject(background)) ok = 0;
    if(rectangle && !DeleteObject(rectangle)) ok = 0;
    return ok;
}
static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    if(message == WM_PAINT) {
        PAINTSTRUCT paint;
        HDC dc = BeginPaint(window, &paint);
        if(image_ready && (!dc || !BitBlt(dc, 0, 0, WIDTH, HEIGHT, copy.dc, 0, 0, SRCCOPY))) failed = 1;
        EndPaint(window, &paint); return 0;
    }
    if(message == WM_CLOSE) { closing = 1; DestroyWindow(window); return 0; }
    return DefWindowProcA(window, message, wparam, lparam);
}
static void pump(void)
{
    MSG message; DWORD n = 0;
    while(n++ < 32 && PeekMessageA(&message, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&message); DispatchMessageA(&message);
    }
}
void mainCRTStartup(void)
{
    OSVERSIONINFOA version;
    WNDCLASSA cls;
    HWND window = NULL;
    HDC screen = NULL, painting = NULL;
    RECT rect = {0, 0, WIDTH, HEIGHT};
    POINT origin = {0, 0};
    DWORD i, started, bpp, expected = pixel_hash(NULL, 1);
    int registered = 0, source_released, copy_released;
    logfile = CreateFileA("C:\\VXDLAB\\SHZPRB.LOG", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if(logfile == INVALID_HANDLE_VALUE) ExitProcess(20);
    text("SCHEMA=SHZGOP_GDI_PROBE_1\r\nSCOPE=NATIVE_WIN32_GDI_DISPLAY_SURFACE\r\nBACKEND_HARDWARE_VERIFIED=0\r\n");
    hex("RUN_TOKEN=", GetTickCount() ^ GetCurrentProcessId());
    zero(&version, sizeof(version)); version.dwOSVersionInfoSize = sizeof(version);
    if(!GetVersionExA(&version)) { fail("GetVersionExA"); goto end; }
    number("OS_MAJOR=", version.dwMajorVersion); number("OS_MINOR=", version.dwMinorVersion);
    number("OS_BUILD=", version.dwBuildNumber & 65535); number("OS_PLATFORM=", version.dwPlatformId);
    if(version.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS || version.dwMajorVersion != 4 || version.dwMinorVersion != 10) {
        fail("native-Windows98-version-required"); goto end;
    }
    if(!adapter()) fail("primary-adapter-enumeration");
    screen = GetDC(NULL);
    if(!screen) { fail("GetDC-screen"); goto end; }
    number("DISPLAY_WIDTH=", (DWORD)GetDeviceCaps(screen, HORZRES));
    number("DISPLAY_HEIGHT=", (DWORD)GetDeviceCaps(screen, VERTRES));
    bpp = (DWORD)GetDeviceCaps(screen, BITSPIXEL) * (DWORD)GetDeviceCaps(screen, PLANES);
    number("DISPLAY_BPP=", bpp);
    number("DISPLAY_DRIVER_VERSION=", (DWORD)GetDeviceCaps(screen, DRIVERVERSION));
    number("DISPLAY_RASTERCAPS=", (DWORD)GetDeviceCaps(screen, RASTERCAPS));
    if(bpp != 32) fail("32-bit-display-required-for-exact-color-readback");
    if(!create_dib(screen, &source) || !create_dib(screen, &copy)) { fail("CreateDIBSection"); goto end; }
    text("RGB_FNV1A_BYTE_ORDER=B,G,R\r\n");
    hex("EXPECTED_RGB_FNV1A=", expected);
    if(!fill_pattern()) { fail("GDI-fill-pixels"); goto end; }
    hex("GDI_FILL_RGB_FNV1A=", pixel_hash(source.pixels, 0)); text("GDI_FILL=PASS\r\n");
    if(!BitBlt(copy.dc, 0, 0, WIDTH, HEIGHT, source.dc, 0, 0, SRCCOPY) || !GdiFlush() || !exact_pixels(copy.pixels)) {
        fail("GDI-copy-pixels"); goto end;
    }
    hex("GDI_COPY_RGB_FNV1A=", pixel_hash(copy.pixels, 0)); text("GDI_COPY=PASS\r\n");
    zero(&cls, sizeof(cls)); cls.lpfnWndProc = window_proc; cls.hInstance = GetModuleHandleA(NULL);
    cls.lpszClassName = "SHZGOP_PROBE"; cls.hCursor = LoadCursorA(NULL, IDC_ARROW);
    if(!RegisterClassA(&cls)) { fail("RegisterClassA"); goto end; }
    registered = 1;
    if(!AdjustWindowRect(&rect, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE)) { fail("AdjustWindowRect"); goto end; }
    window = CreateWindowExA(WS_EX_TOPMOST, cls.lpszClassName, "Shizuku GDI diagnostic", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                             16, 16, rect.right - rect.left, rect.bottom - rect.top, NULL, NULL, cls.hInstance, NULL);
    if(!window) { fail("CreateWindowExA"); goto end; }
    image_ready = 1; ShowWindow(window, SW_SHOWNORMAL); UpdateWindow(window); pump();
    started = GetTickCount();
    for(i = 0; i < 100 && !closing; i++) { pump(); Sleep(50); }
    number("VISIBLE_DURATION_MS=", GetTickCount() - started);
    if(closing) { fail("window-closed-before-readback"); goto end; }
    if(!ClientToScreen(window, &origin)) { fail("ClientToScreen"); goto end; }
    number("PATTERN_SCREEN_X=", (DWORD)origin.x); number("PATTERN_SCREEN_Y=", (DWORD)origin.y);
    number("PATTERN_WIDTH=", WIDTH); number("PATTERN_HEIGHT=", HEIGHT);
    painting = GetDC(window);
    if(!painting || !BitBlt(source.dc, 0, 0, WIDTH, HEIGHT, painting, 0, 0, SRCCOPY) || !GdiFlush()) {
        fail("window-display-readback"); goto end;
    }
    hex("DISPLAY_READBACK_RGB_FNV1A=", pixel_hash(source.pixels, 0));
    if(!exact_pixels(source.pixels)) { fail("display-readback-pixels"); goto end; }
    text("DISPLAY_READBACK=PASS\r\n");
end:
    image_ready = 0;
    if(painting && !ReleaseDC(window, painting)) fail("ReleaseDC-window");
    if(window && !closing && !DestroyWindow(window)) fail("DestroyWindow");
    if(registered && !UnregisterClassA(cls.lpszClassName, cls.hInstance)) fail("UnregisterClassA");
    source_released = release_dib(&source);
    copy_released = release_dib(&copy);
    if(!source_released || !copy_released) fail("release-DIB-resources");
    if(screen && !ReleaseDC(NULL, screen)) fail("ReleaseDC-screen");
    text(failed || io_failed ? "STATUS=FAIL\r\n" : "STATUS=PASS\r\n");
    if(!CloseHandle(logfile)) io_failed = 1;
    ExitProcess(failed || io_failed ? 1 : 0);
}
