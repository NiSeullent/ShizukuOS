/* SPDX-License-Identifier: GPL-2.0-only
 * Original Win32 probe. Uses native, classic GDI; has no CRT entry/runtime. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#define WINVER 0x0400
#include <windows.h>
#include "adapter.h"

#define WIDTH 320u
#define HEIGHT 200u
typedef struct native_backend {
    HDC memory, painting;
    HBITMAP bitmap;
    HGDIOBJ previous;
    HWND window;
} native_backend;
static native_backend native;
static ntwg98_view view;
static HANDLE logfile;
static int failed, io_failed, closing, cleanup_failed;
static uint32_t paints;

static void log_text(const char *text)
{
    DWORD length = 0, written = 0;
    while (text[length]) ++length;
    if (!WriteFile(logfile, text, length, &written, NULL) || written != length) io_failed = 1;
}
static void log_number(const char *name, uint32_t value)
{
    char buffer[12]; unsigned count = 0, i;
    log_text(name);
    do { buffer[count++] = (char)('0' + value % 10u); value /= 10u; } while (value);
    for (i = 0; i < count / 2u; ++i) {
        char ch = buffer[i]; buffer[i] = buffer[count - i - 1u]; buffer[count - i - 1u] = ch;
    }
    buffer[count] = 0; log_text(buffer); log_text("\r\n");
}
static void record_failure(const char *stage)
{
    DWORD error = GetLastError();
    failed = 1; log_text("FAIL_STAGE="); log_text(stage); log_text("\r\n");
    log_number("LAST_ERROR=", error);
}
static void *allocate(void *user, size_t bytes)
{
    (void)user;
    return HeapAlloc(GetProcessHeap(), 0, bytes);
}
static void deallocate(void *user, void *memory, size_t bytes)
{
    (void)user; (void)bytes;
    if (!HeapFree(GetProcessHeap(), 0, memory)) {
        cleanup_failed = 1; record_failure("HeapFree");
    }
}
static int synchronize(void *user)
{
    (void)user;
    return GdiFlush() != 0;
}
static int create_dib(void *user, uint32_t width, uint32_t height, ntwg98_dib *dib)
{
    native_backend *b = user;
    BITMAPINFO info = {0};
    HDC screen = GetDC(b->window);
    if (!screen) return 0;
    b->memory = CreateCompatibleDC(screen);
    if (!ReleaseDC(b->window, screen)) {
        cleanup_failed = 1; record_failure("ReleaseDC");
    }
    if (!b->memory) return 0;
    dib->handle = b;
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = (LONG)width;
    info.bmiHeader.biHeight = -(LONG)height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    b->bitmap = CreateDIBSection(b->memory, &info, DIB_RGB_COLORS, &dib->pixels, NULL, 0);
    if (!b->bitmap || !dib->pixels) return 0;
    dib->pitch = width * 4u; dib->bytes = (size_t)dib->pitch * height;
    b->previous = SelectObject(b->memory, b->bitmap);
    if (!b->previous || b->previous == HGDI_ERROR) { b->previous = NULL; return 0; }
    return 1;
}
static int paint_dib(void *user, const ntwg98_dib *dib, uint32_t width, uint32_t height)
{
    native_backend *b = user;
    if (dib->handle != b || !b->painting || !b->bitmap) return 0;
    if (!BitBlt(b->painting, 0, 0, (int)width, (int)height, b->memory, 0, 0, SRCCOPY)) return 0;
    return GdiFlush() != 0;
}
static int release_dib(void *user, ntwg98_dib *dib)
{
    native_backend *b = user;
    if (b->previous) {
        HGDIOBJ old = SelectObject(b->memory, b->previous);
        if (!old || old == HGDI_ERROR) return 0;
        b->previous = NULL;
    }
    if (b->bitmap) {
        if (!DeleteObject(b->bitmap)) return 0;
        b->bitmap = NULL; dib->pixels = NULL;
    }
    if (b->memory) {
        if (!DeleteDC(b->memory)) return 0;
        b->memory = NULL;
    }
    dib->handle = NULL;
    return 1;
}
static const ntwg98_ops operations = { allocate, deallocate, create_dib,
                                      synchronize, paint_dib, release_dib };

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT paint;
        native.painting = BeginPaint(window, &paint);
        if (!native.painting) record_failure("BeginPaint");
        else {
            if (ntwg98_paint(&view) != NTWG_OK) record_failure("BitBlt/GdiFlush");
            else ++paints;
            if (!EndPaint(window, &paint)) record_failure("EndPaint");
        }
        native.painting = NULL;
        return 0;
    }
    case WM_CLOSE:
        closing = 1;
        return 0;
    case WM_DESTROY:
        closing = 1;
        return 0;
    default:
        return DefWindowProcA(window, message, wparam, lparam);
    }
}

void mainCRTStartup(void)
{
    WNDCLASSA window_class = {0};
    RECT rectangle = {0, 0, WIDTH, HEIGHT};
    MSG message;
    OSVERSIONINFOA os = {0};
    HINSTANCE instance = GetModuleHandleA(NULL);
    HDC screen;
    DWORD start, last_repaint;
    uint32_t checks = 0;
    int result;
    ATOM registered = 0;
    static const char class_name[] = "NTWGOriginalProbe";
    const DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    logfile = CreateFileA("NTWGPROB.LOG", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (logfile == INVALID_HANDLE_VALUE) ExitProcess(2);
    log_text("NTWDDMWrapper9x native GDI probe v1\r\nSCOPE=app-owned software DIB; no WDDM/D3D/GPU claim\r\n");
    os.dwOSVersionInfoSize = sizeof(os);
    if (!GetVersionExA(&os)) { record_failure("GetVersionExA"); goto done; }
    log_number("OS_PLATFORM=", os.dwPlatformId); log_number("OS_MAJOR=", os.dwMajorVersion);
    log_number("OS_MINOR=", os.dwMinorVersion); log_number("OS_BUILD=", os.dwBuildNumber);
    log_text(os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 10 ?
             "WIN98_IDENTIFIED=1\r\n" : "WIN98_IDENTIFIED=0\r\n");
    window_class.lpfnWndProc = window_proc; window_class.hInstance = instance;
    window_class.hCursor = LoadCursorA(NULL, IDC_ARROW);
    window_class.lpszClassName = class_name;
    registered = RegisterClassA(&window_class);
    if (!registered) { record_failure("RegisterClassA"); goto done; }
    if (!AdjustWindowRect(&rectangle, style, FALSE)) { record_failure("AdjustWindowRect"); goto done; }
    native.window = CreateWindowExA(0, class_name, "NTWDDMWrapper9x - software GDI probe",
        style, CW_USEDEFAULT, CW_USEDEFAULT, rectangle.right - rectangle.left,
        rectangle.bottom - rectangle.top, NULL, NULL, instance, NULL);
    if (!native.window) { record_failure("CreateWindowExA"); goto done; }
    screen = GetDC(native.window);
    if (!screen) { record_failure("GetDC"); goto done; }
    log_number("DISPLAY_BITSPIXEL=", (uint32_t)GetDeviceCaps(screen, BITSPIXEL));
    log_number("DISPLAY_PLANES=", (uint32_t)GetDeviceCaps(screen, PLANES));
    if (!ReleaseDC(native.window, screen)) { cleanup_failed = 1; record_failure("ReleaseDC"); goto done; }
    result = ntwg98_open(&view, &operations, &native, WIDTH, HEIGHT);
    if (result != NTWG_OK) { record_failure("adapter-open"); goto done; }
    result = ntwg98_selftest(&view, &checks);
    log_number("PIXEL_CONTRACT_CHECKS=", checks);
    if (result != NTWG_OK) { record_failure("pixel-contracts"); goto done; }
    log_text("PIXEL_CONTRACTS=PASS\r\nFENCE_SCOPE=CPU copy only\r\n");
    ShowWindow(native.window, SW_SHOW);
    if (!UpdateWindow(native.window)) { record_failure("UpdateWindow"); goto done; }
    start = GetTickCount(); last_repaint = start;
    /* A polling message loop gives a wall-clock bound even if timer messages
     * are starved; dispatch itself cannot interrupt a hung native GDI call. */
    while (!closing && !failed && (DWORD)(GetTickCount() - start) < 5000u) {
        unsigned batch = 0;
        while (batch++ < 32 && PeekMessageA(&message, NULL, 0, 0, PM_REMOVE)) {
            if (message.message == WM_QUIT) { closing = 1; break; }
            TranslateMessage(&message); DispatchMessageA(&message);
        }
        if ((DWORD)(GetTickCount() - last_repaint) >= 250u) {
            last_repaint = GetTickCount();
            if (!InvalidateRect(native.window, NULL, FALSE)) record_failure("InvalidateRect");
        }
        Sleep(10);
    }
    if (!paints) record_failure("no-successful-paint");
done:
    result = ntwg98_close(&view);
    if (result != NTWG_OK) { cleanup_failed = 1; record_failure("adapter-close"); }
    if (native.window && !DestroyWindow(native.window)) { cleanup_failed = 1; record_failure("DestroyWindow"); }
    if (registered && !UnregisterClassA(class_name, instance)) { cleanup_failed = 1; record_failure("UnregisterClassA"); }
    log_number("SUCCESSFUL_PAINTS=", paints);
    log_text(!cleanup_failed ? "CLEANUP=PASS\r\n" : "CLEANUP=FAIL\r\n");
    log_text(failed ? "RESULT=FAIL\r\n" : "RESULT=PASS\r\n");
    if (!CloseHandle(logfile)) io_failed = 1;
    ExitProcess(io_failed ? 2u : failed ? 1u : 0u);
}
