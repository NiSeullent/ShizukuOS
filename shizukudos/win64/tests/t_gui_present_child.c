/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine same-desktop cross-process raster presentation. The child draws
 * only its own pixels into the parent's live HWND; the parent reads the
 * actual kernel compositor surface through PrintWindow, not a shared copy.
 * This private NtGdiPresent contract needs the Kernel64 standalone display.
 */
#include <limits.h>
#include "k32test.h"
#include "shzgfx.h"

#define WIDTH 32
#define HEIGHT 24
#define ST_INVALID_HANDLE ((int32_t)0xc0000008u)
#define ST_INVALID_PARAMETER ((int32_t)0xc000000du)
#define ST_ACCESS_VIOLATION ((int32_t)0xc0000005u)
#define ST_ACCESS_DENIED ((int32_t)0xc0000022u)

static void present(shz_present_t *p, HWND hwnd, DWORD *pixels)
{
    memset(p, 0, sizeof *p);
    p->hwnd = (uint64_t)(uintptr_t)hwnd;
    p->bits = (uint64_t)(uintptr_t)pixels;
    p->w = p->surf_w = WIDTH; p->h = p->surf_h = HEIGHT;
    p->stride = WIDTH * 4;
}
static int child(HWND hwnd, HWND stale)
{
    DWORD pixels[WIDTH * HEIGHT], old_protection, *fault;
    shz_present_t p, bad;
    shz_prop_t property;
    RECT rect;
    HDC dc;
    unsigned i;
    CHECK(IsWindow(hwnd) && GetWindowThreadProcessId(hwnd, &old_protection) != 0 &&
          old_protection != GetCurrentProcessId(), "child targets real live parent-process window");
    CHECK(GetClientRect(hwnd, &rect) && rect.right == WIDTH && rect.bottom == HEIGHT,
          "foreign client bounds describe actual target surface");
    for (i = 0; i < WIDTH * HEIGHT; ++i) pixels[i] = 0x123456u;
    pixels[65] = 0xabcdefu; pixels[WIDTH * HEIGHT - 1] = 0x445566u;
    present(&p, hwnd, pixels);
    CHECK(NtGdiPresent(&p) == 0, "real child-owned pixels present into live parent window on shared desktop");
    dc = GetDC(hwnd);
    CHECK(dc != NULL, "GetDC obtains actual foreign-window raster DC");
    if (dc) {
        CHECK(SetPixel(dc, 0, 0, RGB(0x98, 0x76, 0x54)) == RGB(0x98, 0x76, 0x54),
              "child raster draws a distinct pixel through foreign GetDC");
        CHECK(ReleaseDC(hwnd, dc) == 1 && GdiFlush(), "child releases DC and flushes genuine window presentation");
    }
    bad = p; bad.hwnd = 0;
    CHECK(NtGdiPresent(&bad) == ST_INVALID_HANDLE, "null HWND does not grant desktop presentation");
    bad.hwnd = UINT64_C(0xffffffffffffffff);
    CHECK(NtGdiPresent(&bad) == ST_INVALID_HANDLE, "unrecognized HWND fails live lookup");
    bad.hwnd = (uint64_t)(uintptr_t)stale;
    CHECK(NtGdiPresent(&bad) == ST_INVALID_HANDLE, "destroyed generation-stamped HWND is rejected");
    bad = p; bad.bits = 1;
    CHECK(NtGdiPresent(&bad) == ST_ACCESS_VIOLATION, "caller pixels cannot come from null guard address");
    bad.bits = UINT64_C(0xffff800000000000);
    CHECK(NtGdiPresent(&bad) == ST_ACCESS_VIOLATION, "kernel pointer cannot supply child pixels");
    bad = p; bad.stride = WIDTH * 4 - 1;
    CHECK(NtGdiPresent(&bad) == ST_INVALID_PARAMETER, "undersized pixel stride is rejected");
    bad = p; bad.surf_w++;
    CHECK(NtGdiPresent(&bad) == ST_INVALID_PARAMETER, "target surface dimensions must match actual client");
    bad = p; bad.w = -1;
    CHECK(NtGdiPresent(&bad) == ST_INVALID_PARAMETER, "negative copy extent is rejected");
    bad = p; bad.x = INT_MAX; bad.w = INT_MAX;
    CHECK(NtGdiPresent(&bad) == 0, "large offscreen rectangle clips safely without signed wrapping");
    bad = p; bad.w = 0; bad.bits = 1;
    CHECK(NtGdiPresent(&bad) == 0, "empty rectangle reads no user pixels");
    /* First row is readable, second row is genuinely protected. Failure
     * must not commit the staged first row into the parent's surface. */
    fault = VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(fault != NULL, "actual caller mapping allocated for row-fault boundary");
    if (fault) {
        DWORD *last_row = (DWORD *)((BYTE *)fault + 4096 - WIDTH * 4);
        for (i = 0; i < WIDTH; ++i) last_row[i] = 0xdeadbeefu;
        CHECK(VirtualProtect((BYTE *)fault + 4096, 4096, PAGE_NOACCESS, &old_protection),
              "second source row is made genuinely inaccessible");
        bad = p; bad.bits = (uint64_t)(uintptr_t)last_row; bad.h = 2;
        CHECK(NtGdiPresent(&bad) == ST_ACCESS_VIOLATION,
              "later-row caller memory fault rejects presentation instead of retaining source pointer");
        CHECK(VirtualFree(fault, 0, MEM_RELEASE), "faulting caller mapping is released");
    }
    memset(&property, 0, sizeof property);
    property.hwnd = (uint64_t)(uintptr_t)hwnd;
    property.op = SHZ_PROP_SET; property.key = 0x1234; property.value = 0x5678;
    CHECK(NtUserProp(&property) == ST_ACCESS_DENIED, "cross-process window metadata ownership gate remains enforced");
    CHECK(NtUserDestroyWindow((uint64_t)(uintptr_t)hwnd) == ST_ACCESS_DENIED,
          "presentation permission does not allow child to destroy parent window");
    return k32t_finish("T_GUI_PRESENT_CHILD_WORKER");
}
static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcW(hwnd, message, wparam, lparam);
}
static HWND create_window(void)
{
    return CreateWindowExW(0, L"ShzCrossPresent", L"Cross-process present", WS_POPUP | WS_VISIBLE,
                           20, 20, WIDTH, HEIGHT, NULL, NULL, GetModuleHandleW(NULL), NULL);
}
static uint64_t parse_handle(const char *text)
{
    uint64_t value = 0;
    unsigned digit, count = 0;
    for (; *text; ++text) {
        if (++count > 16) return 0;
        if (*text >= '0' && *text <= '9') digit = (unsigned)(*text - '0');
        else if (*text >= 'a' && *text <= 'f') digit = (unsigned)(*text - 'a') + 10u;
        else if (*text >= 'A' && *text <= 'F') digit = (unsigned)(*text - 'A') + 10u;
        else return 0;
        value = (value << 4) | digit;
    }
    return value;
}
int main(int argc, char **argv)
{
    WNDCLASSEXW wc;
    HWND hwnd, stale, replacement;
    HDC dc;
    HBITMAP bitmap, old;
    BITMAPINFO info;
    DWORD *pixels = NULL, exit_code = STILL_ACTIVE;
    PROCESS_INFORMATION process;
    STARTUPINFOA startup;
    char executable[512], command[768];
    int readback;
    if (argc == 4 && !strcmp(argv[1], "--child"))
        return child((HWND)(uintptr_t)parse_handle(argv[2]),
                     (HWND)(uintptr_t)parse_handle(argv[3]));
    if (!GetSystemMetrics(SM_CXSCREEN)) {
        printf("T_GUI_PRESENT_CHILD: display unavailable; guest contract not executed\n");
        return 2;
    }
    memset(&wc, 0, sizeof wc); wc.cbSize = sizeof wc;
    wc.hInstance = GetModuleHandleW(NULL); wc.lpfnWndProc = window_proc;
    wc.lpszClassName = L"ShzCrossPresent";
    CHECK(RegisterClassExW(&wc) != 0, "parent registers real window class");
    stale = create_window();
    CHECK(stale && DestroyWindow(stale), "parent creates and destroys real stale HWND");
    replacement = create_window(); hwnd = replacement;
    CHECK(hwnd && hwnd != stale && !IsWindow(stale), "new live window has different generation from destroyed HWND");
    if (!hwnd) return 1;
    memset(&startup, 0, sizeof startup); startup.cb = sizeof startup;
    memset(&process, 0, sizeof process);
    CHECK(GetModuleFileNameA(NULL, executable, sizeof executable) != 0, "actual guest executable path discovered");
    snprintf(command, sizeof command, "\"%s\" --child %llx %llx", executable,
             (unsigned long long)(uintptr_t)hwnd, (unsigned long long)(uintptr_t)stale);
    CHECK(CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process),
          "genuine child process starts foreign-window drawing");
    if (process.hProcess) {
        CHECK(WaitForSingleObject(process.hProcess, 20000) == WAIT_OBJECT_0,
              "actual child presentation completes");
        CHECK(GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 0,
              "child process's actual API and fault checks pass");
        if (exit_code == STILL_ACTIVE) { TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, 5000); }
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
    }
    dc = CreateCompatibleDC(NULL);
    memset(&info, 0, sizeof info); info.bmiHeader.biSize = sizeof info.bmiHeader;
    info.bmiHeader.biWidth = WIDTH; info.bmiHeader.biHeight = -HEIGHT;
    info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32;
    bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&pixels, NULL, 0);
    CHECK(dc && bitmap && pixels, "parent creates genuine raster readback target");
    if (dc && bitmap && pixels) {
        old = SelectObject(dc, bitmap);
        readback = PrintWindow(hwnd, dc, PW_CLIENTONLY);
        CHECK(readback, "owning parent reads actual kernel window surface through PrintWindow");
        CHECK(readback && pixels[0] == 0x987654u,
              "kernel readback contains child's actual foreign GetDC pixel");
        CHECK(readback && pixels[1] == 0x123456u && pixels[65] == 0xabcdefu &&
              pixels[WIDTH * HEIGHT - 1] == 0x445566u,
              "kernel readback preserves child NtGdiPresent pixels, stride and final row");
        CHECK(readback && pixels[0] != 0xdeadbeefu && pixels[31] == 0x123456u,
              "later-row source fault commits no partial first-row pixels");
        if (old) SelectObject(dc, old);
    }
    if (bitmap) DeleteObject(bitmap);
    if (dc) DeleteDC(dc);
    CHECK(DestroyWindow(hwnd), "owning parent retains genuine window destruction authority");
    CHECK(UnregisterClassW(wc.lpszClassName, wc.hInstance), "parent releases actual class");
    return k32t_finish("T_GUI_PRESENT_CHILD");
}
