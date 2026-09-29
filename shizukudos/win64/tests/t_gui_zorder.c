/* SPDX-License-Identifier: GPL-2.0-only
 * GUI: two overlapping top-level windows. Stacking, activation (caption colours), raising, hiding and moving are shown as
 * four scenes for the host runner (run_k64_gui.py), which recomputes the expected screen for each from the window
 * rectangles below and compares every pixel:
 *   z1  A (red client) at (100,100) 300x200 and B (blue client) at (220,160) 300x200; B was created last: B on top and active
 *   z2  BringWindowToTop(A): A on top and active
 *   z3  B hidden: only A remains
 *   z4  A moved to (300,300): the area it left shows the desktop again
 * Reports SKIP and exits 0 when there is no display. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

static int g_paints[2];

static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_PAINT) {
        PAINTSTRUCT ps;
        BeginPaint(h, &ps);
        EndPaint(h, &ps);
        ++g_paints[GetWindowLongPtrW(h, GWLP_USERDATA) == 1];
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static void pump_ms(UINT ms)
{
    MSG msg;
    UINT_PTR id = SetTimer(0, 0, ms, 0);
    while (GetMessageW(&msg, 0, 0, 0) > 0) {
        if (msg.message == WM_TIMER && msg.hwnd == 0 && msg.wParam == id) break;
        DispatchMessageW(&msg);
    }
    KillTimer(0, id);
}

int main(void)
{
    HINSTANCE inst = GetModuleHandleW(0);
    WNDCLASSW wa, wb;
    HWND a, b;
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    memset(&wa, 0, sizeof wa);
    wa.lpfnWndProc = proc;
    wa.hInstance = inst;
    wa.hbrBackground = CreateSolidBrush(RGB(255, 0, 0));
    wa.lpszClassName = L"ShzZOrderA";
    wb = wa;
    wb.hbrBackground = CreateSolidBrush(RGB(0, 0, 255));
    wb.lpszClassName = L"ShzZOrderB";
    CHECK(RegisterClassW(&wa) && RegisterClassW(&wb), "two window classes with different background brushes");
    a = CreateWindowExW(0, L"ShzZOrderA", L"Window A", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 300, 200, 0, 0, inst, 0);
    b = CreateWindowExW(0, L"ShzZOrderB", L"Window B", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 220, 160, 300, 200, 0, 0, inst, 0);
    CHECK(a && b, "two overlapped windows");
    if (!a || !b) return 1;
    SetWindowLongPtrW(a, GWLP_USERDATA, 0);
    SetWindowLongPtrW(b, GWLP_USERDATA, 1);
    UpdateWindow(a);
    UpdateWindow(b);
    CHECK(g_paints[0] == 1 && g_paints[1] == 1, "each window painted once (background erased by BeginPaint)");
    CHECK(GetWindow(b, GW_HWNDNEXT) == a && GetWindow(a, GW_HWNDPREV) == b && GetTopWindow(0) == b, "B is above A in the z-order");
    CHECK(GetActiveWindow() == b && GetForegroundWindow() == b, "B (created last) is the active window");
    printf("GUI-READY: z1\n");
    pump_ms(1200);

    CHECK(BringWindowToTop(a), "BringWindowToTop(A)");
    CHECK(GetTopWindow(0) == a && GetWindow(a, GW_HWNDNEXT) == b && GetActiveWindow() == a, "A is now on top and active");
    UpdateWindow(a);
    printf("GUI-READY: z2\n");
    pump_ms(1200);

    CHECK(ShowWindow(b, SW_HIDE) != 0, "ShowWindow(SW_HIDE) reports the window was visible");
    CHECK(!IsWindowVisible(b) && IsWindowVisible(a) && GetActiveWindow() == a, "B hidden, A still visible and active");
    printf("GUI-READY: z3\n");
    pump_ms(1200);

    CHECK(SetWindowPos(a, 0, 300, 300, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos moves A to (300,300)");
    {
        RECT r;
        GetWindowRect(a, &r);
        CHECK(r.left == 300 && r.top == 300 && r.right == 600 && r.bottom == 500, "the moved window keeps its size");
    }
    printf("GUI-READY: z4\n");
    pump_ms(1200);

    CHECK(DestroyWindow(a) && DestroyWindow(b), "both windows destroyed");
    CHECK(g_paints[0] == 1 && g_paints[1] == 1, "moving and hiding never asked for a repaint: window contents persist");
    printf("%s: z-order test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
