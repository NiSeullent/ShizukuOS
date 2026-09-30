/* SPDX-License-Identifier: GPL-2.0-only
 * GUI: child windows. A parent (WS_OVERLAPPEDWINDOW at (100,100) 400x300, gray class brush) holds three children:
 *   C1 (20,20) 150x100  WS_BORDER            red    class brush
 *   C2 (100,60) 150x100 WS_EX_CLIENTEDGE     blue   class brush, created after C1 so it is above it
 *   C3 (330,200) 100x100 (no border)         green  class brush, extends beyond the parent's client area and is clipped by it
 * Each child paints a white 10x10 box at its client (5,5) and, for C3, a second box far outside the parent (fully clipped).
 * Scenes for the host (run_k64_gui.py, whole-screen comparison):
 *   c1 as created;  c2 after BringWindowToTop(C1);  c3 after MoveWindow(C3, 300,150,100,100) and hiding C2;
 *   c4 after growing C1 to 200x140. Reports SKIP and exits 0 without a display. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

static int g_child_paints;

static LRESULT CALLBACK child_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        HBRUSH wb = CreateSolidBrush(RGB(255, 255, 255)), old = SelectObject(dc, wb);
        PatBlt(dc, 5, 5, 10, 10, PATCOPY);
        if (GetWindowLongPtrW(h, GWLP_ID) == 3) PatBlt(dc, 80, 80, 15, 15, PATCOPY);       /* lies outside the parent's client area */
        SelectObject(dc, old);
        DeleteObject(wb);
        EndPaint(h, &ps);
        ++g_child_paints;
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static LRESULT CALLBACK parent_proc(HWND h, UINT m, WPARAM w, LPARAM l) { return DefWindowProcW(h, m, w, l); }

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
    WNDCLASSW pc, c1c, c2c, c3c;
    HWND p, c1, c2, c3;
    RECT r, pcr;
    POINT org = { 0, 0 };
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    memset(&pc, 0, sizeof pc);
    pc.lpfnWndProc = parent_proc;
    pc.hInstance = inst;
    pc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    pc.lpszClassName = L"ShzChildParent";
    memset(&c1c, 0, sizeof c1c);
    c1c.lpfnWndProc = child_proc;
    c1c.hInstance = inst;
    c1c.hbrBackground = CreateSolidBrush(RGB(255, 0, 0));
    c1c.lpszClassName = L"ShzChild1";
    c2c = c1c; c2c.hbrBackground = CreateSolidBrush(RGB(0, 0, 255)); c2c.lpszClassName = L"ShzChild2";
    c3c = c1c; c3c.hbrBackground = CreateSolidBrush(RGB(0, 160, 0)); c3c.lpszClassName = L"ShzChild3";
    CHECK(RegisterClassW(&pc) && RegisterClassW(&c1c) && RegisterClassW(&c2c) && RegisterClassW(&c3c), "four classes");
    p = CreateWindowExW(0, L"ShzChildParent", L"Parent", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, 0, 0, inst, 0);
    c1 = CreateWindowExW(0, L"ShzChild1", L"", WS_CHILD | WS_VISIBLE | WS_BORDER, 20, 20, 150, 100, p, (HMENU)1, inst, 0);
    c2 = CreateWindowExW(WS_EX_CLIENTEDGE, L"ShzChild2", L"", WS_CHILD | WS_VISIBLE, 100, 60, 150, 100, p, (HMENU)2, inst, 0);
    c3 = CreateWindowExW(0, L"ShzChild3", L"", WS_CHILD | WS_VISIBLE, 330, 200, 100, 100, p, (HMENU)3, inst, 0);
    CHECK(p && c1 && c2 && c3, "parent and three children");
    if (!(p && c1 && c2 && c3)) return 1;
    UpdateWindow(p);
    UpdateWindow(c1); UpdateWindow(c2); UpdateWindow(c3);
    GetClientRect(c1, &r);
    CHECK(r.right == 148 && r.bottom == 98, "WS_BORDER child: 1-pixel border, client 148x98");
    GetClientRect(c2, &r);
    CHECK(r.right == 146 && r.bottom == 96, "WS_EX_CLIENTEDGE child: 2-pixel edge, client 146x96");
    ClientToScreen(p, &org);
    CHECK(org.x == 104 && org.y == 123, "parent client origin is (104,123)");
    GetWindowRect(c2, &r);
    CHECK(r.left == 204 && r.top == 183 && r.right == 354 && r.bottom == 283, "child window rectangle in screen coordinates");
    CHECK(GetTopWindow(p) == c3 && GetWindow(c3, GW_HWNDNEXT) == c2 && GetWindow(c2, GW_HWNDNEXT) == c1, "children are stacked C3 over C2 over C1 (creation order)");
    {
        POINT pt = { 210, 190 };
        CHECK(WindowFromPoint(pt) == c2, "WindowFromPoint in the C1/C2 overlap finds the upper child C2");
        pt.x = 130; pt.y = 150;
        CHECK(WindowFromPoint(pt) == c1, "and finds C1 where C2 does not reach");
        pt.x = 480; pt.y = 380;
        CHECK(WindowFromPoint(pt) == c3, "C3 is hit inside the parent's client area");
        pt.x = 500; pt.y = 400;
        CHECK(WindowFromPoint(pt) != c3, "but not in the part clipped away outside it");
    }
    GetClientRect(p, &pcr);
    CHECK(pcr.right == 392 && pcr.bottom == 273, "parent client 392x273");
    CHECK(g_child_paints == 3, "each child painted once");
    printf("GUI-READY: c1\n");
    pump_ms(1200);

    CHECK(BringWindowToTop(c1) && GetTopWindow(p) == c1 && GetWindow(c1, GW_HWNDNEXT) == c3, "BringWindowToTop(C1) raises a child within its parent");
    {
        POINT pt = { 210, 190 };
        CHECK(WindowFromPoint(pt) == c1, "the overlap now belongs to C1");
    }
    printf("GUI-READY: c2\n");
    pump_ms(1200);

    CHECK(MoveWindow(c3, 300, 150, 100, 100, TRUE), "MoveWindow(C3)");
    ShowWindow(c2, SW_HIDE);
    UpdateWindow(c3);
    CHECK(!IsWindowVisible(c2) && IsWindowVisible(c1) && IsWindowVisible(c3), "C2 hidden, the others visible");
    printf("GUI-READY: c3\n");
    pump_ms(1200);

    g_child_paints = 0;
    SetWindowPos(c1, 0, 0, 0, 200, 140, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    GetClientRect(c1, &r);
    CHECK(r.right == 198 && r.bottom == 138, "C1 resized: client 198x138");
    UpdateWindow(c1);
    CHECK(g_child_paints == 1, "the resize repainted the child once");
    printf("GUI-READY: c4\n");
    pump_ms(1200);

    CHECK(DestroyWindow(p) && !IsWindow(c1) && !IsWindow(c2) && !IsWindow(c3), "destroying the parent destroys all children");
    printf("%s: child window test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
