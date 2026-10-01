/* SPDX-License-Identifier: GPL-2.0-only
 * Guest probe for the Shizuku port's event loop (WTF RunLoopWin): what WTF's Windows RunLoop needs from user32 --
 * RegisterClass + CreateWindow with the HWND_MESSAGE parent, PostMessage from another thread, SetTimer/WM_TIMER on
 * that window, and the PeekMessage/MsgWaitForMultipleObjectsEx pump. Prints one PASS/FAIL line per item. */
#include <windows.h>
#include <stdio.h>

static int failures, posted, timers, cross_thread;
static HWND win;
#define CHECK(c) do { if (c) printf("PASS %s\n", #c); else { printf("FAIL %s (error %lu)\n", #c, GetLastError()); ++failures; } fflush(stdout); } while (0)

static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_USER + 1) { posted += (int)w; return 0; }
    if (m == WM_USER + 2) { cross_thread = 1; return 0; }
    if (m == WM_TIMER && w == 7) { if (++timers == 3) KillTimer(h, 7); return 0; }
    return DefWindowProcW(h, m, w, l);
}

static DWORD WINAPI poster(void *p)
{
    (void)p;
    Sleep(50);
    PostMessageW(win, WM_USER + 2, 0, 0);
    return 0;
}

int main(void)
{
    WNDCLASSW wc;
    MSG msg;
    DWORD t0;
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"ShzRunLoopProbe";
    CHECK(RegisterClassW(&wc) != 0);
    win = CreateWindowW(L"ShzRunLoopProbe", NULL, 0, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, HWND_MESSAGE, NULL,
                        wc.hInstance, NULL);
    CHECK(win != NULL);
    if (!win) return failures;
    PostMessageW(win, WM_USER + 1, 5, 0);
    PostMessageW(win, WM_USER + 1, 6, 0);
    CHECK(SetTimer(win, 7, 20, NULL) != 0);
    CloseHandle(CreateThread(NULL, 0, poster, NULL, 0, NULL));
    t0 = GetTickCount();
    while (GetTickCount() - t0 < 3000 && (posted != 11 || timers < 3 || !cross_thread)) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
        MsgWaitForMultipleObjectsEx(0, NULL, 50, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
    }
    printf("posted=%d timers=%d cross_thread=%d after %lu ms\n", posted, timers, cross_thread, GetTickCount() - t0);
    CHECK(posted == 11);
    CHECK(timers == 3);
    CHECK(cross_thread == 1);
    CHECK(DestroyWindow(win));
    printf("t_wk_msgloop: %d failure(s)\n", failures);
    return failures;
}
