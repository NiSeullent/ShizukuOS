/* SPDX-License-Identifier: GPL-2.0-only
 * GUI resource hygiene: window/class/queue/pending-send counts and the kernel pages held by window surfaces (NtUserThreadOp
 * STATS) must return to their baseline after create/destroy loops, resizes, a thread that exits without destroying its
 * windows, window-table exhaustion and message-pool exhaustion; a SendMessage to a thread that dies must not hang, and the
 * limits (timers, posted-message quota) must fail cleanly. Reports SKIP and exits 0 without a display. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"
#include "shzgfx.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

typedef struct { unsigned windows, classes, queues, sends; unsigned long long arena_pages, free_pages; } stats_t;

static void get_stats(stats_t *s)
{
    shz_threadop_t t;
    memset(&t, 0, sizeof t);
    t.op = SHZ_TOP_STATS;
    NtUserThreadOp(&t);
    s->windows = (unsigned)(t.out0 & 0xffff);
    s->classes = (unsigned)((t.out0 >> 16) & 0xffff);
    s->queues = (unsigned)((t.out0 >> 32) & 0xffff);
    s->sends = (unsigned)((t.out0 >> 48) & 0xffff);
    s->arena_pages = t.out1 & 0xffffffffull;
    s->free_pages = t.out1 >> 32;
}

static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l) { return DefWindowProcW(h, m, w, l); }

static HINSTANCE g_inst;
static HANDLE g_ready;
static HWND g_theirs;

static DWORD WINAPI dies_without_destroying(LPVOID a)
{
    int i;
    (void)a;
    for (i = 0; i < 3; ++i)
        CreateWindowExW(0, L"ShzLeak", L"orphan", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 400 + 20 * i, 300 + 20 * i, 200, 120, 0, 0, g_inst, 0);
    return 0;                                             /* thread exit with three visible windows */
}

static DWORD WINAPI dies_while_being_sent_to(LPVOID a)
{
    (void)a;
    g_theirs = CreateWindowExW(0, L"ShzLeak", L"victim", WS_OVERLAPPED, 0, 0, 10, 10, HWND_MESSAGE, 0, g_inst, 0);
    SetEvent(g_ready);
    Sleep(150);                                           /* never pumps, then exits */
    return 0;
}

int main(void)
{
    WNDCLASSW wc;
    stats_t base, now;
    HWND w, hs[256];
    int i, n;
    DWORD tid, t0;
    HANDLE th;
    g_inst = GetModuleHandleW(0);
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = g_inst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ShzLeak";
    RegisterClassW(&wc);
    g_ready = CreateEventW(0, TRUE, FALSE, 0);
    for (i = 0; i < 2; ++i) {                                                         /* warm-up: page tables, heaps */
        w = CreateWindowExW(0, L"ShzLeak", L"warm", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 50, 50, 300, 200, 0, 0, g_inst, 0);
        UpdateWindow(w);
        DestroyWindow(w);
    }
    get_stats(&base);
    CHECK(base.windows == 0 && base.classes >= 1 && base.queues >= 1 && base.sends == 0, "baseline: no windows, our class and queue exist, no pending sends");

    for (i = 0; i < 30; ++i) {
        HDC dc;
        w = CreateWindowExW(0, L"ShzLeak", L"loop", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 60 + i, 60, 300, 200, 0, 0, g_inst, 0);
        UpdateWindow(w);
        dc = GetDC(w);
        PatBlt(dc, 0, 0, 100, 100, BLACKNESS);
        ReleaseDC(w, dc);
        DestroyWindow(w);
    }
    get_stats(&now);
    CHECK(now.windows == base.windows && now.arena_pages == base.arena_pages, "30 create/paint/destroy cycles leave no window and no surface page behind");
    CHECK(now.free_pages + 100 >= base.free_pages, "and no gross loss of physical pages");

    w = CreateWindowExW(0, L"ShzLeak", L"resize", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 60, 60, 100, 100, 0, 0, g_inst, 0);
    for (i = 0; i < 20; ++i) SetWindowPos(w, 0, 0, 0, 100 + 37 * i, 80 + 23 * ((i * 7) % 11), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(w, 0, 0, 0, 5, 5, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);       /* smaller than its frame: client 0x0 */
    { RECT r; GetClientRect(w, &r); CHECK(r.right == 0 && r.bottom == 0, "a window smaller than its frame has an empty client area"); }
    DestroyWindow(w);
    get_stats(&now);
    CHECK(now.windows == base.windows && now.arena_pages == base.arena_pages, "21 resizes then destroy: surface pages back to baseline");

    th = CreateThread(0, 0, dies_without_destroying, 0, 0, &tid);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    Sleep(150);                                                                        /* the reaper thread runs every 20 ms */
    get_stats(&now);
    CHECK(now.windows == base.windows && now.queues == base.queues && now.arena_pages == base.arena_pages,
          "a thread that exited with three windows: windows, queue and surfaces were reclaimed");

    ResetEvent(g_ready);
    th = CreateThread(0, 0, dies_while_being_sent_to, 0, 0, &tid);
    WaitForSingleObject(g_ready, 5000);
    t0 = GetTickCount();
    SetLastError(0);
    n = (int)SendMessageW(g_theirs, WM_APP + 1, 0, 0);
    CHECK(n == 0 && GetTickCount() - t0 < 2000, "SendMessage to a thread that dies without pumping returns 0 instead of hanging");
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    Sleep(100);
    get_stats(&now);
    CHECK(now.sends == 0 && now.windows == base.windows && now.queues == base.queues, "no send record, window or queue is left over");

    n = 0;
    for (i = 0; i < 256; ++i) {
        hs[i] = CreateWindowExW(0, L"ShzLeak", L"many", WS_OVERLAPPED | WS_VISIBLE, 0, 0, 40, 40, 0, 0, g_inst, 0);
        if (!hs[i]) break;
        ++n;
    }
    CHECK(n > 100 && n < 256 && i < 256 && GetLastError() == ERROR_NOT_ENOUGH_MEMORY, "window table exhaustion fails cleanly with ERROR_NOT_ENOUGH_MEMORY");
    for (i = 0; i < n; ++i) DestroyWindow(hs[i]);
    get_stats(&now);
    CHECK(now.windows == base.windows && now.arena_pages == base.arena_pages, "and everything is released again");

    w = CreateWindowExW(0, L"ShzLeak", L"q", WS_OVERLAPPED, 0, 0, 0, 0, HWND_MESSAGE, 0, g_inst, 0);
    for (n = 0; n < 5000; ++n) if (!PostMessageW(w, WM_APP + 2, 0, 0)) break;
    CHECK(n == 1024 && GetLastError() == ERROR_NOT_ENOUGH_QUOTA, "the posted-message quota is 1024 per queue, then ERROR_NOT_ENOUGH_QUOTA");
    {
        MSG msg;
        int drained = 0;
        while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE)) ++drained;
        CHECK(drained == 1024 && PostMessageW(w, WM_APP + 2, 0, 0), "draining the queue makes room again");
        while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE)) { }
    }
    for (n = 0; n < 40; ++n) if (!SetTimer(w, (UINT_PTR)(n + 1), 1000, 0)) break;
    CHECK(n == 16 && GetLastError() == ERROR_NOT_ENOUGH_QUOTA, "at most 16 timers per thread");
    for (i = 1; i <= 16; ++i) KillTimer(w, (UINT_PTR)i);
    {
        HDC dc = GetDC(w);
        (void)dc;
    }
    DestroyWindow(w);
    {                                                                                   /* a DC that outlives its window must be harmless */
        HWND v = CreateWindowExW(0, L"ShzLeak", L"dc", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 200, 150, 0, 0, g_inst, 0);
        HDC dc = GetDC(v);
        DestroyWindow(v);
        PatBlt(dc, 0, 0, 50, 50, BLACKNESS);
        CHECK(ReleaseDC(v, dc) == 1, "drawing on and releasing a DC after its window was destroyed is harmless");
    }
    get_stats(&now);
    CHECK(now.windows == base.windows && now.arena_pages == base.arena_pages, "final state equals the baseline");
    CloseHandle(g_ready);
    printf("%s: resource test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
