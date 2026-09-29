/* SPDX-License-Identifier: GPL-2.0-only
 * Waitable timers (relative, absolute, periodic, manual and auto reset, completion routines, cancel, named), registered
 * waits (signal, timeout, WT_EXECUTEONLYONCE, WT_EXECUTEINWAITTHREAD, auto-reset consumption, UnregisterWaitEx that waits
 * for a running callback), QueueUserWorkItem, and ReadDirectoryChangesW (added / modified / renamed / removed records,
 * subtrees, overlapped and completion-routine forms, overflow, the end of a watch when its handle closes).
 */
#include "ipc_test.h"

/* ---------------------------------------------------------------- timers */
static volatile LONG g_apc_calls;
static DWORD g_apc_low, g_apc_high;
static VOID CALLBACK timer_apc(LPVOID arg, DWORD low, DWORD high)
{
    InterlockedExchangeAdd(&g_apc_calls, (LONG)(ULONG_PTR)arg);
    g_apc_low = low;
    g_apc_high = high;
}

static void test_timers(void)
{
    HANDLE t = CreateWaitableTimerW(0, TRUE, 0), a, n1, n2;
    LARGE_INTEGER due;
    DWORD t0, el;
    FILETIME now;
    ULARGE_INTEGER u;
    CHECK(t != 0, "CreateWaitableTimer (manual reset)");
    CHECK(WaitForSingleObject(t, 0) == WAIT_TIMEOUT, "a new timer is not signaled");
    due.QuadPart = -100 * 10000ll;                              /* 100 ms */
    t0 = GetTickCount();
    CHECK(SetWaitableTimer(t, &due, 0, 0, 0, FALSE), "SetWaitableTimer(-100 ms)");
    CHECK(WaitForSingleObject(t, 5000) == WAIT_OBJECT_0, "the timer fires");
    el = GetTickCount() - t0;
    CHECK(el >= 95 && el < 3000, "after about 100 ms (%u ms)", (unsigned)el);
    CHECK(WaitForSingleObject(t, 0) == WAIT_OBJECT_0 && WaitForSingleObject(t, 0) == WAIT_OBJECT_0, "a manual-reset timer stays signaled");
    due.QuadPart = -10000000ll;
    SetWaitableTimer(t, &due, 0, 0, 0, FALSE);
    CHECK(WaitForSingleObject(t, 0) == WAIT_TIMEOUT, "setting it again resets it");
    CHECK(CancelWaitableTimer(t) && WaitForSingleObject(t, 1200) == WAIT_TIMEOUT, "a cancelled timer never fires");
    /* absolute due time */
    GetSystemTimeAsFileTime(&now);
    u.LowPart = now.dwLowDateTime; u.HighPart = now.dwHighDateTime;
    due.QuadPart = (LONGLONG)u.QuadPart + 150 * 10000ll;
    t0 = GetTickCount();
    CHECK(SetWaitableTimer(t, &due, 0, 0, 0, FALSE) && WaitForSingleObject(t, 5000) == WAIT_OBJECT_0, "an absolute due time 150 ms ahead");
    el = GetTickCount() - t0;
    CHECK(el >= 100 && el < 3000, "fires at that time (%u ms)", (unsigned)el);
    CloseHandle(t);
    /* periodic, auto reset */
    a = CreateWaitableTimerExW(0, 0, 0, TIMER_ALL_ACCESS);
    due.QuadPart = -20 * 10000ll;
    CHECK(a && SetWaitableTimer(a, &due, 30, 0, 0, FALSE), "a periodic (30 ms) synchronization timer");
    {
        int i, ok = 1;
        t0 = GetTickCount();
        for (i = 0; i < 5; ++i) if (WaitForSingleObject(a, 2000) != WAIT_OBJECT_0) ok = 0;
        el = GetTickCount() - t0;
        CHECK(ok && el >= 100 && el < 5000, "fires five times, each wait consuming one signal (%u ms)", (unsigned)el);
    }
    CancelWaitableTimer(a);
    /* completion routine */
    g_apc_calls = 0;
    due.QuadPart = -30 * 10000ll;
    CHECK(SetWaitableTimer(a, &due, 0, timer_apc, (LPVOID)5, FALSE), "a timer with a completion routine");
    Sleep(100);
    CHECK(g_apc_calls == 0, "the routine does not run outside an alertable wait");
    CHECK(SleepEx(1000, TRUE) == WAIT_IO_COMPLETION && g_apc_calls == 5, "it runs in the next alertable wait");
    GetSystemTimeAsFileTime(&now);
    {
        ULARGE_INTEGER fired, cur;
        fired.LowPart = g_apc_low; fired.HighPart = g_apc_high;
        cur.LowPart = now.dwLowDateTime; cur.HighPart = now.dwHighDateTime;
        CHECK(fired.QuadPart <= cur.QuadPart && cur.QuadPart - fired.QuadPart < 50000000ull, "with the FILETIME it fired at");
    }
    CloseHandle(a);
    /* names */
    n1 = CreateWaitableTimerW(0, FALSE, L"Local\\ipcmisc_timer");
    n2 = OpenWaitableTimerW(TIMER_ALL_ACCESS, FALSE, L"ipcmisc_timer");
    due.QuadPart = -10 * 10000ll;
    CHECK(n1 && n2 && SetWaitableTimer(n2, &due, 0, 0, 0, FALSE) && WaitForSingleObject(n1, 2000) == WAIT_OBJECT_0,
          "a named timer set through one handle signals the other");
    CHECK(!CreateWaitableTimerW(0, FALSE, L"ipcmisc_timer") || GetLastError() == ERROR_ALREADY_EXISTS, "re-creating it opens it");
    CloseHandle(n1); CloseHandle(n2);
}

/* ---------------------------------------------------------------- registered waits, work items */
static volatile LONG g_cb_signal, g_cb_timeout, g_cb_thread_ok, g_cb_running;
static DWORD g_main_tid;
static HANDLE g_cb_release;
static VOID CALLBACK wait_cb(PVOID ctx, BOOLEAN timed_out)
{
    if (timed_out) InterlockedIncrement(&g_cb_timeout); else InterlockedIncrement(&g_cb_signal);
    if (GetCurrentThreadId() != g_main_tid) g_cb_thread_ok = 1;
    (void)ctx;
}
static VOID CALLBACK slow_cb(PVOID ctx, BOOLEAN timed_out)
{
    (void)ctx; (void)timed_out;
    g_cb_running = 1;
    WaitForSingleObject(g_cb_release, 5000);
    Sleep(50);
    g_cb_running = 0;
}
static volatile LONG g_work;
static DWORD WINAPI work_fn(LPVOID v) { InterlockedExchangeAdd(&g_work, (LONG)(ULONG_PTR)v); return 0; }

static void test_waits(void)
{
    HANDLE ev = CreateEventW(0, FALSE, FALSE, 0), w;
    int i;
    g_main_tid = GetCurrentThreadId();
    CHECK(RegisterWaitForSingleObject(&w, ev, wait_cb, 0, INFINITE, WT_EXECUTEDEFAULT), "RegisterWaitForSingleObject");
    for (i = 0; i < 3; ++i) { SetEvent(ev); Sleep(60); }
    CHECK(g_cb_signal == 3 && g_cb_thread_ok, "three signals, three callbacks on a pool thread (%d)", (int)g_cb_signal);
    CHECK(WaitForSingleObject(ev, 0) == WAIT_TIMEOUT, "the wait consumed the auto-reset event's signals");
    CHECK(UnregisterWaitEx(w, INVALID_HANDLE_VALUE), "UnregisterWaitEx(INVALID_HANDLE_VALUE)");
    SetEvent(ev);
    Sleep(60);
    CHECK(g_cb_signal == 3, "no callback after unregistering");
    ResetEvent(ev);
    /* timeouts and WT_EXECUTEONLYONCE */
    g_cb_timeout = 0;
    CHECK(RegisterWaitForSingleObject(&w, ev, wait_cb, 0, 40, WT_EXECUTEINWAITTHREAD), "a 40 ms timeout, run in the wait thread");
    Sleep(230);
    CHECK(g_cb_timeout >= 3 && g_cb_timeout <= 7, "the timeout repeats (%d callbacks in 230 ms)", (int)g_cb_timeout);
    UnregisterWaitEx(w, INVALID_HANDLE_VALUE);
    g_cb_signal = 0;
    CHECK(RegisterWaitForSingleObject(&w, ev, wait_cb, 0, INFINITE, WT_EXECUTEONLYONCE), "WT_EXECUTEONLYONCE");
    SetEvent(ev); Sleep(60); SetEvent(ev); Sleep(60);
    CHECK(g_cb_signal == 1 && WaitForSingleObject(ev, 0) == WAIT_OBJECT_0, "fires once; the second signal stays unconsumed");
    CHECK(UnregisterWait(w), "UnregisterWait of the spent wait");
    /* unregistering while a callback runs */
    g_cb_release = CreateEventW(0, TRUE, FALSE, 0);
    CHECK(RegisterWaitForSingleObject(&w, ev, slow_cb, 0, INFINITE, WT_EXECUTEONLYONCE), "a wait with a slow callback");
    SetEvent(ev);
    for (i = 0; i < 100 && !g_cb_running; ++i) Sleep(5);
    CHECK(!UnregisterWait(w) && GetLastError() == ERROR_IO_PENDING, "UnregisterWait while it runs: ERROR_IO_PENDING");
    SetEvent(g_cb_release);
    Sleep(150);
    CHECK(!g_cb_running, "the callback finished on its own");
    ResetEvent(g_cb_release);
    CHECK(RegisterWaitForSingleObject(&w, ev, slow_cb, 0, INFINITE, WT_EXECUTEONLYONCE), "again");
    SetEvent(ev);
    for (i = 0; i < 100 && !g_cb_running; ++i) Sleep(5);
    SetEvent(g_cb_release);
    CHECK(UnregisterWaitEx(w, INVALID_HANDLE_VALUE) && !g_cb_running, "UnregisterWaitEx(INVALID_HANDLE_VALUE) returns after the callback");
    CloseHandle(g_cb_release);
    CloseHandle(ev);
    /* work items */
    for (i = 1; i <= 10; ++i) QueueUserWorkItem(work_fn, (LPVOID)(ULONG_PTR)i, WT_EXECUTEDEFAULT);
    for (i = 0; i < 200 && g_work != 55; ++i) Sleep(5);
    CHECK(g_work == 55, "ten QueueUserWorkItem items ran (sum %d)", (int)g_work);
}

/* ---------------------------------------------------------------- directory changes */
typedef struct { DWORD next, action, len; WCHAR name[1]; } fni_t;

static int has_record(const BYTE *buf, DWORD n, DWORD action, const char *name)
{
    DWORD off = 0;
    while (n && off < n) {
        const fni_t *r = (const fni_t *)(buf + off);
        DWORD i, l = (DWORD)strlen(name);
        int eq = r->len == l * 2;
        for (i = 0; eq && i < l; ++i) if ((r->name[i] | 32) != ((WCHAR)(unsigned char)name[i] | 32)) eq = 0;
        if (eq && r->action == action) return 1;
        if (!r->next) break;
        off += r->next;
    }
    return 0;
}

static void touch(const WCHAR *path, const char *data)
{
    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    DWORD n;
    if (data) WriteFile(f, data, (DWORD)strlen(data), &n, 0);
    CloseHandle(f);
}

static DWORD WINAPI late_touch(LPVOID a) { (void)a; Sleep(100); touch(L"C:\\TEMP\\ipcw\\c.txt", 0); return 0; }

static volatile LONG g_dir_routine;
static DWORD g_dir_bytes;
static VOID CALLBACK dir_done(DWORD err, DWORD bytes, LPOVERLAPPED ov) { (void)ov; if (!err) g_dir_bytes = bytes; ++g_dir_routine; }

static void test_dirs(void)
{
    static BYTE buf[4096];
    HANDLE d, ev;
    DWORD n;
    OVERLAPPED ov;
    CreateDirectoryW(L"C:\\TEMP", 0);
    CreateDirectoryW(L"C:\\TEMP\\ipcw", 0);
    CreateDirectoryW(L"C:\\TEMP\\ipcw\\sub", 0);
    DeleteFileW(L"C:\\TEMP\\ipcw\\a.txt");
    d = CreateFileW(L"C:\\TEMP\\ipcw", FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, 0);
    CHECK(d != INVALID_HANDLE_VALUE, "a directory handle for notifications");
    ev = CreateEventW(0, TRUE, FALSE, 0);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = ev;
    CHECK(ReadDirectoryChangesW(d, buf, sizeof buf, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                FILE_NOTIFY_CHANGE_LAST_WRITE, 0, &ov, 0), "an overlapped ReadDirectoryChangesW (subtree)");
    CHECK(WaitForSingleObject(ev, 50) == WAIT_TIMEOUT, "nothing changed yet");
    touch(L"C:\\TEMP\\ipcw\\a.txt", 0);
    CHECK(WaitForSingleObject(ev, 2000) == WAIT_OBJECT_0 && GetOverlappedResult(d, &ov, &n, FALSE) &&
          has_record(buf, n, FILE_ACTION_ADDED, "a.txt"), "creating a.txt reports FILE_ACTION_ADDED a.txt");
    /* changes made between requests are kept */
    touch(L"C:\\TEMP\\ipcw\\sub\\deep.txt", "x");
    MoveFileW(L"C:\\TEMP\\ipcw\\a.txt", L"C:\\TEMP\\ipcw\\b.txt");
    ResetEvent(ev);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = ev;
    ReadDirectoryChangesW(d, buf, sizeof buf, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                          FILE_NOTIFY_CHANGE_LAST_WRITE, 0, &ov, 0);
    CHECK(WaitForSingleObject(ev, 2000) == WAIT_OBJECT_0 && GetOverlappedResult(d, &ov, &n, FALSE), "the buffered changes complete the next request at once");
    CHECK(has_record(buf, n, FILE_ACTION_ADDED, "sub\\deep.txt") && has_record(buf, n, FILE_ACTION_MODIFIED, "sub\\deep.txt"),
          "a subtree change is named relative to the watched directory");
    CHECK(has_record(buf, n, FILE_ACTION_RENAMED_OLD_NAME, "a.txt") && has_record(buf, n, FILE_ACTION_RENAMED_NEW_NAME, "b.txt"),
          "MoveFile reports RENAMED_OLD_NAME a.txt and RENAMED_NEW_NAME b.txt");
    /* completion routine */
    g_dir_routine = 0;
    memset(&ov, 0, sizeof ov);
    CHECK(ReadDirectoryChangesW(d, buf, sizeof buf, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, 0, &ov, dir_done), "a request with a completion routine");
    DeleteFileW(L"C:\\TEMP\\ipcw\\b.txt");
    CHECK(SleepEx(2000, TRUE) == WAIT_IO_COMPLETION && g_dir_routine == 1 && has_record(buf, g_dir_bytes, FILE_ACTION_REMOVED, "b.txt"),
          "deleting b.txt runs the routine with FILE_ACTION_REMOVED");
    /* overflow: more changes than the buffer holds */
    {
        int i;
        WCHAR p[64];
        for (i = 0; i < 400; ++i) {
            char a[64];
            snprintf(a, sizeof a, "C:\\TEMP\\ipcw\\sub\\f%03d.txt", i);
            wcopy(p, a);
            touch(p, 0);
            DeleteFileW(p);
        }
        ResetEvent(ev);
        memset(&ov, 0, sizeof ov);
        ov.hEvent = ev;
        ReadDirectoryChangesW(d, buf, sizeof buf, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, 0, &ov, 0);
        CHECK(WaitForSingleObject(ev, 2000) == WAIT_OBJECT_0 && GetOverlappedResult(d, &ov, &n, FALSE) && n == 0,
              "an overflowed buffer completes with 0 bytes (rescan)");
    }
    /* closing the handle ends a pending request */
    ResetEvent(ev);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = ev;
    ReadDirectoryChangesW(d, buf, sizeof buf, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, 0, &ov, 0);
    CloseHandle(d);
    CHECK(WaitForSingleObject(ev, 2000) == WAIT_OBJECT_0 && ov.Internal == 0x10B, "closing the directory completes it (STATUS_NOTIFY_CLEANUP)");
    CloseHandle(ev);
    /* synchronous form: the call waits for the change another thread makes */
    {
        HANDLE sd = CreateFileW(L"C:\\TEMP\\ipcw", FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS, 0);
        HANDLE t = CreateThread(0, 0, late_touch, 0, 0, 0);
        n = 0;
        CHECK(sd != INVALID_HANDLE_VALUE && ReadDirectoryChangesW(sd, buf, sizeof buf, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &n, 0, 0) &&
              has_record(buf, n, FILE_ACTION_ADDED, "c.txt"), "a synchronous ReadDirectoryChangesW waits for c.txt");
        WaitForSingleObject(t, 2000);
        CloseHandle(t);
        CloseHandle(sd);
        DeleteFileW(L"C:\\TEMP\\ipcw\\c.txt");
    }
    DeleteFileW(L"C:\\TEMP\\ipcw\\sub\\deep.txt");
    RemoveDirectoryW(L"C:\\TEMP\\ipcw\\sub");
    RemoveDirectoryW(L"C:\\TEMP\\ipcw");
}

int main(void)
{
    kstats_t k0, k1;
    kstats(&k0);
    test_timers();
    test_waits();
    test_dirs();
    Sleep(50);
    kstats(&k1);
    CHECK(k1.irps == k0.irps, "no IRP leaked (%llu -> %llu)", k0.irps, k1.irps);
    printf("%s: %d check(s) failed\n", g_bad ? "FAIL" : "PASS", g_bad);
    return g_bad;
}
