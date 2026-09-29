/* SPDX-License-Identifier: GPL-2.0-only
 * GUI across processes: a child process opens a window and later exits WITHOUT destroying it. The parent (no windows of its
 * own) sees the child's window through FindWindow/GetWindowText, learns that SendMessage across processes is refused while
 * PostMessage works, and the host runner verifies two screens: "orphan1" with the child's window composited, "orphan2" with the
 * bare desktop after the kernel reaped the dead process's window. Also shows a process exiting while another of its threads
 * is blocked inside GetMessage. Reports SKIP and exits 0 when there is no display. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_APP + 9) ExitProcess(0);                   /* leave with the window still on screen */
    if (m == WM_TIMER) ExitProcess(3);                     /* the parent vanished: do not linger */
    return DefWindowProcW(h, m, w, l);
}

static DWORD WINAPI blocked_reader(LPVOID arg)
{
    MSG msg;
    (void)arg;
    GetMessageW(&msg, 0, 0, 0);                            /* never returns: the process is ended around it */
    return 0;
}

static int child_main(void)
{
    WNDCLASSW wc;
    HWND h;
    MSG msg;
    HINSTANCE inst = GetModuleHandleW(0);
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = inst;
    wc.hbrBackground = CreateSolidBrush(RGB(0, 128, 0));
    wc.lpszClassName = L"ShzOrphan";
    if (!RegisterClassW(&wc)) return 10;
    h = CreateWindowExW(0, L"ShzOrphan", L"Orphan", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 560, 380, 240, 160, 0, 0, inst, 0);
    if (!h) return 11;
    SetTimer(h, 1, 15000, 0);
    CreateThread(0, 0, blocked_reader, 0, 0, 0);           /* a second thread parked inside GetMessage while the process exits */
    while (GetMessageW(&msg, 0, 0, 0) > 0) DispatchMessageW(&msg);
    return 12;
}

int main(int argc, char **argv)
{
    WCHAR path[300], cmd[340];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HWND orphan = 0;
    DWORD t0, pid = 0, code = 99, el;
    WCHAR title[32];
    int i, n;
    if (argc >= 2 && !strcmp(argv[1], "child")) return child_main();
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    n = (int)GetModuleFileNameW(0, path, 300);
    CHECK(n > 0, "GetModuleFileNameW");
    cmd[0] = '"';
    for (i = 0; i < n; ++i) cmd[1 + i] = path[i];
    cmd[1 + n] = '"';
    { static const WCHAR tail[] = { ' ', 'c', 'h', 'i', 'l', 'd', 0 }; for (i = 0; i < 7; ++i) cmd[2 + n + i] = tail[i]; }
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    CHECK(CreateProcessW(path, cmd, 0, 0, FALSE, 0, 0, 0, &si, &pi), "CreateProcessW starts the child");
    t0 = GetTickCount();
    while (GetTickCount() - t0 < 8000 && !(orphan = FindWindowW(L"ShzOrphan", 0))) Sleep(10);
    CHECK(orphan != 0, "FindWindow finds the window of the other process by its class name");
    if (!orphan) return 1;
    GetWindowThreadProcessId(orphan, &pid);
    CHECK(pid == pi.dwProcessId && pid != GetCurrentProcessId(), "GetWindowThreadProcessId reports the child's process id");
    CHECK(GetWindowTextW(orphan, title, 32) == 6 && title[0] == 'O' && title[5] == 'n', "GetWindowText reads the title of another process's window");
    SetLastError(0);
    CHECK(SendMessageW(orphan, WM_APP + 5, 0, 0) == 0 && GetLastError() == ERROR_NOT_SUPPORTED, "SendMessage across processes is refused (ERROR_NOT_SUPPORTED)");
    CHECK(PostMessageW(orphan, WM_APP + 5, 0, 0), "PostMessage across processes works");
    Sleep(200);                                            /* let it settle and be painted */
    printf("GUI-READY: orphan1\n");
    Sleep(1200);
    PostMessageW(orphan, WM_APP + 9, 0, 0);                /* the child calls ExitProcess without DestroyWindow */
    CHECK(WaitForSingleObject(pi.hProcess, 8000) == WAIT_OBJECT_0, "the child process ended (although one of its threads was blocked in GetMessage)");
    GetExitCodeProcess(pi.hProcess, &code);
    CHECK(code == 0, "the child's exit code is 0");
    t0 = GetTickCount();
    while (GetTickCount() - t0 < 3000 && IsWindow(orphan)) Sleep(5);
    el = GetTickCount() - t0;
    CHECK(!IsWindow(orphan) && el < 500, "the dead process's window was reaped promptly");
    CHECK(FindWindowW(L"ShzOrphan", 0) == 0, "and FindWindow no longer sees it");
    printf("GUI-READY: orphan2\n");
    Sleep(1200);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("%s: process test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
