/* Executes the exact platform helpers injected into pinned WTF RunLoopWin.
 * Native Win98 evidence only: this executable rejects other OS versions.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 */
#include "RunLoopWin9x.h"
#include <stdio.h>

#define WORK_MESSAGE (WM_USER + 1)
#define THREAD_MESSAGE (WM_USER + 4)
static FILE* log_file;
struct LoopState { unsigned work, threaded, timer, destroyed; };

static void record(const char* key, unsigned long value)
{
    fprintf(log_file, "%s=%lu\r\n", key, value);
    fflush(log_file);
}

static LRESULT CALLBACK loop_window(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    struct LoopState* state = (struct LoopState*)iewkRunLoopGetContextA(window);
    if (message == WM_CREATE) {
        state = (struct LoopState*)((CREATESTRUCTA*)lparam)->lpCreateParams;
        iewkRunLoopSetContextA(window, state);
        return 0;
    }
    if (state) {
        if (message == WORK_MESSAGE) { ++state->work; return 0; }
        if (message == THREAD_MESSAGE) { ++state->threaded; return 0; }
        if (message == WM_TIMER) { ++state->timer; KillTimer(window, wparam); return 0; }
        if (message == WM_NCDESTROY) {
            ++state->destroyed;
            iewkRunLoopSetContextA(window, NULL);
        }
    }
    return DefWindowProcA(window, message, wparam, lparam);
}

static DWORD WINAPI post_worker(LPVOID argument)
{
    HWND window = (HWND)argument;
    for (unsigned i = 0; i < 96; ++i)
        if (!PostMessageA(window, THREAD_MESSAGE, i, 0)) return 1;
    return 0;
}

static int run(void)
{
    OSVERSIONINFOA version = { 0 };
    version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version)) return 2;
    record("os.major", version.dwMajorVersion);
    record("os.minor", version.dwMinorVersion);
    record("os.platform", version.dwPlatformId);
    record("os.build", version.dwBuildNumber & 0xffff);
    if (version.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS ||
        version.dwMajorVersion != 4 || version.dwMinorVersion != 10) return 3;

    ATOM klass = iewkRunLoopRegisterClassA(loop_window);
    record("register.atom", klass);
    if (!klass) { record("register.error", GetLastError()); return 4; }
    struct LoopState baseline = { 0 };
    SetLastError(0);
    HWND original = CreateWindowExA(0, IEWK_RUNLOOP_CLASS_A, NULL, 0,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, (HWND)(intptr_t)-3,
        NULL, GetModuleHandleA(NULL), &baseline);
    record("upstream.HWND_MESSAGE.created", original != NULL);
    record("upstream.HWND_MESSAGE.error", GetLastError());
    if (original) DestroyWindow(original);

    struct LoopState state = { 0 };
    HWND window = iewkRunLoopCreateWindowA(&state);
    if (!window) { record("create.error", GetLastError()); return 5; }
    record("port.created", IsWindow(window));
    record("port.visible", IsWindowVisible(window));
    record("port.context", iewkRunLoopGetContextA(window) == &state);
    if (!IsWindow(window) || IsWindowVisible(window) ||
        iewkRunLoopGetContextA(window) != &state) return 6;
    if (!PostMessageA(window, WORK_MESSAGE, 0, 0) ||
        !SetTimer(window, 1, 55, NULL)) return 7;
    DWORD thread_id = 0;
    HANDLE worker = CreateThread(NULL, 0, post_worker, window, 0, &thread_id);
    record("worker.id", thread_id);
    if (!worker) { record("worker.error", GetLastError()); return 8; }
    DWORD deadline = GetTickCount();
    while (state.work != 1 || state.threaded != 96 || !state.timer) {
        MSG message;
        while (PeekMessageA(&message, NULL, 0, 0, PM_REMOVE)) {
            if (message.message == WM_QUIT) return 9;
            TranslateMessage(&message);
            DispatchMessageA(&message);
        }
        if (GetTickCount() - deadline >= 5000) return 10;
        DWORD wait = iewkRunLoopWait(100);
        if (wait == WAIT_FAILED) { record("wait.error", GetLastError()); return 11; }
    }
    if (WaitForSingleObject(worker, 1000) != WAIT_OBJECT_0) return 12;
    DWORD worker_exit = 99;
    if (!GetExitCodeThread(worker, &worker_exit)) return 13;
    CloseHandle(worker);
    record("worker.exit", worker_exit);
    record("work.delivered", state.work);
    record("thread.delivered", state.threaded);
    record("timer.delivered", state.timer);
    if (worker_exit) return 14;
    if (!DestroyWindow(window) || state.destroyed != 1 || IsWindow(window)) return 15;
    record("destroy.delivered", state.destroyed);
    if (!UnregisterClassA(IEWK_RUNLOOP_CLASS_A, GetModuleHandleA(NULL))) return 16;
    PostQuitMessage(37);
    MSG quit;
    if (!PeekMessageA(&quit, NULL, 0, 0, PM_REMOVE) ||
        quit.message != WM_QUIT || quit.wParam != 37) return 17;
    record("quit.code", quit.wParam);
    return 0;
}

int main(int argc, char** argv)
{
    log_file = fopen(argc > 1 ? argv[1] : "C:\\GOPLAB\\RL9X.LOG", "wb");
    if (!log_file) return 1;
    record("fixture.schema", 1);
    record("fixture.full_engine", 0);
    int result = run();
    record("exit", result);
    fclose(log_file);
    return result;
}
