/* Native diagnostic of the actual RunLoop object's ANSI/Unicode dependencies.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 * This is not a WebKit renderer or an engine ABI provider.
 */
#include <windows.h>
#include <stdio.h>
#include "src/RunLoopWin9x.h"

static unsigned original_context;
static unsigned ported_context;
static unsigned original_create;
static unsigned ported_create;

static LRESULT CALLBACK original_proc(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_CREATE) {
        const CREATESTRUCTW* creation = (const CREATESTRUCTW*)l;
        SetWindowLongW(window, 0, (LONG)creation->lpCreateParams);
        original_create++;
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

static LRESULT CALLBACK ported_proc(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_CREATE) {
        const CREATESTRUCTA* creation = (const CREATESTRUCTA*)l;
        iewkRunLoopSetContextA(window, creation->lpCreateParams);
        ported_create++;
        return 0;
    }
    return DefWindowProcA(window, message, w, l);
}

int main(int argc, char** argv)
{
    const char* path = argc > 1 ? argv[1] : "C:\\GOPLAB\\RLCMP.LOG";
    FILE* log = fopen(path, "wb");
    DWORD version = GetVersion();
    WNDCLASSW klass = { 0 };
    ATOM original_class, ported_class;
    DWORD original_register_error, original_window_error, original_context_error;
    HWND original_window = NULL, ported_window;
    int result;
    if (!log)
        return 2;
    fprintf(log, "scope=Actual-WTF-RunLoop-Windows-API-comparison\r\n");
    fprintf(log, "os.major=%lu\r\nos.minor=%lu\r\nos.win9x=%u\r\n",
            version & 255, (version >> 8) & 255, (unsigned)(version >> 31));
    if (!(version & 0x80000000UL) || (version & 255) != 4 || ((version >> 8) & 255) != 10) {
        fprintf(log, "exit=3\r\n");
        fclose(log);
        return 3;
    }
    klass.lpfnWndProc = original_proc;
    klass.cbWndExtra = sizeof(void*);
    klass.lpszClassName = L"RunLoopOriginalUnicodeDiagnostic";
    SetLastError(0);
    original_class = RegisterClassW(&klass);
    original_register_error = GetLastError();
    fprintf(log, "original.RegisterClassW.atom=%u\r\noriginal.RegisterClassW.error=%lu\r\n",
            (unsigned)original_class, original_register_error);
    if (original_class) {
        SetLastError(0);
        original_window = CreateWindowExW(0, klass.lpszClassName, NULL, 0,
            CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, HWND_MESSAGE, NULL, NULL, &original_context);
        original_window_error = GetLastError();
        SetLastError(0);
        result = original_window && (void*)GetWindowLongW(original_window, 0) == &original_context;
        original_context_error = GetLastError();
        fprintf(log, "original.CreateWindowExW.created=%u\r\noriginal.CreateWindowExW.error=%lu\r\n"
                     "original.GetWindowLongW.context=%u\r\noriginal.GetWindowLongW.error=%lu\r\n"
                     "original.WM_CREATE=%u\r\n", original_window != NULL, original_window_error,
                (unsigned)result, original_context_error, original_create);
    } else {
        fprintf(log, "original.CreateWindowExW.skipped=class-registration-failed\r\n");
    }
    SetLastError(0);
    ported_class = iewkRunLoopRegisterClassA(ported_proc);
    fprintf(log, "ported.RegisterClassA.atom=%u\r\nported.RegisterClassA.error=%lu\r\n",
            (unsigned)ported_class, GetLastError());
    SetLastError(0);
    ported_window = ported_class ? iewkRunLoopCreateWindowA(&ported_context) : NULL;
    fprintf(log, "ported.CreateWindowExA.created=%u\r\nported.CreateWindowExA.error=%lu\r\n",
            ported_window != NULL, GetLastError());
    result = ported_window && iewkRunLoopGetContextA(ported_window) == &ported_context;
    fprintf(log, "ported.GetWindowLongA.context=%u\r\nported.WM_CREATE=%u\r\n",
            (unsigned)result, ported_create);
    result = result && ported_create == 1;
    if (original_window)
        DestroyWindow(original_window);
    if (ported_window)
        result = DestroyWindow(ported_window) && result;
    fprintf(log, "exit=%d\r\n", result ? 0 : 4);
    fclose(log);
    return result ? 0 : 4;
}
