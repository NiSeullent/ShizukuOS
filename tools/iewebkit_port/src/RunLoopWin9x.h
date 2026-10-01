/* IEWebKit Win9x backend for the pinned WTF RunLoopWin.cpp.
 * This port contains no document renderer or JavaScript substitute.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 */
#pragma once
#include <windows.h>
#include <stdint.h>

#if !defined(_WIN32) || !defined(__i386__)
#error The Win9x RunLoop backend requires the native Win32 x86 ABI.
#endif

#define IEWK_RUNLOOP_CLASS_A "IEWKWin9xRunLoopMessageWindow"

/* A hidden, unowned popup supplies a real message queue on Win9x. Unlike
 * HWND_MESSAGE it can receive broadcasts; the WTF WndProc only handles its
 * own work/timer messages and delegates other messages to DefWindowProcA.
 * No WS_VISIBLE style and no ShowWindow call are used.
 */
static inline ATOM iewkRunLoopRegisterClassA(WNDPROC callback)
{
    WNDCLASSA klass = { 0 };
    klass.lpfnWndProc = callback;
    klass.cbWndExtra = sizeof(void*);
    klass.hInstance = GetModuleHandleA(NULL);
    klass.lpszClassName = IEWK_RUNLOOP_CLASS_A;
    return RegisterClassA(&klass);
}

static inline HWND iewkRunLoopCreateWindowA(void* context)
{
    return CreateWindowExA(WS_EX_TOOLWINDOW, IEWK_RUNLOOP_CLASS_A, "", WS_POPUP,
        0, 0, 0, 0, NULL, NULL, GetModuleHandleA(NULL), context);
}

static inline void* iewkRunLoopGetContextA(HWND window)
{
    return (void*)(uintptr_t)(uint32_t)GetWindowLongA(window, 0);
}

static inline void iewkRunLoopSetContextA(HWND window, void* context)
{
    SetWindowLongA(window, 0, (LONG)(uintptr_t)context);
}

static inline DWORD iewkRunLoopWait(DWORD timeout)
{
    return MsgWaitForMultipleObjectsEx(0, NULL, timeout, QS_ALLINPUT,
        MWMO_INPUTAVAILABLE);
}
