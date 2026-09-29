/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: waitable timers (CreateWaitableTimer(Ex)W/A, OpenWaitableTimerW/A, SetWaitableTimer(Ex),
 * CancelWaitableTimer) over the Kernel64 timer objects (kernel64/ipc_timer.c). A completion routine runs as an APC of the
 * thread that set the timer, during its next alertable wait, with the FILETIME at which the timer fired. */
#include "k32_ipc.h"

K32API HANDLE WINAPI CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    DWORD e;
    if (flags & ~(DWORD)(CREATE_WAITABLE_TIMER_MANUAL_RESET | 2 /* CREATE_WAITABLE_TIMER_HIGH_RESOLUTION */)) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if ((flags & 2) && name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }   /* high resolution: unnamed only */
    e = k32_ipc_oa(name, sa && sa->bInheritHandle, TRUE, &oa, &us);
    if (e) { shz_set_last_error(e); return 0; }
    st = NtCreateTimer(&h, access ? access : TIMER_ALL_ACCESS, &oa, (flags & CREATE_WAITABLE_TIMER_MANUAL_RESET) ? 0 : 1);
    if (st == STATUS_OBJECT_NAME_EXISTS) { shz_set_last_error(ERROR_ALREADY_EXISTS); return h; }
    if (st) { k32_nt_error(st); return 0; }
    shz_set_last_error(0);
    return h;
}

K32API HANDLE WINAPI CreateWaitableTimerW(LPSECURITY_ATTRIBUTES sa, BOOL manual, LPCWSTR name)
{
    return CreateWaitableTimerExW(sa, name, manual ? CREATE_WAITABLE_TIMER_MANUAL_RESET : 0, TIMER_ALL_ACCESS);
}

K32API HANDLE WINAPI CreateWaitableTimerA(LPSECURITY_ATTRIBUTES sa, BOOL manual, LPCSTR name)
{
    WCHAR w[128];
    if (name && k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return CreateWaitableTimerW(sa, manual, name ? w : 0);
}

K32API HANDLE WINAPI CreateWaitableTimerExA(LPSECURITY_ATTRIBUTES sa, LPCSTR name, DWORD flags, DWORD access)
{
    WCHAR w[128];
    if (name && k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return CreateWaitableTimerExW(sa, name ? w : 0, flags, access);
}

K32API HANDLE WINAPI OpenWaitableTimerW(DWORD access, BOOL inherit, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    DWORD e;
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    e = k32_ipc_oa(name, inherit, FALSE, &oa, &us);
    if (e) { shz_set_last_error(e); return 0; }
    st = NtOpenTimer(&h, access, &oa);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}

K32API HANDLE WINAPI OpenWaitableTimerA(DWORD access, BOOL inherit, LPCSTR name)
{
    WCHAR w[128];
    if (!name || k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return OpenWaitableTimerW(access, inherit, w);
}

K32API BOOL WINAPI SetWaitableTimerEx(HANDLE h, const LARGE_INTEGER *due, LONG period, PTIMERAPCROUTINE fn, LPVOID arg,
                                      PREASON_CONTEXT wake, ULONG tolerable_delay)
{
    NTSTATUS st;
    (void)wake; (void)tolerable_delay;                          /* no power states to wake from; delay is a hint */
    if (!due || period < 0) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = NtSetTimer(h, (PLARGE_INTEGER)due, (PVOID)fn, arg, FALSE, period, 0);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI SetWaitableTimer(HANDLE h, const LARGE_INTEGER *due, LONG period, PTIMERAPCROUTINE fn, LPVOID arg, BOOL resume)
{
    (void)resume;                                               /* no suspend states: ERROR_NOT_SUPPORTED is only a warning */
    return SetWaitableTimerEx(h, due, period, fn, arg, 0, 0);
}

K32API BOOL WINAPI CancelWaitableTimer(HANDLE h)
{
    NTSTATUS st = NtCancelTimer(h, 0);
    return st ? k32_ipc_fail(st) : TRUE;
}
