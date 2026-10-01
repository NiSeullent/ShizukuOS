/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Win32/RTL thread error-mode translation ported from Wine
 * dlls/kernelbase/thread.c, commit db11d0fe6a169c457e23d007e20404643d067aa8,
 * GetThreadErrorMode, SetThreadErrorMode and rtlmode_to_win32mode.
 * Copyright 1996, 2002, 2019 Alexandre Julliard; Wine authors.
 * Adaptation: existing Shizuku export and NTSTATUS error helpers.
 * No process error-mode inheritance or error-reporting UI is introduced here.
 */
#include "k32.h"

ULONG NTAPI RtlGetThreadErrorMode(void);
NTSTATUS NTAPI RtlSetThreadErrorMode(ULONG, PULONG);

static DWORD thread_mode_to_win32(ULONG mode)
{
    DWORD result = 0;
    if (mode & 0x10u) result |= SEM_FAILCRITICALERRORS;
    if (mode & 0x20u) result |= SEM_NOGPFAULTERRORBOX;
    if (mode & 0x40u) result |= SEM_NOOPENFILEERRORBOX;
    return result;
}

K32API DWORD WINAPI GetThreadErrorMode(void)
{
    return thread_mode_to_win32(RtlGetThreadErrorMode());
}

K32API BOOL WINAPI SetThreadErrorMode(DWORD mode, LPDWORD old_mode)
{
    ULONG rtl_mode = 0, previous;
    NTSTATUS status;
    if (mode & ~(DWORD)(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (mode & SEM_FAILCRITICALERRORS) rtl_mode |= 0x10u;
    if (mode & SEM_NOGPFAULTERRORBOX) rtl_mode |= 0x20u;
    if (mode & SEM_NOOPENFILEERRORBOX) rtl_mode |= 0x40u;
    status = RtlSetThreadErrorMode(rtl_mode, old_mode ? &previous : NULL);
    if (status) { k32_nt_error(status); return FALSE; }
    if (old_mode) *old_mode = thread_mode_to_win32(previous);
    return TRUE;
}
