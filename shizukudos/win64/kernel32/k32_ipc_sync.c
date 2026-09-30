/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: opening named synchronisation objects (OpenEvent / OpenMutex / OpenSemaphore) - an existing object of
 * that type or ERROR_FILE_NOT_FOUND, never a new one (kernel64/ipc_core.c: ipc_open_named). */
#include "k32_ipc.h"

typedef NTSTATUS (NTAPI *open_fn)(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);

static HANDLE open_named(open_fn fn, DWORD access, BOOL inherit, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    DWORD e;
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    e = k32_ipc_oa(name, inherit, FALSE, &oa, &us);
    if (e) { shz_set_last_error(e); return 0; }
    st = fn(&h, access, &oa);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}

static HANDLE open_named_a(open_fn fn, DWORD access, BOOL inherit, LPCSTR name)
{
    WCHAR w[128];
    if (!name || k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return open_named(fn, access, inherit, w);
}

K32API HANDLE WINAPI OpenEventW(DWORD access, BOOL inherit, LPCWSTR name) { return open_named(NtOpenEvent, access, inherit, name); }
K32API HANDLE WINAPI OpenEventA(DWORD access, BOOL inherit, LPCSTR name) { return open_named_a(NtOpenEvent, access, inherit, name); }
K32API HANDLE WINAPI OpenMutexW(DWORD access, BOOL inherit, LPCWSTR name) { return open_named(NtOpenMutant, access, inherit, name); }
K32API HANDLE WINAPI OpenMutexA(DWORD access, BOOL inherit, LPCSTR name) { return open_named_a(NtOpenMutant, access, inherit, name); }
K32API HANDLE WINAPI OpenSemaphoreW(DWORD access, BOOL inherit, LPCWSTR name) { return open_named(NtOpenSemaphore, access, inherit, name); }
K32API HANDLE WINAPI OpenSemaphoreA(DWORD access, BOOL inherit, LPCSTR name) { return open_named_a(NtOpenSemaphore, access, inherit, name); }
