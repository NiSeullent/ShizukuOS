/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: DLL search directories (SetDllDirectory, GetDllDirectory, SetDefaultDllDirectories, AddDllDirectory,
 * RemoveDllDirectory) on top of ntdll's loader state (ntdll/ldr_search.c), and GetCurrentThreadStackLimits.
 * Behaviour follows the public documentation of each function on learn.microsoft.com.
 */
#include "k32.h"

int k32_utf8_to_wide(const char *s, int n, WCHAR *w, int cap);
int k32_wide_to_utf8(const WCHAR *w, int n, char *s, int cap);
NTSTATUS NTAPI LdrSetDllDirectory(const SHZ_UNICODE_STRING *);
NTSTATUS NTAPI LdrGetDllDirectory(SHZ_UNICODE_STRING *);
NTSTATUS NTAPI LdrSetDefaultDllDirectories(ULONG);
NTSTATUS NTAPI LdrAddDllDirectory(const SHZ_UNICODE_STRING *, PVOID *);
NTSTATUS NTAPI LdrRemoveDllDirectory(PVOID);

/* NULL restores the default search order; "" removes the current directory from it; a directory is searched right
 * after the application directory. */
K32API BOOL WINAPI SetDllDirectoryW(LPCWSTR dir)
{
    SHZ_UNICODE_STRING us;
    NTSTATUS st;
    if (dir) RtlInitUnicodeString(&us, dir);
    st = LdrSetDllDirectory(dir ? &us : 0);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI SetDllDirectoryA(LPCSTR dir)
{
    WCHAR w[MAX_PATH];
    if (!dir) return SetDllDirectoryW(0);
    if (k32_utf8_to_wide(dir, -1, w, MAX_PATH) <= 0) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
    return SetDllDirectoryW(w);
}

/* Returns the characters copied (without the terminator), or the size needed (with it) when `len` is too small. */
K32API DWORD WINAPI GetDllDirectoryW(DWORD len, LPWSTR buf)
{
    WCHAR tmp[MAX_PATH + 1];
    SHZ_UNICODE_STRING us;
    DWORD n;
    us.Buffer = tmp;
    us.Length = 0;
    us.MaximumLength = sizeof tmp;
    if (LdrGetDllDirectory(&us)) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    n = us.Length / sizeof(WCHAR);
    if (!buf || len <= n) return n + 1;
    memcpy(buf, tmp, (n + 1) * sizeof(WCHAR));
    return n;
}

K32API DWORD WINAPI GetDllDirectoryA(DWORD len, LPSTR buf)
{
    WCHAR w[MAX_PATH + 1];
    char a[3 * MAX_PATH + 1];
    DWORD n = GetDllDirectoryW(MAX_PATH + 1, w);
    int r;
    if (n > MAX_PATH) return 0;
    r = k32_wide_to_utf8(w, (int)n + 1, a, sizeof a);
    if (r <= 0) return 0;
    if (!buf || len < (DWORD)r) return (DWORD)r;
    memcpy(buf, a, (size_t)r);
    return (DWORD)r - 1;
}

K32API BOOL WINAPI SetDefaultDllDirectories(DWORD flags)
{
    NTSTATUS st = LdrSetDefaultDllDirectories(flags);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* The directory must be fully qualified; the cookie identifies it for RemoveDllDirectory. */
K32API DLL_DIRECTORY_COOKIE WINAPI AddDllDirectory(PCWSTR dir)
{
    SHZ_UNICODE_STRING us;
    PVOID cookie = 0;
    NTSTATUS st;
    if (!dir) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    RtlInitUnicodeString(&us, dir);
    st = LdrAddDllDirectory(&us, &cookie);
    if (st) { k32_nt_error(st); return 0; }
    return cookie;
}

K32API BOOL WINAPI RemoveDllDirectory(DLL_DIRECTORY_COOKIE cookie)
{
    NTSTATUS st = LdrRemoveDllDirectory(cookie);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* The whole stack reservation of the calling thread: [TEB.DeallocationStack, TEB.NtTib.StackBase). */
K32API VOID WINAPI GetCurrentThreadStackLimits(PULONG_PTR low, PULONG_PTR high)
{
    const uint64_t teb = shz_teb();
    const ULONG_PTR base = *(const ULONG_PTR *)(teb + 0x08), limit = *(const ULONG_PTR *)(teb + 0x10);
    const ULONG_PTR dealloc = *(const ULONG_PTR *)(teb + 0x1478);
    *low = dealloc ? dealloc : limit;
    *high = base;
}
