/* SPDX-License-Identifier: GPL-2.0-only
 * E1 Electron/Node eager imports. Original implementation against documented Win32 contracts
 * and the current Kernel64 facilities; no upstream code copied. Unsupported operations return
 * errors rather than fabricated data, cancellation, or a path-based imitation of ReOpenFile.
 */
#include "k32.h"
#ifndef APPMODEL_ERROR_NO_PACKAGE
#define APPMODEL_ERROR_NO_PACKAGE 15700L
#endif

K32API BOOL WINAPI CancelSynchronousIo(HANDLE thread)
{
    DWORD code;
    if (!GetExitCodeThread(thread, &code)) return FALSE;
    /* ERROR_NOT_FOUND would assert that the target has no request. We cannot determine that. */
    shz_set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

K32API BOOLEAN WINAPI CreateSymbolicLinkW(LPCWSTR link, LPCWSTR target, DWORD flags)
{
    if (!link || !target || !*link || !*target ||
        (flags & ~(DWORD)(SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    shz_set_last_error(ERROR_NOT_SUPPORTED);              /* neither mounted filesystem stores symlinks */
    return FALSE;
}

K32API HANDLE WINAPI ReOpenFile(HANDLE orig, DWORD access, DWORD share, DWORD flags)
{
    BY_HANDLE_FILE_INFORMATION info;
    const DWORD allowed = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_NO_BUFFERING |
        FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED | FILE_FLAG_POSIX_SEMANTICS |
        FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_WRITE_THROUGH;
    (void)access;
    if ((share & ~(DWORD)(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) || (flags & ~allowed)) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    if (!GetFileInformationByHandle(orig, &info)) return INVALID_HANDLE_VALUE;
    if (GetFileType(orig) != FILE_TYPE_DISK) { shz_set_last_error(ERROR_INVALID_HANDLE); return INVALID_HANDLE_VALUE; }
    /* Kernel64 NtCreateFile ignores RootDirectory and has no open-by-file-ID operation.
     * Reopening a reported path races rename/replacement and loses the original object's identity. */
    shz_set_last_error(ERROR_NOT_SUPPORTED);
    return INVALID_HANDLE_VALUE;
}

K32API BOOL WINAPI GetProcessIoCounters(HANDLE process, PIO_COUNTERS counters)
{
    DWORD code;
    if (!GetExitCodeProcess(process, &code)) return FALSE;
    if (!counters) { shz_set_last_error(ERROR_NOACCESS); return FALSE; }
    shz_set_last_error(ERROR_NOT_SUPPORTED);              /* preserve caller output: kernel keeps no I/O counters */
    return FALSE;
}

K32API LONG WINAPI GetCurrentPackageFullName(UINT32 *len, PWSTR name)
{
    if (!len || (*len && !name)) return ERROR_INVALID_PARAMETER;
    return APPMODEL_ERROR_NO_PACKAGE;                    /* result code, not LastError; outputs unchanged */
}

K32API LONG WINAPI GetPackageFamilyName(HANDLE process, UINT32 *len, PWSTR name)
{
    DWORD code, saved = GetLastError();
    if (!len || (*len && !name)) return ERROR_INVALID_PARAMETER;
    if (!GetExitCodeProcess(process, &code)) {
        DWORD error = GetLastError();
        SetLastError(saved);
        return (LONG)error;
    }
    SetLastError(saved);
    return APPMODEL_ERROR_NO_PACKAGE;
}

K32API BOOL WINAPI NeedCurrentDirectoryForExePathW(LPCWSTR exe)
{
    WCHAR value;
    const WCHAR *p;
    DWORD n, error, saved = GetLastError();
    if (!exe) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (p = exe; *p; ++p) if (*p == '\\') return TRUE;
    SetLastError(ERROR_SUCCESS);
    n = GetEnvironmentVariableW(L"NoDefaultCurrentDirectoryInExePath", &value, 1);
    error = GetLastError();
    SetLastError(saved);
    /* An empty but present variable also disables the search. Only an absent variable enables it. */
    return !n && error == ERROR_ENVVAR_NOT_FOUND;
}
