/* SPDX-License-Identifier: GPL-2.0-only
 * Windows 10 kernel32 entry points a native shell (file manager / Start menu), Chromium, Office and Steam import:
 *   MoveFileWithProgressW/A, MoveFileExA (MoveFileExW is routed here from k32_file.c) -- real flag handling: same-volume
 *       rename through NtSetInformationFile(FileRenameInformation); MOVEFILE_COPY_ALLOWED falls back to CopyFileExW +
 *       DeleteFileW when the kernel reports STATUS_NOT_SAME_DEVICE; MOVEFILE_DELAY_UNTIL_REBOOT, CREATE_HARDLINK and
 *       FAIL_IF_NOT_TRACKABLE need boot-time pending-rename / hard-link / link-tracking services that do not exist yet and
 *       fail with ERROR_NOT_SUPPORTED instead of silently renaming now.
 *   GetSystemWindowsDirectoryW/A (single-session system: the Windows directory), GetSystemWow64DirectoryW/A and the
 *       Wow64*FsRedirection family (Kernel64 has no WOW64 layer: ERROR_CALL_NOT_IMPLEMENTED / ERROR_INVALID_FUNCTION, the
 *       documented results on a system / process without WOW64).
 *   GetCompressedFileSizeW/A (no compressing or sparse filesystem here: the documented "actual file size" result; a file the
 *       filesystem reports as compressed/sparse fails ERROR_NOT_SUPPORTED rather than reporting a guessed on-disk size).
 *   GlobalMemoryStatus, GetPhysicallyInstalledSystemMemory (Kernel64 physical page accounting, NtQuerySystemInformation 0x100).
 *   CreateMutexExW/A (requested access mask passed to NtCreateMutant).
 *   GetCurrentPackageId/Path/Info, GetCurrentApplicationUserModelId, GetApplicationUserModelId -- unpackaged desktop
 *       processes: APPMODEL_ERROR_NO_PACKAGE / APPMODEL_ERROR_NO_APPLICATION (Win10 results for a non-packaged process).
 *   GetConsoleWindow -- the Kernel64 console is a text device with no HWND: NULL, the documented "no window" result.
 * Semantics follow the Microsoft documentation and Wine kernelbase/file.c + ReactOS dll/win32/kernel32 behaviour;
 * original project source (no third-party code copied).
 */
#include "k32_ipc.h"

BOOL k32_rename_path(LPCWSTR from, LPCWSTR to, BOOL replace);      /* k32_file.c */

/* ---------------------------------------------------------------- move */
#define MOVE_KNOWN (MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_DELAY_UNTIL_REBOOT | \
                    MOVEFILE_WRITE_THROUGH | MOVEFILE_CREATE_HARDLINK | MOVEFILE_FAIL_IF_NOT_TRACKABLE)

K32API BOOL WINAPI MoveFileWithProgressW(LPCWSTR from, LPCWSTR to, LPPROGRESS_ROUTINE progress, LPVOID data, DWORD flags)
{
    DWORD attributes;
    if (flags & ~(DWORD)MOVE_KNOWN) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!from || !*from) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (flags & MOVEFILE_DELAY_UNTIL_REBOOT)
        return k32_unsupported("MoveFileWithProgressW", "boot-time pending rename/delete service absent", ERROR_NOT_SUPPORTED);
    if (flags & (MOVEFILE_CREATE_HARDLINK | MOVEFILE_FAIL_IF_NOT_TRACKABLE))
        return k32_unsupported("MoveFileWithProgressW", "hard-link / link-tracking service absent", ERROR_NOT_SUPPORTED);
    if (!to || !*to) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    attributes = GetFileAttributesW(from);
    if (attributes == INVALID_FILE_ATTRIBUTES) return FALSE;            /* last error from the lookup (not found, bad path) */
    if (k32_rename_path(from, to, (flags & MOVEFILE_REPLACE_EXISTING) != 0)) return TRUE;
    if (shz_last_error() != ERROR_NOT_SAME_DEVICE || !(flags & MOVEFILE_COPY_ALLOWED)) return FALSE;
    /* Cross-volume: Windows moves only files this way; a directory tree is not copied by MoveFile. */
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) { shz_set_last_error(ERROR_NOT_SAME_DEVICE); return FALSE; }
    if (!CopyFileExW(from, to, progress, data, 0, (flags & MOVEFILE_REPLACE_EXISTING) ? 0 : COPY_FILE_FAIL_IF_EXISTS)) return FALSE;
    if (flags & MOVEFILE_WRITE_THROUGH) {
        HANDLE h = CreateFileW(to, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
        BOOL ok = h != INVALID_HANDLE_VALUE && FlushFileBuffers(h);
        DWORD error = shz_last_error();
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        if (!ok) { shz_set_last_error(error); return FALSE; }
    }
    /* The copy is complete; failing to remove the source leaves both (as on Windows) and reports why. */
    return DeleteFileW(from);
}

K32API BOOL WINAPI MoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags) { return MoveFileWithProgressW(from, to, 0, 0, flags); }

static BOOL widen_path(LPCSTR s, WCHAR *w, int cap)
{
    if (!s) return TRUE;
    if (k32_utf8_to_wide(s, -1, w, cap) <= 0) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI MoveFileWithProgressA(LPCSTR from, LPCSTR to, LPPROGRESS_ROUTINE progress, LPVOID data, DWORD flags)
{
    WCHAR wf[MAX_PATH + 1], wt[MAX_PATH + 1];
    if (!widen_path(from, wf, MAX_PATH + 1) || !widen_path(to, wt, MAX_PATH + 1)) return FALSE;
    return MoveFileWithProgressW(from ? wf : 0, to ? wt : 0, progress, data, flags);
}
K32API BOOL WINAPI MoveFileExA(LPCSTR from, LPCSTR to, DWORD flags) { return MoveFileWithProgressA(from, to, 0, 0, flags); }

/* ---------------------------------------------------------------- directories / WOW64 */
K32API UINT WINAPI GetSystemWindowsDirectoryW(LPWSTR buf, UINT cap) { return GetWindowsDirectoryW(buf, cap); }
K32API UINT WINAPI GetSystemWindowsDirectoryA(LPSTR buf, UINT cap) { return GetWindowsDirectoryA(buf, cap); }
K32API UINT WINAPI GetSystemWow64DirectoryW(LPWSTR buf, UINT cap) { (void)buf; (void)cap; shz_set_last_error(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
K32API UINT WINAPI GetSystemWow64DirectoryA(LPSTR buf, UINT cap) { (void)buf; (void)cap; shz_set_last_error(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
/* STATUS_NOT_IMPLEMENTED from RtlWow64EnableFsRedirectionEx in a native 64-bit process -> ERROR_INVALID_FUNCTION. */
K32API BOOL WINAPI Wow64DisableWow64FsRedirection(PVOID *old) { (void)old; shz_set_last_error(ERROR_INVALID_FUNCTION); return FALSE; }
K32API BOOL WINAPI Wow64RevertWow64FsRedirection(PVOID old) { (void)old; shz_set_last_error(ERROR_INVALID_FUNCTION); return FALSE; }
K32API BOOLEAN WINAPI Wow64EnableWow64FsRedirection(BOOLEAN enable) { (void)enable; shz_set_last_error(ERROR_INVALID_FUNCTION); return FALSE; }

/* ---------------------------------------------------------------- compressed size */
K32API DWORD WINAPI GetCompressedFileSizeW(LPCWSTR name, LPDWORD high)
{
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_FILE_SIZE; }
    if (!GetFileAttributesExW(name, GetFileExInfoStandard, &d)) return INVALID_FILE_SIZE;
    if (d.dwFileAttributes & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE)) {
        k32_unsupported("GetCompressedFileSizeW", "on-disk size of compressed/sparse file not reported by filesystem", ERROR_NOT_SUPPORTED);
        return INVALID_FILE_SIZE;
    }
    if (high) *high = d.nFileSizeHigh;
    /* INVALID_FILE_SIZE is also a valid low part: callers then check GetLastError() == NO_ERROR. */
    shz_set_last_error(NO_ERROR);
    return d.nFileSizeLow;
}
K32API DWORD WINAPI GetCompressedFileSizeA(LPCSTR name, LPDWORD high)
{
    WCHAR w[MAX_PATH + 1];
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_FILE_SIZE; }
    if (!widen_path(name, w, MAX_PATH + 1)) return INVALID_FILE_SIZE;
    return GetCompressedFileSizeW(w, high);
}

/* ---------------------------------------------------------------- memory */
K32API VOID WINAPI GlobalMemoryStatus(LPMEMORYSTATUS m)
{
    MEMORYSTATUSEX x;
    if (!m) return;
    x.dwLength = sizeof x;
    memset(m, 0, sizeof *m);
    m->dwLength = sizeof *m;
    if (!GlobalMemoryStatusEx(&x)) return;                  /* GlobalMemoryStatus has no failure result; fields stay zero */
    m->dwMemoryLoad = x.dwMemoryLoad;
    m->dwTotalPhys = (SIZE_T)x.ullTotalPhys;
    m->dwAvailPhys = (SIZE_T)x.ullAvailPhys;
    m->dwTotalPageFile = (SIZE_T)x.ullTotalPageFile;
    m->dwAvailPageFile = (SIZE_T)x.ullAvailPageFile;
    m->dwTotalVirtual = (SIZE_T)x.ullTotalVirtual;
    m->dwAvailVirtual = (SIZE_T)x.ullAvailVirtual;
}

/* Windows reads the SMBIOS memory-device table. Kernel64 does not parse SMBIOS yet, so this reports the RAM the kernel
 * actually manages (firmware-reserved ranges excluded): a lower bound of the installed amount, never an invented figure. */
K32API BOOL WINAPI GetPhysicallyInstalledSystemMemory(PULONGLONG kib)
{
    struct { ULONG64 total_pages, free_pages; } q;
    NTSTATUS st;
    if (!kib) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = NtQuerySystemInformation(0x100, &q, sizeof q, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    if (!q.total_pages) { shz_set_last_error(ERROR_INVALID_DATA); return FALSE; }
    *kib = q.total_pages * 4;
    return TRUE;
}

/* ---------------------------------------------------------------- mutex */
K32API HANDLE WINAPI CreateMutexExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = NULL;
    NTSTATUS st;
    DWORD error;
    if (flags & ~(DWORD)CREATE_MUTEX_INITIAL_OWNER) { shz_set_last_error(ERROR_INVALID_PARAMETER); return NULL; }
    if (sa && sa->nLength != sizeof *sa) { shz_set_last_error(ERROR_INVALID_PARAMETER); return NULL; }
    if (sa && sa->lpSecurityDescriptor) { shz_set_last_error(ERROR_NOT_SUPPORTED); return NULL; }   /* DACL not enforced yet */
    error = k32_ipc_oa(name, sa && sa->bInheritHandle, TRUE, &oa, &us);
    if (error) { shz_set_last_error(error); return NULL; }
    st = NtCreateMutant(&h, access, &oa, (flags & CREATE_MUTEX_INITIAL_OWNER) != 0);
    if (st == STATUS_OBJECT_NAME_EXISTS) { shz_set_last_error(ERROR_ALREADY_EXISTS); return h; }
    if (st) { k32_nt_error(st); return NULL; }
    shz_set_last_error(0);
    return h;
}
K32API HANDLE WINAPI CreateMutexExA(LPSECURITY_ATTRIBUTES sa, LPCSTR name, DWORD flags, DWORD access)
{
    WCHAR w[MAX_PATH + 1];
    if (name && !widen_path(name, w, MAX_PATH + 1)) return NULL;
    return CreateMutexExW(sa, name ? w : 0, flags, access);
}

/* ---------------------------------------------------------------- app model (unpackaged desktop process) */
K32API LONG WINAPI GetCurrentPackageId(UINT32 *len, BYTE *buf)
{
    if (!len || (*len && !buf)) return ERROR_INVALID_PARAMETER;
    return APPMODEL_ERROR_NO_PACKAGE;
}
K32API LONG WINAPI GetCurrentPackagePath(UINT32 *len, PWSTR buf)
{
    if (!len || (*len && !buf)) return ERROR_INVALID_PARAMETER;
    return APPMODEL_ERROR_NO_PACKAGE;
}
K32API LONG WINAPI GetCurrentPackageInfo(UINT32 flags, UINT32 *len, BYTE *buf, UINT32 *count)
{
    (void)flags; (void)count;
    if (!len || (*len && !buf)) return ERROR_INVALID_PARAMETER;
    return APPMODEL_ERROR_NO_PACKAGE;
}
K32API LONG WINAPI GetCurrentApplicationUserModelId(UINT32 *len, PWSTR buf)
{
    if (!len || (*len && !buf)) return ERROR_INVALID_PARAMETER;
    return APPMODEL_ERROR_NO_APPLICATION;
}
K32API LONG WINAPI GetApplicationUserModelId(HANDLE process, UINT32 *len, PWSTR buf)
{
    DWORD code, saved = GetLastError();
    if (!len || (*len && !buf)) return ERROR_INVALID_PARAMETER;
    if (!GetExitCodeProcess(process, &code)) {             /* a real, accessible process handle is required */
        DWORD error = GetLastError();
        SetLastError(saved);
        return (LONG)error;
    }
    SetLastError(saved);
    return APPMODEL_ERROR_NO_APPLICATION;
}

/* ---------------------------------------------------------------- console */
K32API HWND WINAPI GetConsoleWindow(void) { return NULL; }
