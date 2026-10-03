/* SPDX-License-Identifier: GPL-2.0-only
 * Native PE64 contract fixture for the Windows 10 kernel32/shell32 entry points a native shell / file manager uses
 * (kernel32/k32_win10_shellapi.c, dlls/shell32/shell_fileop.c). Expected values come from the Microsoft documentation of
 * each function (return codes, last errors, buffer contracts), not from the implementation. Works under C:\T_W10SH. */
#include "k32test.h"
#include <shlobj.h>
#include <shellapi.h>

#define D L"C:\\T_W10SH"

LONG WINAPI GetCurrentPackageId(UINT32 *, BYTE *);              /* appmodel.h */
LONG WINAPI GetCurrentApplicationUserModelId(UINT32 *, PWSTR);

static BOOL put(const WCHAR *path, const char *text)
{
    DWORD n = 0, w = 0;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    BOOL ok;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    while (text[n]) ++n;
    ok = WriteFile(h, text, n, &w, 0) && w == n;
    CloseHandle(h);
    return ok;
}
static BOOL exists(const WCHAR *p) { return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES; }

int main(void)
{
    SHFILEOPSTRUCTW op;
    WCHAR buf[MAX_PATH];
    DWORD high = 7, v;
    ULONGLONG kib = 0;
    MEMORYSTATUS ms;
    UINT32 len;
    HANDLE m;
    int r;

    printf("-- kernel32\n");
    /* clean leftovers of an earlier run */
    memset(&op, 0, sizeof op);
    op.wFunc = FO_DELETE; op.pFrom = D L"\0"; op.fFlags = FOF_NOCONFIRMATION | FOF_SILENT;
    SHFileOperationW(&op);

    CHECK(SHCreateDirectoryExW(0, D L"\\a\\b\\c", 0) == ERROR_SUCCESS, "SHCreateDirectoryExW creates every missing parent");
    CHECK(SHCreateDirectoryExW(0, D L"\\a\\b\\c", 0) == ERROR_ALREADY_EXISTS, "SHCreateDirectoryExW on an existing folder: ERROR_ALREADY_EXISTS");
    CHECK(SHCreateDirectoryExW(0, L"rel\\dir", 0) == ERROR_BAD_PATHNAME, "SHCreateDirectoryExW refuses a relative path");
    CHECK(put(D L"\\a\\f1.txt", "hello") && put(D L"\\a\\b\\f2.txt", "world!"), "fixture files written");

    v = GetCompressedFileSizeW(D L"\\a\\f1.txt", &high);
    CHECKV(v == 5 && high == 0 && GetLastError() == NO_ERROR, "GetCompressedFileSizeW = file size on an uncompressed volume", "%lu/%lu", (unsigned long)v, (unsigned long)high);
    v = GetCompressedFileSizeW(D L"\\missing.txt", 0);
    CHECK(v == INVALID_FILE_SIZE && GetLastError() == ERROR_FILE_NOT_FOUND, "GetCompressedFileSizeW of a missing file: ERROR_FILE_NOT_FOUND");

    CHECK(MoveFileWithProgressW(D L"\\a\\f1.txt", D L"\\a\\g1.txt", 0, 0, 0) && exists(D L"\\a\\g1.txt") && !exists(D L"\\a\\f1.txt"),
          "MoveFileWithProgressW same-volume rename");
    CHECK(!MoveFileExW(D L"\\a\\g1.txt", D L"\\a\\b\\f2.txt", 0) && GetLastError() == ERROR_ALREADY_EXISTS,
          "MoveFileExW without REPLACE_EXISTING onto a file: ERROR_ALREADY_EXISTS");
    CHECK(!MoveFileExW(D L"\\a\\g1.txt", 0, MOVEFILE_DELAY_UNTIL_REBOOT) && GetLastError() == ERROR_NOT_SUPPORTED && exists(D L"\\a\\g1.txt"),
          "MOVEFILE_DELAY_UNTIL_REBOOT is refused (no pending-rename service) and nothing is changed now");
    CHECK(!MoveFileExW(D L"\\a\\g1.txt", D L"\\a\\h.txt", 0x80000000u) && GetLastError() == ERROR_INVALID_PARAMETER, "MoveFileExW unknown flag: ERROR_INVALID_PARAMETER");
    CHECK(MoveFileExA("C:\\T_W10SH\\a\\g1.txt", "C:\\T_W10SH\\a\\f1.txt", 0) && exists(D L"\\a\\f1.txt"), "MoveFileExA");

    v = GetSystemWindowsDirectoryW(buf, MAX_PATH);
    { WCHAR w[MAX_PATH]; UINT n = GetWindowsDirectoryW(w, MAX_PATH); CHECK(v == n && n && k32t_weq(buf, w), "GetSystemWindowsDirectoryW = GetWindowsDirectoryW (single session)"); }
    CHECK(GetSystemWindowsDirectoryW(buf, 1) == v + 1, "GetSystemWindowsDirectoryW small buffer returns the required size incl. NUL");
    CHECK(GetSystemWow64DirectoryW(buf, MAX_PATH) == 0 && GetLastError() == ERROR_CALL_NOT_IMPLEMENTED, "GetSystemWow64DirectoryW without WOW64: ERROR_CALL_NOT_IMPLEMENTED");
    { PVOID old = 0; CHECK(!Wow64DisableWow64FsRedirection(&old) && GetLastError() == ERROR_INVALID_FUNCTION, "Wow64DisableWow64FsRedirection in a native 64-bit process fails"); }

    CHECK(GetPhysicallyInstalledSystemMemory(&kib) && kib >= 16 * 1024, "GetPhysicallyInstalledSystemMemory reports at least 16 MiB");
    SetLastError(0xdead);
    CHECK(!GetPhysicallyInstalledSystemMemory(0) && GetLastError() == ERROR_INVALID_PARAMETER, "GetPhysicallyInstalledSystemMemory(NULL): ERROR_INVALID_PARAMETER");
    GlobalMemoryStatus(&ms);
    CHECK(ms.dwLength == sizeof ms && ms.dwTotalPhys && ms.dwAvailPhys <= ms.dwTotalPhys && ms.dwTotalPhys / 1024 <= kib, "GlobalMemoryStatus consistent with the installed amount");

    m = CreateMutexExW(0, L"Local\\t_w10sh_mutex", CREATE_MUTEX_INITIAL_OWNER, SYNCHRONIZE | MUTEX_MODIFY_STATE);
    CHECK(m && GetLastError() == 0, "CreateMutexExW new named mutex, initial owner");
    CHECK(m && ReleaseMutex(m), "ReleaseMutex of the initially owned mutex (MUTEX_MODIFY_STATE granted)");
    { HANDLE m2 = CreateMutexExW(0, L"Local\\t_w10sh_mutex", 0, SYNCHRONIZE);
      CHECK(m2 && GetLastError() == ERROR_ALREADY_EXISTS, "CreateMutexExW existing name: ERROR_ALREADY_EXISTS + handle");
      if (m2) CloseHandle(m2); }
    if (m) CloseHandle(m);
    CHECK(!CreateMutexExW(0, 0, 2, MUTEX_ALL_ACCESS) && GetLastError() == ERROR_INVALID_PARAMETER, "CreateMutexExW unknown flag");

    len = 0;
    CHECK(GetCurrentPackageId(&len, 0) == APPMODEL_ERROR_NO_PACKAGE, "GetCurrentPackageId: unpackaged process");
    CHECK(GetCurrentApplicationUserModelId(&len, 0) == APPMODEL_ERROR_NO_APPLICATION, "GetCurrentApplicationUserModelId: no application identity");
    CHECK(GetCurrentPackageId(0, 0) == ERROR_INVALID_PARAMETER, "GetCurrentPackageId(NULL length): ERROR_INVALID_PARAMETER");

    printf("-- shell32\n");
    memset(&op, 0, sizeof op);
    op.wFunc = FO_COPY; op.pFrom = D L"\\a\0"; op.pTo = D L"\\copy\0"; op.fFlags = FOF_NOCONFIRMMKDIR;
    r = SHFileOperationW(&op);
    CHECKV(r == 0 && exists(D L"\\copy\\b\\c") && exists(D L"\\copy\\b\\f2.txt") && exists(D L"\\copy\\f1.txt") && !op.fAnyOperationsAborted,
           "FO_COPY copies a folder tree to a new name", "r=%d", r);
    r = SHFileOperationW(&op);
    CHECK(r == ERROR_NOT_SUPPORTED && exists(D L"\\copy\\f1.txt"), "FO_COPY onto an existing target without FOF_NOCONFIRMATION is refused (no confirmation UI)");
    op.pFrom = D L"\\a\\*.txt\0"; op.pTo = D L"\\wild\0"; op.fFlags = FOF_NOCONFIRMMKDIR | FOF_FILESONLY;
    r = SHFileOperationW(&op);
    CHECKV(r == 0 && exists(D L"\\wild\\f1.txt") && !exists(D L"\\wild\\b"), "FO_COPY wildcard into a created folder, FOF_FILESONLY", "r=%d", r);
    op.pFrom = D L"\\a\0"; op.pTo = D L"\\a\\b\0"; op.fFlags = FOF_NOCONFIRMATION;
    CHECK(SHFileOperationW(&op) == 0x76, "FO_COPY into its own subtree: DE_DESTSUBTREE");

    op.wFunc = FO_MOVE; op.pFrom = D L"\\copy\\b\0"; op.pTo = D L"\\moved\0"; op.fFlags = 0;
    r = SHFileOperationW(&op);
    CHECKV(r == 0 && exists(D L"\\moved\\f2.txt") && !exists(D L"\\copy\\b"), "FO_MOVE renames a folder", "r=%d", r);
    op.wFunc = FO_RENAME; op.pFrom = D L"\\moved\\f2.txt\0"; op.pTo = L"r2.txt\0";
    r = SHFileOperationW(&op);
    CHECKV(r == 0 && exists(D L"\\moved\\r2.txt"), "FO_RENAME with a bare name stays in the source folder", "r=%d", r);

    op.wFunc = FO_DELETE; op.pFrom = D L"\\moved\0"; op.pTo = 0; op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION;
    CHECK(SHFileOperationW(&op) == ERROR_NOT_SUPPORTED && exists(D L"\\moved"), "FO_DELETE to the Recycle Bin is refused (none exists); nothing deleted");
    op.fFlags = 0;
    CHECK(SHFileOperationW(&op) == ERROR_NOT_SUPPORTED && exists(D L"\\moved"), "FO_DELETE needing confirmation is refused without FOF_NOCONFIRMATION");
    op.fFlags = FOF_NOCONFIRMATION;
    CHECK(SHFileOperationW(&op) == 0 && !exists(D L"\\moved"), "FO_DELETE removes a folder tree");

    CHECK(PathYetAnotherMakeUniqueName(buf, D L"\\a", 0, L"f1.txt") && k32t_weq(buf, D L"\\a\\f1 (2).txt"), "PathYetAnotherMakeUniqueName picks \"name (2).ext\"");
    CHECK(PathYetAnotherMakeUniqueName(buf, D L"\\a", 0, L"New Folder") && k32t_weq(buf, D L"\\a\\New Folder"), "PathYetAnotherMakeUniqueName free name unchanged");
    {
        HRESULT hr = SHGetFolderPathAndSubDirW(0, CSIDL_WINDOWS | CSIDL_FLAG_DONT_VERIFY, 0, 0, L"Fonts", buf);
        WCHAR w[MAX_PATH]; GetWindowsDirectoryW(w, MAX_PATH);
        CHECK(hr == S_OK && k32t_wlen(buf) == k32t_wlen(w) + 6, "SHGetFolderPathAndSubDirW appends the subfolder");
    }
    { ULARGE_INTEGER a, t, f; CHECK(SHGetDiskFreeSpaceExW(L"C:\\", &a, &t, &f) && t.QuadPart && f.QuadPart <= t.QuadPart, "SHGetDiskFreeSpaceExW (kernel32 forwarder)"); }
    { void *p = SHAlloc(64); CHECK(p != 0, "SHAlloc"); SHFree(p); }

    op.wFunc = FO_DELETE; op.pFrom = D L"\0"; op.pTo = 0; op.fFlags = FOF_NOCONFIRMATION;
    CHECK(SHFileOperationW(&op) == 0 && !exists(D), "cleanup");
    return k32t_finish("t_win10_shellapi");
}
