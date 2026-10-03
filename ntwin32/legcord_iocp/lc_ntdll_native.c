/* Win98 KERNEL32 backend and ShizukuLc_Nt* / ShizukuLc_Rtl* exports.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The libuv patch (UV_SHIZUKU_LCIOCP) resolves its ntdll function pointers from
 * these exports instead of ntdll.dll. Argument counts/NTAPI (stdcall) match the
 * NT prototypes in libuv winapi.h. Win98 imports only (see check.py inventory).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include "lc_ntdll.h"

typedef struct io_status { ULONG_PTR status; ULONG_PTR information; } io_status;
#define NTAPI_EXPORT __stdcall

static uint32_t nt_error(void *o) { (void)o; return GetLastError(); }

static uint64_t ft_to_u64(FILETIME t) { return (uint64_t)t.dwLowDateTime | (uint64_t)t.dwHighDateTime << 32; }
static void u64_to_ft(uint64_t v, FILETIME *t) { t->dwLowDateTime = (DWORD)v; t->dwHighDateTime = (DWORD)(v >> 32); }

static int nt_file_info(void *o, uintptr_t h, lc_nt_file_info *f)
{
    BY_HANDLE_FILE_INFORMATION i;
    (void)o;
    if (!GetFileInformationByHandle((HANDLE)h, &i)) return 0;
    f->attributes = i.dwFileAttributes;
    f->volume_serial = i.dwVolumeSerialNumber;
    f->links = i.nNumberOfLinks;
    f->creation = ft_to_u64(i.ftCreationTime);
    f->access = ft_to_u64(i.ftLastAccessTime);
    f->write = ft_to_u64(i.ftLastWriteTime);
    f->size = (uint64_t)i.nFileSizeHigh << 32 | i.nFileSizeLow;
    f->index = (uint64_t)i.nFileIndexHigh << 32 | i.nFileIndexLow;
    return 1;
}

static int nt_seek(void *o, uintptr_t h, int64_t offset, int whence, uint64_t *position)
{
    LONG high = (LONG)(offset >> 32);
    DWORD low;
    (void)o;
    SetLastError(NO_ERROR);
    low = SetFilePointer((HANDLE)h, (LONG)offset, &high,
                         whence == LC_SEEK_SET ? FILE_BEGIN : whence == LC_SEEK_CUR ? FILE_CURRENT : FILE_END);
    if (low == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) return 0;
    *position = (uint64_t)(uint32_t)high << 32 | low;
    return 1;
}

static int nt_set_eof(void *o, uintptr_t h) { (void)o; return SetEndOfFile((HANDLE)h) != 0; }

static int nt_set_times(void *o, uintptr_t h, const uint64_t *c, const uint64_t *a, const uint64_t *w)
{
    FILETIME fc, fa, fw;
    (void)o;
    if (c) u64_to_ft(*c, &fc);
    if (a) u64_to_ft(*a, &fa);
    if (w) u64_to_ft(*w, &fw);
    return SetFileTime((HANDLE)h, c ? &fc : NULL, a ? &fa : NULL, w ? &fw : NULL) != 0;
}

/* Only the current process (pseudo handle) can be resolved on Win98: there is
 * no GetProcessId. The parent comes from the Toolhelp snapshot. */
static int nt_process_ids(void *o, uintptr_t h, uint32_t *pid, uint32_t *parent)
{
    HANDLE snap;
    PROCESSENTRY32 e;
    BOOL more;
    DWORD self = GetCurrentProcessId();
    (void)o;
    if (h != (uintptr_t)GetCurrentProcess()) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return 0;
    }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    e.dwSize = sizeof(e);
    for (more = Process32First(snap, &e); more; more = Process32Next(snap, &e)) {
        if (e.th32ProcessID == self) {
            *pid = self;
            *parent = e.th32ParentProcessID;
            CloseHandle(snap);
            return 1;
        }
    }
    CloseHandle(snap);
    SetLastError(ERROR_NOT_FOUND);
    return 0;
}

static const lc_nt_ops ops = { NULL, nt_file_info, nt_seek, nt_set_eof, nt_set_times, nt_process_ids, nt_error };

static uint32_t finish(io_status *iosb, uint32_t status, uint32_t information)
{
    if (iosb) { iosb->status = status; iosb->information = information; }
    return status;
}

ULONG NTAPI_EXPORT ShizukuLc_RtlNtStatusToDosError(ULONG status) { return lc_nt_status_to_dos(status); }

LONG NTAPI_EXPORT ShizukuLc_NtQueryInformationFile(HANDLE h, io_status *iosb, PVOID buf, ULONG len, ULONG cls)
{
    uint32_t info = 0, st = lc_nt_query_information_file(&ops, (uintptr_t)h, buf, len, cls, &info);
    return (LONG)finish(iosb, st, st ? 0 : info);
}

LONG NTAPI_EXPORT ShizukuLc_NtSetInformationFile(HANDLE h, io_status *iosb, PVOID buf, ULONG len, ULONG cls)
{
    uint32_t info = 0, st = lc_nt_set_information_file(&ops, (uintptr_t)h, buf, len, cls, &info);
    return (LONG)finish(iosb, st, st ? 0 : info);
}

LONG NTAPI_EXPORT ShizukuLc_NtQueryVolumeInformationFile(HANDLE h, io_status *iosb, PVOID buf, ULONG len, ULONG cls)
{
    uint32_t info = 0, st = lc_nt_query_volume_information_file(&ops, (uintptr_t)h, buf, len, cls, &info);
    return (LONG)finish(iosb, st, st ? 0 : info);
}

LONG NTAPI_EXPORT ShizukuLc_NtQueryInformationProcess(HANDLE h, ULONG cls, PVOID buf, ULONG len, PULONG ret)
{
    return (LONG)lc_nt_query_information_process(&ops, (uintptr_t)h, buf, len, cls, (uint32_t *)ret);
}

/* Win98 has no handle-based directory enumeration (FindFirstFile is path based):
 * the exact NT failure, no side effect. (11 stdcall arguments.) */
LONG NTAPI_EXPORT ShizukuLc_NtQueryDirectoryFile(HANDLE h, HANDLE ev, PVOID apc, PVOID ctx, io_status *iosb,
                                                 PVOID buf, ULONG len, ULONG cls, BOOLEAN single, PVOID name,
                                                 BOOLEAN restart)
{
    (void)h; (void)ev; (void)apc; (void)ctx; (void)buf; (void)len; (void)cls; (void)single; (void)name; (void)restart;
    return (LONG)finish(iosb, LC_STATUS_NOT_IMPLEMENTED, 0);
}

/* AFD/pipe/console device ioctls have no Win98 counterpart. (10 arguments.) */
LONG NTAPI_EXPORT ShizukuLc_NtDeviceIoControlFile(HANDLE h, HANDLE ev, PVOID apc, PVOID ctx, io_status *iosb,
                                                  ULONG code, PVOID in, ULONG inlen, PVOID out, ULONG outlen)
{
    (void)h; (void)ev; (void)apc; (void)ctx; (void)code; (void)in; (void)inlen; (void)out; (void)outlen;
    return (LONG)finish(iosb, LC_STATUS_INVALID_DEVICE_REQUEST, 0);
}

/* System information classes libuv uses (processor performance, process list)
 * have no Win98 source. (4 arguments.) */
LONG NTAPI_EXPORT ShizukuLc_NtQuerySystemInformation(ULONG cls, PVOID buf, ULONG len, PULONG ret)
{
    (void)cls; (void)buf; (void)len;
    if (ret) *ret = 0;
    return (LONG)LC_STATUS_NOT_IMPLEMENTED;
}

/* RtlGetVersion: the real Win98 version, platform id 1 (VER_PLATFORM_WIN32_WINDOWS),
 * build number masked to its low word as on Win9x. (OSVERSIONINFOW = 276 bytes.) */
LONG NTAPI_EXPORT ShizukuLc_RtlGetVersion(PVOID out)
{
    unsigned char *b = out;
    OSVERSIONINFOA v;
    DWORD size, i;
    if (!out) return (LONG)LC_STATUS_INVALID_PARAMETER;
    size = *(DWORD *)b;
    if (size < 276) return (LONG)LC_STATUS_INVALID_PARAMETER;
    v.dwOSVersionInfoSize = sizeof(v);
    if (!GetVersionExA(&v)) return (LONG)lc_nt_status_from_win32(GetLastError());
    ((DWORD *)b)[1] = v.dwMajorVersion;
    ((DWORD *)b)[2] = v.dwMinorVersion;
    ((DWORD *)b)[3] = v.dwBuildNumber & 0xFFFFu;
    ((DWORD *)b)[4] = v.dwPlatformId;
    for (i = 0; i < 128; i++) {
        unsigned char ch = (unsigned char)v.szCSDVersion[i];
        ((unsigned short *)(b + 20))[i] = ch;
        if (!ch) break;
    }
    return 0;
}
