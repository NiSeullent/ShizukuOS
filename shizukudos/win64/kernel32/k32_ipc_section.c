/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: file mappings (CreateFileMapping / OpenFileMapping / MapViewOfFile(Ex) / UnmapViewOfFile /
 * FlushViewOfFile) over Kernel64 sections (kernel64/ipc_section.c). A mapping object is shared by every process that opens
 * it by name, inherits it or receives a duplicated handle; all their views see the same pages.
 */
#include "k32_ipc.h"

static ACCESS_MASK section_access_for(DWORD protect)
{
    ACCESS_MASK a = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ;
    switch (protect & 0xff) {
    case PAGE_READWRITE: a |= SECTION_MAP_WRITE; break;
    case PAGE_EXECUTE_READ: case PAGE_EXECUTE_WRITECOPY: a |= SECTION_MAP_EXECUTE; break;
    case PAGE_EXECUTE_READWRITE: a |= SECTION_MAP_WRITE | SECTION_MAP_EXECUTE; break;
    default: break;
    }
    return a;
}

K32API HANDLE WINAPI CreateFileMappingW(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD protect, DWORD max_hi, DWORD max_lo,
                                        LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    LARGE_INTEGER size;
    HANDLE h = 0;
    NTSTATUS st;
    const DWORD attrs = protect & 0xffffff00u, prot = protect & 0xff;
    DWORD e = k32_ipc_oa(name, sa && sa->bInheritHandle, TRUE, &oa, &us);
    if (e) { shz_set_last_error(e); return 0; }
    size.QuadPart = ((LONGLONG)max_hi << 32) | max_lo;
    if (file == INVALID_HANDLE_VALUE) {
        file = 0;                                               /* backed by the paging file */
        if (!size.QuadPart) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    }
    st = NtCreateSection(&h, section_access_for(prot), &oa, size.QuadPart ? &size : 0, prot, attrs ? attrs : SEC_COMMIT, file);
    if (st == STATUS_OBJECT_NAME_EXISTS) { shz_set_last_error(ERROR_ALREADY_EXISTS); return h; }
    if (st) { k32_nt_error(st); return 0; }
    shz_set_last_error(0);
    return h;
}

K32API HANDLE WINAPI CreateFileMappingA(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD protect, DWORD max_hi, DWORD max_lo,
                                        LPCSTR name)
{
    WCHAR w[128];
    if (name && k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return CreateFileMappingW(file, sa, protect, max_hi, max_lo, name ? w : 0);
}

K32API HANDLE WINAPI OpenFileMappingW(DWORD access, BOOL inherit, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    DWORD e;
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    e = k32_ipc_oa(name, inherit, FALSE, &oa, &us);
    if (e) { shz_set_last_error(e); return 0; }
    if (access == FILE_MAP_COPY) access = SECTION_MAP_READ;     /* copy-on-write views need read access only */
    st = NtOpenSection(&h, access, &oa);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}

K32API HANDLE WINAPI OpenFileMappingA(DWORD access, BOOL inherit, LPCSTR name)
{
    WCHAR w[128];
    if (!name || k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return OpenFileMappingW(access, inherit, w);
}

K32API LPVOID WINAPI MapViewOfFileEx(HANDLE h, DWORD access, DWORD off_hi, DWORD off_lo, SIZE_T bytes, LPVOID base)
{
    LARGE_INTEGER off;
    PVOID addr = base;
    SIZE_T size = bytes;
    ULONG prot;
    NTSTATUS st;
    off.QuadPart = ((LONGLONG)off_hi << 32) | off_lo;
    if (off.QuadPart & 0xffff) { shz_set_last_error(ERROR_MAPPED_ALIGNMENT); return 0; }   /* allocation granularity */
    if (access & FILE_MAP_COPY && !(access & ~(FILE_MAP_COPY | FILE_MAP_EXECUTE)))
        prot = (access & FILE_MAP_EXECUTE) ? PAGE_EXECUTE_WRITECOPY : PAGE_WRITECOPY;
    else if (access & FILE_MAP_WRITE)
        prot = (access & FILE_MAP_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    else if (access & (FILE_MAP_READ | FILE_MAP_EXECUTE))
        prot = (access & FILE_MAP_EXECUTE) ? PAGE_EXECUTE_READ : PAGE_READONLY;
    else { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    st = NtMapViewOfSection(h, CURRENT_PROCESS, &addr, 0, 0, &off, &size, 1 /* ViewShare */, 0, prot);
    if (st) { k32_nt_error(st); return 0; }
    return addr;
}

K32API LPVOID WINAPI MapViewOfFile(HANDLE h, DWORD access, DWORD off_hi, DWORD off_lo, SIZE_T bytes)
{
    return MapViewOfFileEx(h, access, off_hi, off_lo, bytes, 0);
}

K32API BOOL WINAPI UnmapViewOfFile(LPCVOID base)
{
    NTSTATUS st = NtUnmapViewOfSection(CURRENT_PROCESS, (PVOID)base);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI UnmapViewOfFileEx(PVOID base, ULONG flags)
{
    (void)flags;                                                /* MEM_UNMAP_WITH_TRANSIENT_BOOST: a scheduling hint */
    return UnmapViewOfFile(base);
}

K32API BOOL WINAPI FlushViewOfFile(LPCVOID base, SIZE_T bytes)
{
    PVOID b = (PVOID)base;
    SIZE_T n = bytes;
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = NtFlushVirtualMemory(CURRENT_PROCESS, &b, &n, &iosb);
    return st ? k32_ipc_fail(st) : TRUE;
}
