/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: file mappings over the Kernel64 section objects (kernel64/section.c): CreateFileMappingW/A,
 * OpenFileMappingW/A, MapViewOfFile, MapViewOfFileEx, UnmapViewOfFile, FlushViewOfFile. Paging-file mappings
 * (INVALID_HANDLE_VALUE) are shared memory; file mappings read the file on first touch; FILE_MAP_COPY views are
 * copy-on-write. Named mappings share the kernel's object name space ("Local\" / "Global\" prefixes are part of the name).
 */
#include "k32.h"

static NTSTATUS map_name(LPCWSTR name, SHZ_OBJECT_ATTRIBUTES *oa, SHZ_UNICODE_STRING *us, BOOL inherit)
{
    memset(oa, 0, sizeof *oa);
    oa->Length = sizeof *oa;
    oa->Attributes = inherit ? 2 : 0;                                    /* OBJ_INHERIT */
    if (name && name[0]) {
        const size_t n = k32_wlen(name);
        if (n >= 127) return STATUS_OBJECT_NAME_INVALID;
        us->Buffer = (PWSTR)name;
        us->Length = (USHORT)(n * 2);
        us->MaximumLength = us->Length;
        oa->ObjectName = us;
    }
    return STATUS_SUCCESS;
}

K32API HANDLE WINAPI CreateFileMappingW(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD protect, DWORD size_high, DWORD size_low, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    LARGE_INTEGER max;
    HANDLE h = 0;
    NTSTATUS st;
    const DWORD attrs = protect & 0xff000000u;                          /* SEC_* */
    const DWORD prot = protect & 0x00ffffffu;
    ACCESS_MASK access = SECTION_QUERY | SECTION_MAP_READ | STANDARD_RIGHTS_REQUIRED;
    if (map_name(name, &oa, &us, sa && sa->bInheritHandle)) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    if (prot == PAGE_READWRITE || prot == PAGE_EXECUTE_READWRITE) access |= SECTION_MAP_WRITE;
    if (prot >= PAGE_EXECUTE_READ) access |= SECTION_MAP_EXECUTE;
    max.QuadPart = ((LONGLONG)size_high << 32) | size_low;
    if (file == INVALID_HANDLE_VALUE) {
        file = 0;
        if (!max.QuadPart) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    }
    st = NtCreateSection(&h, access, &oa, max.QuadPart ? &max : 0, prot, attrs ? attrs : SEC_COMMIT, file);
    if (st == (NTSTATUS)0x40000000) { shz_set_last_error(ERROR_ALREADY_EXISTS); return h; }   /* STATUS_OBJECT_NAME_EXISTS */
    if (st) { k32_nt_error(st); return 0; }
    shz_set_last_error(0);
    return h;
}

K32API HANDLE WINAPI CreateFileMappingA(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD protect, DWORD size_high, DWORD size_low, LPCSTR name)
{
    WCHAR w[128];
    if (name && k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return CreateFileMappingW(file, sa, protect, size_high, size_low, name ? w : 0);
}

K32API HANDLE WINAPI OpenFileMappingW(DWORD access, BOOL inherit, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    if (!name || !name[0]) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (map_name(name, &oa, &us, inherit)) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    if (access == FILE_MAP_ALL_ACCESS) access = SECTION_ALL_ACCESS;
    st = NtOpenSection(&h, access, &oa);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}

K32API HANDLE WINAPI OpenFileMappingA(DWORD access, BOOL inherit, LPCSTR name)
{
    WCHAR w[128];
    if (!name || k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return OpenFileMappingW(access, inherit, w);
}

/* FILE_MAP_* access -> the page protection of the view. */
static ULONG view_protect(DWORD access)
{
    const int exec = (access & FILE_MAP_EXECUTE) != 0;
    if (access & FILE_MAP_COPY && !(access & FILE_MAP_WRITE)) return exec ? PAGE_EXECUTE_WRITECOPY : PAGE_WRITECOPY;
    if (access & FILE_MAP_WRITE) return exec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    if (access & (FILE_MAP_READ | FILE_MAP_COPY)) return exec ? PAGE_EXECUTE_READ : PAGE_READONLY;
    return exec ? PAGE_EXECUTE_READ : 0;
}

K32API LPVOID WINAPI MapViewOfFileEx(HANDLE mapping, DWORD access, DWORD off_high, DWORD off_low, SIZE_T bytes, LPVOID base)
{
    PVOID addr = base;
    SIZE_T size = bytes;
    LARGE_INTEGER off;
    const ULONG prot = view_protect(access);
    NTSTATUS st;
    if (!prot) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    off.QuadPart = ((LONGLONG)off_high << 32) | off_low;
    st = NtMapViewOfSection(mapping, CURRENT_PROCESS, &addr, 0, 0, &off, &size, 1 /* ViewShare */, 0, prot);
    if (st) { k32_nt_error(st); return 0; }
    return addr;
}

K32API LPVOID WINAPI MapViewOfFile(HANDLE mapping, DWORD access, DWORD off_high, DWORD off_low, SIZE_T bytes)
{
    return MapViewOfFileEx(mapping, access, off_high, off_low, bytes, 0);
}

K32API BOOL WINAPI UnmapViewOfFile(LPCVOID base)
{
    NTSTATUS st = NtUnmapViewOfSection(CURRENT_PROCESS, (PVOID)base);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI UnmapViewOfFileEx(PVOID base, ULONG flags)
{
    (void)flags;                                                          /* MEM_UNMAP_WITH_TRANSIENT_BOOST / MEM_PRESERVE_PLACEHOLDER */
    if (flags & ~1u) return k32_unsupported("UnmapViewOfFileEx", "MEM_PRESERVE_PLACEHOLDER (no placeholders)", ERROR_INVALID_PARAMETER);
    return UnmapViewOfFile(base);
}

K32API BOOL WINAPI FlushViewOfFile(LPCVOID base, SIZE_T bytes)
{
    PVOID b = (PVOID)base;
    SIZE_T n = bytes;
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st = NtFlushVirtualMemory(CURRENT_PROCESS, &b, &n, &io);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
