/* SPDX-License-Identifier: GPL-2.0-only
 * Exact basic current-process translations; never emulate placeholders or ignore flags.
 * Original implementation from the documented ABI; no Microsoft/Wine code copied.
 */
#include "bridge.h"

static int failure(uint32_t error) { SetLastError(error); return 0; }

/* Real handles require access checks unavailable through the current-process-only
 * MapViewOfFileEx endpoint. Do not turn a query-only handle into the pseudo handle.
 * Query only to distinguish invalid handles; valid real handles remain unsupported.
 */
static int current_process(MB_HANDLE process, int null_is_current)
{
    uint32_t incoming = GetLastError();
    MB_HANDLE current = GetCurrentProcess();
    if (process == current || (!process && null_is_current)) {
        SetLastError(incoming);
        return 1;
    }
    if (!process) return failure(MB_ERROR_INVALID_HANDLE);
    if (!GetProcessId(process)) {
        uint32_t error = GetLastError();
        return failure(error ? error : MB_ERROR_INVALID_HANDLE);
    }
    return failure(MB_ERROR_NOT_SUPPORTED);
}

static int no_extensions(MB_EXTENDED_PARAMETER *parameters, uint32_t count)
{
    if (!count) return 1; /* No element is read, even when the pointer is non-NULL. */
    return failure(parameters ? MB_ERROR_NOT_SUPPORTED : MB_ERROR_INVALID_PARAMETER);
}

static int layout(MB_SYSTEM_INFO *info)
{
    uint32_t incoming = GetLastError();
    GetSystemInfo(info);
    SetLastError(incoming);
    if (!info->dwPageSize || (info->dwPageSize & (info->dwPageSize - 1)) ||
        !info->dwAllocationGranularity ||
        (info->dwAllocationGranularity & (info->dwAllocationGranularity - 1)) ||
        info->dwAllocationGranularity < info->dwPageSize ||
        (uintptr_t)info->lpMinimumApplicationAddress > (uintptr_t)info->lpMaximumApplicationAddress)
        return failure(MB_ERROR_NOT_SUPPORTED);
    return 1;
}

static int span(void *base, size_t size, const MB_SYSTEM_INFO *info)
{
    uintptr_t start = (uintptr_t)base, maximum = (uintptr_t)info->lpMaximumApplicationAddress;
    if (size && size % info->dwPageSize) return failure(MB_ERROR_INVALID_PARAMETER);
    if (start && (start < (uintptr_t)info->lpMinimumApplicationAddress || start > maximum ||
                  (size && size - 1 > maximum - start))) return failure(MB_ERROR_INVALID_ADDRESS);
    /* Even a system-chosen address cannot fit a size wider than user space. */
    if (!start && size && size - 1 > maximum - (uintptr_t)info->lpMinimumApplicationAddress)
        return failure(MB_ERROR_INVALID_PARAMETER);
    return 1;
}

void *MB_ABI m98mb_VirtualAlloc2(MB_HANDLE process, void *base, size_t size,
                               MB_ULONG allocation, MB_ULONG protection,
                               MB_EXTENDED_PARAMETER *parameters, MB_ULONG count)
{
    MB_SYSTEM_INFO info;
    if (!current_process(process, 1) || !no_extensions(parameters, count)) return 0;
    if (!(allocation & (MB_MEM_COMMIT | MB_MEM_RESERVE))) {
        failure(allocation ? MB_ERROR_NOT_SUPPORTED : MB_ERROR_INVALID_PARAMETER); return 0;
    }
    if (allocation & ~(MB_MEM_COMMIT | MB_MEM_RESERVE | MB_MEM_TOP_DOWN)) {
        failure(MB_ERROR_NOT_SUPPORTED); return 0;
    }
    switch (protection) {
    case MB_PAGE_NOACCESS: case MB_PAGE_READONLY: case MB_PAGE_READWRITE:
    case MB_PAGE_EXECUTE: case MB_PAGE_EXECUTE_READ: case MB_PAGE_EXECUTE_READWRITE: break;
    default: failure(MB_ERROR_NOT_SUPPORTED); return 0;
    }
    if (!size) { failure(MB_ERROR_INVALID_PARAMETER); return 0; }
    if (!layout(&info) || !span(base, size, &info)) return 0;
    if ((uintptr_t)base % info.dwAllocationGranularity) {
        failure(MB_ERROR_INVALID_PARAMETER); return 0;
    }
    /* No extra memory or handle ownership is acquired by the adapter. */
    return VirtualAllocEx(GetCurrentProcess(), base, size, allocation, protection);
}

void *MB_ABI m98mb_MapViewOfFile3(MB_HANDLE mapping, MB_HANDLE process, void *base,
                                uint64_t offset, size_t size, MB_ULONG allocation,
                                MB_ULONG protection, MB_EXTENDED_PARAMETER *parameters, MB_ULONG count)
{
    MB_SYSTEM_INFO info;
    uint32_t access;
    if (!current_process(process, 1) || !no_extensions(parameters, count)) return 0;
    if (allocation) { failure(MB_ERROR_NOT_SUPPORTED); return 0; }
    switch (protection) {
    case MB_PAGE_READONLY: access = MB_FILE_MAP_READ; break;
    case MB_PAGE_READWRITE: access = MB_FILE_MAP_WRITE; break;
    case MB_PAGE_WRITECOPY: access = MB_FILE_MAP_COPY; break;
    case MB_PAGE_EXECUTE_READ: access = MB_FILE_MAP_READ | MB_FILE_MAP_EXECUTE; break;
    case MB_PAGE_EXECUTE_READWRITE: access = MB_FILE_MAP_WRITE | MB_FILE_MAP_EXECUTE; break;
    case MB_PAGE_EXECUTE_WRITECOPY: access = MB_FILE_MAP_COPY | MB_FILE_MAP_EXECUTE; break;
    default: failure(MB_ERROR_NOT_SUPPORTED); return 0;
    }
    if (!layout(&info)) return 0;
    if (offset % info.dwAllocationGranularity) { failure(MB_ERROR_MAPPED_ALIGNMENT); return 0; }
    /* The owner's signed LARGE_INTEGER construction cannot represent >= 2^63. */
    if (offset > INT64_MAX || (size && size > INT64_MAX - offset)) {
        failure(MB_ERROR_NOT_SUPPORTED); return 0;
    }
    if (base && (uintptr_t)base < (uintptr_t)info.lpMinimumApplicationAddress) {
        failure(MB_ERROR_INVALID_ADDRESS); return 0;
    }
    base = (void *)((uintptr_t)base & ~((uintptr_t)info.dwAllocationGranularity - 1));
    if (!span(base, size, &info)) return 0;
    return MapViewOfFileEx(mapping, access, (uint32_t)(offset >> 32), (uint32_t)offset, size, base);
}

MB_BOOL MB_ABI m98mb_UnmapViewOfFile2(MB_HANDLE process, void *base, MB_ULONG flags)
{
    MB_MEMORY_BASIC_INFORMATION info;
    uint32_t incoming;
    size_t got;
    if (!current_process(process, 0)) return 0;
    if (flags) return failure(MB_ERROR_NOT_SUPPORTED);
    if (!base) return failure(MB_ERROR_INVALID_ADDRESS);
    incoming = GetLastError();
    got = VirtualQuery(base, &info, sizeof info);
    if (!got) return 0; /* Preserve the endpoint's failure status. */
    if (got != sizeof info) return failure(MB_ERROR_NOT_SUPPORTED);
    if (info.AllocationBase != base) return failure(MB_ERROR_INVALID_ADDRESS);
    if (info.Type != MB_MEM_MAPPED) return failure(info.Type == MB_MEM_IMAGE ? MB_ERROR_NOT_SUPPORTED : MB_ERROR_INVALID_ADDRESS);
    if (info.State != MB_MEM_COMMIT && info.State != MB_MEM_RESERVE) return failure(MB_ERROR_INVALID_ADDRESS);
    SetLastError(incoming);
    /* Kernel reference counting and write-back remain with the genuine owner. */
    return UnmapViewOfFile(base);
}

#if defined(_WIN32)
/* Keep explicit image relocations for the private loader's relocation gate.
 * This is immutable pointer metadata, not runtime initialization or extra API.
 */
static const uintptr_t adapter_addresses[] __attribute__((used)) = {
    (uintptr_t)&m98mb_VirtualAlloc2, (uintptr_t)&m98mb_MapViewOfFile3, (uintptr_t)&m98mb_UnmapViewOfFile2
};
MB_BOOL MB_ABI DllMain(MB_HANDLE module, uint32_t reason, void *reserved)
{
    (void)module; (void)reason; (void)reserved;
    return 1; /* No heap, API call, thread, hook or initialization in the loader lock. */
}
#endif
