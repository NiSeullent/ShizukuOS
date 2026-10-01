/* Shared native Win9x memory backend for actual pinned WTF sources.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 * Committed private virtual bytes are a conservative proxy, not a resident
 * working set. No missing modern Windows API is emulated here.
 */
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#if !defined(_WIN32) || (!defined(__i386__) && !defined(_M_IX86))
#error The Win9x memory backend requires the native Win32 x86 ABI.
#endif

typedef struct IEWKWin9xMemoryStatus {
    size_t totalPhysical;
    size_t availablePhysical;
    size_t totalVirtual;
    size_t availableVirtual;
    DWORD memoryLoad;
} IEWKWin9xMemoryStatus;

enum IEWKWin9xMemoryPressure {
    IEWK_MEMORY_NORMAL = 0,
    IEWK_MEMORY_WARNING = 1,
    IEWK_MEMORY_CRITICAL = 2
};

/* For a 128 MiB guest, the physical thresholds are 16 MiB and 8 MiB.
 * The same fractions protect the current process's available virtual address
 * space. These are explicit polling policy, not NT notification thresholds.
 */
#define IEWK_MEMORY_WARNING_DIVISOR 8
#define IEWK_MEMORY_CRITICAL_DIVISOR 16
#define IEWK_MEMORY_PRIVATE_ADDRESS_LIMIT UINT64_C(0x80000000)

static inline int iewkWin9xQueryMemoryStatus(IEWKWin9xMemoryStatus* result)
{
    MEMORYSTATUS status = { 0 };
    IEWKWin9xMemoryStatus measured;
    if (!result)
        return 0;
    status.dwLength = sizeof(status);
    GlobalMemoryStatus(&status);
    /* This API returns void. Validate its output instead of treating an
     * unchanged last-error value as a successful measurement.
     */
    if (!status.dwTotalPhys || !status.dwTotalVirtual
        || status.dwAvailPhys > status.dwTotalPhys
        || status.dwAvailVirtual > status.dwTotalVirtual
        || status.dwMemoryLoad > 100)
        return 0;
    measured.totalPhysical = status.dwTotalPhys;
    measured.availablePhysical = status.dwAvailPhys;
    measured.totalVirtual = status.dwTotalVirtual;
    measured.availableVirtual = status.dwAvailVirtual;
    measured.memoryLoad = status.dwMemoryLoad;
    *result = measured;
    return 1;
}

static inline enum IEWKWin9xMemoryPressure iewkWin9xMemoryPressureLevel(const IEWKWin9xMemoryStatus* status)
{
    if (status->availablePhysical <= status->totalPhysical / IEWK_MEMORY_CRITICAL_DIVISOR
        || status->availableVirtual <= status->totalVirtual / IEWK_MEMORY_CRITICAL_DIVISOR)
        return IEWK_MEMORY_CRITICAL;
    if (status->availablePhysical <= status->totalPhysical / IEWK_MEMORY_WARNING_DIVISOR
        || status->availableVirtual <= status->totalVirtual / IEWK_MEMORY_WARNING_DIVISOR)
        return IEWK_MEMORY_WARNING;
    return IEWK_MEMORY_NORMAL;
}

static inline int iewkWin9xCommittedPrivateBytes(size_t* result)
{
    SYSTEM_INFO system = { 0 };
    uint64_t cursor, limit, total = 0;
    DWORD regions = 0;
    if (!result)
        return 0;
    GetSystemInfo(&system);
    cursor = (uintptr_t)system.lpMinimumApplicationAddress;
    limit = (uint64_t)(uintptr_t)system.lpMaximumApplicationAddress + 1;
    /* Win9x's upper half contains shared/global system mappings. Only the
     * lower process address space contributes to this per-process proxy.
     */
    if (limit > IEWK_MEMORY_PRIVATE_ADDRESS_LIMIT)
        limit = IEWK_MEMORY_PRIVATE_ADDRESS_LIMIT;
    if (!system.dwPageSize || (system.dwPageSize & (system.dwPageSize - 1))
        || !cursor || cursor >= limit || limit > UINT64_C(0x100000000)
        || cursor % system.dwPageSize || limit % system.dwPageSize)
        return 0;
    while (cursor < limit) {
        MEMORY_BASIC_INFORMATION region = { 0 };
        uint64_t base, end, boundedEnd, bytes;
        /* An x86 address space contains at most 2^20 4 KiB pages. This
         * independent bound also prevents malformed metadata from looping.
         */
        if (++regions > 1048576UL)
            return 0;
        if (VirtualQuery((LPCVOID)(uintptr_t)cursor, &region, sizeof(region)) != sizeof(region))
            return 0;
        base = (uintptr_t)region.BaseAddress;
        end = base + (uint64_t)region.RegionSize;
        if (!region.RegionSize || base > cursor || end <= cursor
            || end > UINT64_C(0x100000000)
            || base % system.dwPageSize || end % system.dwPageSize
            || (region.State != MEM_COMMIT && region.State != MEM_RESERVE && region.State != MEM_FREE)
            || (region.State == MEM_COMMIT && region.Type != MEM_PRIVATE && region.Type != MEM_MAPPED && region.Type != MEM_IMAGE))
            return 0;
        boundedEnd = end < limit ? end : limit;
        bytes = boundedEnd - cursor;
        if (region.State == MEM_COMMIT && region.Type == MEM_PRIVATE) {
            if (bytes > (uint64_t)SIZE_MAX - total)
                return 0;
            total += bytes;
        }
        /* Use a 64-bit endpoint so a region ending at 2^32 cannot wrap the
         * next x86 query to address zero. Only query inside the OS range.
         */
        cursor = boundedEnd;
    }
    *result = (size_t)total;
    return 1;
}
