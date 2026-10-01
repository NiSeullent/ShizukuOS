/* SPDX-License-Identifier: GPL-2.0-only
 * Host-owned heap regions model the endpoint's ownership. This exercises adapter
 * validation/delegation and deliberately does not claim guest kernel semantics.
 */
#include "bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static uint32_t error_value, page_size = 4096, granularity = 65536;
static unsigned allocations, maps, unmaps, queries, process_queries;
static int alloc_fail, map_fail, unmap_fail, query_fail, query_short;
static void *allocation_owned, *view_owned;
static size_t allocation_bytes, view_bytes;
static MB_MEMORY_BASIC_INFORMATION query_override;
static int use_override;
static struct { MB_HANDLE process, mapping; void *base; size_t size; uint32_t type, protection, access, high, low; } last;

MB_HANDLE GetCurrentProcess(void) { return (void *)(uintptr_t)UINTPTR_MAX; }
uint32_t GetCurrentProcessId(void) { return 60; }
uint32_t GetProcessId(MB_HANDLE handle)
{
    ++process_queries;
    if (handle == (void *)0xc1) return 60;
    if (handle == (void *)0xc2) return 77;
    error_value = 1236; return 0;
}
uint32_t GetLastError(void) { return error_value; }
void SetLastError(uint32_t error) { error_value = error; }
void GetSystemInfo(MB_SYSTEM_INFO *info)
{
    memset(info, 0, sizeof *info);
    info->dwPageSize = page_size; info->dwAllocationGranularity = granularity;
    info->lpMinimumApplicationAddress = (void *)0x10000;
    info->lpMaximumApplicationAddress = (void *)0x7ffffffeffffull;
}
void *VirtualAllocEx(MB_HANDLE process, void *base, size_t size, uint32_t type, uint32_t protection)
{
    ++allocations;
    last.process = process; last.base = base; last.size = size; last.type = type; last.protection = protection;
    if (alloc_fail) { error_value = 8; return 0; }
    CHECK(!allocation_owned);
    if (base) return base; /* Delegate reservation compatibility; no guessed ownership. */
    allocation_owned = calloc(1, size); allocation_bytes = size;
    CHECK(allocation_owned != 0);
    return allocation_owned;
}
void *MapViewOfFileEx(MB_HANDLE mapping, uint32_t access, uint32_t high, uint32_t low, size_t size, void *base)
{
    ++maps;
    last.mapping = mapping; last.access = access; last.high = high; last.low = low; last.size = size; last.base = base;
    if (map_fail) { error_value = 5; return 0; }
    CHECK(!view_owned);
    view_bytes = size ? size : 65536;
    view_owned = malloc(view_bytes); CHECK(view_owned != 0); memset(view_owned, 0x5a, view_bytes);
    return view_owned;
}
size_t VirtualQuery(const void *base, MB_MEMORY_BASIC_INFORMATION *info, size_t bytes)
{
    ++queries; CHECK(bytes == sizeof *info);
    if (query_fail) { error_value = 31; return 0; }
    memset(info, 0, sizeof *info);
    if (use_override) *info = query_override;
    else if (view_owned && (uintptr_t)base >= (uintptr_t)view_owned && (uintptr_t)base < (uintptr_t)view_owned + view_bytes) {
        info->AllocationBase = view_owned; info->BaseAddress = view_owned;
        info->RegionSize = view_bytes; info->Type = MB_MEM_MAPPED; info->State = MB_MEM_COMMIT;
    }
    error_value = 777; /* Adapter must restore the incoming status before the actual unmap. */
    return query_short ? sizeof *info - 1 : sizeof *info;
}
MB_BOOL UnmapViewOfFile(const void *base)
{
    ++unmaps;
    if (unmap_fail) { error_value = 1450; return 0; }
    CHECK(base == view_owned); free(view_owned); view_owned = 0; view_bytes = 0; return 1;
}

static void release_allocation(void)
{
    free(allocation_owned); allocation_owned = 0; allocation_bytes = 0;
}
static void rejected_alloc(MB_HANDLE process, void *base, size_t size, uint32_t type, uint32_t protection,
                           MB_EXTENDED_PARAMETER *parameters, uint32_t count, uint32_t expected)
{
    unsigned calls = allocations; void *owned = allocation_owned; size_t bytes = allocation_bytes;
    MB_EXTENDED_PARAMETER snapshot = {0}; if (parameters && parameters != (void *)1) snapshot = *parameters;
    error_value = 991;
    CHECK(!m98mb_VirtualAlloc2(process, base, size, type, protection, parameters, count));
    CHECK(error_value == expected); CHECK(allocations == calls);
    CHECK(owned == allocation_owned && bytes == allocation_bytes);
    if (owned) CHECK(((unsigned char *)owned)[0] == 0x4d);
    if (parameters && parameters != (void *)1) CHECK(!memcmp(&snapshot, parameters, sizeof snapshot));
}
static void rejected_map(MB_HANDLE process, void *base, uint64_t offset, size_t size, uint32_t type,
                         uint32_t protection, MB_EXTENDED_PARAMETER *parameters, uint32_t count, uint32_t expected)
{
    unsigned calls = maps; void *owned = view_owned; size_t bytes = view_bytes;
    error_value = 991;
    CHECK(!m98mb_MapViewOfFile3((void *)0x42, process, base, offset, size, type, protection, parameters, count));
    CHECK(error_value == expected); CHECK(maps == calls);
    CHECK(owned == view_owned && bytes == view_bytes);
    if (owned) CHECK(((unsigned char *)owned)[0] == 0x71);
}
static void rejected_unmap(MB_HANDLE process, void *base, uint32_t flags, uint32_t expected)
{
    unsigned calls = unmaps; void *owned = view_owned; size_t bytes = view_bytes;
    error_value = 991;
    CHECK(!m98mb_UnmapViewOfFile2(process, base, flags)); CHECK(error_value == expected);
    CHECK(unmaps == calls); CHECK(view_owned == owned && view_bytes == bytes);
    if (owned) CHECK(((unsigned char *)owned)[0] == 0x71);
}

int main(void)
{
    const uint32_t alloc_protections[] = {1, 2, 4, 0x10, 0x20, 0x40};
    const uint32_t map_protections[] = {2, 4, 8, 0x20, 0x40, 0x80};
    const uint32_t map_access[] = {4, 2, 1, 4 | 0x20, 2 | 0x20, 1 | 0x20};
    const uint32_t unsupported_alloc[] = {0x40000, 0x4000, 0x80000, 0x1000000, 0x20000000, 0x200000, 0x400000, 0x800000};
    const uint32_t unsupported_protection[] = {0, 3, 8, 0x80, 0x104, 0x204, 0x404, 0x40000040, 0xffffffff};
    MB_EXTENDED_PARAMETER parameters = {0xfeed000000000001ull, {.ULong64 = 0x1234567887654321ull}};
    void *memory, *view;
    unsigned i, j;

    for (i = 0; i < sizeof alloc_protections / sizeof *alloc_protections; ++i) {
        for (j = 0; j < 3; ++j) {
            uint32_t types[] = {MB_MEM_COMMIT, MB_MEM_RESERVE, MB_MEM_COMMIT | MB_MEM_RESERVE | MB_MEM_TOP_DOWN};
            error_value = 909;
            memory = m98mb_VirtualAlloc2(j ? GetCurrentProcess() : 0, 0, 8192, types[j], alloc_protections[i], (void *)1, 0);
            CHECK(memory == allocation_owned && memory); CHECK(last.process == GetCurrentProcess());
            CHECK(last.type == types[j] && last.protection == alloc_protections[i] && last.size == 8192);
            CHECK(error_value == 909);
            unsigned char combined = 0;
            for (size_t n = 0; n < 8192; ++n) combined |= ((unsigned char *)memory)[n];
            CHECK(combined == 0);
            release_allocation();
        }
    }
    memory = m98mb_VirtualAlloc2(0, 0, 4096, MB_MEM_COMMIT | MB_MEM_RESERVE, 4, 0, 0);
    CHECK(memory); ((unsigned char *)memory)[0] = 0x4d;
    for (i = 0; i < sizeof unsupported_alloc / sizeof *unsupported_alloc; ++i)
        rejected_alloc(0, 0, 4096, MB_MEM_RESERVE | unsupported_alloc[i], 4, 0, 0, 50);
    for (i = 0; i < sizeof unsupported_protection / sizeof *unsupported_protection; ++i)
        rejected_alloc(0, 0, 4096, MB_MEM_RESERVE, unsupported_protection[i], 0, 0, 50);
    rejected_alloc(0, 0, 4096, 0, 4, 0, 0, 87);
    rejected_alloc(0, 0, 0, MB_MEM_RESERVE, 4, 0, 0, 87);
    rejected_alloc(0, 0, 4097, MB_MEM_RESERVE, 4, 0, 0, 87);
    rejected_alloc(0, (void *)0x10001, 4096, MB_MEM_RESERVE, 4, 0, 0, 87);
    rejected_alloc(0, (void *)0xffffffffffff0000ull, 4096, MB_MEM_RESERVE, 4, 0, 0, 487);
    rejected_alloc(0, (void *)0x7ffffffe0000ull, 131072, MB_MEM_RESERVE, 4, 0, 0, 487);
    rejected_alloc(0, 0, SIZE_MAX - 4095, MB_MEM_RESERVE, 4, 0, 0, 87);
    rejected_alloc(0, 0, 4096, MB_MEM_RESERVE, 4, &parameters, 1, 50);
    rejected_alloc(0, 0, 4096, MB_MEM_RESERVE, 4, (void *)1, UINT32_MAX, 50);
    rejected_alloc(0, 0, 4096, MB_MEM_RESERVE, 4, 0, 1, 87);
    rejected_alloc((void *)0xc1, 0, 4096, MB_MEM_RESERVE, 4, 0, 0, 50);
    rejected_alloc((void *)0xc2, 0, 4096, MB_MEM_RESERVE, 4, 0, 0, 50);
    rejected_alloc((void *)0xbad, 0, 4096, MB_MEM_RESERVE, 4, 0, 0, 1236);
    page_size = 0; rejected_alloc(0, 0, 4096, MB_MEM_RESERVE, 4, 0, 0, 50); page_size = 4096;
    granularity = 6000; rejected_alloc(0, 0, 4096, MB_MEM_RESERVE, 4, 0, 0, 50); granularity = 65536;
    release_allocation(); alloc_fail = 1; error_value = 909;
    CHECK(!m98mb_VirtualAlloc2(0, 0, 4096, MB_MEM_COMMIT, 4, 0, 0)); CHECK(error_value == 8 && !allocation_owned);
    alloc_fail = 0;
    CHECK(m98mb_VirtualAlloc2(0, (void *)0x20000, 4096, MB_MEM_COMMIT, 4, 0, 0) == (void *)0x20000);
    CHECK(last.base == (void *)0x20000 && last.type == MB_MEM_COMMIT);

    for (i = 0; i < sizeof map_protections / sizeof *map_protections; ++i) {
        error_value = 909;
        view = m98mb_MapViewOfFile3((void *)0x42, i & 1 ? GetCurrentProcess() : 0, (void *)0x12345678abcdull,
                                   0x123400000000ull, i & 1 ? 4096 : 0, 0, map_protections[i], (void *)1, 0);
        CHECK(view && view == view_owned); CHECK(last.mapping == (void *)0x42 && last.access == map_access[i]);
        CHECK(last.base == (void *)0x123456780000ull && last.high == 0x1234 && last.low == 0);
        CHECK(last.size == (i & 1 ? 4096u : 0u) && error_value == 909);
        CHECK(((unsigned char *)view)[0] == 0x5a); ((unsigned char *)view)[0] = 0x71;
        error_value = 909; CHECK(m98mb_UnmapViewOfFile2(GetCurrentProcess(), view, 0));
        CHECK(!view_owned && error_value == 909);
    }
    view = m98mb_MapViewOfFile3((void *)0x42, 0, 0, 0, 4096, 0, 4, 0, 0);
    CHECK(view); ((unsigned char *)view)[0] = 0x71;
    for (i = 0; i < sizeof unsupported_alloc / sizeof *unsupported_alloc; ++i)
        rejected_map(0, 0, 0, 4096, unsupported_alloc[i], 4, 0, 0, 50);
    rejected_map(0, 0, 0, 4096, MB_MEM_RESERVE, 4, 0, 0, 50);
    for (i = 0; i < 4; ++i) {
        uint32_t p[] = {MB_PAGE_NOACCESS, MB_PAGE_EXECUTE, 0x104, 0};
        rejected_map(0, 0, 0, 4096, 0, p[i], 0, 0, 50);
    }
    rejected_map(0, 0, 1, 4096, 0, 4, 0, 0, 1132);
    rejected_map(0, 0, 0, 4097, 0, 4, 0, 0, 87);
    rejected_map(0, 0, 0x8000000000000000ull, 4096, 0, 4, 0, 0, 50);
    rejected_map(0, 0, 0x7fffffffffff0000ull, 65536, 0, 4, 0, 0, 50);
    rejected_map(0, (void *)UINTPTR_MAX, 0, 4096, 0, 4, 0, 0, 487);
    rejected_map(0, (void *)1, 0, 4096, 0, 4, 0, 0, 487);
    rejected_map(0, 0, 0, 4096, 0, 4, &parameters, 1, 50);
    rejected_map(0, 0, 0, 4096, 0, 4, 0, 1, 87);
    rejected_map((void *)0xc1, 0, 0, 4096, 0, 4, 0, 0, 50);
    rejected_map((void *)0xc2, 0, 0, 4096, 0, 4, 0, 0, 50);
    rejected_map((void *)0xbad, 0, 0, 4096, 0, 4, 0, 0, 1236);
    for (i = 0; i < 4; ++i) rejected_unmap(GetCurrentProcess(), view, i ? i : UINT32_MAX, 50);
    rejected_unmap(0, view, 0, 6);
    rejected_unmap((void *)0xc1, view, 0, 50);
    rejected_unmap((void *)0xc2, view, 0, 50);
    rejected_unmap((void *)0xbad, view, 0, 1236);
    rejected_unmap(GetCurrentProcess(), 0, 0, 487);
    rejected_unmap(GetCurrentProcess(), (char *)view + 1, 0, 487);
    query_short = 1; rejected_unmap(GetCurrentProcess(), view, 0, 50); query_short = 0;
    query_fail = 1; rejected_unmap(GetCurrentProcess(), view, 0, 31); query_fail = 0;
    use_override = 1; memset(&query_override, 0, sizeof query_override); query_override.AllocationBase = view;
    query_override.State = MB_MEM_COMMIT;
    rejected_unmap(GetCurrentProcess(), view, 0, 487);
    query_override.Type = MB_MEM_IMAGE; rejected_unmap(GetCurrentProcess(), view, 0, 50);
    query_override.Type = MB_MEM_MAPPED; query_override.State = 0; rejected_unmap(GetCurrentProcess(), view, 0, 487);
    use_override = 0; unmap_fail = 1; error_value = 909;
    CHECK(!m98mb_UnmapViewOfFile2(GetCurrentProcess(), view, 0)); CHECK(error_value == 1450 && view_owned == view);
    unmap_fail = 0; error_value = 909;
    CHECK(m98mb_UnmapViewOfFile2(GetCurrentProcess(), view, 0)); CHECK(!view_owned && error_value == 909);
    rejected_unmap(GetCurrentProcess(), view, 0, 487);
    map_fail = 1; error_value = 909;
    CHECK(!m98mb_MapViewOfFile3((void *)0x42, 0, 0, 0, 4096, 0, 4, 0, 0)); CHECK(error_value == 5 && !view_owned);
    CHECK(!allocation_owned && !view_owned && process_queries > 0 && queries > 0);
    printf("PASS: %u basic-memory translation, failure, untouched-input and ownership assertions\n", checks);
    return 0;
}
