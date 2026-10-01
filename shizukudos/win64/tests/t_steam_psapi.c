/* SPDX-License-Identifier: GPL-2.0-only
 * Actual legacy PSAPI imports forward to measured kernel accounting/modules.
 * Define version 1 so headers do not silently redirect imports to K32* names.
 */
#define PSAPI_VERSION 1
#include "k32test.h"
#include <psapi.h>

int main(void)
{
    HMODULE module = GetModuleHandleW(NULL), psapi = LoadLibraryW(L"psapi.dll");
    MODULEINFO information;
    WCHAR ordinary[512], forwarded[512];
    PROCESS_MEMORY_COUNTERS_EX before, after;
    BYTE *allocated;
    SIZE_T n;
    DWORD length, expected;

    CHECK(psapi != NULL && GetProcAddress(psapi, "GetProcessMemoryInfo") && GetProcAddress(psapi, "GetModuleFileNameExW") &&
          GetProcAddress(psapi, "GetModuleInformation"), "actual PSAPI module exports all three Steam eager import names");
    memset(&information, 0, sizeof information);
    CHECK(GetModuleInformation(GetCurrentProcess(), module, &information, sizeof information) && information.lpBaseOfDll == module && information.SizeOfImage > 0 &&
          (ULONG_PTR)information.EntryPoint >= (ULONG_PTR)module && (ULONG_PTR)information.EntryPoint < (ULONG_PTR)module + information.SizeOfImage,
          "legacy PSAPI import reports the actual loaded main image bounds and entry point");
    CHECK(!GetModuleInformation(GetCurrentProcess(), module, &information, sizeof information - 1) && GetLastError() == ERROR_INSUFFICIENT_BUFFER,
          "forwarded module query preserves backend short-buffer failure");
    expected = GetModuleFileNameW(module, ordinary, 512);
    length = GetModuleFileNameExW(GetCurrentProcess(), module, forwarded, 512);
    CHECK(length == expected && length > 0 && k32t_weq(forwarded, ordinary), "legacy PSAPI module name equals actual loader path");
    memset(&before, 0, sizeof before);
    CHECK(GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&before, sizeof before) && before.cb == sizeof before &&
          before.WorkingSetSize > 0 && before.PeakWorkingSetSize >= before.WorkingSetSize && before.PrivateUsage == before.PagefileUsage,
          "legacy PSAPI reports nonzero measured working set and consistent private commitment");
    allocated = VirtualAlloc(NULL, 1024 * 1024, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(allocated != NULL, "actual committed allocation created for accounting query");
    if (allocated) {
        for (n = 0; n < 1024 * 1024; n += 4096) allocated[n] = (BYTE)n;
        memset(&after, 0, sizeof after);
        CHECK(GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&after, sizeof after) &&
              after.PrivateUsage >= before.PrivateUsage + 1024 * 1024 && after.WorkingSetSize >= before.WorkingSetSize + 1024 * 1024,
              "PSAPI forwarder observes actual allocation commitment and touched physical pages");
        VirtualFree(allocated, 0, MEM_RELEASE);
    }
    CHECK(!GetProcessMemoryInfo(NULL, (PROCESS_MEMORY_COUNTERS *)&after, sizeof after) && GetLastError() == ERROR_INVALID_HANDLE,
          "legacy PSAPI validates an actual process handle");
    if (psapi) FreeLibrary(psapi);
    return k32t_finish("T_STEAM_PSAPI");
}
