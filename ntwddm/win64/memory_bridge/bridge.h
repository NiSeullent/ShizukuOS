/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_MEMORY_BRIDGE_H
#define M98_MEMORY_BRIDGE_H
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
# define MB_IMPORT __declspec(dllimport)
# define MB_ABI __attribute__((stdcall))
#else
# define MB_IMPORT
# define MB_ABI
#endif
typedef void *MB_HANDLE;
typedef uint32_t MB_ULONG;
typedef int32_t MB_BOOL;
typedef struct {
    uint64_t Type; /* Windows MEM_EXTENDED_PARAMETER: low 8 bits Type, reserved upper 56. */
    union { uint64_t ULong64; void *Pointer; size_t Size; MB_HANDLE Handle; MB_ULONG ULong; } u;
} MB_EXTENDED_PARAMETER;
typedef struct {
    union { uint32_t dwOemId; struct { uint16_t wProcessorArchitecture, wReserved; } cpu; } u;
    uint32_t dwPageSize;
    void *lpMinimumApplicationAddress, *lpMaximumApplicationAddress;
    uintptr_t dwActiveProcessorMask;
    uint32_t dwNumberOfProcessors, dwProcessorType, dwAllocationGranularity;
    uint16_t wProcessorLevel, wProcessorRevision;
} MB_SYSTEM_INFO;
typedef struct {
    void *BaseAddress, *AllocationBase;
    uint32_t AllocationProtect, padding1;
    size_t RegionSize;
    uint32_t State, Protect, Type, padding2;
} MB_MEMORY_BASIC_INFORMATION;

_Static_assert(sizeof(void *) == 8, "AMD64 adapter only");
_Static_assert(sizeof(MB_EXTENDED_PARAMETER) == 16, "Windows extended parameter ABI");
_Static_assert(sizeof(MB_SYSTEM_INFO) == 48, "Windows AMD64 SYSTEM_INFO ABI");
_Static_assert(sizeof(MB_MEMORY_BASIC_INFORMATION) == 48, "consumer AMD64 MBI ABI");

#define MB_MEM_COMMIT 0x1000u
#define MB_MEM_RESERVE 0x2000u
#define MB_MEM_TOP_DOWN 0x100000u
#define MB_MEM_MAPPED 0x40000u
#define MB_MEM_IMAGE 0x1000000u
#define MB_PAGE_NOACCESS 0x01u
#define MB_PAGE_READONLY 0x02u
#define MB_PAGE_READWRITE 0x04u
#define MB_PAGE_WRITECOPY 0x08u
#define MB_PAGE_EXECUTE 0x10u
#define MB_PAGE_EXECUTE_READ 0x20u
#define MB_PAGE_EXECUTE_READWRITE 0x40u
#define MB_PAGE_EXECUTE_WRITECOPY 0x80u
#define MB_FILE_MAP_COPY 0x01u
#define MB_FILE_MAP_WRITE 0x02u
#define MB_FILE_MAP_READ 0x04u
#define MB_FILE_MAP_EXECUTE 0x20u
#define MB_ERROR_INVALID_HANDLE 6u
#define MB_ERROR_NOT_SUPPORTED 50u
#define MB_ERROR_INVALID_PARAMETER 87u
#define MB_ERROR_INVALID_ADDRESS 487u
#define MB_ERROR_MAPPED_ALIGNMENT 1132u

MB_IMPORT MB_HANDLE MB_ABI GetCurrentProcess(void);
MB_IMPORT uint32_t MB_ABI GetCurrentProcessId(void);
MB_IMPORT uint32_t MB_ABI GetProcessId(MB_HANDLE);
MB_IMPORT uint32_t MB_ABI GetLastError(void);
MB_IMPORT void MB_ABI SetLastError(uint32_t);
MB_IMPORT void MB_ABI GetSystemInfo(MB_SYSTEM_INFO *);
MB_IMPORT void *MB_ABI VirtualAllocEx(MB_HANDLE, void *, size_t, uint32_t, uint32_t);
MB_IMPORT void *MB_ABI MapViewOfFileEx(MB_HANDLE, uint32_t, uint32_t, uint32_t, size_t, void *);
MB_IMPORT MB_BOOL MB_ABI UnmapViewOfFile(const void *);
MB_IMPORT size_t MB_ABI VirtualQuery(const void *, MB_MEMORY_BASIC_INFORMATION *, size_t);

void *MB_ABI m98mb_VirtualAlloc2(MB_HANDLE, void *, size_t, MB_ULONG, MB_ULONG,
                               MB_EXTENDED_PARAMETER *, MB_ULONG);
void *MB_ABI m98mb_MapViewOfFile3(MB_HANDLE, MB_HANDLE, void *, uint64_t, size_t,
                                MB_ULONG, MB_ULONG, MB_EXTENDED_PARAMETER *, MB_ULONG);
MB_BOOL MB_ABI m98mb_UnmapViewOfFile2(MB_HANDLE, void *, MB_ULONG);
#endif
