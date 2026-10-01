/* SPDX-License-Identifier: GPL-2.0-only
 * Exact LLP64 types and explicit host heap/address-wait/clock adapters.
 * No Windows syscall or application execution is claimed by this fixture. */
#ifndef SHZ_RTL_BOOTSTRAP_HOST_CONTRACT_H
#define SHZ_RTL_BOOTSTRAP_HOST_CONTRACT_H
#include <stdint.h>
#include <stddef.h>
typedef void VOID,*PVOID;
typedef uint16_t WCHAR,USHORT;
typedef int32_t LONG,BOOL,NTSTATUS;
typedef uint32_t ULONG,DWORD;
typedef uint8_t BOOLEAN;
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
typedef union {int64_t QuadPart;} LARGE_INTEGER,*PLARGE_INTEGER;
typedef struct {USHORT Length,MaximumLength;WCHAR *Buffer;} SHZ_UNICODE_STRING;
typedef struct {USHORT Length,MaximumLength;char *Buffer;} SHZ_BOOTSTRAP_ANSI_STRING;
typedef struct _RTL_RUN_ONCE {PVOID Ptr;} RTL_RUN_ONCE,*PRTL_RUN_ONCE;
typedef DWORD (*PRTL_RUN_ONCE_INIT_FN)(PRTL_RUN_ONCE,PVOID,PVOID *);
#define SHZ_EXPORT
#define NTAPI
#define TRUE 1
#define FALSE 0
#define NT_SUCCESS(x) ((NTSTATUS)(x)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_INVALID_PARAMETER_2 ((NTSTATUS)0xc00000f0)
#define STATUS_NO_MEMORY ((NTSTATUS)0xc0000017)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define STATUS_SOME_NOT_MAPPED ((NTSTATUS)0x00000107)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022)
PVOID ShzProcessHeap(void);
PVOID RtlAllocateHeap(PVOID,ULONG,SIZE_T);
BOOLEAN RtlFreeHeap(PVOID,ULONG,PVOID);
NTSTATUS NtYieldExecution(void);
NTSTATUS NtQueryPerformanceCounter(PLARGE_INTEGER,PLARGE_INTEGER);
NTSTATUS RtlWaitOnAddress(volatile VOID *,PVOID,SIZE_T,PLARGE_INTEGER);
VOID RtlWakeAddressAll(PVOID);
SIZE_T RtlCompareMemory(const VOID *,const VOID *,SIZE_T);
LONG RtlCompareUnicodeString(const SHZ_UNICODE_STRING *,const SHZ_UNICODE_STRING *,BOOLEAN);
BOOLEAN RtlEqualUnicodeString(const SHZ_UNICODE_STRING *,const SHZ_UNICODE_STRING *,BOOLEAN);
NTSTATUS RtlDuplicateUnicodeString(ULONG,const SHZ_UNICODE_STRING *,SHZ_UNICODE_STRING *);
NTSTATUS RtlAnsiStringToUnicodeString(SHZ_UNICODE_STRING *,const SHZ_BOOTSTRAP_ANSI_STRING *,BOOLEAN);
BOOL RtlQueryPerformanceCounter(PLARGE_INTEGER);
VOID RtlRunOnceInitialize(PRTL_RUN_ONCE);
NTSTATUS RtlRunOnceExecuteOnce(PRTL_RUN_ONCE,PRTL_RUN_ONCE_INIT_FN,PVOID,PVOID *);
_Static_assert(sizeof(SHZ_UNICODE_STRING)==16 && offsetof(SHZ_UNICODE_STRING,Buffer)==8,"native string ABI");
_Static_assert(sizeof(RTL_RUN_ONCE)==8 && sizeof(WCHAR)==2 && sizeof(LONG)==4,"native once/WCHAR/LONG ABI");
#endif
