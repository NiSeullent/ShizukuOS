/* SPDX-License-Identifier: GPL-2.0-only; hosted ABI fixture, not native evidence. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <wchar.h>
#include <sched.h>
#define DLLAPI
#define WINAPI
#define NULL_HANDLE ((void *)0)
typedef int32_t LONG, PDH_STATUS;
typedef uint32_t DWORD, *LPDWORD;
typedef uintptr_t ULONG_PTR, DWORD_PTR;
typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;
typedef wchar_t WCHAR;
typedef const WCHAR *LPCWSTR;
typedef void *PDH_HQUERY, *PDH_HCOUNTER;
typedef struct { DWORD dwLowDateTime, dwHighDateTime; } FILETIME;
typedef struct { DWORD CStatus; union { LONG longValue; double doubleValue; LONGLONG largeValue; }; } PDH_FMT_COUNTERVALUE, *PPDH_FMT_COUNTERVALUE;
typedef struct { DWORD CStatus; FILETIME TimeStamp; LONGLONG FirstValue, SecondValue; DWORD MultiCount; } PDH_RAW_COUNTER, *PPDH_RAW_COUNTER;
#define HEAP_ZERO_MEMORY 8
#define PDH_INVALID_ARGUMENT ((PDH_STATUS)0xc0000bbdu)
#define PDH_INVALID_HANDLE ((PDH_STATUS)0xc0000bbcu)
#define PDH_MEMORY_ALLOCATION_FAILURE ((PDH_STATUS)0xc0000bbbu)
#define PDH_NOT_IMPLEMENTED ((PDH_STATUS)0xc0000bd3u)
#define PDH_NO_DATA ((PDH_STATUS)0x800007d5u)
#define PDH_INVALID_DATA ((PDH_STATUS)0xc0000bc6u)
#define PDH_CSTATUS_NO_MACHINE ((PDH_STATUS)0x800007d0u)
#define PDH_CSTATUS_NO_COUNTER ((PDH_STATUS)0xc0000bb9u)
#define PDH_CSTATUS_INVALID_DATA ((DWORD)0xc0000bbau)
#define PDH_CSTATUS_VALID_DATA 0
#define PDH_CSTATUS_NEW_DATA 1
#define PDH_FMT_LONG 0x100u
#define PDH_FMT_DOUBLE 0x200u
#define PDH_FMT_LARGE 0x400u
#define PDH_FMT_NOSCALE 0x1000u
#define PDH_FMT_1000 0x2000u
#define PDH_FMT_NOCAP100 0x8000u
#define PERF_100NSEC_TIMER_INV 0x21510500u
#define PERF_ELAPSED_TIME 0x30240500u
static LONG InterlockedCompareExchange(volatile LONG *p,LONG value,LONG expected)
{ __atomic_compare_exchange_n(p,&expected,value,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return expected; }
static LONG InterlockedExchange(volatile LONG *p,LONG value) { return __atomic_exchange_n(p,value,__ATOMIC_SEQ_CST); }
static void Sleep(DWORD ms) { (void)ms;sched_yield(); }
static void *GetProcessHeap(void) { return (void *)1; }
static void *HeapAlloc(void *h,DWORD flags,size_t size) { (void)h;(void)flags;return calloc(1,size); }
static int HeapFree(void *h,DWORD flags,void *p) { (void)h;(void)flags;free(p);return 1; }
static int GetComputerNameW(WCHAR *out,DWORD *size) { const WCHAR *name=L"ShizukuDOS";size_t n=wcslen(name);if(*size<=n)return 0;wcscpy(out,name);*size=(DWORD)n;return 1; }
static uint64_t snapshot_idle,snapshot_kernel,snapshot_user,snapshot_uptime;
static int snapshot_failure;
static FILETIME ft(uint64_t v) { FILETIME value={(DWORD)v,(DWORD)(v>>32)};return value; }
static int GetSystemTimes(FILETIME *idle,FILETIME *kernel,FILETIME *user)
{ if(snapshot_failure)return 0;*idle=ft(snapshot_idle);*kernel=ft(snapshot_kernel);*user=ft(snapshot_user);return 1; }
static ULONGLONG GetTickCount64(void) { return snapshot_uptime; }
static void GetSystemTimeAsFileTime(FILETIME *stamp) { *stamp=ft(123000000000ull+snapshot_uptime*10000); }
