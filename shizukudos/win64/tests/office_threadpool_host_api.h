/* SPDX-License-Identifier: GPL-2.0-only: host adapters use real pthread ownership. */
#ifndef SHZ_OFFICE_TP_HOST_API_H
#define SHZ_OFFICE_TP_HOST_API_H
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdatomic.h>
#define K32API
#define WINAPI
#define CALLBACK
#define TRUE 1
#define FALSE 0
#define INFINITE 0xffffffffu
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED 0xffffffffu
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define HEAP_ZERO_MEMORY 8u
#define DUPLICATE_SAME_ACCESS 2u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_TOO_MANY_POSTS 298u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_GEN_FAILURE 31u
#define ERROR_MAX_THRDS_REACHED 164u
#define TP_CALLBACK_PRIORITY_NORMAL 1u
typedef int BOOL;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef LONG NTSTATUS;
typedef uint32_t ULONG;
typedef uintptr_t ULONG_PTR;
typedef struct { unsigned short Length,MaximumLength; unsigned short *Buffer; } SHZ_UNICODE_STRING;
#define STATUS_INVALID_PARAMETER_3 ((LONG)0xc00000f1u)
#define STATUS_THREADPOOL_HANDLE_EXCEPTION ((LONG)0xc000070au)
typedef unsigned long long ULONGLONG;
typedef long long LONGLONG;
typedef void *PVOID;
typedef void *HANDLE;
typedef void *HMODULE;
typedef pthread_mutex_t CRITICAL_SECTION;
typedef CRITICAL_SECTION *PCRITICAL_SECTION;
typedef void *PTP_WORK;
typedef void *PTP_TIMER;
typedef void *PTP_WAIT;
typedef void *PTP_CALLBACK_INSTANCE;
typedef void *PTP_CALLBACK_ENVIRON;
typedef void (*PTP_WORK_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID,PTP_WORK);
typedef void (*PTP_TIMER_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID,PTP_TIMER);
typedef void (*PTP_WAIT_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID,PTP_WAIT,DWORD);
typedef void (*PTP_SIMPLE_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID);
typedef struct { DWORD dwLowDateTime,dwHighDateTime; } FILETIME,*PFILETIME;
typedef union { LONGLONG QuadPart; } LARGE_INTEGER;
void InitializeCriticalSection(CRITICAL_SECTION *);
void DeleteCriticalSection(CRITICAL_SECTION *);
void EnterCriticalSection(CRITICAL_SECTION *);
void LeaveCriticalSection(CRITICAL_SECTION *);
HANDLE CreateEventA(void *,BOOL,BOOL,const char *);
HANDLE CreateEventW(void *,BOOL,BOOL,const void *);
HANDLE CreateSemaphoreA(void *,LONG,LONG,const char *);
BOOL SetEvent(HANDLE);
BOOL ResetEvent(HANDLE);
BOOL ReleaseSemaphore(HANDLE,LONG,LONG *);
BOOL ReleaseMutex(HANDLE);
DWORD WaitForSingleObject(HANDLE,DWORD);
DWORD WaitForMultipleObjects(DWORD,const HANDLE *,BOOL,DWORD);
HANDLE CreateThread(void *,size_t,DWORD (*)(void *),void *,DWORD,DWORD *);
BOOL CloseHandle(HANDLE);
HANDLE GetCurrentProcess(void);
BOOL DuplicateHandle(HANDLE,HANDLE,HANDLE,HANDLE *,DWORD,BOOL,DWORD);
void *GetProcessHeap(void);
void *HeapAlloc(void *,DWORD,size_t);
BOOL HeapFree(void *,DWORD,void *);
BOOL FreeLibrary(HMODULE);
DWORD GetCurrentThreadId(void);
DWORD GetLastError(void);
void SetLastError(DWORD);
void Sleep(DWORD);
LONG NtQuerySystemTime(LARGE_INTEGER *);
LONG NtQueryObject(HANDLE,ULONG,PVOID,ULONG,ULONG *);
DWORD k32_nt_error(NTSTATUS);
void RaiseException(DWORD,DWORD,DWORD,const ULONG_PTR *);
void SubmitThreadpoolWork(PTP_WORK);
BOOL CallbackMayRunLong(PTP_CALLBACK_INSTANCE);
#endif
