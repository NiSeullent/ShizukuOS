/* SPDX-License-Identifier: GPL-2.0-only
 * Host-only minimal <windows.h> so lc_iocp_native.c compiles unmodified on the
 * build host for the error-ordering regression. Not a Win32 implementation. */
#ifndef LC_HOST_SHIM_WINDOWS_H
#define LC_HOST_SHIM_WINDOWS_H
#include <stddef.h>
#include <stdint.h>
#define WINAPI
#define TRUE 1
#define FALSE 0
typedef int BOOL; typedef uint32_t DWORD; typedef int32_t LONG; typedef void *LPVOID, *HANDLE;
typedef uintptr_t ULONG_PTR; typedef DWORD *LPDWORD; typedef ULONG_PTR *PULONG_PTR;
typedef HANDLE HINSTANCE;
typedef uint32_t ULONG, *PULONG;
typedef struct _OVERLAPPED { ULONG_PTR Internal, InternalHigh; DWORD Offset, OffsetHigh; HANDLE hEvent; } OVERLAPPED, *LPOVERLAPPED;
typedef struct _OVERLAPPED_ENTRY { ULONG_PTR lpCompletionKey; LPOVERLAPPED lpOverlapped; ULONG_PTR Internal; DWORD dwNumberOfBytesTransferred; } OVERLAPPED_ENTRY, *LPOVERLAPPED_ENTRY;
typedef struct _CRITICAL_SECTION { int depth; } CRITICAL_SECTION;
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define ERROR_INVALID_PARAMETER 87
#define ERROR_NOT_SUPPORTED 50
#define ERROR_DLL_INIT_FAILED 1114
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 258
#define WAIT_FAILED 0xffffffffu
#define DLL_PROCESS_ATTACH 1
#define DLL_PROCESS_DETACH 0
void SetLastError(DWORD); DWORD GetLastError(void);
void InitializeCriticalSection(CRITICAL_SECTION *); void DeleteCriticalSection(CRITICAL_SECTION *);
void EnterCriticalSection(CRITICAL_SECTION *); void LeaveCriticalSection(CRITICAL_SECTION *);
HANDLE CreateSemaphoreA(void *, LONG, LONG, const char *);
BOOL ReleaseSemaphore(HANDLE, LONG, LONG *); DWORD WaitForSingleObject(HANDLE, DWORD); BOOL CloseHandle(HANDLE);
#endif
