/* SPDX-License-Identifier: GPL-2.0-only
 * Test-only declarations for compiling the complete WinHTTP production TU.
 * No Windows API is simulated except the fixture's last-error register.
 */
#ifndef SHZ_WINHTTP_URL_6970_WINDOWS_H
#define SHZ_WINHTTP_URL_6970_WINDOWS_H
#include <stddef.h>
#include <stdint.h>

#define WINAPI
#define CALLBACK
typedef int BOOL;
typedef void VOID;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uintptr_t DWORD_PTR;
typedef wchar_t WCHAR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR, *PCWSTR;
typedef void *LPVOID, *HANDLE;
typedef const void *LPCVOID;
typedef DWORD *LPDWORD;
typedef struct {
    WORD wYear, wMonth, wDayOfWeek, wDay;
    WORD wHour, wMinute, wSecond, wMilliseconds;
} SYSTEMTIME;
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

#define TRUE 1
#define FALSE 0
#define HEAP_ZERO_MEMORY 0x00000008u
#define ERROR_SUCCESS 0u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define ERROR_IO_PENDING 997u
#define ERROR_INVALID_OPERATION 4317u

VOID WINAPI SetLastError(DWORD);
DWORD WINAPI GetLastError(void);
HANDLE WINAPI GetProcessHeap(void);
LPVOID WINAPI HeapAlloc(HANDLE, DWORD, size_t);
BOOL WINAPI HeapFree(HANDLE, DWORD, LPVOID);
BOOL WINAPI IsBadReadPtr(const void *, size_t);
LONG WINAPI InterlockedIncrement(volatile LONG *);
LONG WINAPI InterlockedDecrement(volatile LONG *);
HANDLE WINAPI CreateThread(LPVOID, size_t, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
BOOL WINAPI CloseHandle(HANDLE);

_Static_assert(sizeof(WCHAR) == 2, "fixture requires UTF-16 WCHAR and -fshort-wchar");
_Static_assert(sizeof(DWORD) == 4 && sizeof(LONG) == 4 && sizeof(WORD) == 2,
               "Windows scalar widths changed");
_Static_assert(sizeof(void *) == 8 && sizeof(DWORD_PTR) == 8,
               "this fixture models the Win64 parser's data layout only");
_Static_assert(sizeof(SYSTEMTIME) == 16, "Windows SYSTEMTIME layout changed");
#endif
