/* SPDX-License-Identifier: GPL-2.0-only
 * Host controls for the real provider source. These mock native API results
 * test forwarding/error behavior; they are not Windows execution evidence.
 */
#ifndef VLC_COMPAT_MOCK_WINDOWS_H
#define VLC_COMPAT_MOCK_WINDOWS_H
#include <stddef.h>
#include <stdint.h>
#define WINAPI
#define __declspec(x)
typedef int BOOL;
typedef uint32_t DWORD, ULONG, UINT;
typedef int32_t LONG;
typedef uint16_t WCHAR;
typedef void *HANDLE;
typedef HANDLE HWND, HMODULE, HINSTANCE;
typedef void *PVOID, *LPVOID;
typedef char *LPSTR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef size_t SIZE_T;
/* Match the PE32 SDK's unprototyped, 32-bit generic export pointer. */
typedef int (*FARPROC)();
typedef union { struct { DWORD LowPart; LONG HighPart; }; int64_t QuadPart; } LARGE_INTEGER;
typedef LARGE_INTEGER *PLARGE_INTEGER;
typedef struct { DWORD opaque[12]; } SYSTEM_INFO, *LPSYSTEM_INFO;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define FILE_BEGIN 0
#define FILE_CURRENT 1
#define FILE_END 2
#define FILE_TYPE_UNKNOWN 0
#define FILE_TYPE_DISK 1
#define FILE_TYPE_PIPE 3
#define INVALID_SET_FILE_POINTER 0xffffffffu
#define NO_ERROR 0
#define ERROR_INVALID_FUNCTION 1
#define ERROR_INVALID_HANDLE 6
#define ERROR_NOT_SUPPORTED 50
#define ERROR_INVALID_PARAMETER 87
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_CALL_NOT_IMPLEMENTED 120
#define ERROR_NO_UNICODE_TRANSLATION 1113
#define CP_ACP 0
#define MB_PRECOMPOSED 1
DWORD GetLastError(void);
void SetLastError(DWORD);
DWORD GetFileType(HANDLE);
DWORD SetFilePointer(HANDLE, LONG, LONG *, DWORD);
void GetSystemInfo(LPSYSTEM_INFO);
BOOL HeapValidate(HANDLE, DWORD, const void *);
int WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, const char *, BOOL *);
int MultiByteToWideChar(UINT, DWORD, const char *, int, LPWSTR, int);
BOOL RemoveFontResourceA(const char *);
HMODULE GetModuleHandleA(const char *);
FARPROC GetProcAddress(HMODULE, const char *);
#endif
