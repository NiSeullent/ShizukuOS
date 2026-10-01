/* SPDX-License-Identifier: GPL-2.0-only -- declarations for host controls. */
#ifndef NTW64_HANDLE_TEST_WINDOWS_H
#define NTW64_HANDLE_TEST_WINDOWS_H
#include <stddef.h>
#include <stdint.h>
#define WINAPI
typedef int BOOL;
typedef uint32_t DWORD;
typedef void *HANDLE;
typedef const uint16_t *LPCWSTR;
#define FALSE 0
#define TRUE 1
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define OPEN_EXISTING 3u
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000u
#define INFINITE UINT32_MAX
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_TOO_MANY_OPEN_FILES 4u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_GEN_FAILURE 31u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_BROKEN_PIPE 109u
#define ERROR_BUSY 170u
#define ERROR_BAD_EXE_FORMAT 193u
#define ERROR_REVISION_MISMATCH 1306u
void SetLastError(DWORD error);
DWORD GetLastError(void);
void Sleep(DWORD milliseconds);
DWORD GetTickCount(void);
HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
BOOL DeviceIoControl(HANDLE, DWORD, void *, DWORD, void *, DWORD, DWORD *, void *);
#endif
