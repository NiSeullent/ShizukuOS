/* SPDX-License-Identifier: GPL-2.0-only -- original diagnostic host model. */
#ifndef NTWVDIAG_MOCK_H
#define NTWVDIAG_MOCK_H
#include <stddef.h>
#include <stdint.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef uintptr_t HANDLE;
typedef struct {
    DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber;
    DWORD dwPlatformId;
    char szCSDVersion[128];
} OSVERSIONINFOA;
#define FALSE 0
#define TRUE 1
#define INVALID_HANDLE_VALUE ((HANDLE)~(uintptr_t)0)
#define INVALID_FILE_SIZE 0xffffffffu
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 1u
#define CREATE_NEW 1u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000u
#define ERROR_SUCCESS 0u
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_PATH_NOT_FOUND 3u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_INVALID_DATA 13u
#define ERROR_HANDLE_EOF 38u
#define ERROR_FILE_EXISTS 80u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_BAD_EXE_FORMAT 193u
#define VER_PLATFORM_WIN32_WINDOWS 1u
HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, void *);
BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
BOOL ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
DWORD GetLastError(void);
BOOL GetVersionExA(OSVERSIONINFOA *);
DWORD GetFileSize(HANDLE, DWORD *);
BOOL DeviceIoControl(HANDLE, DWORD, void *, DWORD, void *, DWORD, DWORD *, void *);
_Noreturn void ExitProcess(DWORD);
#endif
