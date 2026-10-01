/* SPDX-License-Identifier: GPL-2.0-only
 * Host lifecycle mocks, not Windows ABI or guest execution evidence.
 */
#ifndef NTTHOBS_MOCK_H
#define NTTHOBS_MOCK_H
#include <stddef.h>
#include <stdint.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef struct {
    DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId;
} OSVERSIONINFOA;
typedef struct { DWORD cb, dwFlags; HANDLE hStdInput, hStdOutput, hStdError; } STARTUPINFOA;
typedef struct { HANDLE hProcess, hThread; DWORD dwProcessId, dwThreadId; } PROCESS_INFORMATION;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define INVALID_FILE_ATTRIBUTES UINT32_C(0xffffffff)
#define VER_PLATFORM_WIN32_WINDOWS 1u
#define LOWORD(value) ((DWORD)(value) & UINT32_C(0xffff))
#define GENERIC_WRITE UINT32_C(0x40000000)
#define GENERIC_READ UINT32_C(0x80000000)
#define FILE_SHARE_READ 1u
#define CREATE_NEW 1u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_NORMAL UINT32_C(0x80)
#define FILE_ATTRIBUTE_DIRECTORY UINT32_C(0x10)
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_TIMEOUT 1460u
#define WAIT_OBJECT_0 0u
#define WAIT_FAILED UINT32_C(0xffffffff)
#define WAIT_TIMEOUT 258u
#define MB_OK 0u
#define MB_ICONERROR 16u
char *GetCommandLineA(void);
DWORD GetModuleFileNameA(HANDLE, char *, DWORD);
HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
BOOL ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
int MessageBoxA(HANDLE, const char *, const char *, unsigned);
BOOL GetVersionExA(OSVERSIONINFOA *);
DWORD GetFileAttributesA(const char *);
DWORD GetLastError(void);
void SetLastError(DWORD);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
BOOL CreateProcessA(const char *, char *, void *, void *, BOOL, DWORD, void *,
                    const char *, STARTUPINFOA *, PROCESS_INFORMATION *);
DWORD WaitForSingleObject(HANDLE, DWORD);
BOOL GetExitCodeProcess(HANDLE, DWORD *);
BOOL TerminateProcess(HANDLE, DWORD);
#endif
