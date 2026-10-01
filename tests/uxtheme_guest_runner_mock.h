/* SPDX-License-Identifier: GPL-2.0-only
 * Minimal API types for host failure injection; never used in the PE build. */
#ifndef M98_GUEST_RUNNER_MOCK_H
#define M98_GUEST_RUNNER_MOCK_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef struct { DWORD nLength; void *lpSecurityDescriptor; BOOL bInheritHandle; } SECURITY_ATTRIBUTES;
typedef struct { DWORD cb, dwFlags; HANDLE hStdInput, hStdOutput, hStdError; } STARTUPINFOA;
typedef struct { HANDLE hProcess, hThread; DWORD dwProcessId, dwThreadId; } PROCESS_INFORMATION;
typedef struct { DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId; } OSVERSIONINFOA;
#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define INVALID_FILE_ATTRIBUTES UINT32_MAX
#define MAX_PATH 260
#define GENERIC_WRITE 0x40000000u
#define GENERIC_READ 0x80000000u
#define FILE_SHARE_READ 1u
#define FILE_SHARE_WRITE 2u
#define CREATE_NEW 1u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define STARTF_USESTDHANDLES 0x100u
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED UINT32_MAX
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_TIMEOUT 1460u
#define VER_PLATFORM_WIN32_WINDOWS 1u
#define LOWORD(v) ((DWORD)(v) & 0xffffu)
BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
DWORD GetFileAttributesA(const char *);
DWORD GetLastError(void);
void SetLastError(DWORD);
BOOL CloseHandle(HANDLE);
HANDLE CreateFileA(const char *, DWORD, DWORD, SECURITY_ATTRIBUTES *, DWORD, DWORD, HANDLE);
BOOL CreateProcessA(const char *, char *, void *, void *, BOOL, DWORD, void *, const char *, STARTUPINFOA *, PROCESS_INFORMATION *);
DWORD WaitForSingleObject(HANDLE, DWORD);
BOOL GetExitCodeProcess(HANDLE, DWORD *);
BOOL TerminateProcess(HANDLE, DWORD);
BOOL FlushFileBuffers(HANDLE);
BOOL GetVersionExA(OSVERSIONINFOA *);
DWORD GetModuleFileNameA(HANDLE, char *, DWORD);
int lstrcmpiA(const char *, const char *);
#endif
