/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_GLOBAL_BOOT_MOCK_H
#define SHZ_GLOBAL_BOOT_MOCK_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef unsigned char BYTE;
typedef void *HANDLE;
typedef void *HMODULE;
typedef struct { DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion,
    dwBuildNumber, dwPlatformId; char szCSDVersion[128]; } OSVERSIONINFOA;
typedef struct { DWORD cb; char *lpReserved, *lpDesktop, *lpTitle;
    DWORD dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars,
    dwFillAttribute, dwFlags; uint16_t wShowWindow, cbReserved2;
    BYTE *lpReserved2; HANDLE hStdInput, hStdOutput, hStdError; } STARTUPINFOA;
typedef struct { HANDLE hProcess, hThread; DWORD dwProcessId, dwThreadId; } PROCESS_INFORMATION;
#define FALSE 0
#define TRUE 1
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 1u
#define CREATE_NEW 1u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define VER_PLATFORM_WIN32_WINDOWS 1u
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED 0xffffffffu
#define ERROR_INVALID_DATA 13u
#define ERROR_READ_FAULT 30u
#define ERROR_WRITE_FAULT 29u
#define ERROR_BUFFER_OVERFLOW 111u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_INVALID_NAME 123u
#define ERROR_OLD_WIN_VERSION 1150u
#define ERROR_TIMEOUT 1460u
#define ERROR_INVALID_HANDLE 6u
HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
BOOL ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
BOOL CloseHandle(HANDLE);
BOOL FlushFileBuffers(HANDLE);
DWORD GetLastError(void);
char *GetCommandLineA(void);
DWORD GetCurrentProcessId(void);
DWORD GetModuleFileNameA(HMODULE,char *,DWORD);
BOOL GetVersionExA(OSVERSIONINFOA *);
BOOL CreateProcessA(const char *,char *,void *,void *,BOOL,DWORD,void *,const char *,STARTUPINFOA *,PROCESS_INFORMATION *);
DWORD WaitForSingleObject(HANDLE,DWORD);
BOOL GetExitCodeProcess(HANDLE,DWORD *);
#endif
