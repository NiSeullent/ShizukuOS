/* SPDX-License-Identifier: GPL-2.0-only; host logic controls, not native ABI proof */
#ifndef RPC_WAIT_MOCK_WINDOWS_H
#define RPC_WAIT_MOCK_WINDOWS_H
#include <stddef.h>
#include <stdint.h>
/* Host handles are opaque numeric tokens; zero is also a null pointer
 * constant for the remaining pointer arguments. Native uses real windows.h. */
#undef NULL
#define NULL 0
typedef uint32_t DWORD;typedef uint8_t BYTE;typedef int BOOL;typedef uintptr_t HANDLE;
typedef struct{DWORD cb;} STARTUPINFOA;
typedef struct{HANDLE hProcess,hThread;DWORD dwProcessId,dwThreadId;} PROCESS_INFORMATION;
typedef struct{DWORD dwOSVersionInfoSize,dwMajorVersion,dwMinorVersion,dwBuildNumber,dwPlatformId;char text[128];} OSVERSIONINFOA;
#define WINAPI
#define FALSE 0
#define TRUE 1
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 1
#define CREATE_NEW 1
#define OPEN_EXISTING 3
#define FILE_ATTRIBUTE_NORMAL 0x80
#define INVALID_FILE_SIZE 0xffffffffu
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 258
#define WAIT_FAILED 0xffffffffu
#define ERROR_TIMEOUT 1460
HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
BOOL ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
DWORD GetFileSize(HANDLE,DWORD *);
BOOL GetVersionExA(OSVERSIONINFOA *);
BOOL CreateProcessA(const char *,char *,void *,void *,BOOL,DWORD,void *,const char *,STARTUPINFOA *,PROCESS_INFORMATION *);
DWORD GetLastError(void);
DWORD WaitForSingleObject(HANDLE,DWORD);
BOOL GetExitCodeProcess(HANDLE,DWORD *);
_Noreturn void ExitProcess(DWORD);
#endif
