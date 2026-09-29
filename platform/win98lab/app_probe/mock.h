/* Original host-only interface declarations, not a Windows implementation. */
#ifndef NTWAPP_MOCK_H
#define NTWAPP_MOCK_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t DWORD;
typedef uint32_t UINT;
typedef int BOOL;
typedef uintptr_t HANDLE;
typedef uintptr_t HWND;
typedef uintptr_t ULONG_PTR;
typedef uintptr_t WPARAM;
typedef intptr_t LPARAM;
typedef struct { DWORD cb; unsigned char remaining[64]; } STARTUPINFOA;
typedef struct { HANDLE hProcess,hThread; DWORD dwProcessId,dwThreadId; } PROCESS_INFORMATION;
typedef struct { DWORD dwOSVersionInfoSize,dwMajorVersion,dwMinorVersion,dwBuildNumber,dwPlatformId; char szCSDVersion[128]; } OSVERSIONINFOA;
#define CALLBACK
#define FALSE 0
#define TRUE 1
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)~(uintptr_t)0)
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 1u
#define CREATE_NEW 1u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED 0xffffffffu
#define VER_PLATFORM_WIN32_WINDOWS 1u
#define SEM_FAILCRITICALERRORS 1u
#define SEM_NOOPENFILEERRORBOX 0x8000u
#define WM_CLOSE 0x10u
DWORD GetModuleFileNameA(void *,char *,DWORD);
HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,void *);
BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
DWORD GetLastError(void);
void SetLastError(DWORD);
BOOL GetVersionExA(OSVERSIONINFOA *);
UINT SetErrorMode(UINT);
DWORD GetTickCount(void);
BOOL CreateProcessA(const char *,char *,void *,void *,BOOL,DWORD,void *,const char *,STARTUPINFOA *,PROCESS_INFORMATION *);
DWORD WaitForSingleObject(HANDLE,DWORD);
BOOL GetExitCodeProcess(HANDLE,DWORD *);
BOOL TerminateProcess(HANDLE,DWORD);
BOOL EnumWindows(BOOL (CALLBACK *)(HWND,LPARAM),LPARAM);
DWORD GetWindowThreadProcessId(HWND,DWORD *);
BOOL IsWindowVisible(HWND);
int GetWindowTextA(HWND,char *,int);
int GetClassNameA(HWND,char *,int);
BOOL PostMessageA(HWND,UINT,WPARAM,LPARAM);
_Noreturn void ExitProcess(DWORD);
#endif
