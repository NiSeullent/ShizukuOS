/* SPDX-License-Identifier: GPL-2.0-only
 * Only the actual native backend's Win32 boundaries are modeled. The genuine
 * executables are separately compiled with the installed MinGW declarations. */
#ifndef SHZ_THEME_MOCK_WINDOWS_H
#define SHZ_THEME_MOCK_WINDOWS_H
#include <stddef.h>
#include <stdint.h>
typedef uint32_t DWORD, COLORREF;
typedef int32_t LONG;
typedef size_t SIZE_T;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HKEY;
typedef struct OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize,dwMajorVersion,dwMinorVersion,dwBuildNumber,dwPlatformId;
    char szCSDVersion[128];
} OSVERSIONINFOA;
#define MAX_PATH 260
#define TRUE 1
#define FALSE 0
#define VER_PLATFORM_WIN32_WINDOWS 1u
#define HKEY_CURRENT_USER ((HKEY)(uintptr_t)0x80000001u)
#define KEY_QUERY_VALUE 1u
#define KEY_SET_VALUE 2u
#define REG_OPTION_NON_VOLATILE 0u
#define ERROR_SUCCESS 0u
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_PATH_NOT_FOUND 3u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_INVALID_DATA 13u
#define ERROR_GEN_FAILURE 31u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_MORE_DATA 234u
#define ERROR_TIMEOUT 1460u
#define WAIT_OBJECT_0 0u
#define WAIT_ABANDONED 0x80u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED 0xffffffffu
DWORD GetLastError(void);
BOOL GetVersionExA(OSVERSIONINFOA *);
DWORD GetModuleFileNameA(HANDLE,char *,DWORD);
HANDLE CreateMutexA(void *,BOOL,const char *);
DWORD WaitForSingleObject(HANDLE,DWORD);
BOOL ReleaseMutex(HANDLE);
BOOL CloseHandle(HANDLE);
DWORD GetSysColor(int);
BOOL SetSysColors(int,const int *,const COLORREF *);
LONG RegOpenKeyExA(HKEY,const char *,DWORD,DWORD,HKEY *);
LONG RegCreateKeyExA(HKEY,const char *,DWORD,char *,DWORD,DWORD,void *,HKEY *,DWORD *);
LONG RegQueryValueExA(HKEY,const char *,DWORD *,DWORD *,unsigned char *,DWORD *);
LONG RegSetValueExA(HKEY,const char *,DWORD,DWORD,const unsigned char *,DWORD);
LONG RegDeleteValueA(HKEY,const char *);
LONG RegFlushKey(HKEY);
LONG RegCloseKey(HKEY);
#endif
