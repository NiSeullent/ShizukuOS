/* SPDX-License-Identifier: GPL-2.0-only — modeled Win32 calls, no Windows */
#include <stdint.h>
#include <stddef.h>
typedef uint32_t DWORD;typedef int32_t LONG;typedef unsigned char *LPBYTE;
typedef void *HANDLE;typedef void *HKEY;
typedef struct {DWORD dwOSVersionInfoSize,dwMajorVersion,dwMinorVersion,dwBuildNumber,dwPlatformId;char text[128];} OSVERSIONINFOA;
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define HKEY_LOCAL_MACHINE ((HKEY)(intptr_t)1)
#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_MORE_DATA 234
#define ERROR_NO_MORE_ITEMS 259
#define REG_SZ 1
#define KEY_QUERY_VALUE 1
#define KEY_ENUMERATE_SUB_KEYS 8
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 1
#define CREATE_NEW 1
#define FILE_ATTRIBUTE_NORMAL 128
#define VER_PLATFORM_WIN32_WINDOWS 1
int WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
LONG RegQueryValueExA(HKEY,const char *,void *,DWORD *,LPBYTE,DWORD *);
LONG RegEnumKeyExA(HKEY,DWORD,char *,DWORD *,void *,void *,void *,void *);
LONG RegOpenKeyExA(HKEY,const char *,DWORD,DWORD,HKEY *);
LONG RegCloseKey(HKEY);
int lstrcmpiA(const char *,const char *);
DWORD GetTickCount(void);
int GetVersionExA(OSVERSIONINFOA *);
HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,void *);
int FlushFileBuffers(HANDLE);
int CloseHandle(HANDLE);
int DeleteFileA(const char *);
_Noreturn void ExitProcess(DWORD);
