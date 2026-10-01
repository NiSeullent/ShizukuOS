/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit host-only adapters for real Win64 provider contracts. This file is
 * never a production ABI header. Native fixtures use actual imported APIs. */
#ifndef SHZ_UCRT_LEGACY_HOST_CONTRACT_H
#define SHZ_UCRT_LEGACY_HOST_CONTRACT_H
#include "../dlls/ucrtbase/crtint.h"
typedef uint32_t os_dword;
typedef void *os_handle;
typedef int os_bool;
#define IMP_
#define WINAPI_
typedef struct {
    os_dword cb; wchar16 *lpReserved,*lpDesktop,*lpTitle;
    os_dword dwX,dwY,dwXSize,dwYSize,dwXCountChars,dwYCountChars,dwFillAttribute,dwFlags;
    uint16_t wShowWindow,cbReserved2; unsigned char *lpReserved2;
    os_handle hStdInput,hStdOutput,hStdError;
} os_startupinfow;
#define OS_CP_ACP 0
#define OS_CP_UTF8 65001
#define OS_FILE_ATTRIBUTE_READONLY 1
#define OS_FILE_ATTRIBUTE_DIRECTORY 16
#define OS_FILE_ATTRIBUTE_NORMAL 128
#define OS_INVALID_FILE_ATTRIBUTES UINT32_MAX
#define OS_STD_INPUT ((os_dword)-10)
#define OS_STD_OUTPUT ((os_dword)-11)
#define OS_STD_ERROR ((os_dword)-12)
#define OS_INFINITE UINT32_MAX
os_dword GetLastError(void);
os_dword GetCurrentProcessId(void);
int MultiByteToWideChar(unsigned,os_dword,const char *,int,wchar16 *,int);
int WideCharToMultiByte(unsigned,os_dword,const wchar16 *,int,char *,int,const char *,int *);
os_dword GetFileAttributesW(const wchar16 *);
os_dword GetFullPathNameW(const wchar16 *,os_dword,wchar16 *,wchar16 **);
os_dword GetCurrentDirectoryW(os_dword,wchar16 *);
os_handle GetModuleHandleW(const wchar16 *);
void *GetProcAddress(os_handle,const char *);
os_handle GetStdHandle(os_dword);
os_bool WriteFile(os_handle,const void *,os_dword,os_dword *,void *);
os_bool CreateProcessW(const wchar16 *,wchar16 *,void *,void *,os_bool,os_dword,void *,const wchar16 *,os_startupinfow *,void *);
os_dword WaitForSingleObject(os_handle,os_dword);
os_bool GetExitCodeProcess(os_handle,os_dword *);
os_bool CloseHandle(os_handle);
#endif
