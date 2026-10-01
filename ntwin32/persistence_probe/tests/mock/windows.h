/* SPDX-License-Identifier: GPL-2.0-only -- host model, never native Windows. */
#ifndef PERSCHK_MOCK_WINDOWS_H
#define PERSCHK_MOCK_WINDOWS_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
#define FALSE 0
#define TRUE 1
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define CREATE_NEW 1u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define STD_OUTPUT_HANDLE ((DWORD)-11)
HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
BOOL ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
DWORD GetFileSize(HANDLE,DWORD *);
DWORD GetVersion(void);
HANDLE GetStdHandle(DWORD);
char *GetCommandLineA(void);
void ExitProcess(DWORD);
#endif
