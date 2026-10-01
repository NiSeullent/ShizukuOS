/* SPDX-License-Identifier: GPL-2.0-only -- host callback controls only. */
#ifndef MEMPROBE_MOCK_WINDOWS_H
#define MEMPROBE_MOCK_WINDOWS_H
#include <stddef.h>
#include <stdint.h>
#define WINAPI
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void (*FARPROC)(void);
typedef uintptr_t UINT_PTR;
typedef struct {void *BaseAddress,*AllocationBase;DWORD AllocationProtect;size_t RegionSize;DWORD State,Protect,Type;} MEMORY_BASIC_INFORMATION;
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define GENERIC_WRITE 0x40000000u
#define CREATE_NEW 1u
#define FILE_ATTRIBUTE_NORMAL 128u
#define MEM_COMMIT 0x1000u
#define PAGE_READONLY 2u
#define PAGE_READWRITE 4u
#define PAGE_WRITECOPY 8u
#define PAGE_EXECUTE_READ 32u
#define PAGE_EXECUTE_READWRITE 64u
#define PAGE_EXECUTE_WRITECOPY 128u
DWORD GetLastError(void);
void SetLastError(DWORD);
HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
HMODULE GetModuleHandleA(const char *);
size_t VirtualQuery(const void *,MEMORY_BASIC_INFORMATION *,size_t);
#endif
