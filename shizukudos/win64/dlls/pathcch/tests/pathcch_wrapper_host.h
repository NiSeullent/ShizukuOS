/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stddef.h>
#include <wchar.h>
typedef wchar_t WCHAR;
typedef uint32_t DWORD;
typedef int32_t HRESULT;
typedef int BOOL;
typedef size_t SIZE_T;
typedef uintptr_t ULONG_PTR;
typedef void *HMODULE;
typedef int (*FARPROC)(void);
#define K32API
#define WINAPI
#define FALSE 0
#define S_OK ((HRESULT)0)
#define S_FALSE ((HRESULT)1)
#define ERROR_MOD_NOT_FOUND 126
#define ERROR_PROC_NOT_FOUND 127
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x800
#define HRESULT_FROM_WIN32(x) ((HRESULT)((x) ? (0x80070000u | ((x) & 0xffffu)) : 0))
static HMODULE LoadLibraryExW(const WCHAR *name, void *file, DWORD flags);
static FARPROC GetProcAddress(HMODULE module, const char *name);
static BOOL FreeLibrary(HMODULE module);
static DWORD GetLastError(void);
static void SetLastError(DWORD error);
