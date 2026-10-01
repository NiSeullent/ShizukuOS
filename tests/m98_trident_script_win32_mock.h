/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_SCRIPT_WIN32_MOCK_H
#define M98_SCRIPT_WIN32_MOCK_H
#include <stdint.h>
#include <stddef.h>
#define __cdecl
#define WINAPI
#define MAX_PATH 260
#define TRUE 1
#define TIME_ZONE_ID_INVALID UINT32_MAX
typedef uint32_t DWORD;typedef unsigned UINT;typedef int BOOL;
typedef void *HMODULE;typedef void *HINSTANCE;typedef void *LPVOID;
typedef void (*FARPROC)(void);
typedef struct {DWORD dwLowDateTime,dwHighDateTime;} FILETIME;
typedef struct {int dummy;} TIME_ZONE_INFORMATION;
DWORD GetCurrentThreadId(void);
UINT GetSystemDirectoryA(char *,UINT);
HMODULE GetModuleHandleA(const char *);
DWORD GetModuleFileNameA(HMODULE,char *,DWORD);
int lstrcmpiA(const char *,const char *);
DWORD GetTimeZoneInformation(TIME_ZONE_INFORMATION *);
FARPROC GetProcAddress(HMODULE,const char *);
void GetSystemTimeAsFileTime(FILETIME *);
#endif
