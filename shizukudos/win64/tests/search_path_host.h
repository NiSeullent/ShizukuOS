/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
typedef uint16_t WCHAR;
typedef uint32_t DWORD, ULONG;
typedef int32_t LONG, BOOL, NTSTATUS;
typedef void *HANDLE, *HMODULE;
typedef const WCHAR *LPCWSTR;
typedef WCHAR *LPWSTR;
typedef const char *LPCSTR;
typedef char *LPSTR;
typedef struct { uint16_t Length, MaximumLength; WCHAR *Buffer; } SHZ_UNICODE_STRING;
typedef struct { ULONG Length; HANDLE RootDirectory; SHZ_UNICODE_STRING *ObjectName; ULONG Attributes;
                 void *SecurityDescriptor, *SecurityQualityOfService; } SHZ_OBJECT_ATTRIBUTES;
#define K32API
#define WINAPI
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define ARRAYSIZE(a) (sizeof(a)/sizeof((a)[0]))
#define NT_SUCCESS(s) ((s)>=0)
#define CP_ACP 0
#define SHZ_KeyValuePartialInformation 2
#define INVALID_FILE_ATTRIBUTES 0xffffffffu
#define FILE_ATTRIBUTE_DIRECTORY 16
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_PARAMETER 87
#define ERROR_FILENAME_EXCED_RANGE 206
static _Thread_local DWORD last_error;
static void SetLastError(DWORD e) { last_error=e; }
static size_t k32_wlen(const WCHAR *s) { size_t n=0; while(s[n])++n; return n; }
static NTSTATUS NtOpenKey(HANDLE *, DWORD, SHZ_OBJECT_ATTRIBUTES *);
static NTSTATUS NtQueryValueKey(HANDLE, SHZ_UNICODE_STRING *, DWORD, void *, ULONG, ULONG *);
static NTSTATUS NtClose(HANDLE);
static DWORD GetFileAttributesW(LPCWSTR);
static DWORD GetFullPathNameW(LPCWSTR,DWORD,LPWSTR,LPWSTR *);
static DWORD GetModuleFileNameW(HMODULE,LPWSTR,DWORD);
static DWORD GetSystemDirectoryW(LPWSTR,DWORD);
static DWORD GetWindowsDirectoryW(LPWSTR,DWORD);
static DWORD GetCurrentDirectoryW(DWORD,LPWSTR);
static DWORD GetEnvironmentVariableW(LPCWSTR,LPWSTR,DWORD);
static int MultiByteToWideChar(unsigned,DWORD,LPCSTR,int,LPWSTR,int);
static int WideCharToMultiByte(unsigned,DWORD,LPCWSTR,int,LPSTR,int,LPCSTR,BOOL *);
