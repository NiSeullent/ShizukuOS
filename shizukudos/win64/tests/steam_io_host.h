/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_STEAM_IO_HOST_H
#define SHZ_STEAM_IO_HOST_H
#include <stdint.h>
#include <stddef.h>
#define WINAPI __attribute__((ms_abi))
#define K32API
#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define INVALID_FILE_ATTRIBUTES 0xffffffffu
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define FILE_WRITE_ATTRIBUTES 0x100u
#define FILE_SHARE_READ 1u
#define CREATE_NEW 1u
#define CREATE_ALWAYS 2u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_READONLY 1u
#define FILE_ATTRIBUTE_HIDDEN 2u
#define FILE_ATTRIBUTE_DIRECTORY 0x10u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define FILE_ATTRIBUTE_SPARSE_FILE 0x200u
#define FILE_ATTRIBUTE_REPARSE_POINT 0x400u
#define FILE_ATTRIBUTE_COMPRESSED 0x800u
#define FILE_ATTRIBUTE_ENCRYPTED 0x4000u
#define FILE_FLAG_SEQUENTIAL_SCAN 0x08000000u
#define COPY_FILE_FAIL_IF_EXISTS 1u
#define COPY_FILE_OPEN_SOURCE_FOR_WRITE 4u
#define PROGRESS_CONTINUE 0u
#define PROGRESS_CANCEL 1u
#define PROGRESS_STOP 2u
#define PROGRESS_QUIET 3u
#define CALLBACK_CHUNK_FINISHED 0u
#define CALLBACK_STREAM_SWITCH 1u
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_WRITE_FAULT 29u
#define ERROR_HANDLE_EOF 38u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_FILE_EXISTS 80u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_REQUEST_ABORTED 1235u

typedef uint8_t BYTE;
typedef uint16_t WCHAR;
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef void *PVOID;
typedef void *LPVOID;
typedef BOOL *LPBOOL;
typedef const WCHAR *LPCWSTR;
typedef union { struct { DWORD LowPart; int32_t HighPart; }; int64_t QuadPart; } LARGE_INTEGER;
typedef struct { DWORD dwLowDateTime, dwHighDateTime; } FILETIME;
typedef struct { DWORD dwFileAttributes; FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
    DWORD dwVolumeSerialNumber,nFileSizeHigh,nFileSizeLow,nNumberOfLinks,nFileIndexHigh,nFileIndexLow; } BY_HANDLE_FILE_INFORMATION;
typedef DWORD (WINAPI *LPPROGRESS_ROUTINE)(LARGE_INTEGER,LARGE_INTEGER,LARGE_INTEGER,LARGE_INTEGER,DWORD,DWORD,HANDLE,HANDLE,LPVOID);
DWORD shz_last_error(void);
void shz_set_last_error(DWORD);
BOOL k32_unsupported(const char *,const char *,DWORD);
void *ShzProcessHeap(void);
void *RtlAllocateHeap(void *,DWORD,size_t);
BOOL RtlFreeHeap(void *,DWORD,void *);
HANDLE WINAPI CreateFileW(LPCWSTR,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
BOOL WINAPI GetFileInformationByHandle(HANDLE,BY_HANDLE_FILE_INFORMATION *);
BOOL WINAPI GetFileSizeEx(HANDLE,LARGE_INTEGER *);
DWORD WINAPI GetFileAttributesW(LPCWSTR);
BOOL WINAPI ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
BOOL WINAPI WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
BOOL WINAPI SetFileTime(HANDLE,const FILETIME *,const FILETIME *,const FILETIME *);
BOOL WINAPI SetFileAttributesW(LPCWSTR,DWORD);
BOOL WINAPI CloseHandle(HANDLE);
BOOL WINAPI DeleteFileW(LPCWSTR);
#endif
