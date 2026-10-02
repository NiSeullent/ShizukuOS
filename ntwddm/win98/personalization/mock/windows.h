/* SPDX-License-Identifier: GPL-2.0-only
 * Only file boundaries are modeled. Production is separately compiled against
 * the installed real MinGW Win32 declarations. */
#ifndef PZ98_MOCK_WINDOWS_H
#define PZ98_MOCK_WINDOWS_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define MAX_PATH 260
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 1u
#define CREATE_NEW 1u
#define OPEN_EXISTING 3u
#define OPEN_ALWAYS 4u
#define FILE_ATTRIBUTE_NORMAL 128u
#define FILE_ATTRIBUTE_DIRECTORY 16u
#define INVALID_FILE_ATTRIBUTES 0xffffffffu
#define INVALID_FILE_SIZE 0xffffffffu
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_PATH_NOT_FOUND 3u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_INVALID_DATA 13u
#define ERROR_WRITE_FAULT 29u
#define ERROR_READ_FAULT 30u
#define ERROR_SHARING_VIOLATION 32u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_BUFFER_OVERFLOW 111u
#define ERROR_ALREADY_EXISTS 183u
#define ERROR_CRC 23u
DWORD GetLastError(void);
void SetLastError(DWORD);
HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
BOOL ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
DWORD GetFileSize(HANDLE,DWORD *);
DWORD GetFileAttributesA(const char *);
BOOL DeleteFileA(const char *);
BOOL MoveFileA(const char *,const char *);
#endif
