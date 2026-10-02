/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_PROFILE_WIN32_MOCK_H
#define M98_PROFILE_WIN32_MOCK_H
#include <stddef.h>
#include <stdint.h>
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef int32_t HRESULT;
typedef unsigned char BYTE;
typedef uintptr_t HKEY;
#define WINAPI
#define HKEY_CURRENT_USER ((HKEY)0x80000001u)
#define KEY_QUERY_VALUE 1u
#define KEY_SET_VALUE 2u
#define REG_OPTION_NON_VOLATILE 0u
#define REG_DWORD 4u
#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_HANDLE 6
#define ERROR_MORE_DATA 234
#define S_OK ((HRESULT)0)
#define E_INVALIDARG ((HRESULT)0x80070057u)
#define E_OUTOFMEMORY ((HRESULT)0x8007000eu)
#define HRESULT_FROM_WIN32(e) ((HRESULT)((e) <= 0 ? (e) : ((uint32_t)(e) & 0xffffu) | 0x80070000u))
LONG RegOpenKeyExA(HKEY, const char *, DWORD, DWORD, HKEY *);
LONG RegQueryValueExA(HKEY, const char *, DWORD *, DWORD *, BYTE *, DWORD *);
LONG RegCloseKey(HKEY);
LONG RegCreateKeyExA(HKEY, const char *, DWORD, char *, DWORD, DWORD, void *, HKEY *, DWORD *);
LONG RegSetValueExA(HKEY, const char *, DWORD, DWORD, const BYTE *, DWORD);
HRESULT m98e_ShizukuOSLoadUserTheme(void);
HRESULT m98e_ShizukuOSSaveUserTheme(DWORD);
#endif
