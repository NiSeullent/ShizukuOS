/* SPDX-License-Identifier: GPL-2.0-only
 * AMD64/UTF16 host compile contract; native build uses the actual SDK header. */
#ifndef SHZ_NCRYPT_BOUNDARY_HOST_CONTRACT_H
#define SHZ_NCRYPT_BOUNDARY_HOST_CONTRACT_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef LONG SECURITY_STATUS;
typedef uint16_t WCHAR;
typedef const WCHAR *LPCWSTR;
typedef uintptr_t NCRYPT_HANDLE;
typedef NCRYPT_HANDLE NCRYPT_PROV_HANDLE;
typedef NCRYPT_HANDLE NCRYPT_KEY_HANDLE;
typedef unsigned char BYTE, *PBYTE;
typedef void VOID;
typedef void *HANDLE;
typedef size_t SIZE_T;
typedef int BOOL;
typedef struct { DWORD cbBuffer, BufferType; VOID *pvBuffer; } NCryptBuffer;
typedef struct { DWORD ulVersion, cBuffers; NCryptBuffer *pBuffers; } NCryptBufferDesc;
#define WINAPI
#define DLLAPI
#define NTE_INVALID_HANDLE ((SECURITY_STATUS)0x80090026u)
#define NTE_INVALID_PARAMETER ((SECURITY_STATUS)0x80090027u)
#define NTE_BAD_FLAGS ((SECURITY_STATUS)0x80090009u)
#define NTE_PROV_DLL_NOT_FOUND ((SECURITY_STATUS)0x8009001eu)
static DWORD shz_last_error(void);
static void shz_set_last_error(DWORD);
static DWORD GetEnvironmentVariableW(LPCWSTR, WCHAR *, DWORD);
static LONG InterlockedCompareExchange(volatile LONG *, LONG, LONG);
static LONG NtShzDebugPrint(const char *, DWORD);
static HANDLE GetCurrentProcess(void);
static BOOL ReadProcessMemory(HANDLE, const void *, void *, SIZE_T, SIZE_T *);
_Static_assert(sizeof(WCHAR) == 2 && sizeof(SECURITY_STATUS) == 4, "Windows scalar ABI");
_Static_assert(sizeof(NCRYPT_HANDLE) == 8 && sizeof(NCryptBufferDesc) == 16, "AMD64 CNG ABI");
#endif
