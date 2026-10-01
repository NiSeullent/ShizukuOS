/* SPDX-License-Identifier: GPL-2.0-only
 * Hosted ABI/dependency fixture, never native device or product evidence.
 * Compile with -fshort-wchar: WCHAR is genuinely 16-bit here as on Windows.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <sched.h>
#define DLLAPI
#define WINAPI
typedef int32_t LONG, NTSTATUS, BOOL;
typedef uint32_t DWORD, ULONG, REGSAM, DEVPROPTYPE;
typedef uint16_t WORD;
typedef uint8_t BYTE, *PBYTE;
typedef uintptr_t ULONG_PTR;
typedef wchar_t WCHAR;
typedef const WCHAR *PCWSTR;
typedef DWORD *PDWORD;
typedef void *HDEVINFO, *HWND, *HKEY;
typedef struct { DWORD Data1; WORD Data2,Data3; BYTE Data4[8]; } GUID;
typedef struct { GUID fmtid; DWORD pid; } DEVPROPKEY;
typedef struct { DWORD cbSize; GUID ClassGuid; DWORD DevInst; ULONG_PTR Reserved; } SP_DEVINFO_DATA,*PSP_DEVINFO_DATA;
typedef struct { DWORD cbSize; GUID InterfaceClassGuid; DWORD Flags; ULONG_PTR Reserved; } SP_DEVICE_INTERFACE_DATA,*PSP_DEVICE_INTERFACE_DATA;
typedef struct { DWORD cbSize; WCHAR DevicePath[1]; } SP_DEVICE_INTERFACE_DETAIL_DATA_W,*PSP_DEVICE_INTERFACE_DETAIL_DATA_W;
_Static_assert(sizeof(WCHAR)==2,"host uses actual WCHAR width");
_Static_assert(sizeof(SP_DEVINFO_DATA)==32,"AMD64 device info ABI");
_Static_assert(sizeof(SP_DEVICE_INTERFACE_DATA)==32,"AMD64 interface info ABI");
_Static_assert(sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)==8,"AMD64 interface detail cbSize ABI");
#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE ((void *)(uintptr_t)-1)
#define HKEY_LOCAL_MACHINE ((void *)(uintptr_t)0x80000002u)
#define HEAP_ZERO_MEMORY 8
#define ERROR_SUCCESS 0u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_INVALID_DATA 13u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define ERROR_INVALID_FLAGS 1004u
#define ERROR_INVALID_USER_BUFFER 1784u
#define ERROR_NO_MORE_ITEMS 259u
#define ERROR_NOT_FOUND 1168u
#define ERROR_RETRY 1237u
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_MORE_DATA 234u
#define ERROR_CLASS_MISMATCH 0xe0000201u
#define ERROR_NO_SUCH_DEVINST 0xe000020bu
#define ERROR_KEY_DOES_NOT_EXIST 0xe0000204u
#define ERROR_NO_SUCH_DEVICE_INTERFACE 0xe0000225u
#define SPINT_ACTIVE 1u
#define DIGCF_DEFAULT 1u
#define DIGCF_PRESENT 2u
#define DIGCF_ALLCLASSES 4u
#define DIGCF_PROFILE 8u
#define DIGCF_DEVICEINTERFACE 16u
#define DIOD_INHERIT_CLASSDRVS 2u
#define DIOD_CANCEL_REMOVE 4u
#define DIODI_NO_ADD 1u
#define DICS_FLAG_GLOBAL 1u
#define DICS_FLAG_CONFIGSPECIFIC 2u
#define DIREG_DEV 1u
#define DIREG_DRV 2u
#define REG_SZ 1u
#define REG_BINARY 3u
#define REG_MULTI_SZ 7u
#define KEY_QUERY_VALUE 1u
#define KEY_READ 0x20019u
#define DEVPROP_TYPE_GUID 13u
#define DEVPROP_TYPE_STRING 18u
#define DEVPROP_TYPE_STRING_LIST (18u|0x2000u)
static _Thread_local DWORD last_error;
static void SetLastError(DWORD error) { last_error=error; }
static DWORD GetLastError(void) { return last_error; }
static LONG InterlockedCompareExchange(volatile LONG *p,LONG value,LONG expected)
{ __atomic_compare_exchange_n(p,&expected,value,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return expected; }
static LONG InterlockedExchange(volatile LONG *p,LONG value) { return __atomic_exchange_n(p,value,__ATOMIC_SEQ_CST); }
static void Sleep(DWORD ms) { (void)ms;sched_yield(); }
static void *GetProcessHeap(void) { return (void *)1; }
static int allocation_fail=-1;
static void *HeapAlloc(void *h,DWORD flags,size_t size)
{ (void)h;(void)flags;if(allocation_fail==0)return NULL;if(allocation_fail>0)--allocation_fail;return calloc(1,size); }
static int HeapFree(void *h,DWORD flags,void *p) { (void)h;(void)flags;free(p);return 1; }
static ULONG RtlNtStatusToDosError(NTSTATUS status)
{ return status==(NTSTATUS)0xc0000003u?ERROR_NOT_SUPPORTED:ERROR_INVALID_DATA; }
static NTSTATUS NtQuerySystemInformation(ULONG,void *,ULONG,ULONG *);
static LONG RegOpenKeyExW(HKEY,PCWSTR,DWORD,REGSAM,HKEY *);
static LONG RegQueryValueExW(HKEY,PCWSTR,DWORD *,DWORD *,BYTE *,DWORD *);
static LONG RegCloseKey(HKEY);
