/* SPDX-License-Identifier: GPL-2.0-only
 * Native registry interface shared by ntdll (RtlFormatCurrentUserKeyPath), advapi32 and the registry test programs:
 * the Kernel64 registry system calls (kernel64/sysreg.c) and the information records they return (Windows x64 layouts).
 */
#ifndef SHZ_WIN64_NTREG_H
#define SHZ_WIN64_NTREG_H
#include "nt.h"

/* Compatibility identity for the actual legacy pre-enrollment token (auth_id
 * 0x4e7 and authoritative account count zero). Enrolled account TokenUser SIDs
 * use this machine-domain prefix with their UID1000..1015. HKCU resolves the
 * current token on every call; these constants are not a fallback identity. */
#define SHZ_USER_SID_A "S-1-5-21-2210311251-3305482031-1094512843-1001"
#define SHZ_USER_SID_W L"S-1-5-21-2210311251-3305482031-1094512843-1001"
#define SHZ_USER_NAME_W L"shizuku"

/* ntdll Rtl helpers used with the registry (ntdll/rtlreg.c, ntdll_main.c) */
VOID NTAPI RtlInitUnicodeString(SHZ_UNICODE_STRING *, PCWSTR);
VOID NTAPI RtlFreeUnicodeString(SHZ_UNICODE_STRING *);
NTSTATUS NTAPI RtlFormatCurrentUserKeyPath(SHZ_UNICODE_STRING *);
NTSTATUS NTAPI RtlGetLastNtStatus(void);

NTSTATUS NTAPI NtCreateKey(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, ULONG TitleIndex, SHZ_UNICODE_STRING *Class,
                           ULONG CreateOptions, PULONG Disposition);
NTSTATUS NTAPI NtOpenKey(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtOpenKeyEx(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, ULONG OpenOptions);
NTSTATUS NTAPI NtQueryValueKey(HANDLE, SHZ_UNICODE_STRING *ValueName, ULONG InfoClass, PVOID, ULONG, PULONG ResultLength);
NTSTATUS NTAPI NtSetValueKey(HANDLE, SHZ_UNICODE_STRING *ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
NTSTATUS NTAPI NtDeleteKey(HANDLE);
NTSTATUS NTAPI NtDeleteValueKey(HANDLE, SHZ_UNICODE_STRING *ValueName);
NTSTATUS NTAPI NtEnumerateKey(HANDLE, ULONG Index, ULONG InfoClass, PVOID, ULONG, PULONG ResultLength);
NTSTATUS NTAPI NtEnumerateValueKey(HANDLE, ULONG Index, ULONG InfoClass, PVOID, ULONG, PULONG ResultLength);
NTSTATUS NTAPI NtQueryKey(HANDLE, ULONG InfoClass, PVOID, ULONG, PULONG ResultLength);
NTSTATUS NTAPI NtFlushKey(HANDLE);
NTSTATUS NTAPI NtQueryObject(HANDLE, ULONG InfoClass, PVOID, ULONG, PULONG ResultLength);
NTSTATUS NTAPI NtNotifyChangeKey(HANDLE, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, SHZ_IO_STATUS_BLOCK *, ULONG CompletionFilter,
                                 BOOLEAN WatchTree, PVOID Buffer, ULONG BufferSize, BOOLEAN Asynchronous);

/* KEY_INFORMATION_CLASS */
#define SHZ_KeyBasicInformation 0
#define SHZ_KeyNodeInformation 1
#define SHZ_KeyFullInformation 2
#define SHZ_KeyNameInformation 3
#define SHZ_KeyCachedInformation 4
/* KEY_VALUE_INFORMATION_CLASS */
#define SHZ_KeyValueBasicInformation 0
#define SHZ_KeyValueFullInformation 1
#define SHZ_KeyValuePartialInformation 2
/* OBJECT_INFORMATION_CLASS */
#define SHZ_ObjectBasicInformation 0
#define SHZ_ObjectNameInformation 1
#define SHZ_ObjectTypeInformation 2

typedef struct { LONGLONG LastWriteTime; ULONG TitleIndex, NameLength; WCHAR Name[1]; } SHZ_KEY_BASIC_INFORMATION;
typedef struct { LONGLONG LastWriteTime; ULONG TitleIndex, ClassOffset, ClassLength, NameLength; WCHAR Name[1]; } SHZ_KEY_NODE_INFORMATION;
typedef struct {
    LONGLONG LastWriteTime; ULONG TitleIndex, ClassOffset, ClassLength, SubKeys, MaxNameLen, MaxClassLen, Values,
             MaxValueNameLen, MaxValueDataLen; WCHAR Class[1];
} SHZ_KEY_FULL_INFORMATION;
typedef struct { ULONG NameLength; WCHAR Name[1]; } SHZ_KEY_NAME_INFORMATION;
typedef struct { ULONG TitleIndex, Type, NameLength; WCHAR Name[1]; } SHZ_KEY_VALUE_BASIC_INFORMATION;
typedef struct { ULONG TitleIndex, Type, DataOffset, DataLength, NameLength; WCHAR Name[1]; } SHZ_KEY_VALUE_FULL_INFORMATION;
typedef struct { ULONG TitleIndex, Type, DataLength; UCHAR Data[1]; } SHZ_KEY_VALUE_PARTIAL_INFORMATION;
#define SHZ_KEY_VALUE_PARTIAL_HEADER 12u
#define SHZ_KEY_VALUE_FULL_HEADER 20u
#define SHZ_KEY_NODE_HEADER 24u
#define SHZ_KEY_FULL_HEADER 44u

#endif
