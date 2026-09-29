/* SPDX-License-Identifier: GPL-2.0-only
 * Internal header of the Shizuku kernel32.dll implementation. */
#ifndef SHZ_K32_H
#define SHZ_K32_H
#define _KERNEL32_
#include "../include/nt.h"
#include <string.h>
#include <winnls.h>

#define K32API __declspec(dllexport)

/* ntdll exports used by kernel32 (imported through libntdll.a built from ntdll's export list). */
NTSTATUS NTAPI RtlInitializeCriticalSectionEx(RTL_CRITICAL_SECTION *, ULONG, ULONG);
NTSTATUS NTAPI RtlEnterCriticalSection(RTL_CRITICAL_SECTION *);
NTSTATUS NTAPI RtlLeaveCriticalSection(RTL_CRITICAL_SECTION *);
BOOLEAN NTAPI RtlTryEnterCriticalSection(RTL_CRITICAL_SECTION *);
NTSTATUS NTAPI RtlDeleteCriticalSection(RTL_CRITICAL_SECTION *);
VOID NTAPI RtlInitializeSRWLock(RTL_SRWLOCK *);
VOID NTAPI RtlAcquireSRWLockExclusive(RTL_SRWLOCK *);
VOID NTAPI RtlReleaseSRWLockExclusive(RTL_SRWLOCK *);
VOID NTAPI RtlAcquireSRWLockShared(RTL_SRWLOCK *);
VOID NTAPI RtlReleaseSRWLockShared(RTL_SRWLOCK *);
BOOLEAN NTAPI RtlTryAcquireSRWLockExclusive(RTL_SRWLOCK *);
BOOLEAN NTAPI RtlTryAcquireSRWLockShared(RTL_SRWLOCK *);
VOID NTAPI RtlInitializeConditionVariable(RTL_CONDITION_VARIABLE *);
VOID NTAPI RtlWakeConditionVariable(RTL_CONDITION_VARIABLE *);
VOID NTAPI RtlWakeAllConditionVariable(RTL_CONDITION_VARIABLE *);
NTSTATUS NTAPI RtlSleepConditionVariableSRW(RTL_CONDITION_VARIABLE *, RTL_SRWLOCK *, PLARGE_INTEGER, ULONG);
NTSTATUS NTAPI RtlSleepConditionVariableCS(RTL_CONDITION_VARIABLE *, RTL_CRITICAL_SECTION *, PLARGE_INTEGER);
NTSTATUS NTAPI RtlWaitOnAddress(volatile VOID *, PVOID, SIZE_T, PLARGE_INTEGER);
VOID NTAPI RtlWakeAddressSingle(PVOID);
VOID NTAPI RtlWakeAddressAll(PVOID);
PVOID NTAPI RtlAddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
ULONG NTAPI RtlRemoveVectoredExceptionHandler(PVOID);
PVOID NTAPI RtlAddVectoredContinueHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
ULONG NTAPI RtlRemoveVectoredContinueHandler(PVOID);
PTOP_LEVEL_EXCEPTION_FILTER NTAPI RtlSetUnhandledExceptionFilter(PTOP_LEVEL_EXCEPTION_FILTER);
VOID NTAPI RtlRaiseException(PEXCEPTION_RECORD);
VOID NTAPI RtlInitUnicodeString(SHZ_UNICODE_STRING *, PCWSTR);
NTSTATUS NTAPI LdrLoadDll(PWSTR, PULONG, SHZ_UNICODE_STRING *, PVOID *);
NTSTATUS NTAPI LdrGetDllHandle(PWSTR, PULONG, SHZ_UNICODE_STRING *, PVOID *);
NTSTATUS NTAPI LdrUnloadDll(PVOID);
NTSTATUS NTAPI LdrGetProcedureAddress(PVOID, const void *, ULONG, PVOID *);
PVOID NTAPI RtlCreateHeap(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
BOOLEAN NTAPI RtlDestroyHeap(PVOID);
BOOLEAN NTAPI RtlValidateHeap(PVOID, ULONG, PVOID);

DWORD k32_nt_error(NTSTATUS st);                       /* maps + stores LastError, returns the Win32 code */

/* Windows path <-> NT path conversion (k32_file.c) */
NTSTATUS k32_dos_to_nt(LPCWSTR dos, WCHAR *nt, size_t cap);
DWORD k32_current_directory(WCHAR *buf, DWORD cap);
size_t k32_wlen(const WCHAR *s);
#endif
