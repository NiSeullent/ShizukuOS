/* SPDX-License-Identifier: GPL-2.0-only
 * Common definitions for the Shizuku Win64 user-mode runtime (ntdll, kernel32, CRT).
 * Types come from the mingw-w64 public headers; system calls follow ntsys.h of Kernel64.
 */
#ifndef SHZ_WIN64_NT_H
#define SHZ_WIN64_NT_H
#include <stdarg.h>
#define WIN32_NO_STATUS
#define WIN32_LEAN_AND_MEAN
#ifdef SHZ_NTDLL_BUILD
#define _NTSYSTEM_                              /* ntdll defines the Rtl* functions it declares: no dllimport */
#endif
#include <windef.h>
#include <winbase.h>
#include <winnt.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <stdint.h>
#include <stddef.h>

#ifndef NTAPI
#define NTAPI __stdcall
#endif
#define SHZ_EXPORT __declspec(dllexport)
#define NT_SUCCESS(s) ((LONG)(s) >= 0)

typedef LONG NTSTATUS;
typedef struct _UNICODE_STRING_SHZ { USHORT Length, MaximumLength; PWSTR Buffer; } SHZ_UNICODE_STRING;
typedef struct _SHZ_OBJECT_ATTRIBUTES {
    ULONG Length; HANDLE RootDirectory; SHZ_UNICODE_STRING *ObjectName; ULONG Attributes;
    PVOID SecurityDescriptor, SecurityQualityOfService;
} SHZ_OBJECT_ATTRIBUTES;
typedef struct _SHZ_IO_STATUS_BLOCK { ULONG_PTR Status; ULONG_PTR Information; } SHZ_IO_STATUS_BLOCK;

/* ---- TEB / PEB access (Windows x64 layout: GS:[0x30] = TEB, TEB+0x60 = PEB) ---- */
#define SHZ_GS_READ64(off, out) __asm__ volatile("movq %%gs:%c1, %0" : "=r"(out) : "i"(off))
static inline uint64_t shz_teb(void) { uint64_t v; SHZ_GS_READ64(0x30, v); return v; }
static inline uint64_t shz_peb(void) { uint64_t v; SHZ_GS_READ64(0x60, v); return v; }
static inline DWORD shz_last_error(void) { DWORD v; __asm__ volatile("movl %%gs:%c1, %0" : "=r"(v) : "i"(0x68)); return v; }
static inline void shz_set_last_error(DWORD e) { __asm__ volatile("movl %0, %%gs:%c1" : : "r"(e), "i"(0x68) : "memory"); }
static inline DWORD shz_tid(void) { uint64_t v; SHZ_GS_READ64(0x48, v); return (DWORD)v; }
static inline DWORD shz_pid(void) { uint64_t v; SHZ_GS_READ64(0x40, v); return (DWORD)v; }

/* ---- native system calls (ntdll exports; implemented in the generated stubs) ---- */
NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
NTSTATUS NTAPI NtTerminateThread(HANDLE, NTSTATUS);
NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PVOID, PVOID, SHZ_IO_STATUS_BLOCK *, const void *, ULONG, PLARGE_INTEGER, PULONG);
NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PVOID, PVOID, SHZ_IO_STATUS_BLOCK *, void *, ULONG, PLARGE_INTEGER, PULONG);
NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, SHZ_IO_STATUS_BLOCK *, PLARGE_INTEGER, ULONG,
                            ULONG, ULONG, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtClose(HANDLE);
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG);
NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSTATUS NTAPI NtWaitForMultipleObjects(ULONG, HANDLE *, ULONG, BOOLEAN, PLARGE_INTEGER);
NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, ULONG, BOOLEAN);
NTSTATUS NTAPI NtSetEvent(HANDLE, PLONG);
NTSTATUS NTAPI NtResetEvent(HANDLE, PLONG);
NTSTATUS NTAPI NtCreateMutant(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, BOOLEAN);
NTSTATUS NTAPI NtReleaseMutant(HANDLE, PLONG);
NTSTATUS NTAPI NtCreateSemaphore(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, LONG, LONG);
NTSTATUS NTAPI NtReleaseSemaphore(HANDLE, LONG, PLONG);
NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER);
NTSTATUS NTAPI NtQueryPerformanceCounter(PLARGE_INTEGER, PLARGE_INTEGER);
NTSTATUS NTAPI NtYieldExecution(void);
NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtQueryInformationThread(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtContinue(PCONTEXT, BOOLEAN);
NTSTATUS NTAPI NtRaiseException(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN);
NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
NTSTATUS NTAPI NtQueryInformationFile(HANDLE, SHZ_IO_STATUS_BLOCK *, PVOID, ULONG, ULONG);
NTSTATUS NTAPI NtSetInformationFile(HANDLE, SHZ_IO_STATUS_BLOCK *, PVOID, ULONG, ULONG);
NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, SHZ_IO_STATUS_BLOCK *, ULONG, ULONG);
NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE, HANDLE, PVOID, PVOID, SHZ_IO_STATUS_BLOCK *, PVOID, ULONG, ULONG, BOOLEAN,
                                    SHZ_UNICODE_STRING *, BOOLEAN);
NTSTATUS NTAPI NtSetInformationThread(HANDLE, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtCreateProcessEx(PHANDLE, PHANDLE, SHZ_UNICODE_STRING *, SHZ_UNICODE_STRING *, SHZ_UNICODE_STRING *);
NTSTATUS NTAPI NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtLoadImage(SHZ_UNICODE_STRING *, PULONG64);
NTSTATUS NTAPI NtShzDebugPrint(const char *, ULONG);
NTSTATUS NTAPI NtShzEvidence(ULONG, ULONG64);
NTSTATUS NTAPI NtCreateTimer(PHANDLE, ACCESS_MASK, PVOID, ULONG);
NTSTATUS NTAPI NtSetTimer(HANDLE, PLARGE_INTEGER, PVOID, PVOID, BOOLEAN, LONG, PBOOLEAN);
NTSTATUS NTAPI NtCancelTimer(HANDLE, PBOOLEAN);
NTSTATUS NTAPI NtWaitForAlertByThreadId(PVOID, PLARGE_INTEGER);
NTSTATUS NTAPI NtAlertThreadByThreadId(ULONG_PTR);

#define CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)
#define CURRENT_THREAD ((HANDLE)(LONG_PTR)-2)

/* Loader database layout published by Kernel64 (see kernel64/ldr.c). */
#define SHZ_LDR_NEEDS_INIT 0x1u
#define SHZ_LDR_IMAGE_DLL 0x4u
typedef struct _SHZ_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks, InMemoryOrderLinks, InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage, pad0;
    SHZ_UNICODE_STRING FullDllName;
    SHZ_UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount, TlsIndex;
} SHZ_LDR_ENTRY;
typedef struct _SHZ_PEB_LDR_DATA {
    ULONG Length; BOOLEAN Initialized; PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList;
} SHZ_PEB_LDR_DATA;

/* PEB fields we use (documented x64 offsets). */
#define PEB_IMAGE_BASE(peb) (*(PVOID *)((peb) + 0x10))
#define PEB_LDR(peb) (*(SHZ_PEB_LDR_DATA **)((peb) + 0x18))
#define PEB_PARAMS(peb) (*(PUCHAR *)((peb) + 0x20))
#define PEB_PROCESS_HEAP(peb) (*(PVOID *)((peb) + 0x30))
#define PEB_OS_MAJOR(peb) (*(ULONG *)((peb) + 0x118))
#define PEB_OS_MINOR(peb) (*(ULONG *)((peb) + 0x11c))
#define PEB_OS_BUILD(peb) (*(USHORT *)((peb) + 0x120))
#define PEB_OS_PLATFORM(peb) (*(ULONG *)((peb) + 0x124))

/* ntdll internals shared between its translation units. */
void ShzInitHeap(void);
PVOID NTAPI RtlAllocateHeap(PVOID heap, ULONG flags, SIZE_T size);
BOOLEAN NTAPI RtlFreeHeap(PVOID heap, ULONG flags, PVOID p);
SIZE_T NTAPI RtlSizeHeap(PVOID heap, ULONG flags, PVOID p);
PVOID NTAPI RtlReAllocateHeap(PVOID heap, ULONG flags, PVOID p, SIZE_T size);
PVOID ShzProcessHeap(void);
ULONG NTAPI RtlNtStatusToDosError(NTSTATUS status);
void ShzRunInitRoutines(int reason, void *reserved);
void ShzRunThreadAttach(int reason);
void ShzDebugLine(const char *s);
__attribute__((noreturn)) VOID NTAPI RtlExitUserProcess(NTSTATUS);
__attribute__((noreturn)) VOID NTAPI RtlExitUserThread(NTSTATUS);
void ShzEvidence(unsigned slot, unsigned long long v);
#endif
