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
#ifndef DLLAPI
#define DLLAPI __declspec(dllexport)      /* exported function of an extra module under win64/dlls/<name>/ */
#endif
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
NTSTATUS NTAPI NtCreateProcessEx(PHANDLE, PHANDLE, SHZ_UNICODE_STRING *, SHZ_UNICODE_STRING *, SHZ_UNICODE_STRING *, void *ext);
NTSTATUS NTAPI NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtLoadImage(SHZ_UNICODE_STRING *, PULONG64, ULONG, SHZ_UNICODE_STRING *);   /* name, base, flags, dirs (ldr_search.c) */
NTSTATUS NTAPI NtShzDebugPrint(const char *, ULONG);
NTSTATUS NTAPI NtShzEvidence(ULONG, ULONG64);
NTSTATUS NTAPI NtCreateTimer(PHANDLE, ACCESS_MASK, PVOID, ULONG);
NTSTATUS NTAPI NtSetTimer(HANDLE, PLARGE_INTEGER, PVOID, PVOID, BOOLEAN, LONG, PBOOLEAN);
NTSTATUS NTAPI NtCancelTimer(HANDLE, PBOOLEAN);
NTSTATUS NTAPI NtWaitForAlertByThreadId(PVOID, PLARGE_INTEGER);
NTSTATUS NTAPI NtAlertThreadByThreadId(ULONG_PTR);
NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, SHZ_IO_STATUS_BLOCK *, PVOID, ULONG, ULONG);
NTSTATUS NTAPI NtLockFile(HANDLE, HANDLE, PVOID, PVOID, SHZ_IO_STATUS_BLOCK *, PLARGE_INTEGER, PLARGE_INTEGER, ULONG, BOOLEAN, BOOLEAN);
NTSTATUS NTAPI NtUnlockFile(HANDLE, SHZ_IO_STATUS_BLOCK *, PLARGE_INTEGER, PLARGE_INTEGER, ULONG);
NTSTATUS NTAPI NtCancelIoFile(HANDLE, SHZ_IO_STATUS_BLOCK *);
NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
/* kernel32 support calls (kernel64/sysk32_proc.c; the class numbers are the kernel's K32Q_* / K32S_*) */
NTSTATUS NTAPI NtShzQueryK32(ULONG cls, HANDLE h, PVOID buf, ULONG len, PULONG ret);
NTSTATUS NTAPI NtShzSetK32(ULONG cls, HANDLE h, PVOID buf, ULONG len);
#define K32Q_THREAD_TIMES 1         /* {create FILETIME, exit FILETIME, kernel 100ns, user 100ns, cycles} (5 x ULONG64) */
#define K32Q_PROCESS_TIMES 2        /* same layout, all threads of the process (exited ones included) */
#define K32Q_PROCESS_INFO 3         /* ULONG {handles, threads, pid, parent pid, priority class, 0} */
#define K32Q_PROCESS_LIST 4         /* array of {ULONG pid, ppid, threads, priority class; char name[32]} */
#define K32Q_MODULE_LIST 5          /* h = process id (0: caller): array of {ULONG64 base, size; char name[48]; char path[128]} */
#define K32Q_SYSTEM_PERF 7          /* {total pages, free pages, commit, peak commit, kernel heap total, used; ULONG procs, threads, handles, 0} */
#define K32Q_PROCESS_MEMORY 8       /* ULONG64 {page faults, working set, peak working set, private bytes, peak private bytes} */
#define K32Q_WORKING_SET_EX 9       /* in/out array of PSAPI_WORKING_SET_EX_INFORMATION */
#define K32Q_IMAGE_PATH 10          /* the executable's path on C: as a NUL-terminated byte string */
#define K32Q_FIRMWARE 11            /* ULONG FIRMWARE_TYPE */
#define K32Q_THREAD_SETTINGS 12     /* ULONG {priority boost disabled, memory priority, power throttling control, state} */
#define K32Q_PROCESS_SETTINGS 13    /* ULONG {memory priority, power throttling control, state} */
#define K32S_PRIORITY_CLASS 1       /* ULONG class value (process handle) */
#define K32S_THREAD_BOOST 2         /* ULONG disable (thread handle) */
#define K32S_THREAD_MEM_PRIORITY 3  /* ULONG 1..5 (thread handle) */
#define K32S_DISCARD 4              /* ULONG64 {base, size}: contents discarded, pages stay committed */
#define K32S_LOCK 5                 /* ULONG64 {base, size}: VirtualLock */
#define K32S_UNLOCK 6               /* ULONG64 {base, size}: VirtualUnlock */
#define K32S_PREFETCH 7             /* ULONG64 {base, size}: fault committed pages in */
#define K32S_THREAD_POWER 8         /* ULONG {control mask, state mask} (thread handle) */
#define K32S_PROCESS_MEM_PRIORITY 9 /* ULONG 1..5 (process handle) */
#define K32S_PROCESS_POWER 10       /* ULONG {control mask, state mask} (process handle) */
#define K32S_SUSPEND_PROCESS 11     /* every thread of the process (NtSuspendProcess) */
#define K32S_RESUME_PROCESS 12      /* NtResumeProcess */

/* kernel32/advapi32 support calls 0x95-0x9e (kernel64/sysk32_obj.c; operation codes as in kernel64/ntsys.h) */
NTSTATUS NTAPI NtShzSection(ULONG_PTR op, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSTATUS NTAPI NtShzIoCompletion(ULONG_PTR op, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSTATUS NTAPI NtShzJob(ULONG_PTR op, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSTATUS NTAPI NtShzToken(ULONG_PTR op, ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSTATUS NTAPI NtShzSecurityObject(ULONG_PTR op, ULONG_PTR handle, ULONG_PTR buf, ULONG_PTR len, ULONG_PTR pneeded);
NTSTATUS NTAPI NtCreateNamedPipeFile(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, SHZ_IO_STATUS_BLOCK *, ULONG share, ULONG disposition,
                                     ULONG options, ULONG type, ULONG read_mode, ULONG completion_mode, ULONG max_instances,
                                     ULONG in_quota, ULONG out_quota, PLARGE_INTEGER default_timeout);
NTSTATUS NTAPI NtFsControlFile(HANDLE, HANDLE event, PVOID apc, PVOID apc_ctx, SHZ_IO_STATUS_BLOCK *, ULONG code, PVOID in,
                               ULONG in_len, PVOID out, ULONG out_len);
NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID addr, PVOID buf, SIZE_T size, PSIZE_T done);
NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID addr, const void *buf, SIZE_T size, PSIZE_T done);
NTSTATUS NTAPI NtSetInformationObject(HANDLE, ULONG cls, PVOID buf, ULONG len);
NTSTATUS NTAPI NtQueryObject(HANDLE, ULONG cls, PVOID buf, ULONG len, PULONG ret);
NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, PVOID client_id);
NTSTATUS NTAPI NtOpenThread(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, PVOID client_id);
NTSTATUS NTAPI NtSuspendThread(HANDLE, PULONG);
NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
/* the NT names of the multiplexed services (ntdll/ntobj.c) */
NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, PLARGE_INTEGER, ULONG prot, ULONG attrs, HANDLE file);
NTSTATUS NTAPI NtOpenSection(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
NTSTATUS NTAPI NtFlushVirtualMemory(HANDLE, PVOID *, PSIZE_T, SHZ_IO_STATUS_BLOCK *);
NTSTATUS NTAPI NtQuerySection(HANDLE, ULONG, PVOID, SIZE_T, PSIZE_T);
NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, ULONG);
NTSTATUS NTAPI NtSetIoCompletion(HANDLE, ULONG_PTR, ULONG_PTR, NTSTATUS, ULONG_PTR);
NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PULONG_PTR, PULONG_PTR, SHZ_IO_STATUS_BLOCK *, PLARGE_INTEGER);
NTSTATUS NTAPI NtRemoveIoCompletionEx(HANDLE, PVOID, ULONG, PULONG, PLARGE_INTEGER, BOOLEAN);
NTSTATUS NTAPI NtCancelIoFileEx(HANDLE, SHZ_IO_STATUS_BLOCK *, SHZ_IO_STATUS_BLOCK *);
NTSTATUS NTAPI NtCreateJobObject(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtOpenJobObject(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtAssignProcessToJobObject(HANDLE, HANDLE);
NTSTATUS NTAPI NtTerminateJobObject(HANDLE, NTSTATUS);
NTSTATUS NTAPI NtIsProcessInJob(HANDLE, HANDLE);
NTSTATUS NTAPI NtQueryInformationJobObject(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtSetInformationJobObject(HANDLE, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtOpenProcessToken(HANDLE, ACCESS_MASK, PHANDLE);
NTSTATUS NTAPI NtOpenProcessTokenEx(HANDLE, ACCESS_MASK, ULONG, PHANDLE);
NTSTATUS NTAPI NtOpenThreadToken(HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE);
NTSTATUS NTAPI NtOpenThreadTokenEx(HANDLE, ACCESS_MASK, BOOLEAN, ULONG, PHANDLE);
NTSTATUS NTAPI NtDuplicateToken(HANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, BOOLEAN, ULONG, PHANDLE);
#define SHZ_SEC_CREATE 1
#define SHZ_SEC_OPEN 2
#define SHZ_SEC_MAP 3
#define SHZ_SEC_UNMAP 4
#define SHZ_SEC_FLUSH 5
#define SHZ_SEC_QUERY 6
#define SHZ_IOC_CREATE 1
#define SHZ_IOC_SET 2
#define SHZ_IOC_REMOVE 3
#define SHZ_IOC_CANCEL 4
#define SHZ_IOC_QUERY 5
#define SHZ_JOB_CREATE 1
#define SHZ_JOB_OPEN 2
#define SHZ_JOB_ASSIGN 3
#define SHZ_JOB_TERMINATE 4
#define SHZ_JOB_QUERY 5
#define SHZ_JOB_SET 6
#define SHZ_JOB_IS_IN_JOB 7
#define SHZ_TOK_OPEN_PROCESS 1
#define SHZ_TOK_OPEN_THREAD 2
#define SHZ_TOK_QUERY 3
#define SHZ_TOK_SET 4
#define SHZ_TOK_DUPLICATE 5
#define SHZ_TOK_IMPERSONATE 6
#define SHZ_TOKF_INTEGRITY 1
#define SHZ_TOKF_SESSION 2
#define SHZ_TOKF_PRIVS 3
#define SHZ_SOB_QUERY 1
#define SHZ_SOB_SET 2
/* Token data the kernel keeps (advapi32 renders the Windows information classes from it). */
typedef struct shz_token_info {
    ULONG type, imp_level, integrity_rid, flags;
    ULONG64 id, modified_id, auth_id;
    ULONG session, elevation_type;
    ULONG64 owner_pid;
} shz_token_info;
/* NtCreateProcessEx's extension block (6th argument; kernel64/sysx.c) */
#define SHZ_CPX_SUSPENDED 1
#define SHZ_CPX_INHERIT 2
#define SHZ_CPX_BREAKAWAY 4
#define SHZ_CPX_STD 8
typedef struct shz_process_ex {
    ULONG size, flags;
    ULONG64 env, env_bytes;
    ULONG64 handle_list;
    ULONG handle_count, pad;
    ULONG64 std[3];
} shz_process_ex;

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
/* The process heap handle lives in PEB.ProcessHeap; ntdll publishes it there, every module reads it from there. */
static inline PVOID ShzProcessHeap(void) { return PEB_PROCESS_HEAP(shz_peb()); }
ULONG NTAPI RtlNtStatusToDosError(NTSTATUS status);
void ShzRunInitRoutines(int reason, void *reserved);
void ShzRunThreadAttach(int reason);
void ShzDebugLine(const char *s);
__attribute__((noreturn)) VOID NTAPI RtlExitUserProcess(NTSTATUS);
__attribute__((noreturn)) VOID NTAPI RtlExitUserThread(NTSTATUS);
void ShzEvidence(unsigned slot, unsigned long long v);
#endif
