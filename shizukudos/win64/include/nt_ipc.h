/* SPDX-License-Identifier: GPL-2.0-only
 * Native interface of the Kernel64 IPC / process-model subsystem (kernel64/ipc_*.c, npfs.c): sections, named pipes,
 * I/O completion, APCs, jobs, process creation and cross-process access. Windows x64 layouts and NTSTATUS values;
 * the system-call numbers live in kernel64/ntsys.h (SYSCALL_LIST_MISC / SYSCALL_LIST_IPC) and reach user mode through
 * the generated ntdll stubs.
 */
#ifndef SHZ_NT_IPC_H
#define SHZ_NT_IPC_H
#include "nt.h"

#ifndef STATUS_OBJECT_NAME_EXISTS
#define STATUS_OBJECT_NAME_EXISTS ((NTSTATUS)0x40000000)
#endif
#define SHZ_OBJ_INHERIT 0x00000002u
#define SHZ_OBJ_OPENIF 0x00000080u

typedef struct { HANDLE UniqueProcess, UniqueThread; } SHZ_CLIENT_ID;

/* opening named objects */
NTSTATUS NTAPI NtOpenEvent(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtOpenMutant(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtOpenSemaphore(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtOpenTimer(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtOpenIoCompletion(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);

/* sections */
NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NTSTATUS NTAPI NtOpenSection(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
NTSTATUS NTAPI NtQuerySection(HANDLE, ULONG, PVOID, SIZE_T, PSIZE_T);
NTSTATUS NTAPI NtFlushVirtualMemory(HANDLE, PVOID *, PSIZE_T, SHZ_IO_STATUS_BLOCK *);

/* I/O, completion ports, APCs */
typedef VOID (NTAPI *SHZ_PIO_APC_ROUTINE)(PVOID ApcContext, SHZ_IO_STATUS_BLOCK *IoStatusBlock, ULONG Reserved);
typedef VOID (NTAPI *SHZ_PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef struct { PVOID KeyContext, ApcContext; SHZ_IO_STATUS_BLOCK IoStatusBlock; } SHZ_FILE_IO_COMPLETION_INFORMATION;
NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, ULONG);
NTSTATUS NTAPI NtSetIoCompletion(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR);
NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PVOID *, PVOID *, SHZ_IO_STATUS_BLOCK *, PLARGE_INTEGER);
NTSTATUS NTAPI NtRemoveIoCompletionEx(HANDLE, SHZ_FILE_IO_COMPLETION_INFORMATION *, ULONG, PULONG, PLARGE_INTEGER, BOOLEAN);
NTSTATUS NTAPI NtQueryIoCompletion(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtQueueApcThread(HANDLE, PVOID, PVOID, PVOID, PVOID);
NTSTATUS NTAPI NtTestAlert(void);
NTSTATUS NTAPI NtCancelIoFile(HANDLE, SHZ_IO_STATUS_BLOCK *);
NTSTATUS NTAPI NtCancelIoFileEx(HANDLE, SHZ_IO_STATUS_BLOCK *, SHZ_IO_STATUS_BLOCK *);
NTSTATUS NTAPI NtFsControlFile(HANDLE, HANDLE, PVOID, PVOID, SHZ_IO_STATUS_BLOCK *, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtCreateNamedPipeFile(PHANDLE, ULONG, SHZ_OBJECT_ATTRIBUTES *, SHZ_IO_STATUS_BLOCK *, ULONG, ULONG, ULONG,
                                     ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PLARGE_INTEGER);
NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, SHZ_IO_STATUS_BLOCK *, PVOID, ULONG, ULONG);
NTSTATUS NTAPI NtSetInformationObject(HANDLE, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtQueryObject(HANDLE, ULONG, PVOID, ULONG, PULONG);

/* processes, threads, memory */
NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, SHZ_CLIENT_ID *);
NTSTATUS NTAPI NtOpenThread(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, SHZ_CLIENT_ID *);
NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, const void *, SIZE_T, PSIZE_T);
NTSTATUS NTAPI NtSuspendThread(HANDLE, PULONG);
NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
NTSTATUS NTAPI NtSetInformationProcess(HANDLE, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtShzQueryKernelStats(PVOID, ULONG);
NTSTATUS NTAPI NtFlushInstructionCache(HANDLE, PVOID, SIZE_T);

/* NtCreateThreadEx flags */
#define SHZ_THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x1u

/* NtShzCreateUserProcess: one parameter block (kernel32 CreateProcessW -> kernel64/ipc_proc.c). */
#define SHZ_CUP_VERSION 1u
#define SHZ_CUP_SUSPENDED 0x1u              /* CREATE_SUSPENDED */
#define SHZ_CUP_INHERIT_HANDLES 0x2u        /* bInheritHandles */
#define SHZ_CUP_STD_HANDLES 0x4u            /* STARTF_USESTDHANDLES: StdHandle[] go into the process parameters */
#define SHZ_CUP_BREAKAWAY 0x8u              /* CREATE_BREAKAWAY_FROM_JOB */
#define SHZ_CUP_HANDLE_LIST 0x10u           /* PROC_THREAD_ATTRIBUTE_HANDLE_LIST: only HandleList[] is inherited */
typedef struct {
    ULONG Version, Flags;
    PCWSTR ImagePath; ULONG ImagePathChars;        /* DOS path of the executable ("C:\dir\x.exe") */
    PCWSTR CommandLine; ULONG CommandLineChars;
    PCWSTR CurrentDirectory; ULONG CurrentDirectoryChars;
    PCWSTR Environment; ULONG EnvironmentChars;    /* whole UTF-16 block including its final empty string; 0 = parent's */
    ULONG HandleCount, JobCount;
    HANDLE StdHandle[3];
    const HANDLE *HandleList;                      /* SHZ_CUP_HANDLE_LIST */
    const HANDLE *JobList;                         /* PROC_THREAD_ATTRIBUTE_JOB_LIST: the child is assigned to these */
    HANDLE ParentProcess;                          /* PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: inherit from it; 0 = caller */
    ULONG ProcessAccess, ThreadAccess;
    HANDLE ProcessHandle, ThreadHandle;            /* out */
    ULONG ProcessId, ThreadId;                     /* out */
} SHZ_CREATE_PROCESS;
NTSTATUS NTAPI NtShzCreateUserProcess(SHZ_CREATE_PROCESS *);

/* jobs */
NTSTATUS NTAPI NtCreateJobObject(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtOpenJobObject(PHANDLE, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtAssignProcessToJobObject(HANDLE, HANDLE);
NTSTATUS NTAPI NtSetInformationJobObject(HANDLE, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtQueryInformationJobObject(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtTerminateJobObject(HANDLE, NTSTATUS);
NTSTATUS NTAPI NtIsProcessInJob(HANDLE, HANDLE);

/* kernel statistics for leak checks (NtShzQueryKernelStats) */
typedef struct {
    ULONG64 PmmFree, KernelHeapUsed, Threads, Zombies, Sections, Views, Pipes, Irps, Packets, Jobs, Reserved[6];
} SHZ_KERNEL_STATS;

/* ntdll helpers exported for kernel32 */
ULONG NTAPI ShzIpcStatusToDosError(NTSTATUS status);
#endif
