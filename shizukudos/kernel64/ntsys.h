/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 native system-call interface (NT-style), shared by the kernel and the user-mode
 * runtime libraries. Numbers are Shizuku's own; they are NOT Windows build syscall numbers
 * and user code must reach them through the ntdll layer, never assume a Windows table.
 *
 * Convention (Windows x64 syscall): EAX = number, R10 = arg1, RDX = arg2, R8 = arg3,
 * R9 = arg4, further arguments on the user stack at [rsp+0x28], [rsp+0x30], ...
 * (rsp+0x00 is the return address, 0x08..0x27 the 32-byte shadow space.) RAX = NTSTATUS.
 */
#ifndef NTSYS_H
#define NTSYS_H
#include <stdint.h>

#define SYSCALL_LIST(X) \
    X(NtTerminateProcess, 0x01) X(NtTerminateThread, 0x02) X(NtWriteFile, 0x03) X(NtReadFile, 0x04) \
    X(NtCreateFile, 0x05) X(NtClose, 0x06) X(NtAllocateVirtualMemory, 0x07) X(NtFreeVirtualMemory, 0x08) \
    X(NtProtectVirtualMemory, 0x09) X(NtQueryVirtualMemory, 0x0a) X(NtCreateThreadEx, 0x0b) \
    X(NtWaitForSingleObject, 0x0c) X(NtWaitForMultipleObjects, 0x0d) X(NtCreateEvent, 0x0e) \
    X(NtSetEvent, 0x0f) X(NtResetEvent, 0x10) X(NtCreateMutant, 0x11) X(NtReleaseMutant, 0x12) \
    X(NtCreateSemaphore, 0x13) X(NtReleaseSemaphore, 0x14) X(NtDelayExecution, 0x15) \
    X(NtQuerySystemTime, 0x16) X(NtQueryPerformanceCounter, 0x17) X(NtYieldExecution, 0x18) \
    X(NtQueryInformationProcess, 0x19) X(NtQueryInformationThread, 0x1a) X(NtContinue, 0x1c) \
    X(NtRaiseException, 0x1d) X(NtDuplicateObject, 0x20) X(NtQueryInformationFile, 0x21) \
    X(NtSetInformationFile, 0x22) X(NtOpenFile, 0x23) X(NtQueryDirectoryFile, 0x24) \
    X(NtSetInformationThread, 0x25) X(NtCreateProcessEx, 0x26) X(NtQuerySystemInformation, 0x27) \
    X(NtLoadImage, 0x28) X(NtSetEventBoostPriority, 0x29) X(NtQueryEvent, 0x2a) X(NtQueryMutant, 0x2b) \
    X(NtQuerySemaphore, 0x2c) X(NtFlushBuffersFile, 0x2d) X(NtDeleteFile, 0x2e) X(NtCreateDirectory, 0x2f) \
    X(NtShzDebugPrint, 0x30) X(NtShzEvidence, 0x31) X(NtShzIpcCall, 0x32) X(NtShzGetTeb, 0x33) \
    X(NtGetContextThread, 0x34) X(NtSetContextThread, 0x35) X(NtSuspendThread, 0x36) X(NtResumeThread, 0x37) \
    X(NtCancelIoFile, 0x38) X(NtCreateTimer, 0x39) X(NtSetTimer, 0x3a) X(NtCancelTimer, 0x3b) \
    X(NtOpenProcess, 0x3c) X(NtOpenThread, 0x3d) X(NtSetInformationProcess, 0x3e) X(NtFlushInstructionCache, 0x3f) \
    X(NtWaitForAlertByThreadId, 0x40) X(NtAlertThreadByThreadId, 0x41)

/* Reserved ranges for subsystems that live in their own kernel64 files and their own sys_ext_*() handler (sysext.c).
 * Each subsystem defines ONLY its own list below (numbers must stay inside its range):
 *   registry 0x50-0x5f   graphics/window 0x60-0x7f   network 0x80-0x8f   kernel32 support 0x90-0x9f   misc 0xa0-0xaf
 *   installer (SHZSETUP) 0xb0-0xbf   gpu (P-render) 0xd0-0xdf   NT driver host (N1) 0xe0-0xef
 *   storage raw-sector interface (S1) 0xf0-0xff */
#define SYSCALL_LIST_REGISTRY(X) \
    X(NtCreateKey, 0x50) X(NtOpenKey, 0x51) X(NtOpenKeyEx, 0x52) X(NtQueryValueKey, 0x53) X(NtSetValueKey, 0x54) \
    X(NtDeleteKey, 0x55) X(NtDeleteValueKey, 0x56) X(NtEnumerateKey, 0x57) X(NtEnumerateValueKey, 0x58) \
    X(NtQueryKey, 0x59) X(NtFlushKey, 0x5a) X(NtQueryObject, 0x5b) X(NtNotifyChangeKey, 0x5c)

#define SYSCALL_LIST_GRAPHICS(X) \
    X(NtUserQueryDisplay, 0x60) X(NtUserClassOp, 0x61) X(NtUserCreateWindow, 0x62) X(NtUserDestroyWindow, 0x63) \
    X(NtUserWindowQuery, 0x64) X(NtUserWindowSet, 0x65) X(NtUserShowWindow, 0x66) X(NtUserSetWindowPos, 0x67) \
    X(NtUserPostMessage, 0x68) X(NtUserSendMessage, 0x69) X(NtUserGetMessage, 0x6a) X(NtUserReplyMessage, 0x6b) \
    X(NtUserThreadOp, 0x6c) X(NtUserTimer, 0x6d) X(NtUserInvalidate, 0x6e) X(NtUserPaint, 0x6f) X(NtGdiPresent, 0x70) \
    X(NtUserFocusOp, 0x71) X(NtUserEnumWindows, 0x72) X(NtUserHitTest, 0x73) X(NtUserAtom, 0x74) X(NtUserProp, 0x75)

#define SYSCALL_LIST_NET(X) \
    X(NtShzSocket, 0x80) X(NtShzSockBind, 0x81) X(NtShzSockListen, 0x82) X(NtShzSockAccept, 0x83) \
    X(NtShzSockConnect, 0x84) X(NtShzSockSend, 0x85) X(NtShzSockRecv, 0x86) X(NtShzSockShutdown, 0x87) \
    X(NtShzSockName, 0x88) X(NtShzSockSetOpt, 0x89) X(NtShzSockGetOpt, 0x8a) X(NtShzSockIoctl, 0x8b) \
    X(NtShzSockPoll, 0x8c) X(NtShzNetResolve, 0x8d) X(NtShzNetQuery, 0x8e) X(NtShzNetPing, 0x8f)

#define SYSCALL_LIST_K32(X) \
    X(NtQueryVolumeInformationFile, 0x90) X(NtLockFile, 0x91) X(NtUnlockFile, 0x92) X(NtShzQueryK32, 0x93) X(NtShzSetK32, 0x94)

#define SYSCALL_LIST_MISC(X)

/* Display/GPU (kernel64/gpu_sys.c; structures in win64/include/shzgpu.h) */
#define SYSCALL_LIST_GPU(X) \
    X(NtShzGpuQuery, 0xd0) X(NtShzGpuEdid, 0xd1) X(NtShzGpuCursor, 0xd2) X(NtShzGpuCapset, 0xd3) \
    X(NtShzGpuCtxCreate, 0xd4) X(NtShzGpuCtxDestroy, 0xd5) X(NtShzGpuResourceCreate, 0xd6) \
    X(NtShzGpuResourceDestroy, 0xd7) X(NtShzGpuSubmit, 0xd8) X(NtShzGpuTransfer, 0xd9)

/* Installer 0xb0-0xbf (kernel64/setup_sys.c): block-device enumeration and raw sector I/O for SHZSETUP.EXE until the
 * storage track's raw-sector syscalls (0xf0-0xff) are merged, plus the post-setup power request. See setup_abi.h. */
#define SYSCALL_LIST_SETUP(X) \
    X(NtShzSetupBlkQuery, 0xb0) X(NtShzSetupBlkRead, 0xb1) X(NtShzSetupBlkWrite, 0xb2) X(NtShzSetupBlkFlush, 0xb3) \
    X(NtShzSetupPower, 0xb4)

enum {
#define X(name, num) SYS_##name = num,
    SYSCALL_LIST(X)
    SYSCALL_LIST_REGISTRY(X)
    SYSCALL_LIST_GRAPHICS(X)
    SYSCALL_LIST_NET(X)
    SYSCALL_LIST_K32(X)
    SYSCALL_LIST_MISC(X)
    SYSCALL_LIST_GPU(X)
    SYSCALL_LIST_SETUP(X)
#undef X
    SYS_MAX = 0x100                 /* every number below goes to sys_extended(); sysext.c rejects unrouted ranges */
};

/* NTSTATUS values used by the kernel (subset of ntstatus.h; same numeric values). */
#define STATUS_SUCCESS ((int32_t)0x00000000)
#define STATUS_WAIT_0 ((int32_t)0x00000000)
#define STATUS_ABANDONED_WAIT_0 ((int32_t)0x00000080)
#define STATUS_USER_APC ((int32_t)0x000000C0)
#define STATUS_ALERTED ((int32_t)0x00000101)
#define STATUS_TIMEOUT ((int32_t)0x00000102)
#define STATUS_INVALID_CID ((int32_t)0xC000000B)
#define STATUS_PENDING ((int32_t)0x00000103)
#define STATUS_NOTIFY_CLEANUP ((int32_t)0x0000010B)
#define STATUS_GUARD_PAGE_VIOLATION ((int32_t)0x80000001)
#define STATUS_BUFFER_OVERFLOW ((int32_t)0x80000005)
#define STATUS_NO_MORE_FILES ((int32_t)0x80000006)
#define STATUS_NO_MORE_ENTRIES ((int32_t)0x8000001A)
#define STATUS_UNSUCCESSFUL ((int32_t)0xC0000001)
#define STATUS_NOT_IMPLEMENTED ((int32_t)0xC0000002)
#define STATUS_INVALID_INFO_CLASS ((int32_t)0xC0000003)
#define STATUS_ACCESS_VIOLATION ((int32_t)0xC0000005)
#define STATUS_INVALID_HANDLE ((int32_t)0xC0000008)
#define STATUS_INVALID_PARAMETER ((int32_t)0xC000000D)
#define STATUS_NO_SUCH_FILE ((int32_t)0xC000000F)
#define STATUS_END_OF_FILE ((int32_t)0xC0000011)
#define STATUS_NO_MEMORY ((int32_t)0xC0000017)
#define STATUS_CONFLICTING_ADDRESSES ((int32_t)0xC0000018)
#define STATUS_ACCESS_DENIED ((int32_t)0xC0000022)
#define STATUS_BUFFER_TOO_SMALL ((int32_t)0xC0000023)
#define STATUS_OBJECT_TYPE_MISMATCH ((int32_t)0xC0000024)
#define STATUS_OBJECT_NAME_INVALID ((int32_t)0xC0000033)
#define STATUS_OBJECT_NAME_NOT_FOUND ((int32_t)0xC0000034)
#define STATUS_OBJECT_NAME_COLLISION ((int32_t)0xC0000035)
#define STATUS_OBJECT_PATH_NOT_FOUND ((int32_t)0xC000003A)
#define STATUS_OBJECT_PATH_SYNTAX_BAD ((int32_t)0xC000003B)
#define STATUS_INFO_LENGTH_MISMATCH ((int32_t)0xC0000004)
#define STATUS_CANNOT_DELETE ((int32_t)0xC0000121)
#define STATUS_KEY_DELETED ((int32_t)0xC000017C)
#define STATUS_CHILD_MUST_BE_VOLATILE ((int32_t)0xC0000181)
#define STATUS_INSUFFICIENT_RESOURCES ((int32_t)0xC000009A)
#define STATUS_MUTANT_NOT_OWNED ((int32_t)0xC0000046)
#define STATUS_SEMAPHORE_LIMIT_EXCEEDED ((int32_t)0xC0000047)
#define STATUS_INVALID_SYSTEM_SERVICE ((int32_t)0xC000001C)
#define STATUS_ILLEGAL_INSTRUCTION ((int32_t)0xC000001D)
#define STATUS_PRIVILEGED_INSTRUCTION ((int32_t)0xC0000096)
#define STATUS_UNABLE_TO_FREE_VM ((int32_t)0xC000009A)
#define STATUS_FREE_VM_NOT_AT_BASE ((int32_t)0xC000009F)
#define STATUS_INTEGER_DIVIDE_BY_ZERO ((int32_t)0xC0000094)
#define STATUS_STACK_OVERFLOW ((int32_t)0xC00000FD)
#define STATUS_NOT_SUPPORTED ((int32_t)0xC00000BB)
#define STATUS_DIRECTORY_NOT_EMPTY ((int32_t)0xC0000101)
#define STATUS_INVALID_IMAGE_FORMAT ((int32_t)0xC000007B)
#define STATUS_DLL_NOT_FOUND ((int32_t)0xC0000135)
#define STATUS_ENTRYPOINT_NOT_FOUND ((int32_t)0xC0000139)
#define STATUS_ORDINAL_NOT_FOUND ((int32_t)0xC0000138)
#define STATUS_FILE_IS_A_DIRECTORY ((int32_t)0xC00000BA)
#define STATUS_NOT_A_DIRECTORY ((int32_t)0xC0000103)
#define STATUS_SHARING_VIOLATION ((int32_t)0xC0000043)
#define STATUS_DISK_FULL ((int32_t)0xC000007F)
#define STATUS_CANCELLED ((int32_t)0xC0000120)
#define STATUS_THREAD_IS_TERMINATING ((int32_t)0xC000004B)
#define STATUS_PROCESS_IS_TERMINATING ((int32_t)0xC000010A)
#define STATUS_NO_YIELD_PERFORMED ((int32_t)0x40000024)
#define STATUS_BREAKPOINT ((int32_t)0x80000003)
#define STATUS_SINGLE_STEP ((int32_t)0x80000004)
#define STATUS_DATATYPE_MISALIGNMENT ((int32_t)0x80000002)
#define STATUS_ARRAY_BOUNDS_EXCEEDED ((int32_t)0xC000008C)
#define STATUS_INTEGER_OVERFLOW ((int32_t)0xC0000095)
#define STATUS_IN_PAGE_ERROR ((int32_t)0xC0000006)
#define STATUS_NONCONTINUABLE_EXCEPTION ((int32_t)0xC0000025)

/* Windows page protection constants (memory manager semantics follow these). */
#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_WRITECOPY 0x08
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD 0x100
#define PAGE_NOCACHE 0x200
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_DECOMMIT 0x4000
#define MEM_RELEASE 0x8000
#define MEM_FREE 0x10000
#define MEM_PRIVATE 0x20000
#define MEM_MAPPED 0x40000
#define MEM_IMAGE 0x1000000
#define MEM_TOP_DOWN 0x100000
#endif
