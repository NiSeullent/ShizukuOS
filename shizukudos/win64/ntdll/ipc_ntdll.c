/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll side of the Kernel64 IPC subsystem: the user-mode APC dispatcher and the NTSTATUS -> Win32 error translations of
 * the section, pipe, job and process-model statuses.
 *
 * KiUserApcDispatcher: the kernel delivers a user APC (NtQueueApcThread, QueueUserAPC, ReadFileEx completion routines,
 * waitable-timer completion routines) by saving the interrupted context as a CONTEXT on the user stack - its P1Home..P3Home
 * carry the APC's three arguments and P4Home the routine - and entering here with RCX = that CONTEXT. The routine runs,
 * then NtContinue(context, TestAlert = TRUE) resumes the interrupted wait (which returns STATUS_USER_APC), delivering any
 * further queued APC first, as Windows does.
 */
#include "nt.h"
#include "nt_ipc.h"
#include "ntdll_int.h"

SHZ_EXPORT VOID NTAPI KiUserApcDispatcher(PCONTEXT ctx)
{
    SHZ_PKNORMAL_ROUTINE routine = (SHZ_PKNORMAL_ROUTINE)(ULONG_PTR)ctx->P4Home;
    routine((PVOID)ctx->P1Home, (PVOID)ctx->P2Home, (PVOID)ctx->P3Home);
    NtContinue(ctx, TRUE);
    RtlExitUserProcess(STATUS_INVALID_PARAMETER);          /* NtContinue only fails on a corrupted context */
}

static const struct { NTSTATUS status; ULONG error; } ipc_map[] = {
    {(NTSTATUS)0x40000000, ERROR_ALREADY_EXISTS},              /* STATUS_OBJECT_NAME_EXISTS */
    {(NTSTATUS)0xC000000B, ERROR_INVALID_PARAMETER},           /* STATUS_INVALID_CID */
    {(NTSTATUS)0x8000000D, ERROR_PARTIAL_COPY},                /* STATUS_PARTIAL_COPY */
    {(NTSTATUS)0xC0000010, ERROR_INVALID_FUNCTION},            /* STATUS_INVALID_DEVICE_REQUEST */
    {(NTSTATUS)0xC0000019, ERROR_INVALID_ADDRESS},             /* STATUS_NOT_MAPPED_VIEW */
    {(NTSTATUS)0xC000001B, ERROR_INVALID_PARAMETER},           /* STATUS_UNABLE_TO_DELETE_SECTION */
    {(NTSTATUS)0xC000001F, ERROR_ACCESS_DENIED},               /* STATUS_INVALID_VIEW_SIZE */
    {(NTSTATUS)0xC0000030, ERROR_INVALID_PARAMETER},           /* STATUS_INVALID_PARAMETER_MIX */
    {(NTSTATUS)0xC0000040, ERROR_NOT_ENOUGH_MEMORY},           /* STATUS_SECTION_TOO_BIG */
    {(NTSTATUS)0xC0000045, ERROR_INVALID_PARAMETER},           /* STATUS_INVALID_PAGE_PROTECTION */
    {(NTSTATUS)0xC0000049, ERROR_INVALID_PARAMETER},           /* STATUS_SECTION_NOT_IMAGE */
    {(NTSTATUS)0xC000004A, ERROR_SIGNAL_REFUSED},              /* STATUS_SUSPEND_COUNT_EXCEEDED */
    {(NTSTATUS)0xC000004E, ERROR_ACCESS_DENIED},               /* STATUS_SECTION_PROTECTION */
    {(NTSTATUS)0xC0000061, ERROR_PRIVILEGE_NOT_HELD},          /* STATUS_PRIVILEGE_NOT_HELD */
    {(NTSTATUS)0xC00000AB, ERROR_PIPE_BUSY},                   /* STATUS_INSTANCE_NOT_AVAILABLE */
    {(NTSTATUS)0xC00000AC, ERROR_PIPE_BUSY},                   /* STATUS_PIPE_NOT_AVAILABLE */
    {(NTSTATUS)0xC00000AD, ERROR_BAD_PIPE},                    /* STATUS_INVALID_PIPE_STATE */
    {(NTSTATUS)0xC00000AE, ERROR_PIPE_BUSY},                   /* STATUS_PIPE_BUSY */
    {(NTSTATUS)0xC00000AF, ERROR_INVALID_FUNCTION},            /* STATUS_ILLEGAL_FUNCTION */
    {(NTSTATUS)0xC00000B0, ERROR_PIPE_NOT_CONNECTED},          /* STATUS_PIPE_DISCONNECTED */
    {(NTSTATUS)0xC00000B1, ERROR_NO_DATA},                     /* STATUS_PIPE_CLOSING */
    {(NTSTATUS)0xC00000B2, ERROR_PIPE_CONNECTED},              /* STATUS_PIPE_CONNECTED */
    {(NTSTATUS)0xC00000B3, ERROR_PIPE_LISTENING},              /* STATUS_PIPE_LISTENING */
    {(NTSTATUS)0xC00000B4, ERROR_BAD_PIPE},                    /* STATUS_INVALID_READ_MODE */
    {(NTSTATUS)0xC00000B5, ERROR_SEM_TIMEOUT},                 /* STATUS_IO_TIMEOUT */
    {(NTSTATUS)0xC00000D9, ERROR_NO_DATA},                     /* STATUS_PIPE_EMPTY */
    {(NTSTATUS)0xC00000EF, ERROR_INVALID_PARAMETER}, {(NTSTATUS)0xC00000F0, ERROR_INVALID_PARAMETER},
    {(NTSTATUS)0xC00000F1, ERROR_INVALID_PARAMETER}, {(NTSTATUS)0xC00000F2, ERROR_INVALID_PARAMETER},
    {(NTSTATUS)0xC00000F3, ERROR_INVALID_PARAMETER}, {(NTSTATUS)0xC00000F4, ERROR_INVALID_PARAMETER},
    {(NTSTATUS)0xC00000F5, ERROR_INVALID_PARAMETER}, {(NTSTATUS)0xC00000F6, ERROR_INVALID_PARAMETER},
    {(NTSTATUS)0xC00000F7, ERROR_INVALID_PARAMETER}, {(NTSTATUS)0xC00000F8, ERROR_INVALID_PARAMETER},
    {(NTSTATUS)0xC000011E, ERROR_FILE_INVALID},                /* STATUS_MAPPED_FILE_SIZE_ZERO */
    {(NTSTATUS)0xC000014B, ERROR_BROKEN_PIPE},                 /* STATUS_PIPE_BROKEN */
    {(NTSTATUS)0xC0000220, ERROR_MAPPED_ALIGNMENT},            /* STATUS_MAPPED_ALIGNMENT */
    {(NTSTATUS)0xC0000225, ERROR_NOT_FOUND},                   /* STATUS_NOT_FOUND */
    {(NTSTATUS)0xC0000235, ERROR_INVALID_HANDLE},              /* STATUS_HANDLE_NOT_CLOSABLE */
    {(NTSTATUS)0x0000010C, ERROR_NOTIFY_ENUM_DIR},             /* STATUS_NOTIFY_ENUM_DIR */
    {(NTSTATUS)0xC0000008, ERROR_INVALID_HANDLE},
    {(NTSTATUS)0xC00000BB, ERROR_NOT_SUPPORTED},
    {(NTSTATUS)0xC0000120, ERROR_OPERATION_ABORTED},
    {(NTSTATUS)0xC000010A, ERROR_ACCESS_DENIED},               /* STATUS_PROCESS_IS_TERMINATING */
    {(NTSTATUS)0xC000004B, ERROR_ACCESS_DENIED},               /* STATUS_THREAD_IS_TERMINATING */
    {(NTSTATUS)0xC0000128, ERROR_INVALID_HANDLE},              /* STATUS_FILE_CLOSED */
    {(NTSTATUS)0xC0000275, ERROR_NOT_A_REPARSE_POINT},         /* STATUS_NOT_A_REPARSE_POINT */
    {(NTSTATUS)0xC0000106, ERROR_FILENAME_EXCED_RANGE},       /* STATUS_NAME_TOO_LONG */
};

/* Win32 error for the statuses of this subsystem, (ULONG)-1 when it is not one of them (RtlNtStatusToDosError). */
SHZ_EXPORT ULONG NTAPI ShzIpcStatusToDosError(NTSTATUS status)
{
    unsigned i;
    for (i = 0; i < sizeof ipc_map / sizeof ipc_map[0]; ++i)
        if (ipc_map[i].status == status) return ipc_map[i].error;
    return (ULONG)-1;
}
