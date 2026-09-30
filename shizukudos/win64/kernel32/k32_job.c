/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: job objects over kernel64/sysk32_obj.c: CreateJobObjectW/A, OpenJobObjectW, AssignProcessToJobObject,
 * IsProcessInJob, QueryInformationJobObject, SetInformationJobObject, TerminateJobObject.
 * The kernel enforces JOB_OBJECT_LIMIT_ACTIVE_PROCESS and JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and honours the breakaway and
 * die-on-unhandled-exception flags; a limit it cannot enforce (time, memory, working set, priority, affinity, UI
 * restrictions) is refused with ERROR_NOT_SUPPORTED rather than recorded and ignored.
 */
#include "k32.h"

static HANDLE job_open(int create, DWORD access, BOOL inherit, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.Attributes = inherit ? 2 : 0;
    if (name && name[0]) {
        const size_t n = k32_wlen(name);
        if (n >= 127) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
        us.Buffer = (PWSTR)name;
        us.Length = (USHORT)(n * 2);
        us.MaximumLength = us.Length;
        oa.ObjectName = &us;
    }
    st = create ? NtCreateJobObject(&h, access, &oa) : NtOpenJobObject(&h, access, &oa);
    if (st == (NTSTATUS)0x40000000) { shz_set_last_error(ERROR_ALREADY_EXISTS); return h; }
    if (st) { k32_nt_error(st); return 0; }
    shz_set_last_error(0);
    return h;
}

K32API HANDLE WINAPI CreateJobObjectW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name)
{
    return job_open(1, JOB_OBJECT_ALL_ACCESS, sa && sa->bInheritHandle, name);
}

K32API HANDLE WINAPI CreateJobObjectA(LPSECURITY_ATTRIBUTES sa, LPCSTR name)
{
    WCHAR w[128];
    if (name && k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return CreateJobObjectW(sa, name ? w : 0);
}

K32API HANDLE WINAPI OpenJobObjectW(DWORD access, BOOL inherit, LPCWSTR name)
{
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return job_open(0, access, inherit, name);
}

K32API BOOL WINAPI AssignProcessToJobObject(HANDLE job, HANDLE process)
{
    NTSTATUS st = NtAssignProcessToJobObject(job, process);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI TerminateJobObject(HANDLE job, UINT code)
{
    NTSTATUS st = NtTerminateJobObject(job, (NTSTATUS)code);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI IsProcessInJob(HANDLE process, HANDLE job, PBOOL result)
{
    NTSTATUS st = NtIsProcessInJob(process, job);
    if (st == 0x124) { *result = TRUE; return TRUE; }                     /* STATUS_PROCESS_IN_JOB */
    if (st == 0x123) { *result = FALSE; return TRUE; }                    /* STATUS_PROCESS_NOT_IN_JOB */
    k32_nt_error(st);
    return FALSE;
}

K32API BOOL WINAPI QueryInformationJobObject(HANDLE job, JOBOBJECTINFOCLASS cls, LPVOID info, DWORD len, LPDWORD returned)
{
    ULONG ret = 0;
    NTSTATUS st = NtQueryInformationJobObject(job, (ULONG)cls, info, len, &ret);
    if (returned) *returned = ret;
    if (st == STATUS_NOT_SUPPORTED || st == STATUS_INVALID_INFO_CLASS)
        return k32_unsupported("QueryInformationJobObject", "information class", st == STATUS_NOT_SUPPORTED ? ERROR_NOT_SUPPORTED
                                                                                                             : ERROR_INVALID_PARAMETER);
    if (st && st != STATUS_BUFFER_OVERFLOW) { k32_nt_error(st); return FALSE; }
    if (st == STATUS_BUFFER_OVERFLOW) { shz_set_last_error(ERROR_MORE_DATA); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI SetInformationJobObject(HANDLE job, JOBOBJECTINFOCLASS cls, LPVOID info, DWORD len)
{
    NTSTATUS st = NtSetInformationJobObject(job, (ULONG)cls, info, len);
    if (st == STATUS_NOT_SUPPORTED) return k32_unsupported("SetInformationJobObject", "a limit Kernel64 cannot enforce", ERROR_NOT_SUPPORTED);
    if (st == STATUS_INVALID_INFO_CLASS) return k32_unsupported("SetInformationJobObject", "information class", ERROR_INVALID_PARAMETER);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
