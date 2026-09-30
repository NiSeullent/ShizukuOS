/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: cross-process and handle functions over the Kernel64 process services (kernel64/sysk32_obj.c, sysx.c):
 * OpenProcess, OpenThread, GetProcessId, GetThreadId, GetProcessIdOfThread, CreateRemoteThread(Ex), ReadProcessMemory,
 * WriteProcessMemory, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx, GetHandleInformation, SetHandleInformation,
 * SuspendThread, ResumeThread, the process/thread attribute lists and CreateProcessW (inheritance, environment, directory,
 * standard handles, CREATE_SUSPENDED, job lists).
 */
#include "k32.h"

typedef struct { ULONG64 UniqueProcess, UniqueThread; } client_id_t;

K32API HANDLE WINAPI OpenProcess(DWORD access, BOOL inherit, DWORD pid)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    client_id_t cid = { pid, 0 };
    HANDLE h = 0;
    NTSTATUS st;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.Attributes = inherit ? 2 : 0;
    st = NtOpenProcess(&h, access, &oa, &cid);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}

K32API HANDLE WINAPI OpenThread(DWORD access, BOOL inherit, DWORD tid)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    client_id_t cid = { 0, tid };
    HANDLE h = 0;
    NTSTATUS st;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.Attributes = inherit ? 2 : 0;
    st = NtOpenThread(&h, access, &oa, &cid);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}

K32API DWORD WINAPI GetProcessId(HANDLE h)
{
    struct { LONG64 es; ULONG64 peb, aff; LONG64 prio; ULONG64 pid, ppid; } b;
    NTSTATUS st = NtQueryInformationProcess(h, 0, &b, sizeof b, 0);
    if (st) { k32_nt_error(st); return 0; }
    return (DWORD)b.pid;
}

static NTSTATUS thread_basic(HANDLE h, ULONG64 *pid, ULONG64 *tid)
{
    struct { LONG64 es; ULONG64 teb, pid, tid, aff; LONG prio, base; } b;
    NTSTATUS st = NtQueryInformationThread(h, 0, &b, sizeof b, 0);
    if (st) return st;
    if (pid) *pid = b.pid;
    if (tid) *tid = b.tid;
    return STATUS_SUCCESS;
}

K32API DWORD WINAPI GetThreadId(HANDLE h)
{
    ULONG64 tid = 0;
    NTSTATUS st = thread_basic(h, 0, &tid);
    if (st) { k32_nt_error(st); return 0; }
    return (DWORD)tid;
}

K32API DWORD WINAPI GetProcessIdOfThread(HANDLE h)
{
    ULONG64 pid = 0;
    NTSTATUS st = thread_basic(h, &pid, 0);
    if (st) { k32_nt_error(st); return 0; }
    return (DWORD)pid;
}

K32API HANDLE WINAPI CreateRemoteThreadEx(HANDLE process, LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param,
                                          DWORD flags, LPPROC_THREAD_ATTRIBUTE_LIST attrs, LPDWORD tid)
{
    HANDLE h = 0;
    NTSTATUS st;
    (void)sa;
    if (attrs) return k32_unsupported("CreateRemoteThreadEx", "thread attribute list", ERROR_NOT_SUPPORTED), (HANDLE)0;
    if (flags & ~(DWORD)(CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    st = NtCreateThreadEx(&h, THREAD_ALL_ACCESS, 0, process, (PVOID)start, param, (flags & CREATE_SUSPENDED) ? 1 : 0, 0, stack, 0, 0);
    if (st) { k32_nt_error(st); return 0; }
    if (tid) { ULONG64 t = 0; *tid = thread_basic(h, 0, &t) ? 0 : (DWORD)t; }
    return h;
}

K32API HANDLE WINAPI CreateRemoteThread(HANDLE process, LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param,
                                        DWORD flags, LPDWORD tid)
{
    return CreateRemoteThreadEx(process, sa, stack, start, param, flags, 0, tid);
}

K32API BOOL WINAPI ReadProcessMemory(HANDLE process, LPCVOID addr, LPVOID buf, SIZE_T size, SIZE_T *done)
{
    SIZE_T n = 0;
    NTSTATUS st = NtReadVirtualMemory(process, (PVOID)addr, buf, size, &n);
    if (done) *done = n;
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* As on Windows, WriteProcessMemory makes a read-only (or copy-on-write) target writable for the copy and restores the old
 * protection afterwards; executable code stays executable. */
K32API BOOL WINAPI WriteProcessMemory(HANDLE process, LPVOID addr, LPCVOID buf, SIZE_T size, SIZE_T *done)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T n = 0, ret = 0;
    NTSTATUS st;
    ULONG old = 0;
    int changed = 0;
    if (NtQueryVirtualMemory(process, addr, 0, &mbi, sizeof mbi, &ret) == 0 && mbi.State == MEM_COMMIT &&
        (mbi.Protect & 0xff) != PAGE_READWRITE && (mbi.Protect & 0xff) != PAGE_EXECUTE_READWRITE &&
        (mbi.Protect & 0xff) != PAGE_NOACCESS) {
        PVOID b = addr;
        SIZE_T sz = size;
        const ULONG want = (mbi.Protect & 0xf0) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        if (NtProtectVirtualMemory(process, &b, &sz, want, &old) == 0) changed = 1;
    }
    st = NtWriteVirtualMemory(process, addr, buf, size, &n);
    if (changed) {
        PVOID b = addr;
        SIZE_T sz = size;
        ULONG tmp;
        NtProtectVirtualMemory(process, &b, &sz, old, &tmp);
    }
    if (done) *done = n;
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI VirtualFreeEx(HANDLE process, LPVOID addr, SIZE_T size, DWORD type)
{
    PVOID base = addr;
    SIZE_T sz = size;
    NTSTATUS st = NtFreeVirtualMemory(process, &base, &sz, type);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI VirtualProtectEx(HANDLE process, LPVOID addr, SIZE_T size, DWORD prot, PDWORD old)
{
    PVOID base = addr;
    SIZE_T sz = size;
    ULONG o = 0;
    NTSTATUS st = NtProtectVirtualMemory(process, &base, &sz, prot, &o);
    if (st) { k32_nt_error(st); return FALSE; }
    if (old) *old = o;
    return TRUE;
}

K32API SIZE_T WINAPI VirtualQueryEx(HANDLE process, LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T len)
{
    SIZE_T ret = 0;
    NTSTATUS st;
    if (len < sizeof *mbi) { shz_set_last_error(ERROR_BAD_LENGTH); return 0; }
    st = NtQueryVirtualMemory(process, (PVOID)addr, 0, mbi, sizeof *mbi, &ret);
    if (st) { k32_nt_error(st); return 0; }
    return sizeof *mbi;
}

/* ---------------------------------------------------------------- handle flags */
K32API BOOL WINAPI GetHandleInformation(HANDLE h, LPDWORD flags)
{
    UCHAR v[2];
    NTSTATUS st = NtQueryObject(h, 4, v, sizeof v, 0);                     /* ObjectHandleFlagInformation */
    if (st) { k32_nt_error(st); return FALSE; }
    *flags = (v[0] ? HANDLE_FLAG_INHERIT : 0) | (v[1] ? HANDLE_FLAG_PROTECT_FROM_CLOSE : 0);
    return TRUE;
}

K32API BOOL WINAPI SetHandleInformation(HANDLE h, DWORD mask, DWORD flags)
{
    UCHAR v[2];
    NTSTATUS st = NtQueryObject(h, 4, v, sizeof v, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    if (mask & HANDLE_FLAG_INHERIT) v[0] = (flags & HANDLE_FLAG_INHERIT) != 0;
    if (mask & HANDLE_FLAG_PROTECT_FROM_CLOSE) v[1] = (flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0;
    st = NtSetInformationObject(h, 4, v, sizeof v);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- suspension */
K32API DWORD WINAPI SuspendThread(HANDLE h)
{
    ULONG prev = 0;
    NTSTATUS st = NtSuspendThread(h, &prev);
    if (st) { k32_nt_error(st); return (DWORD)-1; }
    return prev;
}

K32API DWORD WINAPI ResumeThread(HANDLE h)
{
    ULONG prev = 0;
    NTSTATUS st = NtResumeThread(h, &prev);
    if (st) { k32_nt_error(st); return (DWORD)-1; }
    return prev;
}

/* ---------------------------------------------------------------- process/thread attribute lists */
typedef struct { DWORD_PTR attr; SIZE_T size; PVOID value; } k32_attr;
typedef struct { DWORD count, max, flags, pad; k32_attr a[1]; } k32_attr_list;

K32API BOOL WINAPI InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD count, DWORD flags, PSIZE_T size)
{
    const SIZE_T need = 16 + (SIZE_T)(count ? count : 1) * sizeof(k32_attr);
    k32_attr_list *l = (k32_attr_list *)list;
    if (flags || !size) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!list || *size < need) { *size = need; shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    l->count = 0;
    l->max = count;
    l->flags = 0;
    l->pad = 0;
    *size = need;
    return TRUE;
}

K32API BOOL WINAPI UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD flags, DWORD_PTR attr, PVOID value, SIZE_T size,
                                             PVOID prev, PSIZE_T ret_size)
{
    k32_attr_list *l = (k32_attr_list *)list;
    DWORD i;
    if (!l || flags || prev || ret_size) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    switch (attr) {
    case PROC_THREAD_ATTRIBUTE_HANDLE_LIST:
        if (!size || size % sizeof(HANDLE) || size / sizeof(HANDLE) > 64) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        break;
    case PROC_THREAD_ATTRIBUTE_JOB_LIST:
        if (!size || size % sizeof(HANDLE)) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        break;
    case PROC_THREAD_ATTRIBUTE_PARENT_PROCESS:
        if (size != sizeof(HANDLE)) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        break;
    case PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY:
        if (size != sizeof(DWORD64) && size != 2 * sizeof(DWORD64) && size != 3 * sizeof(DWORD64)) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        break;
    default:
        if (!size) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        break;                                                             /* recorded; CreateProcess refuses what it cannot do */
    }
    for (i = 0; i < l->count; ++i)
        if (l->a[i].attr == attr) { shz_set_last_error(ERROR_OBJECT_NAME_EXISTS); return FALSE; }
    if (l->count >= l->max) { shz_set_last_error(ERROR_GEN_FAILURE); return FALSE; }
    l->a[l->count].attr = attr;
    l->a[l->count].size = size;
    l->a[l->count].value = value;
    ++l->count;
    return TRUE;
}

K32API VOID WINAPI DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST list) { (void)list; }   /* the caller owns the memory */

/* ---------------------------------------------------------------- CreateProcessW */
static size_t env_chars_w(const WCHAR *e)
{
    size_t n = 0;
    while (e[n] || e[n + 1]) ++n;
    return n + 2;
}

K32API BOOL WINAPI CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit,
                                  DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    SHZ_UNICODE_STRING image, cmdline, cwd;
    WCHAR path[300], nt[320], full_dir[300];
    WCHAR *wenv = 0;
    HANDLE hp = 0, ht = 0, *jobs = 0;
    shz_process_ex ext;
    NTSTATUS st;
    DWORD njobs = 0, i;
    const DWORD known = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE | CREATE_NO_WINDOW | DETACHED_PROCESS |
                        CREATE_NEW_PROCESS_GROUP | CREATE_DEFAULT_ERROR_MODE | EXTENDED_STARTUPINFO_PRESENT | CREATE_BREAKAWAY_FROM_JOB |
                        INHERIT_PARENT_AFFINITY | CREATE_PRESERVE_CODE_AUTHZ_LEVEL | CREATE_UNICODE_ENVIRONMENT |
                        IDLE_PRIORITY_CLASS | BELOW_NORMAL_PRIORITY_CLASS | NORMAL_PRIORITY_CLASS | ABOVE_NORMAL_PRIORITY_CLASS |
                        HIGH_PRIORITY_CLASS | REALTIME_PRIORITY_CLASS | CREATE_SEPARATE_WOW_VDM | CREATE_SHARED_WOW_VDM;
    (void)pa; (void)ta;
    if (flags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS))
        return k32_unsupported("CreateProcessW", "debugging a child (no debugger interface)", ERROR_NOT_SUPPORTED);
    if (flags & ~known) return k32_unsupported("CreateProcessW", "creation flag", ERROR_INVALID_PARAMETER);
    memset(&ext, 0, sizeof ext);
    ext.size = sizeof ext;
    if (flags & CREATE_BREAKAWAY_FROM_JOB) ext.flags |= SHZ_CPX_BREAKAWAY;
    if (inherit) ext.flags |= SHZ_CPX_INHERIT;
    if (si && (si->dwFlags & STARTF_USESTDHANDLES)) {
        ext.flags |= SHZ_CPX_STD;
        ext.std[0] = (ULONG64)si->hStdInput;
        ext.std[1] = (ULONG64)si->hStdOutput;
        ext.std[2] = (ULONG64)si->hStdError;
    }
    if (si && (flags & EXTENDED_STARTUPINFO_PRESENT)) {
        const k32_attr_list *l = (const k32_attr_list *)((LPSTARTUPINFOEXW)si)->lpAttributeList;
        for (i = 0; l && i < l->count; ++i) {
            switch (l->a[i].attr) {
            case PROC_THREAD_ATTRIBUTE_HANDLE_LIST:
                ext.handle_list = (ULONG64)l->a[i].value;
                ext.handle_count = (ULONG)(l->a[i].size / sizeof(HANDLE));
                break;
            case PROC_THREAD_ATTRIBUTE_JOB_LIST:
                jobs = (HANDLE *)l->a[i].value;
                njobs = (DWORD)(l->a[i].size / sizeof(HANDLE));
                break;
            default:
                return k32_unsupported("CreateProcessW", "process attribute (only HANDLE_LIST and JOB_LIST are provided)", ERROR_NOT_SUPPORTED);
            }
        }
    }
    if (app) {
        size_t n = k32_wlen(app);
        if (n >= 299) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
        memcpy(path, app, (n + 1) * sizeof(WCHAR));
    } else if (cmd) {                                                      /* first token of the command line */
        size_t i2 = 0, o = 0;
        if (cmd[0] == '"') { i2 = 1; while (cmd[i2] && cmd[i2] != '"' && o < 299) path[o++] = cmd[i2++]; }
        else while (cmd[i2] && cmd[i2] != ' ' && cmd[i2] != '\t' && o < 299) path[o++] = cmd[i2++];
        path[o] = 0;
        {
            size_t k = o;
            int dot = 0;
            while (k) { --k; if (path[k] == '.') { dot = 1; break; } if (path[k] == '\\') break; }
            if (!dot && o + 4 < 299) { path[o++] = '.'; path[o++] = 'e'; path[o++] = 'x'; path[o++] = 'e'; path[o] = 0; }
        }
    } else { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = k32_dos_to_nt(path, nt, 320);
    if (st) { k32_nt_error(st); return FALSE; }
    image.Buffer = nt + 4;                                                 /* the kernel takes DOS-style paths */
    image.Length = (USHORT)((k32_wlen(nt) - 4) * 2);
    image.MaximumLength = image.Length + 2;
    if (cmd) RtlInitUnicodeString(&cmdline, cmd);
    if (dir) {
        const DWORD n = GetFullPathNameW(dir, 300, full_dir, 0);
        DWORD attr;
        if (!n || n >= 300) { shz_set_last_error(ERROR_DIRECTORY); return FALSE; }
        attr = GetFileAttributesW(full_dir);
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) { shz_set_last_error(ERROR_DIRECTORY); return FALSE; }
    } else {
        k32_current_directory(full_dir, 300);
    }
    RtlInitUnicodeString(&cwd, full_dir);
    if (env) {
        if (flags & CREATE_UNICODE_ENVIRONMENT) {
            ext.env = (ULONG64)env;
            ext.env_bytes = env_chars_w(env) * 2;
        } else {                                                           /* ANSI block -> UTF-16 */
            const char *a = env;
            size_t n = 0;
            while (a[n] || a[n + 1]) ++n;
            n += 2;
            wenv = RtlAllocateHeap(ShzProcessHeap(), 0, n * 2);
            if (!wenv) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
            for (i = 0; i < n; ++i) wenv[i] = (unsigned char)a[i];
            ext.env = (ULONG64)wenv;
            ext.env_bytes = n * 2;
        }
    }
    if ((flags & CREATE_SUSPENDED) || njobs) ext.flags |= SHZ_CPX_SUSPENDED;  /* jobs are assigned before the first instruction */
    st = NtCreateProcessEx(&hp, &ht, &image, cmd ? &cmdline : 0, &cwd, &ext);
    if (wenv) RtlFreeHeap(ShzProcessHeap(), 0, wenv);
    if (st) { k32_nt_error(st); return FALSE; }
    for (i = 0; i < njobs; ++i) {
        st = NtAssignProcessToJobObject(jobs[i], hp);
        if (st) {
            NtTerminateProcess(hp, (NTSTATUS)ERROR_ACCESS_DENIED);
            NtClose(ht);
            NtClose(hp);
            k32_nt_error(st);
            return FALSE;
        }
    }
    if (flags & (IDLE_PRIORITY_CLASS | BELOW_NORMAL_PRIORITY_CLASS | ABOVE_NORMAL_PRIORITY_CLASS | HIGH_PRIORITY_CLASS | REALTIME_PRIORITY_CLASS))
        SetPriorityClass(hp, flags & (IDLE_PRIORITY_CLASS | BELOW_NORMAL_PRIORITY_CLASS | ABOVE_NORMAL_PRIORITY_CLASS | HIGH_PRIORITY_CLASS |
                                      REALTIME_PRIORITY_CLASS));
    if (njobs && !(flags & CREATE_SUSPENDED)) { ULONG prev; NtResumeThread(ht, &prev); }
    memset(pi, 0, sizeof *pi);
    pi->hProcess = hp;
    pi->hThread = ht;
    pi->dwProcessId = GetProcessId(hp);
    pi->dwThreadId = GetThreadId(ht);
    return TRUE;
}
