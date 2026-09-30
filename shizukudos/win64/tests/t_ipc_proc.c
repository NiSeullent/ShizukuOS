/* SPDX-License-Identifier: GPL-2.0-only
 * Windows process model: CreateProcess (suspended start, handle inheritance and HANDLE_LIST, STARTF_USESTDHANDLES,
 * environment, current directory), OpenProcess/OpenThread and ids, cross-process memory (Read/WriteProcessMemory,
 * VirtualAllocEx/QueryEx/ProtectEx/FreeEx), CreateRemoteThread, cross-process DuplicateHandle (both directions, with
 * DUPLICATE_CLOSE_SOURCE), SuspendThread/ResumeThread, TerminateThread, user APCs, handle flags, the exit code of a process
 * whose last thread calls ExitThread, and job objects (KILL_ON_JOB_CLOSE, TerminateJobObject, accounting, process lists,
 * inheritance by children, the active-process limit).
 * The parent and its children are the same image at the same base, so a global has the same address in each.
 */
#include "ipc_test.h"

typedef struct {
    volatile LONG ready, go, remote_done;
    volatile HANDLE child_event, dup_from_parent;
    char remote_copy[16];
} shared_t;
static shared_t g_sh;

/* ---------------------------------------------------------------- children */
static DWORD WINAPI remote_proc(LPVOID arg)                 /* runs in the child, started by the parent */
{
    memcpy(g_sh.remote_copy, arg, 11);
    g_sh.remote_done = 1;
    return 0x99;
}

static int child_target(void)
{
    DWORD t0 = GetTickCount(), flags;
    int bad = 0;
    g_sh.child_event = CreateEventW(0, TRUE, FALSE, 0);
    g_sh.ready = 1;
    while (!g_sh.go) { if (GetTickCount() - t0 > 20000) return 100; Sleep(5); }
    if (!g_sh.dup_from_parent || !SetEvent(g_sh.dup_from_parent)) bad |= 1;
    if (GetHandleInformation(g_sh.child_event, &flags)) bad |= 2;         /* the parent pulled it out with CLOSE_SOURCE */
    if (!g_sh.remote_done || memcmp(g_sh.remote_copy, "remote data", 11)) bad |= 4;
    return bad;
}

static int child_inherit(char **argv)
{
    HANDLE yes = (HANDLE)(ULONG_PTR)ipc_atoull(argv[2]), no = (HANDLE)(ULONG_PTR)ipc_atoull(argv[3]);
    DWORD flags = 0;
    int bad = 0;
    if (!GetHandleInformation(yes, &flags) || !(flags & HANDLE_FLAG_INHERIT)) bad |= 1;   /* still inheritable */
    if (!SetEvent(yes)) bad |= 2;
    if (GetHandleInformation(no, &flags) || GetLastError() != ERROR_INVALID_HANDLE) bad |= 4;
    return bad;
}

static int child_env(void)
{
    char v[16];
    WCHAR cwd[64];
    DWORD n = GetEnvironmentVariableA("IPCTEST", v, sizeof v);
    int bad = 0;
    if (n != 2 || memcmp(v, "42", 3)) bad |= 1;
    if (GetEnvironmentVariableA("PATH", v, sizeof v) || GetLastError() != ERROR_ENVVAR_NOT_FOUND) bad |= 2;
    n = GetCurrentDirectoryW(64, cwd);
    if (n < 6 || cwd[0] != 'C' || cwd[3] != 'S' || cwd[4] != 'H' || cwd[5] != 'Z') bad |= 4;
    return bad;
}

static DWORD WINAPI late_exit(LPVOID a) { (void)a; Sleep(100); ExitThread(0x33); }

static int child_exitthread(void)
{
    CreateThread(0, 0, late_exit, 0, 0, 0);
    ExitThread(0x44);                                      /* not the last thread: the process lives on */
}

static int child_jobspawn(char **argv)
{
    PROCESS_INFORMATION pi;
    const int expect_fail = argv[2][0] == 'f';
    HANDLE h = ipc_spawn_self("jobwait", 0, FALSE, 0, &pi);
    if (expect_fail) return h ? 1 : (GetLastError() == ERROR_NOT_ENOUGH_QUOTA ? 0 : 2);
    if (!h) return 3;
    {
        BOOL in = FALSE;
        if (!IsProcessInJob(h, 0, &in) || !in) return 4;   /* the grandchild inherited the job */
    }
    CloseHandle(pi.hThread);
    CloseHandle(h);
    return 0;
}

/* ---------------------------------------------------------------- in-process tests */
static volatile LONG g_spin, g_ran, g_apc;
static HANDLE g_never;
static DWORD WINAPI spinner(LPVOID a) { (void)a; while (g_spin >= 0) InterlockedIncrement(&g_spin); return 0; }
static DWORD WINAPI blocker(LPVOID a) { (void)a; WaitForSingleObject(g_never, INFINITE); return 1; }
static DWORD WINAPI marker(LPVOID a) { g_ran = (LONG)(ULONG_PTR)a; return 7; }
static VOID CALLBACK apc_fn(ULONG_PTR v) { g_apc += (LONG)v; }
static DWORD WINAPI alert_waiter(LPVOID a) { (void)a; return WaitForSingleObjectEx(g_never, 5000, TRUE); }

static void test_threads(void)
{
    HANDLE t;
    DWORD code = 0, prev, flags;
    LONG a, b;
    /* suspend / resume a spinning thread */
    t = CreateThread(0, 0, spinner, 0, 0, 0);
    Sleep(30);
    prev = SuspendThread(t);
    CHECK(prev == 0, "SuspendThread returns the previous count 0");
    Sleep(20);
    a = g_spin; Sleep(60); b = g_spin;
    CHECK(a == b, "a suspended thread makes no progress (%d -> %d)", (int)a, (int)b);
    CHECK(SuspendThread(t) == 1 && ResumeThread(t) == 2 && ResumeThread(t) == 1, "suspend counts nest: 1, 2, 1");
    a = g_spin; Sleep(60); b = g_spin;
    CHECK(b != a, "the resumed thread runs again");
    CHECK(ResumeThread(t) == 0, "ResumeThread of a running thread returns 0");
    CHECK(TerminateThread(t, 0x66) && WaitForSingleObject(t, 2000) == WAIT_OBJECT_0 && GetExitCodeThread(t, &code) && code == 0x66,
          "TerminateThread of a spinning thread (exit code 0x%x)", (unsigned)code);
    CloseHandle(t);
    /* CREATE_SUSPENDED */
    g_ran = 0;
    t = CreateThread(0, 0, marker, (LPVOID)5, CREATE_SUSPENDED, 0);
    Sleep(50);
    CHECK(t && g_ran == 0, "a CREATE_SUSPENDED thread does not run");
    CHECK(ResumeThread(t) == 1 && WaitForSingleObject(t, 2000) == WAIT_OBJECT_0 && g_ran == 5, "ResumeThread starts it (count was 1)");
    CloseHandle(t);
    /* TerminateThread of a blocked thread */
    g_never = CreateEventW(0, TRUE, FALSE, 0);
    t = CreateThread(0, 0, blocker, 0, 0, 0);
    Sleep(30);
    CHECK(TerminateThread(t, 0x77) && WaitForSingleObject(t, 2000) == WAIT_OBJECT_0 && GetExitCodeThread(t, &code) && code == 0x77,
          "TerminateThread of a thread blocked INFINITE ends it with its code (0x%x)", (unsigned)code);
    CloseHandle(t);
    /* ids */
    CHECK(GetThreadId(GetCurrentThread()) == GetCurrentThreadId() && GetProcessId(GetCurrentProcess()) == GetCurrentProcessId(),
          "GetThreadId/GetProcessId of the pseudo handles");
    {
        DWORD tid = 0;
        HANDLE h2;
        t = CreateThread(0, 0, blocker, 0, 0, &tid);
        h2 = OpenThread(THREAD_QUERY_INFORMATION | THREAD_TERMINATE, FALSE, tid);
        CHECK(h2 && GetThreadId(h2) == tid && GetProcessIdOfThread(h2) == GetCurrentProcessId() && tid != GetCurrentThreadId(),
              "OpenThread by id, GetThreadId and GetProcessIdOfThread agree (%u)", (unsigned)tid);
        CHECK(SuspendThread(h2) == (DWORD)-1 && GetLastError() == ERROR_ACCESS_DENIED, "SuspendThread needs THREAD_SUSPEND_RESUME");
        TerminateThread(h2, 1);
        WaitForSingleObject(t, 2000);
        CloseHandle(h2);
        CloseHandle(t);
        CHECK(!OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid) && GetLastError() == ERROR_INVALID_PARAMETER,
              "an exited thread's id no longer opens");
    }
    /* APCs */
    g_apc = 0;
    CHECK(QueueUserAPC(apc_fn, GetCurrentThread(), 3), "QueueUserAPC to the current thread");
    Sleep(10);
    CHECK(g_apc == 0, "a non-alertable wait does not run APCs");
    CHECK(SleepEx(2000, TRUE) == WAIT_IO_COMPLETION && g_apc == 3, "an alertable SleepEx runs it and returns WAIT_IO_COMPLETION");
    QueueUserAPC(apc_fn, GetCurrentThread(), 10);
    QueueUserAPC(apc_fn, GetCurrentThread(), 20);
    CHECK(WaitForSingleObjectEx(g_never, 2000, TRUE) == WAIT_IO_COMPLETION && g_apc == 33, "every queued APC runs before the wait returns");
    t = CreateThread(0, 0, alert_waiter, 0, 0, 0);
    Sleep(30);
    QueueUserAPC(apc_fn, t, 100);
    CHECK(WaitForSingleObject(t, 3000) == WAIT_OBJECT_0 && GetExitCodeThread(t, &code) && code == WAIT_IO_COMPLETION && g_apc == 133,
          "an APC wakes another thread's alertable wait");
    CloseHandle(t);
    /* named objects: one session, so "Local\\x" and "x" are the same name */
    {
        HANDLE a = CreateEventW(0, TRUE, FALSE, L"Local\\ipcns"), b = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, L"ipcns");
        CHECK(a && b && SetEvent(b) && WaitForSingleObject(a, 0) == WAIT_OBJECT_0, "\"Local\\x\" and \"x\" name the same event");
        CHECK(!OpenMutexW(SYNCHRONIZE, FALSE, L"ipcns") && GetLastError() == ERROR_INVALID_HANDLE,
              "opening it as a mutex fails with ERROR_INVALID_HANDLE (type mismatch)");
        CHECK(!OpenEventW(SYNCHRONIZE, FALSE, L"ipcns_none") && GetLastError() == ERROR_FILE_NOT_FOUND,
              "OpenEvent of a missing name fails with ERROR_FILE_NOT_FOUND");
        CloseHandle(a); CloseHandle(b);
    }
    /* handle flags */
    {
        SECURITY_ATTRIBUTES sa = { sizeof sa, 0, TRUE };
        HANDLE e = CreateEventW(&sa, TRUE, FALSE, 0);
        CHECK(GetHandleInformation(e, &flags) && flags == HANDLE_FLAG_INHERIT, "an event created with bInheritHandle is inheritable");
        CHECK(SetHandleInformation(e, HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE) &&
              GetHandleInformation(e, &flags) && flags == HANDLE_FLAG_PROTECT_FROM_CLOSE, "SetHandleInformation changes both flags");
        CHECK(!CloseHandle(e), "a protected handle cannot be closed");
        CHECK(SetHandleInformation(e, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0) && CloseHandle(e), "after clearing the flag it closes");
        CHECK(!GetHandleInformation(GetCurrentProcess(), &flags), "pseudo handles have no handle flags");
    }
}

/* ---------------------------------------------------------------- cross-process */
static void test_children(void)
{
    PROCESS_INFORMATION pi;
    HANDLE ch, e1, e2;
    SECURITY_ATTRIBUTES sa = { sizeof sa, 0, TRUE };
    char args[96];
    DWORD code;
    /* suspended start */
    {
        HANDLE ev = CreateEventW(0, TRUE, FALSE, L"Local\\ipcproc_susp");
        ch = ipc_spawn_self("marker", CREATE_SUSPENDED, FALSE, 0, &pi);
        CHECK(ch != 0, "CreateProcess(CREATE_SUSPENDED)");
        Sleep(100);
        CHECK(WaitForSingleObject(ev, 0) == WAIT_TIMEOUT && WaitForSingleObject(ch, 0) == WAIT_TIMEOUT, "the suspended child has not run");
        {
            DWORD ec = 0;
            CHECK(GetExitCodeProcess(ch, &ec) && ec == STILL_ACTIVE, "GetExitCodeProcess reports STILL_ACTIVE");
        }
        CHECK(pi.dwProcessId == GetProcessId(ch) && pi.dwThreadId == GetThreadId(pi.hThread) && pi.dwThreadId != pi.dwProcessId,
              "PROCESS_INFORMATION ids match GetProcessId/GetThreadId");
        CHECK(ResumeThread(pi.hThread) == 1, "ResumeThread of the initial thread returns 1");
        CHECK(WaitForSingleObject(ev, 10000) == WAIT_OBJECT_0 && ipc_wait_exit(ch, 10000) == 0, "the resumed child ran and exited");
        CloseHandle(pi.hThread); CloseHandle(ch); CloseHandle(ev);
    }
    /* inheritance: only inheritable handles, same values */
    {                                                   /* push e2 to a high handle value no child owns by itself */
        HANDLE pad[40];
        int i;
        e1 = CreateEventW(&sa, TRUE, FALSE, 0);
        for (i = 0; i < 40; ++i) pad[i] = CreateEventW(0, TRUE, FALSE, 0);
        e2 = CreateEventW(0, TRUE, FALSE, 0);
        for (i = 0; i < 40; ++i) CloseHandle(pad[i]);
    }
    snprintf(args, sizeof args, "inherit %u %u", (unsigned)(ULONG_PTR)e1, (unsigned)(ULONG_PTR)e2);
    ch = ipc_spawn_self(args, 0, TRUE, 0, 0);
    code = ch ? ipc_wait_exit(ch, 10000) : 0xffff;
    CHECK(code == 0 && WaitForSingleObject(e1, 0) == WAIT_OBJECT_0, "bInheritHandles: the inheritable handle has the same value in the child, the other does not exist (exit %u)", (unsigned)code);
    if (ch) CloseHandle(ch);
    ResetEvent(e1);
    ch = ipc_spawn_self(args, 0, FALSE, 0, 0);
    code = ch ? ipc_wait_exit(ch, 10000) : 0xffff;
    CHECK((code & 1) && WaitForSingleObject(e1, 0) == WAIT_TIMEOUT, "without bInheritHandles nothing is inherited (exit %u)", (unsigned)code);
    if (ch) CloseHandle(ch);
    /* PROC_THREAD_ATTRIBUTE_HANDLE_LIST */
    {
        HANDLE e3 = CreateEventW(&sa, TRUE, FALSE, 0), list[1];
        SIZE_T size = 0;
        STARTUPINFOEXW six;
        WCHAR self[260], cmd[400];
        int i = 0, k;
        memset(&six, 0, sizeof six);
        six.StartupInfo.cb = sizeof six;
        CHECK(!InitializeProcThreadAttributeList(0, 1, 0, &size) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && size,
              "InitializeProcThreadAttributeList reports its size");
        six.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, size);
        list[0] = e3;
        CHECK(InitializeProcThreadAttributeList(six.lpAttributeList, 1, 0, &size) &&
              UpdateProcThreadAttribute(six.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, sizeof list, 0, 0),
              "a HANDLE_LIST attribute");
        CHECK(!UpdateProcThreadAttribute(six.lpAttributeList, 0, 0x12345, list, sizeof list, 0, 0) && GetLastError() == ERROR_NOT_SUPPORTED,
              "an unknown attribute is refused");
        GetModuleFileNameW(0, self, 260);
        cmd[i++] = '"'; for (k = 0; self[k]; ++k) cmd[i++] = self[k]; cmd[i++] = '"';
        snprintf(args, sizeof args, " inherit %u %u", (unsigned)(ULONG_PTR)e3, (unsigned)(ULONG_PTR)e1);
        for (k = 0; args[k]; ++k) cmd[i++] = (WCHAR)args[k];
        cmd[i] = 0;
        if (CreateProcessW(self, cmd, 0, 0, TRUE, EXTENDED_STARTUPINFO_PRESENT, 0, 0, &six.StartupInfo, &pi)) {
            code = ipc_wait_exit(pi.hProcess, 10000);
            CHECK(code == 0 && WaitForSingleObject(e3, 0) == WAIT_OBJECT_0,
                  "only the listed inheritable handle reached the child (exit %u)", (unsigned)code);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        } else CHECK(0, "CreateProcess with a HANDLE_LIST");
        DeleteProcThreadAttributeList(six.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, six.lpAttributeList);
        CloseHandle(e3);
    }
    CloseHandle(e1); CloseHandle(e2);
    /* environment and current directory */
    {
        WCHAR self[260], cmd[300];
        STARTUPINFOW si;
        static const WCHAR env[] = L"IPCTEST=42\0OTHER=x\0";
        int i = 0, k;
        memset(&si, 0, sizeof si); si.cb = sizeof si;
        GetModuleFileNameW(0, self, 260);
        cmd[i++] = '"'; for (k = 0; self[k]; ++k) cmd[i++] = self[k]; cmd[i++] = '"';
        cmd[i++] = ' '; cmd[i++] = 'e'; cmd[i++] = 'n'; cmd[i++] = 'v'; cmd[i] = 0;
        if (CreateProcessW(0, cmd, 0, 0, FALSE, CREATE_UNICODE_ENVIRONMENT, (LPVOID)env, L"C:\\SHZ", &si, &pi)) {
            code = ipc_wait_exit(pi.hProcess, 10000);
            CHECK(code == 0, "the child sees the given environment block and current directory (exit %u)", (unsigned)code);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        } else CHECK(0, "CreateProcess with an environment and a directory");
        CHECK(!CreateProcessW(0, cmd, 0, 0, FALSE, 0, 0, L"C:\\NO\\SUCH\\DIR", &si, &pi) && GetLastError() == ERROR_DIRECTORY,
              "a missing current directory fails with ERROR_DIRECTORY");
        CHECK(!CreateProcessW(L"C:\\SHZ\\TESTS\\NOPE.EXE", 0, 0, 0, FALSE, 0, 0, 0, &si, &pi) && GetLastError() == ERROR_FILE_NOT_FOUND,
              "a missing image fails with ERROR_FILE_NOT_FOUND");
    }
    /* the last thread's ExitThread code is the process exit code */
    ch = ipc_spawn_self("exitthread", 0, FALSE, 0, 0);
    code = ch ? ipc_wait_exit(ch, 10000) : 0;
    CHECK(code == 0x33, "a process whose last thread calls ExitThread(0x33) exits with 0x33 (0x%x)", (unsigned)code);
    if (ch) CloseHandle(ch);
    /* cross-process memory, remote thread, handle duplication both ways */
    ch = ipc_spawn_self("target", 0, FALSE, 0, &pi);
    CHECK(ch != 0, "the target child");
    if (ch) {
        DWORD t0 = GetTickCount();
        LONG ready = 0;
        SIZE_T n = 0;
        HANDLE mine = 0, ev = CreateEventW(0, TRUE, FALSE, 0), remote = 0, rt;
        char *rbuf;
        MEMORY_BASIC_INFORMATION mbi;
        DWORD old = 0;
        HANDLE weak = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.dwProcessId);
        HANDLE full = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
        CHECK(weak && full, "OpenProcess by id");
        CHECK(!ReadProcessMemory(weak, (LPCVOID)&g_sh.ready, &ready, 4, &n) && GetLastError() == ERROR_ACCESS_DENIED,
              "ReadProcessMemory needs PROCESS_VM_READ");
        while (ReadProcessMemory(full, (LPCVOID)&g_sh.ready, &ready, 4, &n) && !ready && GetTickCount() - t0 < 10000) Sleep(5);
        CHECK(ready == 1 && n == 4, "ReadProcessMemory sees the child's global");
        CHECK(DuplicateHandle(GetCurrentProcess(), ev, full, &remote, 0, FALSE, DUPLICATE_SAME_ACCESS) && remote,
              "DuplicateHandle into the child");
        {
            HANDLE child_ev = 0;
            ReadProcessMemory(full, (LPCVOID)&g_sh.child_event, &child_ev, sizeof child_ev, &n);
            CHECK(child_ev && DuplicateHandle(full, child_ev, GetCurrentProcess(), &mine, 0, FALSE,
                                              DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE) && mine,
                  "DuplicateHandle out of the child with DUPLICATE_CLOSE_SOURCE");
            CHECK(mine && SetEvent(mine), "the pulled handle works here");
        }
        CHECK(WriteProcessMemory(full, (LPVOID)&g_sh.dup_from_parent, &remote, sizeof remote, &n) && n == sizeof remote,
              "WriteProcessMemory of the value");
        rbuf = VirtualAllocEx(full, 0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        CHECK(rbuf && WriteProcessMemory(full, rbuf, "remote data", 11, &n) && n == 11, "VirtualAllocEx + WriteProcessMemory");
        CHECK(VirtualQueryEx(full, rbuf, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE &&
              mbi.Type == MEM_PRIVATE, "VirtualQueryEx of the child's allocation");
        CHECK(VirtualProtectEx(full, rbuf, 4096, PAGE_READONLY, &old) && old == PAGE_READWRITE, "VirtualProtectEx");
        rt = CreateRemoteThread(full, 0, 0, remote_proc, rbuf, 0, 0);
        CHECK(rt && WaitForSingleObject(rt, 10000) == WAIT_OBJECT_0 && GetExitCodeThread(rt, &code) && code == 0x99,
              "CreateRemoteThread ran in the child (exit 0x%x)", (unsigned)code);
        CHECK(rt && GetProcessIdOfThread(rt) == pi.dwProcessId, "the remote thread belongs to the child");
        if (rt) CloseHandle(rt);
        {
            char probe[4];
            BYTE code_byte = 0;
            CHECK(!ReadProcessMemory(full, (LPCVOID)0x10000, probe, 4, &n) && GetLastError() == ERROR_PARTIAL_COPY && n == 0,
                  "reading unmapped memory fails with ERROR_PARTIAL_COPY");
            CHECK(ReadProcessMemory(full, (LPCVOID)(ULONG_PTR)&remote_proc, &code_byte, 1, &n) &&
                  WriteProcessMemory(full, (LPVOID)(ULONG_PTR)&remote_proc, &code_byte, 1, &n) && n == 1,
                  "WriteProcessMemory into read-only code works (temporarily writable)");
            CHECK(VirtualQueryEx(full, (LPCVOID)(ULONG_PTR)&remote_proc, &mbi, sizeof mbi) && mbi.Protect == PAGE_EXECUTE_READ,
                  "...and the code is read-only again");
        }
        CHECK(VirtualFreeEx(full, rbuf, 0, MEM_RELEASE), "VirtualFreeEx");
        {
            const LONG one = 1;
            WriteProcessMemory(full, (LPVOID)&g_sh.go, &one, 4, &n);
        }
        CHECK(WaitForSingleObject(ev, 10000) == WAIT_OBJECT_0, "the child signalled the duplicated event");
        code = ipc_wait_exit(ch, 10000);
        CHECK(code == 0, "the child verified the pulled handle is gone and the remote thread's work (exit %u)", (unsigned)code);
        CHECK(!ReadProcessMemory(full, (LPCVOID)&g_sh.ready, &ready, 4, &n), "an exited process's memory is gone");
        CloseHandle(weak); CloseHandle(full); CloseHandle(mine); CloseHandle(ev);
        CloseHandle(pi.hThread); CloseHandle(ch);
    }
    CHECK(!OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 0x7ffffff0u) && GetLastError() == ERROR_INVALID_PARAMETER,
          "OpenProcess of an unknown id fails with ERROR_INVALID_PARAMETER");
}

/* ---------------------------------------------------------------- jobs */
static void test_jobs(void)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION xl;
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acc;
    struct { JOBOBJECT_BASIC_PROCESS_ID_LIST h; ULONG_PTR more[7]; } ids;
    PROCESS_INFORMATION pi;
    HANDLE job, ch;
    BOOL in = TRUE;
    DWORD code;
    /* KILL_ON_JOB_CLOSE */
    job = CreateJobObjectW(0, 0);
    memset(&xl, 0, sizeof xl);
    xl.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    CHECK(job && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &xl, sizeof xl), "a KILL_ON_JOB_CLOSE job");
    ch = ipc_spawn_self("jobwait", CREATE_SUSPENDED, FALSE, 0, &pi);
    CHECK(ch && AssignProcessToJobObject(job, ch), "AssignProcessToJobObject of a suspended child");
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CHECK(IsProcessInJob(ch, job, &in) && in, "IsProcessInJob(child, job)");
    CHECK(IsProcessInJob(ch, 0, &in) && in, "IsProcessInJob(child, NULL)");
    CHECK(IsProcessInJob(GetCurrentProcess(), job, &in) && !in, "the parent is not in the job");
    CHECK(QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &acc, sizeof acc, 0) &&
          acc.ActiveProcesses == 1 && acc.TotalProcesses == 1, "accounting: 1 active, 1 total");
    CHECK(QueryInformationJobObject(job, JobObjectBasicProcessIdList, &ids, sizeof ids, 0) && ids.h.NumberOfProcessIdsInList == 1 &&
          ids.h.ProcessIdList[0] == pi.dwProcessId, "the process id list names the child");
    memset(&xl, 0, sizeof xl);
    CHECK(QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &xl, sizeof xl, 0) &&
          xl.BasicLimitInformation.LimitFlags == JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, "the limit reads back");
    {
        HANDLE other = CreateJobObjectW(0, 0);
        CHECK(!AssignProcessToJobObject(other, ch) && GetLastError() == ERROR_ACCESS_DENIED, "a process in a job cannot join another one");
        CloseHandle(other);
    }
    CloseHandle(job);
    code = ch ? ipc_wait_exit(ch, 5000) : 1;
    CHECK(code == 0, "closing the job's last handle killed the child (exit %u)", (unsigned)code);
    if (ch) CloseHandle(ch);
    /* TerminateJobObject, and a grandchild inherits the job */
    job = CreateJobObjectW(0, 0);
    ch = ipc_spawn_self("jobspawn ok", CREATE_SUSPENDED, FALSE, 0, &pi);
    CHECK(ch && AssignProcessToJobObject(job, ch), "a second job and child");
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    code = ch ? ipc_wait_exit(ch, 10000) : 1;
    CHECK(code == 0, "the child's own child was created inside the job (exit %u)", (unsigned)code);
    CHECK(QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &acc, sizeof acc, 0) &&
          acc.TotalProcesses == 2 && acc.ActiveProcesses == 1 && acc.TotalTerminatedProcesses == 1,
          "accounting: 2 total, 1 active (the grandchild), 1 ended (%u %u %u)", (unsigned)acc.TotalProcesses,
          (unsigned)acc.ActiveProcesses, (unsigned)acc.TotalTerminatedProcesses);
    CHECK(TerminateJobObject(job, 0x55), "TerminateJobObject");
    {
        DWORD t0 = GetTickCount();
        do QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &acc, sizeof acc, 0);
        while (acc.ActiveProcesses && GetTickCount() - t0 < 5000 && (Sleep(5), 1));
        CHECK(acc.ActiveProcesses == 0, "every process of the job ended");
    }
    if (ch) CloseHandle(ch);
    CloseHandle(job);
    /* the active-process limit stops a child from creating processes */
    job = CreateJobObjectW(0, 0);
    memset(&xl, 0, sizeof xl);
    xl.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    xl.BasicLimitInformation.ActiveProcessLimit = 1;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &xl, sizeof xl);
    ch = ipc_spawn_self("jobspawn fail", CREATE_SUSPENDED, FALSE, 0, &pi);
    CHECK(ch && AssignProcessToJobObject(job, ch), "a job with ActiveProcessLimit 1");
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    code = ch ? ipc_wait_exit(ch, 10000) : 1;
    CHECK(code == 0, "CreateProcess inside it fails with ERROR_NOT_ENOUGH_QUOTA (child exit %u)", (unsigned)code);
    if (ch) CloseHandle(ch);
    CloseHandle(job);
}

int main(int argc, char **argv)
{
    kstats_t k0, k1;
    if (argc >= 2) {
        if (!strcmp(argv[1], "marker")) { HANDLE e = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\ipcproc_susp"); return e && SetEvent(e) ? 0 : 1; }
        if (!strcmp(argv[1], "target")) return child_target();
        if (!strcmp(argv[1], "inherit") && argc >= 4) return child_inherit(argv);
        if (!strcmp(argv[1], "env")) return child_env();
        if (!strcmp(argv[1], "exitthread")) return child_exitthread();
        if (!strcmp(argv[1], "jobwait")) { Sleep(INFINITE); return 9; }
        if (!strcmp(argv[1], "jobspawn") && argc >= 3) return child_jobspawn(argv);
        return 200;
    }
    kstats(&k0);
    test_threads();
    test_children();
    test_jobs();
    Sleep(50);
    kstats(&k1);
    CHECK(k1.jobs == k0.jobs, "no job object leaked (%llu -> %llu)", k0.jobs, k1.jobs);
    CHECK(k1.threads <= k0.threads + 1, "no thread slot leaked (%llu -> %llu)", k0.threads, k1.threads);
    printf("%s: %d check(s) failed\n", g_bad ? "FAIL" : "PASS", g_bad);
    return g_bad;
}
