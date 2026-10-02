/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64's partial NT user-thread priority contract, through real Win64
 * kernel32 and ntdll exports. This is a guest probe, not Windows 98 acceptance.
 * Expected non-realtime cells come from Microsoft's scheduling-priorities
 * table. Unsupported realtime/background/absolute-priority modes must refuse.
 * No scheduling speed, fairness, quantum or timing ratio is inferred here.
 */
#include "../include/nt.h"
#include "k32test.h"

typedef struct {
    LONG64 exit_status;
    ULONG64 teb, pid, tid, affinity;
    LONG priority, base_increment;
} priority_basic_t;
_Static_assert(sizeof(priority_basic_t) == 48, "Kernel64 ThreadBasicInformation is 48 bytes");

static const DWORD classes[5] = {
    IDLE_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
    ABOVE_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS
};
static const int levels[7] = {
    THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_BELOW_NORMAL,
    THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_HIGHEST,
    THREAD_PRIORITY_TIME_CRITICAL
};
/* https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities */
static const LONG absolute[5][7] = {
    {1,2,3,4,5,6,15}, {1,4,5,6,7,8,15}, {1,6,7,8,9,10,15},
    {1,8,9,10,11,12,15}, {1,11,12,13,14,15,15}
};

static DWORD WINAPI finish_thread(LPVOID p) { return (DWORD)(ULONG_PTR)p; }

static NTSTATUS basic_query(HANDLE h, priority_basic_t *b)
{
    ULONG length = 0;
    const NTSTATUS st = NtQueryInformationThread(h, 0, b, sizeof *b, &length);
    CHECKV(st == 0 && length == 48, "ThreadBasicInformation returns exactly 48 bytes",
           "status=0x%lx length=%lu", (unsigned long)st, (unsigned long)length);
    return st;
}

static void check_table(HANDLE thread)
{
    priority_basic_t b;
    unsigned c, p;
    for (c = 0; c < 5; ++c) {
        CHECKV(SetPriorityClass(GetCurrentProcess(), classes[c]), "set a supported process priority class",
               "class=0x%lx", (unsigned long)classes[c]);
        for (p = 0; p < 7; ++p) {
            const LONG increment = levels[p] == THREAD_PRIORITY_IDLE ? -16 :
                levels[p] == THREAD_PRIORITY_TIME_CRITICAL ? 16 : (LONG)levels[p];
            CHECKV(SetThreadPriority(thread, levels[p]), "set a documented non-realtime thread level",
                   "class=0x%lx level=%d", (unsigned long)classes[c], levels[p]);
            CHECKV(GetThreadPriority(thread) == levels[p], "Win32 priority reads back the requested relative level",
                   "class=0x%lx level=%d", (unsigned long)classes[c], levels[p]);
            if (!basic_query(thread, &b)) {
                CHECKV(b.priority == absolute[c][p] && b.base_increment == increment,
                       "native absolute priority matches the independent 35-cell table",
                       "class=0x%lx level=%d absolute=%ld base=%ld", (unsigned long)classes[c], levels[p],
                       (long)b.priority, (long)b.base_increment);
                CHECK(b.affinity == 1 && b.exit_status == 0x103, "initialized suspended thread has CPU mask 1 and is active");
            }
        }
    }
    /* HIGH/HIGHEST and HIGH/TIME_CRITICAL both have absolute priority 15,
     * but their retained relative increments must retarget differently. */
    CHECK(SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS) && SetThreadPriority(thread, THREAD_PRIORITY_HIGHEST),
          "prepare HIGH/HIGHEST saturation boundary");
    CHECK(SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS), "retarget HIGH/HIGHEST to NORMAL");
    if (!basic_query(thread, &b)) CHECK(b.priority == 10 && b.base_increment == 2, "ordinary HIGH/HIGHEST retains increment 2");
    CHECK(SetThreadPriority(thread, THREAD_PRIORITY_TIME_CRITICAL), "prepare time-critical saturation sentinel");
    CHECK(SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS), "retarget a saturated thread to IDLE process class");
    if (!basic_query(thread, &b)) CHECK(b.priority == 15 && b.base_increment == 16, "time-critical saturation retains increment 16");
    CHECK(GetThreadPriority(thread) == THREAD_PRIORITY_TIME_CRITICAL, "NT saturation 16 converts back to Win32 15");
    CHECK(SetThreadPriority(thread, THREAD_PRIORITY_IDLE), "prepare idle saturation sentinel");
    CHECK(SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS), "retarget an idle thread to HIGH process class");
    if (!basic_query(thread, &b)) CHECK(b.priority == 1 && b.base_increment == -16, "idle saturation retains increment -16");
    CHECK(GetThreadPriority(thread) == THREAD_PRIORITY_IDLE, "NT saturation -16 converts back to Win32 -15");
    CHECK(SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS) && SetThreadPriority(thread, THREAD_PRIORITY_NORMAL),
          "restore normal class and relative level for refusal checks");
}

static void check_query_buffers(HANDLE thread)
{
    struct { priority_basic_t b; ULONG64 tail[2]; } out;
    ULONG length = 0;
    NTSTATUS st;
    memset(&out, 0x5a, sizeof out);
    st = NtQueryInformationThread(thread, 0, &out, 47, &length);
    CHECK(st == STATUS_INFO_LENGTH_MISMATCH && length == 48, "short query reports the required 48-byte length");
    CHECK(out.b.priority == 0x5a5a5a5a && out.tail[0] == UINT64_C(0x5a5a5a5a5a5a5a5a), "short query leaves output unchanged");
    length = 0;
    st = NtQueryInformationThread(thread, 0, &out, sizeof out, &length);
    CHECK(st == 0 && length == 48, "larger query buffer still reports 48 bytes");
    CHECK(out.tail[0] == UINT64_C(0x5a5a5a5a5a5a5a5a) && out.tail[1] == out.tail[0], "query writes only its 48-byte output");
    CHECK(NtQueryInformationThread(thread, 0, (PVOID)(ULONG_PTR)1, 48, 0) == STATUS_ACCESS_VIOLATION,
          "query refuses an inaccessible output pointer");
    CHECK(NtQueryInformationThread(thread, 0, &out, 48, (PULONG)(ULONG_PTR)1) == STATUS_ACCESS_VIOLATION,
          "query refuses an inaccessible return-length pointer");
    CHECK(NtQueryInformationThread(thread, 0x7fff, &out, 48, &length) == STATUS_INVALID_INFO_CLASS,
          "unknown thread query class refuses");
}

static void check_rights(HANDLE thread)
{
    HANDLE set_only = NULL, query_only = NULL;
    priority_basic_t b;
    LONG increment = 1;
    ULONG64 mask = 1;
    CHECK(DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(), &set_only, THREAD_SET_INFORMATION, FALSE, 0),
          "duplicate a SET-only thread handle");
    CHECK(DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(), &query_only, THREAD_QUERY_INFORMATION, FALSE, 0),
          "duplicate a QUERY-only thread handle");
    if (set_only) {
        CHECK(SetThreadPriority(set_only, THREAD_PRIORITY_ABOVE_NORMAL), "SET-only handle can set a thread priority");
        CHECK(NtQueryInformationThread(set_only, 0, &b, sizeof b, 0) == STATUS_ACCESS_DENIED,
              "SET-only handle cannot query thread information");
        CHECK(GetThreadPriority(set_only) == THREAD_PRIORITY_ERROR_RETURN, "Win32 getter refuses a SET-only handle");
        CHECK_ERR(ERROR_ACCESS_DENIED, "getter reports missing QUERY permission");
        CHECK(NtSetInformationThread(set_only, 4, &mask, sizeof mask) == 0, "native affinity setter requires only SET permission");
        /* Microsoft's SetThreadAffinityMask contract requires QUERY plus SET. */
        CHECK(SetThreadAffinityMask(set_only, 1) == 0, "Win32 affinity wrapper also requires QUERY permission");
        CHECK_ERR(ERROR_ACCESS_DENIED, "affinity wrapper reports missing QUERY permission");
    }
    if (query_only) {
        CHECK(GetThreadPriority(query_only) == THREAD_PRIORITY_ABOVE_NORMAL, "QUERY-only getter observes the real level");
        CHECK(NtSetInformationThread(query_only, 3, &increment, sizeof increment) == STATUS_ACCESS_DENIED,
              "QUERY-only handle cannot set thread information");
        CHECK(!SetThreadPriority(query_only, THREAD_PRIORITY_HIGHEST), "Win32 setter refuses a QUERY-only handle");
        CHECK_ERR(ERROR_ACCESS_DENIED, "setter reports missing SET permission");
        CHECK(SetThreadAffinityMask(query_only, 1) == 0, "QUERY-only affinity wrapper cannot set the mask");
        CHECK_ERR(ERROR_ACCESS_DENIED, "affinity wrapper reports missing SET permission");
    }
    CHECK(SetThreadAffinityMask(thread, 1) == 1, "full-rights affinity setter returns the previous UP mask");
    if (set_only) CloseHandle(set_only);
    if (query_only) CloseHandle(query_only);
}

static void check_refusals_and_native(HANDLE thread)
{
    const HANDLE invalid = (HANDLE)(ULONG_PTR)0x7ffffffc;
    static const int bad_levels[] = {-3,3,-14,14,(-2147483647-1),2147483647};
    priority_basic_t b;
    LONG increment = 1;
    ULONG64 mask = 1;
    unsigned i;
    CHECK(SetThreadPriority(thread, THREAD_PRIORITY_NORMAL), "prepare refusal checks at relative level zero");
    for (i = 0; i < sizeof bad_levels / sizeof bad_levels[0]; ++i) {
        CHECK(!SetThreadPriority(thread, bad_levels[i]), "undocumented Win32 priority value refuses");
        CHECK_ERR(ERROR_INVALID_PARAMETER, "invalid Win32 priority reports invalid parameter");
    }
    CHECK(!SetThreadPriority(thread, THREAD_MODE_BACKGROUND_BEGIN), "background scheduling begin is unsupported");
    CHECK_ERR(ERROR_NOT_SUPPORTED, "background begin reports unsupported");
    CHECK(!SetThreadPriority(thread, THREAD_MODE_BACKGROUND_END), "background scheduling end is unsupported");
    CHECK_ERR(ERROR_NOT_SUPPORTED, "background end reports unsupported");
    CHECK(!SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS), "realtime process priority is unsupported");
    CHECK_ERR(ERROR_NOT_SUPPORTED, "realtime class reports unsupported");
    CHECK(GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS, "unsupported realtime request preserves the process class");
    CHECK(!SetThreadPriority(invalid, THREAD_PRIORITY_NORMAL), "invalid thread priority setter refuses");
    CHECK_ERR(ERROR_INVALID_HANDLE, "invalid setter reports invalid handle");
    CHECK(GetThreadPriority(invalid) == THREAD_PRIORITY_ERROR_RETURN, "invalid thread getter returns its error sentinel");
    CHECK_ERR(ERROR_INVALID_HANDLE, "invalid getter reports invalid handle");
    CHECK(SetThreadAffinityMask(invalid, 1) == 0, "invalid affinity handle refuses");
    CHECK_ERR(ERROR_INVALID_HANDLE, "invalid affinity reports invalid handle");
    CHECK(NtSetInformationThread(invalid, 3, &increment, sizeof increment) == STATUS_INVALID_HANDLE,
          "native priority setter checks handle identity");
    CHECK(NtSetInformationThread(GetCurrentProcess(), 3, &increment, sizeof increment) == STATUS_OBJECT_TYPE_MISMATCH,
          "native priority setter rejects a process handle");
    CHECK(NtSetInformationThread(thread, 0x7fff, &increment, sizeof increment) == STATUS_INVALID_INFO_CLASS,
          "unknown native setter class refuses");
    CHECK(NtSetInformationThread(thread, 2, &increment, sizeof increment) == STATUS_NOT_SUPPORTED,
          "absolute native ThreadPriority class is explicitly unsupported");
    for (i = 0; i < 10; ++i) if (i != 4)
        CHECK(NtSetInformationThread(thread, 3, &increment, i) == STATUS_INFO_LENGTH_MISMATCH,
              "native base-priority setter requires exactly a four-byte LONG");
    for (i = 0; i < 10; ++i) if (i != 8)
        CHECK(NtSetInformationThread(thread, 4, &mask, i) == STATUS_INFO_LENGTH_MISMATCH,
              "native affinity setter requires exactly an eight-byte mask");
    CHECK(NtSetInformationThread(thread, 3, (PVOID)(ULONG_PTR)1, 4) == STATUS_ACCESS_VIOLATION,
          "native base setter refuses an inaccessible input pointer");
    CHECK(NtSetInformationThread(thread, 4, (PVOID)(ULONG_PTR)1, 8) == STATUS_ACCESS_VIOLATION,
          "native affinity setter refuses an inaccessible input pointer");
    increment = 15;
    CHECK(NtSetInformationThread(thread, 3, &increment, 4) == STATUS_INVALID_PARAMETER, "raw NT increment 15 is not the saturation sentinel");
    increment = -15;
    CHECK(NtSetInformationThread(thread, 3, &increment, 4) == STATUS_INVALID_PARAMETER, "raw NT increment -15 is not the saturation sentinel");
    increment = 3;
    CHECK(NtSetInformationThread(thread, 3, &increment, 4) == STATUS_INVALID_PARAMETER, "raw NT variable increment outside the supported subset refuses");
    mask = 0;
    CHECK(NtSetInformationThread(thread, 4, &mask, 8) == STATUS_INVALID_PARAMETER, "zero affinity mask refuses");
    mask = 2;
    CHECK(NtSetInformationThread(thread, 4, &mask, 8) == STATUS_INVALID_PARAMETER, "unavailable CPU affinity bit refuses");
    CHECK(SetThreadAffinityMask(thread, 2) == 0, "Win32 affinity refuses an unavailable CPU");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "invalid affinity reports invalid parameter");
    if (!basic_query(thread, &b)) CHECK(b.base_increment == 0 && b.priority == 8 && b.affinity == 1,
                                     "all refusal controls preserve the original policy");
    increment = 16;
    CHECK(NtSetInformationThread(thread, 3, &increment, 4) == 0 && GetThreadPriority(thread) == THREAD_PRIORITY_TIME_CRITICAL,
          "direct NT positive saturation round-trips through Win32");
    increment = -16;
    CHECK(NtSetInformationThread(thread, 3, &increment, 4) == 0 && GetThreadPriority(thread) == THREAD_PRIORITY_IDLE,
          "direct NT negative saturation round-trips through Win32");
    increment = 1;
    CHECK(NtSetInformationThread(thread, 3, &increment, 4) == 0 && GetThreadPriority(thread) == THREAD_PRIORITY_ABOVE_NORMAL,
          "direct NT ordinary increment round-trips through Win32");
    mask = 1;
    CHECK(NtSetInformationThread(thread, 4, &mask, 8) == 0, "direct NT UP affinity succeeds");
    if (!basic_query(thread, &b)) CHECK(b.base_increment == 1 && b.priority == 9 && b.affinity == 1,
                                     "direct native setter updates the actual queried priority");
}

static void check_exit_cache(HANDLE thread, DWORD original_tid)
{
    priority_basic_t b;
    DWORD code = 0;
    LONG increment = 0;
    ULONG64 mask = 1;
    unsigned i;
    CHECK(SetThreadPriority(thread, THREAD_PRIORITY_HIGHEST), "prepare an ordinary priority before thread exit");
    CHECK(ResumeThread(thread) == 1, "resume the initialized suspended thread");
    if (WaitForSingleObject(thread, 2000) != WAIT_OBJECT_0) {
        CHECK(FALSE, "thread exits within the bounded wait");
        TerminateThread(thread, 42);
        WaitForSingleObject(thread, 1000);
        return;
    }
    CHECK(GetExitCodeThread(thread, &code) && code == 42, "exited handle retains the worker's exit code");
    CHECK(NtSetInformationThread(thread, 3, &increment, 4) == STATUS_THREAD_IS_TERMINATING,
          "exited thread refuses priority setters");
    CHECK(NtSetInformationThread(thread, 4, &mask, 8) == STATUS_THREAD_IS_TERMINATING,
          "exited thread refuses affinity setters");
    CHECK(SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS), "retarget the live process while retaining a dead thread handle");
    for (i = 0; i < 4; ++i) {
        DWORD tid = 0;
        HANDLE q = CreateThread(0, 0, finish_thread, (LPVOID)(ULONG_PTR)7, 0, &tid);
        CHECK(q != NULL, "bounded thread churn permits TCB reclamation");
        if (!q) continue;
        CHECK(WaitForSingleObject(q, 1000) == WAIT_OBJECT_0, "churn thread exits within its bounded wait");
        if (!basic_query(q, &b)) CHECK(b.priority == 13 && b.base_increment == 0 && b.tid == tid && b.tid != original_tid,
                                     "new thread defaults to relative zero in its current HIGH class");
        CloseHandle(q);
    }
    if (!basic_query(thread, &b)) {
        CHECK(b.priority == 10 && b.base_increment == 2, "dead cached policy is not retargeted or replaced by slot reuse");
        CHECK(b.pid == GetCurrentProcessId() && b.tid == original_tid && b.teb == 0 && b.exit_status == 42,
              "cached thread query retains its original identity and exit status");
    }
    CHECK(GetThreadPriority(thread) == THREAD_PRIORITY_HIGHEST, "Win32 getter reads the retained dead-thread relative priority");
    {
        HANDLE closed = NULL;
        CHECK(DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(), &closed, THREAD_QUERY_INFORMATION, FALSE, 0),
              "duplicate a retained exited-thread handle");
        if (closed) {
            CHECK(CloseHandle(closed), "close the duplicated thread handle");
            CHECK(NtQueryInformationThread(closed, 0, &b, sizeof b, 0) == STATUS_INVALID_HANDLE,
                  "closed handle refuses before another object can reuse its handle value");
            CHECK(GetThreadPriority(closed) == THREAD_PRIORITY_ERROR_RETURN, "Win32 getter refuses a closed handle");
            CHECK_ERR(ERROR_INVALID_HANDLE, "closed-handle getter reports invalid handle");
        }
    }
}

int main(void)
{
    const DWORD saved_class = GetPriorityClass(GetCurrentProcess());
    const int saved_priority = GetThreadPriority(GetCurrentThread());
    priority_basic_t b;
    DWORD tid = 0;
    HANDLE thread;
    CHECK(saved_class == NORMAL_PRIORITY_CLASS && saved_priority == THREAD_PRIORITY_NORMAL,
          "new user process starts with NORMAL class and relative level zero");
    CHECK(SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS), "prepare a normal process class");
    thread = CreateThread(0, 0, finish_thread, (LPVOID)(ULONG_PTR)42, CREATE_SUSPENDED, &tid);
    CHECK(thread != NULL, "create the bounded suspended priority-probe thread");
    if (thread) {
        if (!basic_query(thread, &b)) CHECK(b.priority == 8 && b.base_increment == 0 && b.pid == GetCurrentProcessId() && b.tid == tid,
                                         "new suspended thread is initialized to absolute 8 before publication");
        check_table(thread);
        check_query_buffers(thread);
        check_rights(thread);
        check_refusals_and_native(thread);
        check_exit_cache(thread, tid);
        CloseHandle(thread);
    }
    CHECK(SetPriorityClass(GetCurrentProcess(), saved_class), "restore the original process priority class");
    CHECK(saved_priority != THREAD_PRIORITY_ERROR_RETURN && SetThreadPriority(GetCurrentThread(), saved_priority),
          "restore the original current-thread relative priority");
    return k32t_finish("t_nt_priority");
}
