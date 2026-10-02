/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64's partial NT user-thread and process priority contracts, through real Win64
 * kernel32 and ntdll exports. This is a guest probe, not Windows 98 acceptance.
 * Expected non-realtime cells come from Microsoft's scheduling-priorities
 * table. Unsupported realtime/background/absolute-priority modes must refuse.
 * Raw process class 18 uses an independent two-byte ABI and native ordinal
 * table. Exact query lengths and unsupported modes describe this selected
 * backend subset; they are not universal Windows acceptance claims.
 * No scheduling speed, fairness, quantum or timing ratio is inferred here.
 */
#include "../include/nt_ipc.h"
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

/* Independent ABI and expectations: do not include the production mapper. */
typedef struct { UCHAR foreground, priority_class; } process_priority_t;
typedef struct {
    LONG64 exit_status;
    ULONG64 peb, affinity;
    LONG64 base_priority;
    ULONG64 pid, parent_pid;
} process_basic_t;
_Static_assert(sizeof(process_priority_t) == 2, "ProcessPriorityClass is two bytes");
_Static_assert(offsetof(process_priority_t, priority_class) == 1, "native ordinal follows Foreground");
_Static_assert(sizeof(process_basic_t) == 48, "ProcessBasicInformation is 48 bytes");
static const UCHAR native_classes[5] = {1, 5, 2, 6, 3};
static const LONG64 process_bases[5] = {4, 6, 8, 10, 13};

static NTSTATUS process_priority_query(HANDLE h, process_priority_t *v)
{
    ULONG length = 0;
    NTSTATUS st = NtQueryInformationProcess(h, 18, v, sizeof *v, &length);
    CHECKV(st == 0 && length == 2, "native process priority query returns exactly two bytes",
           "status=0x%lx length=%lu", (unsigned long)st, (unsigned long)length);
    return st;
}

static NTSTATUS process_basic_query(HANDLE h, process_basic_t *v)
{
    ULONG length = 0;
    NTSTATUS st = NtQueryInformationProcess(h, 0, v, sizeof *v, &length);
    CHECKV(st == 0 && length == 48, "native process basic query returns exactly 48 bytes",
           "status=0x%lx length=%lu", (unsigned long)st, (unsigned long)length);
    return st;
}

/* Each new worker is suspended until its metadata assertions are complete.
 * A timeout remains a failure even if bounded termination later succeeds. */
static void finish_probe_thread(HANDLE thread, DWORD expected_code)
{
    DWORD code = 0, wait;
    CHECK(ResumeThread(thread) == 1, "resume the additional suspended priority worker");
    wait = WaitForSingleObject(thread, 1000);
    CHECK(wait == WAIT_OBJECT_0, "additional priority worker exits within its bounded wait");
    if (wait == WAIT_OBJECT_0) {
        CHECK(GetExitCodeThread(thread, &code) && code == expected_code,
              "additional worker retains its natural exit code");
    } else {
        CHECK(TerminateThread(thread, expected_code), "terminate the failed additional worker for cleanup");
        CHECK(WaitForSingleObject(thread, 1000) == WAIT_OBJECT_0,
              "failed additional worker cleanup completes within a bounded wait");
    }
    CHECK(CloseHandle(thread), "close the additional worker handle");
}

static void check_process_classes(void)
{
    HANDLE process = GetCurrentProcess(), thread;
    priority_basic_t b;
    process_priority_t v;
    process_basic_t pb;
    unsigned c, p;
    thread = CreateThread(0, 0, finish_thread, (LPVOID)(ULONG_PTR)42, CREATE_SUSPENDED, 0);
    CHECK(thread != NULL, "create a suspended worker for native process retargeting");
    if (!thread) return;
    for (c = 0; c < 5; ++c) {
        CHECK(SetPriorityClass(process, classes[c]), "Win32 process setter accepts each of the five supported classes");
        CHECK(GetPriorityClass(process) == classes[c], "Win32 process getter retains the full class flag");
        if (!process_priority_query(process, &v))
            CHECK(v.foreground == 0 && v.priority_class == native_classes[c],
                  "Win32 class projects to its independent native ordinal");
        if (!process_basic_query(process, &pb))
            CHECK(pb.base_priority == process_bases[c] && pb.pid == GetCurrentProcessId() &&
                  pb.affinity == 1 && pb.exit_status == 0x103,
                  "live process basic information reports the selected class base and identity");

        /* First establish a different class. A no-op native setter cannot
         * satisfy the subsequent class and thread-retarget expectations. */
        CHECK(SetThreadPriority(thread, THREAD_PRIORITY_HIGHEST), "prepare relative increment two for native process retargeting");
        CHECK(SetPriorityClass(process, classes[(c + 1) % 5]), "establish a different class before the native setter");
        v.foreground = 0; v.priority_class = native_classes[c];
        CHECK(NtSetInformationProcess(process, 18, &v, sizeof v) == 0,
              "native process setter accepts each supported ordinal");
        CHECK(GetPriorityClass(process) == classes[c], "native process setter changes the real Win32 class");
        CHECK(GetThreadPriority(thread) == THREAD_PRIORITY_HIGHEST, "native process retarget preserves the relative thread level");
        if (!basic_query(thread, &b))
            CHECK(b.priority == absolute[c][5] && b.base_increment == 2,
                  "native process retarget preserves ordinary increment two including HIGH saturation");
        for (p = 0; p < 2; ++p) {
            int level = p ? THREAD_PRIORITY_TIME_CRITICAL : THREAD_PRIORITY_IDLE;
            CHECK(SetThreadPriority(thread, level), "prepare a saturated sentinel before native process retargeting");
            CHECK(SetPriorityClass(process, classes[(c + 1) % 5]), "move a saturated thread to a different process class");
            CHECK(NtSetInformationProcess(process, 18, &v, sizeof v) == 0,
                  "native process retarget accepts the class with a saturated thread");
            CHECK(GetThreadPriority(thread) == level, "native process retarget retains the Win32 saturation sentinel");
            if (!basic_query(thread, &b))
                CHECK(b.priority == (p ? 15 : 1) && b.base_increment == (p ? 16 : -16),
                      "native process retarget retains the exact native saturation increment");
        }
        {
            DWORD tid = 0;
            HANDLE fresh = CreateThread(0, 0, finish_thread, (LPVOID)(ULONG_PTR)7, CREATE_SUSPENDED, &tid);
            CHECK(fresh != NULL, "create a new suspended thread in each native-selected process class");
            if (fresh) {
                if (!basic_query(fresh, &b))
                    CHECK(b.priority == process_bases[c] && b.base_increment == 0 &&
                          b.pid == GetCurrentProcessId() && b.tid == tid && b.affinity == 1 && b.exit_status == 0x103,
                          "new suspended thread has relative zero and the class base before first dispatch");
                finish_probe_thread(fresh, 7);
            }
        }
    }
    CHECK(SetPriorityClass(process, NORMAL_PRIORITY_CLASS), "restore NORMAL after native process class coverage");
    CHECK(SetThreadPriority(thread, THREAD_PRIORITY_NORMAL), "restore the additional worker's ordinary relative level");
    finish_probe_thread(thread, 42);
}

static void check_process_buffers(void)
{
    struct { UCHAR before; process_priority_t v; UCHAR after; } out;
    static const ULONG bad_lengths[] = {0, 1, 3, 4, 8, 0xffffffffu};
    process_priority_t normal = {0, 2};
    ULONG length;
    unsigned i;
    for (i = 0; i < sizeof bad_lengths / sizeof bad_lengths[0]; ++i) {
        memset(&out, 0x5a, sizeof out); length = 0;
        CHECK(NtQueryInformationProcess(GetCurrentProcess(), 18, &out.v, bad_lengths[i], &length) ==
              STATUS_INFO_LENGTH_MISMATCH && length == 2,
              "short and oversized native process priority queries report required length two");
        CHECK(out.before == 0x5a && out.v.foreground == 0x5a && out.v.priority_class == 0x5a && out.after == 0x5a,
              "rejected native process priority lengths leave every output byte untouched");
    }
    memset(&out, 0x5a, sizeof out); length = 0;
    CHECK(NtQueryInformationProcess(GetCurrentProcess(), 18, &out.v, 2, &length) == 0 && length == 2,
          "exact two-byte process query succeeds");
    CHECK(out.before == 0x5a && out.after == 0x5a && out.v.foreground == 0 && out.v.priority_class == 2,
          "successful native process priority query writes only its two ABI bytes");
    CHECK(NtQueryInformationProcess(GetCurrentProcess(), 18, &out.v, 2, 0) == 0,
          "native process priority query permits an omitted return length");
    CHECK(NtQueryInformationProcess(GetCurrentProcess(), 18, (PVOID)(ULONG_PTR)1, 2, 0) == STATUS_ACCESS_VIOLATION,
          "process priority query rejects an inaccessible output pointer");
    CHECK(NtQueryInformationProcess(GetCurrentProcess(), 18, 0, 2, 0) == STATUS_ACCESS_VIOLATION,
          "process priority query rejects a null output pointer");
    CHECK(NtQueryInformationProcess(GetCurrentProcess(), 18, &out.v, 2, (PULONG)(ULONG_PTR)1) == STATUS_ACCESS_VIOLATION,
          "exact process query reports an inaccessible return-length pointer");
    CHECK(NtQueryInformationProcess(GetCurrentProcess(), 18, &out.v, 1, (PULONG)(ULONG_PTR)1) == STATUS_ACCESS_VIOLATION,
          "mismatched process query propagates a required-length write fault");
    for (i = 0; i < sizeof bad_lengths / sizeof bad_lengths[0]; ++i)
        CHECK(NtSetInformationProcess(GetCurrentProcess(), 18, &normal, bad_lengths[i]) == STATUS_INFO_LENGTH_MISMATCH,
              "native process priority setter requires exactly two input bytes");
    CHECK(NtSetInformationProcess(GetCurrentProcess(), 18, (PVOID)(ULONG_PTR)1, 2) == STATUS_ACCESS_VIOLATION,
          "process priority setter rejects an inaccessible input pointer");
    CHECK(NtSetInformationProcess(GetCurrentProcess(), 18, 0, 2) == STATUS_ACCESS_VIOLATION,
          "process priority setter rejects a null input pointer");
    CHECK(GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS,
          "all process priority buffer refusals preserve the process class");
}

static void check_process_rights_and_handles(void)
{
    HANDLE process = GetCurrentProcess(), query[2] = {NULL, NULL}, set_only = NULL, full = NULL;
    const DWORD rights[2] = {PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION};
    const HANDLE invalid = (HANDLE)(ULONG_PTR)0x7ffffffc;
    process_priority_t normal = {0, 2}, v;
    unsigned i;
    CHECK(DuplicateHandle(process, process, process, &set_only, PROCESS_SET_INFORMATION, FALSE, 0),
          "duplicate a SET-only process handle");
    for (i = 0; i < 2; ++i) {
        CHECK(DuplicateHandle(process, process, process, &query[i], rights[i], FALSE, 0),
              "duplicate a process handle with one independent query right");
        if (!query[i]) continue;
        if (!process_priority_query(query[i], &v))
            CHECK(v.foreground == 0 && v.priority_class == 2, "either query right alone permits native process priority reads");
        CHECK(GetPriorityClass(query[i]) == NORMAL_PRIORITY_CLASS, "either query right alone permits the Win32 process getter");
        CHECK(NtSetInformationProcess(query[i], 18, &normal, 2) == STATUS_ACCESS_DENIED,
              "query permission alone cannot set native process priority");
        CHECK(!SetPriorityClass(query[i], ABOVE_NORMAL_PRIORITY_CLASS), "query permission alone cannot use the Win32 process setter");
        CHECK_ERR(ERROR_ACCESS_DENIED, "process setter reports the missing SET right");
    }
    if (set_only) {
        process_priority_t above = {0, 6};
        CHECK(NtSetInformationProcess(set_only, 18, &above, 2) == 0,
              "SET-only process handle permits the native priority setter");
        CHECK(SetPriorityClass(set_only, NORMAL_PRIORITY_CLASS), "SET-only process handle permits the Win32 priority setter");
        CHECK(NtQueryInformationProcess(set_only, 18, &v, 2, 0) == STATUS_ACCESS_DENIED,
              "SET-only process handle cannot query native priority");
        CHECK(GetPriorityClass(set_only) == 0, "Win32 process getter refuses a SET-only handle");
        CHECK_ERR(ERROR_ACCESS_DENIED, "process getter reports its missing query right");
    }
    CHECK(DuplicateHandle(process, process, process, &full, 0, FALSE, DUPLICATE_SAME_ACCESS),
          "duplicate a real full-rights process handle for tag and width checks");
    if (full) {
        for (i = 0; i < 4; ++i) {
            HANDLE tagged = (HANDLE)((ULONG_PTR)full | i);
            if (!process_priority_query(tagged, &v))
                CHECK(v.foreground == 0 && v.priority_class == 2, "native process query ignores the two defined handle tag bits");
            CHECK(GetPriorityClass(tagged) == NORMAL_PRIORITY_CLASS, "Win32 process getter accepts defined handle tags");
            CHECK(NtSetInformationProcess(tagged, 18, &normal, 2) == 0, "native process setter accepts defined handle tags");
            CHECK(SetPriorityClass(tagged, NORMAL_PRIORITY_CLASS), "Win32 process setter accepts defined handle tags");
        }
        {
            HANDLE high = (HANDLE)((ULONG_PTR)full | (ULONG_PTR)UINT64_C(0x100000000));
            CHECK(NtQueryInformationProcess(high, 18, &v, 2, 0) == STATUS_INVALID_HANDLE,
                  "native process getter rejects a high-width alias of a valid handle");
            CHECK(NtSetInformationProcess(high, 18, &normal, 2) == STATUS_INVALID_HANDLE,
                  "native process setter rejects a high-width alias of a valid handle");
            CHECK(GetPriorityClass(high) == 0, "Win32 process getter rejects a high-width handle alias");
            CHECK_ERR(ERROR_INVALID_HANDLE, "high-width getter reports invalid handle");
            CHECK(!SetPriorityClass(high, NORMAL_PRIORITY_CLASS), "Win32 process setter rejects a high-width handle alias");
            CHECK_ERR(ERROR_INVALID_HANDLE, "high-width setter reports invalid handle");
        }
        CHECK(CloseHandle(full), "close the duplicate full-rights process handle");
        CHECK(NtQueryInformationProcess(full, 18, &v, 2, 0) == STATUS_INVALID_HANDLE,
              "closed native process query handle refuses before any slot reuse");
        CHECK(NtSetInformationProcess(full, 18, &normal, 2) == STATUS_INVALID_HANDLE,
              "closed native process setter handle refuses before any slot reuse");
    }
    CHECK(NtQueryInformationProcess(GetCurrentThread(), 18, &v, 2, 0) == STATUS_OBJECT_TYPE_MISMATCH,
          "native process getter rejects a thread handle");
    CHECK(NtSetInformationProcess(GetCurrentThread(), 18, &normal, 2) == STATUS_OBJECT_TYPE_MISMATCH,
          "native process setter rejects a thread handle");
    CHECK(GetPriorityClass(GetCurrentThread()) == 0, "Win32 process getter rejects a thread handle");
    CHECK_ERR(ERROR_INVALID_HANDLE, "wrong-type process getter reports invalid handle");
    CHECK(!SetPriorityClass(GetCurrentThread(), NORMAL_PRIORITY_CLASS), "Win32 process setter rejects a thread handle");
    CHECK_ERR(ERROR_INVALID_HANDLE, "wrong-type process setter reports invalid handle");
    CHECK(NtQueryInformationProcess(invalid, 18, &v, 2, 0) == STATUS_INVALID_HANDLE, "native process getter rejects an invalid handle");
    CHECK(NtSetInformationProcess(invalid, 18, &normal, 2) == STATUS_INVALID_HANDLE, "native process setter rejects an invalid handle");
    CHECK(GetPriorityClass(invalid) == 0, "Win32 process getter rejects an invalid handle");
    CHECK_ERR(ERROR_INVALID_HANDLE, "invalid process getter reports invalid handle");
    CHECK(!SetPriorityClass(invalid, NORMAL_PRIORITY_CLASS), "Win32 process setter rejects an invalid handle");
    CHECK_ERR(ERROR_INVALID_HANDLE, "invalid process setter reports invalid handle");
    for (i = 0; i < 2; ++i) if (query[i]) CHECK(CloseHandle(query[i]), "close the limited-rights process query handle");
    if (set_only) CHECK(CloseHandle(set_only), "close the SET-only process handle");
}

static void check_process_refusals(void)
{
    static const UCHAR bad_ordinals[] = {0, 7, 0x20, 0x80, 0xff};
    static const DWORD bad_flags[] = {0, 1, 0x120, 0x10000020, 0xffffffffu};
    static const DWORD unsupported[] = {
        REALTIME_PRIORITY_CLASS, PROCESS_MODE_BACKGROUND_BEGIN,
        PROCESS_MODE_BACKGROUND_BEGIN, PROCESS_MODE_BACKGROUND_END
    };
    process_priority_t v = {0, 2};
    priority_basic_t b;
    unsigned i;
    for (i = 0; i < sizeof bad_ordinals / sizeof bad_ordinals[0]; ++i) {
        v.priority_class = bad_ordinals[i];
        CHECK(NtSetInformationProcess(GetCurrentProcess(), 18, &v, 2) == STATUS_INVALID_PARAMETER,
              "unknown and invalid native process ordinals refuse without a default alias");
        CHECK(GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS, "invalid native ordinal preserves the process class");
    }
    v.priority_class = 4;
    CHECK(NtSetInformationProcess(GetCurrentProcess(), 18, &v, 2) == STATUS_NOT_SUPPORTED,
          "native realtime process ordinal is explicitly unsupported");
    CHECK(GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS, "unsupported native realtime ordinal preserves the class");
    v.priority_class = 2;
    for (i = 0; i < 2; ++i) {
        v.foreground = i ? 0xff : 1;
        CHECK(NtSetInformationProcess(GetCurrentProcess(), 18, &v, 2) == STATUS_NOT_SUPPORTED,
              "nonzero native Foreground requests are explicitly unsupported");
        CHECK(GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS, "unsupported Foreground request preserves the class");
    }
    for (i = 0; i < sizeof unsupported / sizeof unsupported[0]; ++i) {
        CHECK(!SetPriorityClass(GetCurrentProcess(), unsupported[i]), "unsupported Win32 realtime and process background modes refuse");
        CHECK_ERR(ERROR_NOT_SUPPORTED, "unsupported process mode reports ERROR_NOT_SUPPORTED");
        CHECK(GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS, "unsupported Win32 process mode preserves the real class");
    }
    for (i = 0; i < sizeof bad_flags / sizeof bad_flags[0]; ++i) {
        CHECK(!SetPriorityClass(GetCurrentProcess(), bad_flags[i]), "invalid full-width Win32 class flags cannot truncate to a native ordinal");
        CHECK_ERR(ERROR_INVALID_PARAMETER, "invalid full-width process flag reports invalid parameter");
        CHECK(GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS, "invalid Win32 process flag preserves the class");
    }
    v.foreground = 0; v.priority_class = 2;
    CHECK(NtQueryInformationProcess(GetCurrentProcess(), 0x7fff, &v, 2, 0) == STATUS_INVALID_INFO_CLASS,
          "unknown native process query class remains unsupported");
    CHECK(NtSetInformationProcess(GetCurrentProcess(), 0x7fff, &v, 2) == STATUS_INVALID_INFO_CLASS,
          "unknown native process setter class remains unsupported");
    if (!process_priority_query(GetCurrentProcess(), &v))
        CHECK(v.foreground == 0 && v.priority_class == 2, "all process refusals retain the native NORMAL metadata");
    if (!basic_query(GetCurrentThread(), &b))
        CHECK(b.priority == 8 && b.base_increment == 0 && b.affinity == 1,
              "all process refusals retain the caller's actual ordinary policy");
}

static void check_exited_process(void)
{
    static const WCHAR child_name[] = L"T_HELLO.EXE";
    WCHAR path[MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    process_priority_t v = {0, 2};
    process_basic_t pb;
    DWORD n, at, i, code = 0, wait;
    BOOL started, configured, resumed;
    n = GetModuleFileNameW(0, path, MAX_PATH);
    CHECK(n > 0 && n < MAX_PATH && path[n] == 0, "obtain a complete bounded path for the existing sibling child fixture");
    if (!n || n >= MAX_PATH) return;
    at = n;
    while (at && path[at - 1] != '\\' && path[at - 1] != '/') --at;
    CHECK(at > 0 && at + sizeof child_name / sizeof child_name[0] <= MAX_PATH,
          "the existing child fixture fits beside this probe without path truncation");
    if (!at || at + sizeof child_name / sizeof child_name[0] > MAX_PATH) return;
    for (i = 0; i < sizeof child_name / sizeof child_name[0]; ++i) path[at + i] = child_name[i];
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    started = CreateProcessW(path, 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi);
    CHECK(started, "create the existing exit-seven child suspended without new archive members");
    if (!started) return;
    CHECK(GetPriorityClass(pi.hProcess) == NORMAL_PRIORITY_CLASS, "real new child starts with the normal process class");
    configured = SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);
    CHECK(configured, "set the real child to HIGH before its first dispatch");
    CHECK(GetPriorityClass(pi.hProcess) == HIGH_PRIORITY_CLASS, "live child getter observes its selected HIGH class");
    if (!process_priority_query(pi.hProcess, &v))
        CHECK(v.foreground == 0 && v.priority_class == 3, "live child native query observes HIGH ordinal three");
    if (!process_basic_query(pi.hProcess, &pb))
        CHECK(pb.base_priority == 13 && pb.pid == pi.dwProcessId && pb.parent_pid == GetCurrentProcessId() &&
              pb.affinity == 1 && pb.exit_status == 0x103,
              "live child basic query reports its real identity and HIGH base");
    resumed = ResumeThread(pi.hThread) == 1;
    CHECK(resumed, "resume the real child exactly once");
    wait = WaitForSingleObject(pi.hProcess, 1000);
    CHECK(wait == WAIT_OBJECT_0, "real child process naturally exits within its bounded wait");
    if (wait == WAIT_OBJECT_0) {
        BOOL natural = GetExitCodeProcess(pi.hProcess, &code) && code == 7;
        CHECK(natural, "real child retains its natural exit-seven status");
        if (configured && resumed && natural) {
            CHECK(GetPriorityClass(pi.hProcess) == HIGH_PRIORITY_CLASS, "held exited-process handle retains its Win32 HIGH class");
            if (!process_priority_query(pi.hProcess, &v))
                CHECK(v.foreground == 0 && v.priority_class == 3, "held exited-process query retains its native class metadata");
            if (!process_basic_query(pi.hProcess, &pb))
                CHECK(pb.exit_status == 7 && pb.pid == pi.dwProcessId && pb.parent_pid == GetCurrentProcessId() &&
                      pb.affinity == 1 && pb.base_priority == 13,
                      "held exited-process basic query retains identity, natural exit and HIGH base");
            v.foreground = 0; v.priority_class = 2;
            CHECK(NtSetInformationProcess(pi.hProcess, 18, &v, 2) == STATUS_PROCESS_IS_TERMINATING,
                  "held exited process refuses the native priority setter");
            CHECK(!SetPriorityClass(pi.hProcess, NORMAL_PRIORITY_CLASS), "held exited process refuses the Win32 priority setter");
            CHECK_ERR(ERROR_ACCESS_DENIED, "exited process setter reports termination as access denied");
            CHECK(GetPriorityClass(pi.hProcess) == HIGH_PRIORITY_CLASS, "exited-process setter refusal preserves the retained class");
        }
    } else {
        CHECK(TerminateProcess(pi.hProcess, 99), "terminate the failed real child for bounded cleanup");
        CHECK(WaitForSingleObject(pi.hProcess, 1000) == WAIT_OBJECT_0,
              "failed real child teardown completes within a bounded cleanup wait");
    }
    CHECK(CloseHandle(pi.hThread), "close the real child thread handle");
    CHECK(CloseHandle(pi.hProcess), "release the held real child process handle");
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
    /* Preserve the original 321-check thread flow above. These exercise the
     * native process transport and actual wrappers against fresh artifacts. */
    check_process_classes();
    check_process_buffers();
    check_process_rights_and_handles();
    check_process_refusals();
    check_exited_process();
    return k32t_finish("t_nt_priority");
}
