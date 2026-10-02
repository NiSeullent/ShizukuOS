/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 process / thread / memory information: CPU times and cycles, thread reclamation, priority and information classes,
 * mitigation policies, toolhelp, PSAPI (image names, mapped files, memory counters, working set), VirtualLock / Discard / Prefetch,
 * thread contexts, DebugBreak, InitOnce, heaps. Expectations are the documented Win32 semantics or relations between independent
 * measurements (e.g. a page this program touched must be in its working set), never values read back from the implementation.
 * Process background mode is explicitly unsupported by the selected Kernel64
 * backend; its refusals must preserve the real priority and memory settings.
 */
#include "k32test.h"
#include <tlhelp32.h>
#include <psapi.h>

LONG WINAPI GetPackagePathByFullName(PCWSTR, UINT32 *, PWSTR);
LONG WINAPI GetPackagesByPackageFamily(PCWSTR, UINT32 *, PWSTR *, UINT32 *, WCHAR *);
HRESULT WINAPI WerRegisterRuntimeExceptionModule(PCWSTR, PVOID);
HRESULT WINAPI WerUnregisterRuntimeExceptionModule(PCWSTR, PVOID);
typedef struct { ULONG Version, ControlMask, StateMask; } THREAD_PTS;
#define THREAD_MEMORY_PRIORITY_CLASS 0
#define THREAD_POWER_THROTTLING_CLASS 3

static ULONGLONG ft_u64(FILETIME f) { return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }
static int wieq_tail(const WCHAR *s, const char *tail)
{
    size_t n = 0, t = strlen(tail), i;
    while (s[n]) ++n;
    if (n < t) return 0;
    for (i = 0; i < t; ++i) {
        WCHAR a = s[n - t + i], b = (WCHAR)(unsigned char)tail[i];
        if (a >= 'a' && a <= 'z') a -= 32;
        if (b >= 'a' && b <= 'z') b -= 32;
        if (a != b) return 0;
    }
    return 1;
}
static int wstarts(const WCHAR *s, const char *head) { size_t i; for (i = 0; head[i]; ++i) if (s[i] != (WCHAR)(unsigned char)head[i]) return 0; return 1; }

static volatile ULONGLONG g_sink;
static void burn(DWORD ms)                                /* user-mode work; the clock is read rarely */
{
    const ULONGLONG end = GetTickCount64() + ms;
    ULONGLONG x = 1;
    while (GetTickCount64() < end) { unsigned i; for (i = 0; i < 200000; ++i) x = x * 6364136223846793005ull + 1442695040888963407ull; }
    g_sink = x;
}

static DWORD WINAPI spin_thread(LPVOID p) { burn((DWORD)(ULONG_PTR)p); return 42; }
static DWORD WINAPI quick_thread(LPVOID p) { (void)p; return 7; }

/* ---------------------------------------------------------------- times, cycles, reclamation */
static void test_times(void)
{
    FILETIME c, e, k, u, now, c2, e2, k2, u2;
    ULONG64 cyc0 = 0, cyc1 = 0, tcyc = 0;
    ULONGLONG t0, t1;
    HANDLE th;
    DWORD code = 0, i;
    GetSystemTimeAsFileTime(&now);
    CHECK(GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u), "GetProcessTimes(current process)");
    CHECKV(ft_u64(c) <= ft_u64(now) + 10000 * 1000 && ft_u64(now) - ft_u64(c) < 10ull * 60 * 10000000, "the process was created within the last 10 minutes",
           "create=%llu now=%llu", ft_u64(c), ft_u64(now));
    CHECK(QueryProcessCycleTime(GetCurrentProcess(), &cyc0), "QueryProcessCycleTime");
    t0 = ft_u64(u);
    burn(150);
    CHECK(GetProcessTimes(GetCurrentProcess(), &c2, &e2, &k2, &u2), "GetProcessTimes again");
    t1 = ft_u64(u2);
    CHECKV(t1 > t0, "150 ms of computation is charged as user time", "user %llu -> %llu", t0, t1);
    GetSystemTimeAsFileTime(&now);
    CHECKV(ft_u64(k2) + ft_u64(u2) <= ft_u64(now) - ft_u64(c2) + 20 * 10000, "CPU time never exceeds the time the process has existed (1 CPU)",
           "cpu=%llu alive=%llu", ft_u64(k2) + ft_u64(u2), ft_u64(now) - ft_u64(c2));
    CHECK(QueryProcessCycleTime(GetCurrentProcess(), &cyc1) && cyc1 > cyc0, "the cycle count grows while the process computes");
    CHECK(QueryThreadCycleTime(GetCurrentThread(), &tcyc) && tcyc > 0 && tcyc <= cyc1 + cyc1 / 2, "QueryThreadCycleTime(current thread)");
    SetLastError(0);
    CHECK(!GetProcessTimes((HANDLE)(ULONG_PTR)0x7ffc, &c, &e, &k, &u), "GetProcessTimes(invalid handle) fails");
    CHECK_ERR(ERROR_INVALID_HANDLE, "... with ERROR_INVALID_HANDLE");

    th = CreateThread(0, 0, spin_thread, (LPVOID)(ULONG_PTR)100, 0, 0);
    CHECK(th != NULL, "CreateThread(spinning thread)");
    CHECK(WaitForSingleObject(th, 20000) == WAIT_OBJECT_0, "the spinning thread ends");
    CHECK(GetThreadTimes(th, &c, &e, &k, &u), "GetThreadTimes(exited thread)");
    CHECKV(ft_u64(e) >= ft_u64(c) && ft_u64(e) != 0, "an exited thread has an exit time not before its creation", "c=%llu e=%llu", ft_u64(c), ft_u64(e));
    CHECKV(ft_u64(u) > 0, "the thread's 100 ms of computation is its user time", "user=%llu", ft_u64(u));
    t0 = ft_u64(u);
    /* Creating more threads reclaims the exited one in the kernel: its handle must keep answering. */
    for (i = 0; i < 4; ++i) { HANDLE q = CreateThread(0, 0, quick_thread, 0, 0, 0); if (q) { WaitForSingleObject(q, 5000); CloseHandle(q); } }
    CHECK(GetExitCodeThread(th, &code) && code == 42, "the exit code survives after the thread was reclaimed");
    CHECK(GetThreadTimes(th, &c2, &e2, &k2, &u2) && ft_u64(u2) == t0 && ft_u64(e2) == ft_u64(e), "... and so do its times");
    CHECK(QueryThreadCycleTime(th, &tcyc) && tcyc > 0, "... and its cycle count");
    CHECK(GetProcessTimes(GetCurrentProcess(), &c2, &e2, &k2, &u2) && ft_u64(u2) >= t0, "the process time includes its exited threads");
    CloseHandle(th);

    /* The kernel scheduler has 96 thread slots; exited threads must give theirs back. */
    {
        DWORD ok = 0;
        for (i = 0; i < 130; ++i) {
            HANDLE q = CreateThread(0, 0, quick_thread, 0, 0, 0);
            if (!q) break;
            if (WaitForSingleObject(q, 5000) == WAIT_OBJECT_0 && GetExitCodeThread(q, &code) && code == 7) ++ok;
            CloseHandle(q);
        }
        CHECKV(ok == 130, "130 short-lived threads in a row (more than the 96 scheduler slots) all start and finish", "ok=%u", (unsigned)ok);
    }
}

static void test_counts_priority(void)
{
    DWORD n0 = 0, n1 = 0, n2 = 0, lvl = 0, fl = 0;
    BOOL b = TRUE;
    HANDLE ev;
    MEMORY_PRIORITY_INFORMATION mp;
    PROCESS_POWER_THROTTLING_STATE ps;
    THREAD_PTS ts;
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &n0) && n0 >= 3, "GetProcessHandleCount (at least the 3 standard handles)");
    ev = CreateEventW(0, TRUE, FALSE, 0);
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &n1) && n1 == n0 + 1, "a new event adds one handle");
    CloseHandle(ev);
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &n2) && n2 == n0, "closing it removes it again");

    CHECK(GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS, "a new process runs at NORMAL_PRIORITY_CLASS");
    CHECK(SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS) && GetPriorityClass(GetCurrentProcess()) == BELOW_NORMAL_PRIORITY_CLASS,
          "SetPriorityClass(BELOW_NORMAL) is reported back");
    SetLastError(0);
    CHECK(!SetPriorityClass(GetCurrentProcess(), 0x12345), "an unknown priority class is refused");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "... with ERROR_INVALID_PARAMETER");
    CHECK(SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS), "back to NORMAL_PRIORITY_CLASS");
    SetLastError(0);
    CHECK(!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_END), "unsupported PROCESS_MODE_BACKGROUND_END fails");
    CHECK_ERR(ERROR_NOT_SUPPORTED, "... with ERROR_NOT_SUPPORTED");
    CHECK(!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN), "unsupported PROCESS_MODE_BACKGROUND_BEGIN fails");
    CHECK_ERR(ERROR_NOT_SUPPORTED, "... with ERROR_NOT_SUPPORTED");
    SetLastError(0);
    CHECK(!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN), "a repeated unsupported BEGIN still fails");
    CHECK_ERR(ERROR_NOT_SUPPORTED, "... with ERROR_NOT_SUPPORTED");
    CHECK(GetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &mp, sizeof mp) && mp.MemoryPriority == MEMORY_PRIORITY_NORMAL,
          "unsupported background requests leave actual default memory priority unchanged");
    CHECK(!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_END), "unsupported END after refused BEGIN still fails");
    CHECK_ERR(ERROR_NOT_SUPPORTED, "... with ERROR_NOT_SUPPORTED");
    CHECK(GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS, "unsupported background requests leave the real priority class unchanged");

    CHECK(GetThreadPriorityBoost(GetCurrentThread(), &b) && b == FALSE, "priority boosting is enabled by default");
    CHECK(SetThreadPriorityBoost(GetCurrentThread(), TRUE) && GetThreadPriorityBoost(GetCurrentThread(), &b) && b == TRUE,
          "SetThreadPriorityBoost(TRUE) is reported back");
    SetThreadPriorityBoost(GetCurrentThread(), FALSE);

    CHECK(GetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &mp, sizeof mp) && mp.MemoryPriority == MEMORY_PRIORITY_NORMAL,
          "the default memory priority is MEMORY_PRIORITY_NORMAL");
    mp.MemoryPriority = MEMORY_PRIORITY_LOW;
    CHECK(SetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &mp, sizeof mp), "SetProcessInformation(ProcessMemoryPriority, LOW)");
    mp.MemoryPriority = 0;
    CHECK(GetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &mp, sizeof mp) && mp.MemoryPriority == MEMORY_PRIORITY_LOW, "... reported back");
    CHECK(!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN), "background mode remains unsupported with a stored LOW memory setting");
    CHECK_ERR(ERROR_NOT_SUPPORTED, "... with ERROR_NOT_SUPPORTED");
    CHECK(GetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &mp, sizeof mp) && mp.MemoryPriority == MEMORY_PRIORITY_LOW &&
          GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS,
          "unsupported background mode preserves the actual stored LOW memory setting and process class");
    mp.MemoryPriority = 0;
    SetLastError(0);
    CHECK(!SetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &mp, sizeof mp), "memory priority 0 is invalid");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "... with ERROR_INVALID_PARAMETER");
    SetLastError(0);
    CHECK(!GetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &mp, 2), "a wrong size fails");
    CHECK_ERR(ERROR_BAD_LENGTH, "... with ERROR_BAD_LENGTH");
    memset(&ps, 0, sizeof ps);
    ps.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    ps.ControlMask = ps.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    CHECK(SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &ps, sizeof ps), "SetProcessInformation(ProcessPowerThrottling, EcoQoS)");
    memset(&ps, 0, sizeof ps);
    ps.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    CHECK(GetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &ps, sizeof ps) &&
          ps.ControlMask == PROCESS_POWER_THROTTLING_EXECUTION_SPEED && ps.StateMask == PROCESS_POWER_THROTTLING_EXECUTION_SPEED, "... reported back");
    ps.ControlMask = 0; ps.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    SetLastError(0);
    CHECK(!SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &ps, sizeof ps) && GetLastError() == ERROR_INVALID_PARAMETER,
          "a state bit outside the control mask is ERROR_INVALID_PARAMETER");
    {
        PROCESS_PROTECTION_LEVEL_INFORMATION pl;
        PROCESS_MACHINE_INFORMATION mi;
        CHECK(GetProcessInformation(GetCurrentProcess(), ProcessProtectionLevelInfo, &pl, sizeof pl) && pl.ProtectionLevel == PROTECTION_LEVEL_NONE,
              "the process is not a protected process");
        CHECK(GetProcessInformation(GetCurrentProcess(), ProcessMachineTypeInfo, &mi, sizeof mi) && mi.ProcessMachine == IMAGE_FILE_MACHINE_AMD64,
              "the process machine is AMD64");
    }
    mp.MemoryPriority = MEMORY_PRIORITY_BELOW_NORMAL;
    CHECK(SetThreadInformation(GetCurrentThread(), THREAD_MEMORY_PRIORITY_CLASS, &mp, sizeof mp), "SetThreadInformation(ThreadMemoryPriority)");
    mp.MemoryPriority = 0;
    CHECK(GetThreadInformation(GetCurrentThread(), THREAD_MEMORY_PRIORITY_CLASS, &mp, sizeof mp) && mp.MemoryPriority == MEMORY_PRIORITY_BELOW_NORMAL,
          "... reported back");
    ts.Version = 1; ts.ControlMask = 1; ts.StateMask = 1;
    CHECK(SetThreadInformation(GetCurrentThread(), THREAD_POWER_THROTTLING_CLASS, &ts, sizeof ts), "SetThreadInformation(ThreadPowerThrottling)");
    ts.ControlMask = ts.StateMask = 0;
    CHECK(GetThreadInformation(GetCurrentThread(), THREAD_POWER_THROTTLING_CLASS, &ts, sizeof ts) && ts.ControlMask == 1 && ts.StateMask == 1, "... reported back");

    CHECK(SetProcessShutdownParameters(0x300, SHUTDOWN_NORETRY) && GetProcessShutdownParameters(&lvl, &fl) && lvl == 0x300 && fl == SHUTDOWN_NORETRY,
          "SetProcessShutdownParameters(0x300, SHUTDOWN_NORETRY) is reported back");
    SetLastError(0);
    CHECK(!SetProcessShutdownParameters(0x500, 0), "shutdown level 0x500 is outside 0x000-0x4FF");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "... with ERROR_INVALID_PARAMETER");

    CHECK(IsWow64Process(GetCurrentProcess(), &b) && b == FALSE, "IsWow64Process: a native x64 process");
    CHECK(CheckRemoteDebuggerPresent(GetCurrentProcess(), &b) && b == FALSE, "CheckRemoteDebuggerPresent: no debugger");
    SetLastError(0);
    CHECK(!CheckRemoteDebuggerPresent(GetCurrentProcess(), 0), "CheckRemoteDebuggerPresent(NULL flag) fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "... with ERROR_INVALID_PARAMETER");
    {
        DWORD s = 0xdead;
        CHECK(ProcessIdToSessionId(GetCurrentProcessId(), &s) && s == WTSGetActiveConsoleSessionId(), "the process runs in the console session");
        SetLastError(0);
        CHECK(!ProcessIdToSessionId(0x7ffffff0, &s), "ProcessIdToSessionId(no such process) fails");
        CHECK_ERR(ERROR_INVALID_PARAMETER, "... with ERROR_INVALID_PARAMETER");
    }
    CHECK(!IsThreadAFiber(), "the thread is not a fiber");
}

static void test_mitigation(void)
{
    PROCESS_MITIGATION_DEP_POLICY dep;
    PROCESS_MITIGATION_ASLR_POLICY aslr;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn;
    memset(&dep, 0xff, sizeof dep);
    CHECK(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDEPPolicy, &dep, sizeof dep) && dep.Enable == 1 && dep.Permanent,
          "DEP is on and permanent for an x64 process");
    memset(&aslr, 0xff, sizeof aslr);
    CHECK(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessASLRPolicy, &aslr, sizeof aslr) && aslr.Flags == 0, "no ASLR policy is enforced");
    memset(&dyn, 0, sizeof dyn);
    dyn.ProhibitDynamicCode = 1;
    SetLastError(0);
    CHECK(!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dyn, sizeof dyn), "a policy that cannot be enforced is refused");
    CHECK_ERR(ERROR_NOT_SUPPORTED, "... with ERROR_NOT_SUPPORTED");
    dyn.Flags = 0;
    CHECK(SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dyn, sizeof dyn), "asking for no mitigation succeeds");
    SetLastError(0);
    CHECK(!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessASLRPolicy, &aslr, 2), "a wrong policy size fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "... with ERROR_INVALID_PARAMETER");
}

/* ---------------------------------------------------------------- DebugBreak */
static volatile LONG g_bp_hits;
static volatile ULONG_PTR g_bp_addr, g_bp_rip;
static LONG CALLBACK bp_handler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
    ++g_bp_hits;
    g_bp_addr = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;
    g_bp_rip = ep->ContextRecord->Rip;
    ep->ContextRecord->Rip += 1;                          /* step over the INT3 */
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void test_debugbreak(void)
{
    PVOID h = AddVectoredExceptionHandler(1, bp_handler);
    const ULONG_PTR fn = (ULONG_PTR)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "DebugBreak");
    DebugBreak();
    RemoveVectoredExceptionHandler(h);
    CHECK(g_bp_hits == 1, "DebugBreak raises EXCEPTION_BREAKPOINT once");
    CHECKV(g_bp_addr == g_bp_rip && g_bp_addr >= fn && g_bp_addr < fn + 16 && *(const BYTE *)g_bp_addr == 0xcc,
           "the breakpoint is reported at the INT3 inside DebugBreak (ExceptionAddress == Context.Rip)", "addr=%p rip=%p fn=%p",
           (void *)g_bp_addr, (void *)g_bp_rip, (void *)fn);
}

/* ---------------------------------------------------------------- names, toolhelp, PSAPI */
static void test_names_toolhelp(void)
{
    WCHAR img[MAX_PATH], mod[MAX_PATH], nat[MAX_PATH];
    char imga[MAX_PATH];
    DWORD n = MAX_PATH, na = MAX_PATH, n2 = MAX_PATH;
    HANDLE snap;
    PROCESSENTRY32W pe;
    MODULEENTRY32W me;
    int found_self = 0, found_k32 = 0, first_is_exe = 0, count = 0;
    CHECK(QueryFullProcessImageNameW(GetCurrentProcess(), 0, img, &n), "QueryFullProcessImageNameW");
    GetModuleFileNameW(0, mod, MAX_PATH);
    /* the loader publishes module paths without the drive (GetModuleFileName returns "\\SHZ\\..."); the volume is C: */
    CHECK(n == (DWORD)k32t_wlen(img) && CompareStringOrdinal(mod[0] == '\\' ? img + 2 : img, -1, mod, -1, TRUE) == CSTR_EQUAL,
          "the image name is the executable's path");
    CHECK(wieq_tail(img, "\\T_K32_PROC.EXE") && img[1] == ':', "a Win32 path ending in T_K32_PROC.EXE");
    CHECK(QueryFullProcessImageNameW(GetCurrentProcess(), PROCESS_NAME_NATIVE, nat, &n2) && wstarts(nat, "\\Device\\HarddiskVolume1\\") &&
          wieq_tail(nat, "\\T_K32_PROC.EXE"), "PROCESS_NAME_NATIVE: the NT device path");
    CHECK(QueryFullProcessImageNameA(GetCurrentProcess(), 0, imga, &na) && na == n, "QueryFullProcessImageNameA");
    n = 5;
    SetLastError(0);
    CHECK(!QueryFullProcessImageNameW(GetCurrentProcess(), 0, img, &n), "a 5-character buffer is too small");
    CHECK_ERR(ERROR_INSUFFICIENT_BUFFER, "... with ERROR_INSUFFICIENT_BUFFER");

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
    CHECK(snap != INVALID_HANDLE_VALUE, "CreateToolhelp32Snapshot(processes and modules of this process)");
    pe.dwSize = 8;
    SetLastError(0);
    CHECK(!Process32FirstW(snap, &pe), "Process32FirstW with a short dwSize fails");
    CHECK_ERR(ERROR_BAD_LENGTH, "... with ERROR_BAD_LENGTH");
    pe.dwSize = sizeof pe;
    if (Process32FirstW(snap, &pe)) {
        do {
            ++count;
            if (pe.th32ProcessID == GetCurrentProcessId()) {
                found_self = wieq_tail(pe.szExeFile, "T_K32_PROC.EXE") && pe.cntThreads >= 1 && pe.pcPriClassBase == 8;
            }
        } while (Process32NextW(snap, &pe));
    }
    CHECK(GetLastError() == ERROR_NO_MORE_FILES, "the process list ends with ERROR_NO_MORE_FILES");
    CHECKV(found_self, "this process is listed with its executable name, a thread and base priority 8", "count=%d", count);
    me.dwSize = sizeof me;
    if (Module32FirstW(snap, &me)) {
        first_is_exe = me.hModule == GetModuleHandleW(0) && me.modBaseAddr == (BYTE *)GetModuleHandleW(0) && me.th32ProcessID == GetCurrentProcessId();
        do {
            if (me.hModule == GetModuleHandleW(L"kernel32.dll")) {
                const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)((const BYTE *)me.hModule + ((const IMAGE_DOS_HEADER *)me.hModule)->e_lfanew);
                found_k32 = me.modBaseSize == nt->OptionalHeader.SizeOfImage && wieq_tail(me.szModule, "kernel32.dll") && wieq_tail(me.szExePath, "\\kernel32.dll");
            }
        } while (Module32NextW(snap, &me));
    }
    CHECK(first_is_exe, "the first module is the executable");
    CHECK(found_k32, "kernel32.dll is listed with its base, SizeOfImage and path");
    CHECK(CloseHandle(snap), "CloseHandle(snapshot)");
    pe.dwSize = sizeof pe;
    SetLastError(0);
    CHECK(!Process32FirstW(snap, &pe) && GetLastError() == ERROR_INVALID_HANDLE, "a closed snapshot is ERROR_INVALID_HANDLE");
    SetLastError(0);
    CHECK(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0x7ffffff0) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER,
          "a module snapshot of a process that does not exist fails with ERROR_INVALID_PARAMETER");

    {
        WCHAR mapped[MAX_PATH];
        void *heap = HeapAlloc(GetProcessHeap(), 0, 64);
        MEMORY_BASIC_INFORMATION mbi;
        ULONG_PTR a;
        DWORD r = GetMappedFileNameW(GetCurrentProcess(), (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcessTimes"), mapped, MAX_PATH);
        CHECK(r > 0 && wstarts(mapped, "\\Device\\HarddiskVolume1\\") && wieq_tail(mapped, "\\kernel32.dll") && r == (DWORD)k32t_wlen(mapped),
              "GetMappedFileNameW(code of kernel32) is kernel32.dll's NT path");
        SetLastError(0);
        CHECK(GetMappedFileNameW(GetCurrentProcess(), heap, mapped, MAX_PATH) == 0 && GetLastError() == ERROR_FILE_INVALID,
              "heap memory maps no file (ERROR_FILE_INVALID)");
        for (a = 0x20000; a < 0x10000000; a += 0x10000)
            if (VirtualQuery((LPCVOID)a, &mbi, sizeof mbi) && mbi.State == MEM_FREE) break;
        SetLastError(0);
        CHECK(GetMappedFileNameW(GetCurrentProcess(), (LPVOID)a, mapped, MAX_PATH) == 0 && GetLastError() == ERROR_UNEXP_NET_ERR,
              "free address space is STATUS_INVALID_ADDRESS (ERROR_UNEXP_NET_ERR)");
        HeapFree(GetProcessHeap(), 0, heap);
    }
}

static void test_memory_info(void)
{
    PERFORMANCE_INFORMATION pi;
    PROCESS_MEMORY_COUNTERS_EX m0, m1, m2, m3;
    MEMORYSTATUSEX ms;
    PSAPI_WORKING_SET_EX_INFORMATION ws[3];
    BYTE *p;
    DWORD i, n;
    const DWORD pages = 64;
    memset(&pi, 0, sizeof pi);
    ms.dwLength = sizeof ms;
    CHECK(GetPerformanceInfo(&pi, sizeof pi), "GetPerformanceInfo");
    CHECK(GlobalMemoryStatusEx(&ms) && pi.PageSize == 4096 && (ULONGLONG)pi.PhysicalTotal * 4096 == ms.ullTotalPhys,
          "PhysicalTotal agrees with GlobalMemoryStatusEx");
    CHECK(pi.ProcessCount >= 1 && pi.ThreadCount >= 1 && pi.CommitPeak >= pi.CommitTotal && pi.CommitTotal > 0, "process/thread counts and commit");
    GetProcessHandleCount(GetCurrentProcess(), &n);
    CHECK(pi.HandleCount >= n, "the system handle count includes this process' handles");
    SetLastError(0);
    CHECK(!GetPerformanceInfo(&pi, 8) && GetLastError() == ERROR_BAD_LENGTH, "a short cb is ERROR_BAD_LENGTH");

    CHECK(GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&m0, sizeof m0) && m0.cb == sizeof m0, "GetProcessMemoryInfo (EX)");
    CHECK(m0.PrivateUsage == m0.PagefileUsage && m0.PeakWorkingSetSize >= m0.WorkingSetSize && m0.WorkingSetSize > 0, "counter relations");
    p = VirtualAlloc(0, pages * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(p != NULL, "commit 64 pages");
    GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&m1, sizeof m1);
    CHECKV(m1.PagefileUsage >= m0.PagefileUsage + pages * 4096, "committing 256 KiB raises the commit charge by 256 KiB", "%llu -> %llu",
           (ULONGLONG)m0.PagefileUsage, (ULONGLONG)m1.PagefileUsage);
    ws[0].VirtualAddress = p;
    CHECK(QueryWorkingSetEx(GetCurrentProcess(), ws, sizeof ws[0]) && !ws[0].VirtualAttributes.Valid, "an untouched committed page is not in the working set");
    for (i = 0; i < pages; ++i) p[i * 4096] = (BYTE)i;
    GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&m2, sizeof m2);
    CHECKV(m2.WorkingSetSize >= m1.WorkingSetSize + (pages - 4) * 4096, "touching 64 pages grows the working set by them", "%llu -> %llu",
           (ULONGLONG)m1.WorkingSetSize, (ULONGLONG)m2.WorkingSetSize);
    CHECKV(m2.PageFaultCount >= m1.PageFaultCount + pages, "each first touch was a page fault", "%u -> %u", (unsigned)m1.PageFaultCount, (unsigned)m2.PageFaultCount);
    ws[0].VirtualAddress = p;
    CHECK(QueryWorkingSetEx(GetCurrentProcess(), ws, sizeof ws[0]) && ws[0].VirtualAttributes.Valid && ws[0].VirtualAttributes.Win32Protection == PAGE_READWRITE &&
          !ws[0].VirtualAttributes.Locked, "a touched page is valid, PAGE_READWRITE, not locked");
    VirtualFree(p, 0, MEM_RELEASE);
    GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&m3, sizeof m3);
    CHECKV(m3.WorkingSetSize + (pages - 4) * 4096 <= m2.WorkingSetSize, "releasing the pages shrinks the working set", "%llu -> %llu",
           (ULONGLONG)m2.WorkingSetSize, (ULONGLONG)m3.WorkingSetSize);
    CHECKV(m3.PeakWorkingSetSize >= m2.WorkingSetSize, "the peak working set keeps the maximum reached before the release", "peak=%llu seen=%llu",
           (ULONGLONG)m3.PeakWorkingSetSize, (ULONGLONG)m2.WorkingSetSize);
    CHECK(m3.PeakPagefileUsage >= m1.PagefileUsage && m3.PagefileUsage + pages * 4096 <= m1.PagefileUsage, "commit charge: released, peak kept");
    SetLastError(0);
    CHECK(!QueryWorkingSetEx(GetCurrentProcess(), ws, 10) && GetLastError() == ERROR_BAD_LENGTH, "QueryWorkingSetEx with a partial entry is ERROR_BAD_LENGTH");
}

static void test_residency(void)
{
    BYTE *p = VirtualAlloc(0, 8 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), *na;
    PSAPI_WORKING_SET_EX_INFORMATION w;
    WIN32_MEMORY_RANGE_ENTRY r;
    MEMORY_BASIC_INFORMATION mbi;
    CHECK(p != NULL, "commit 8 pages");
    SetLastError(0);
    CHECK(!VirtualUnlock(p, 4096) && GetLastError() == ERROR_NOT_LOCKED, "VirtualUnlock of a page that is not locked is ERROR_NOT_LOCKED");
    CHECK(VirtualLock(p + 4096, 4096), "VirtualLock(an untouched page)");
    w.VirtualAddress = p + 4096;
    CHECK(QueryWorkingSetEx(GetCurrentProcess(), &w, sizeof w) && w.VirtualAttributes.Valid && w.VirtualAttributes.Locked, "a locked page is resident and locked");
    CHECK(VirtualUnlock(p + 4096, 4096), "VirtualUnlock");
    w.VirtualAddress = p + 4096;
    CHECK(QueryWorkingSetEx(GetCurrentProcess(), &w, sizeof w) && !w.VirtualAttributes.Locked, "... no longer locked");
    SetLastError(0);
    CHECK(!VirtualUnlock(p + 4096, 4096) && GetLastError() == ERROR_NOT_LOCKED, "unlocking twice is ERROR_NOT_LOCKED");
    na = VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    SetLastError(0);
    CHECK(na && !VirtualLock(na, 4096) && GetLastError() == ERROR_NOACCESS, "a PAGE_NOACCESS page cannot be locked (ERROR_NOACCESS)");
    if (na) VirtualFree(na, 0, MEM_RELEASE);

    r.VirtualAddress = p + 2 * 4096;
    r.NumberOfBytes = 4096;
    CHECK(PrefetchVirtualMemory(GetCurrentProcess(), 1, &r, 0), "PrefetchVirtualMemory");
    w.VirtualAddress = p + 2 * 4096;
    CHECK(QueryWorkingSetEx(GetCurrentProcess(), &w, sizeof w) && w.VirtualAttributes.Valid, "the prefetched page is resident");
    SetLastError(0);
    CHECK(!PrefetchVirtualMemory(GetCurrentProcess(), 1, &r, 1) && GetLastError() == ERROR_INVALID_PARAMETER, "flags must be 0");

    memset(p + 4 * 4096, 0x5a, 2 * 4096);
    CHECK(DiscardVirtualMemory(p + 4 * 4096, 2 * 4096) == ERROR_SUCCESS, "DiscardVirtualMemory");
    w.VirtualAddress = p + 4 * 4096;
    CHECK(QueryWorkingSetEx(GetCurrentProcess(), &w, sizeof w) && !w.VirtualAttributes.Valid, "discarded pages leave the working set");
    CHECK(VirtualQuery(p + 4 * 4096, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE, "... but stay committed");
    p[4 * 4096] = 1;
    CHECK(p[4 * 4096] == 1, "... and usable");
    CHECK(DiscardVirtualMemory(0, 0) == ERROR_INVALID_PARAMETER, "DiscardVirtualMemory(NULL, 0) is ERROR_INVALID_PARAMETER");
    VirtualLock(p, 4096);
    VirtualFree(p, 0, MEM_RELEASE);
    p = VirtualAlloc(p, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p) {
        SetLastError(0);
        CHECK(!VirtualUnlock(p, 4096) && GetLastError() == ERROR_NOT_LOCKED, "freeing memory unlocks it (a new allocation at the address is not locked)");
        VirtualFree(p, 0, MEM_RELEASE);
    }
}

/* ---------------------------------------------------------------- thread context */
static volatile ULONG_PTR g_waiter_local;
static HANDLE g_wait_event;
static DWORD WINAPI waiter(LPVOID p)
{
    volatile int local = 0;
    (void)p;
    g_waiter_local = (ULONG_PTR)&local;
    WaitForSingleObject(g_wait_event, INFINITE);
    return (DWORD)local;
}

static void test_context(void)
{
    CONTEXT ctx;
    const BYTE *ntdll = (const BYTE *)GetModuleHandleW(L"ntdll.dll");
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(ntdll + ((const IMAGE_DOS_HEADER *)ntdll)->e_lfanew);
    const ULONG_PTR lo = (ULONG_PTR)ntdll, hi = lo + nt->OptionalHeader.SizeOfImage;
    volatile int here = 0;
    HANDLE th;
    WOW64_CONTEXT wc;
    memset(&ctx, 0, sizeof ctx);
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    CHECK(GetThreadContext(GetCurrentThread(), &ctx), "GetThreadContext(current thread)");
    CHECKV(ctx.Rip >= lo && ctx.Rip < hi, "the current thread is inside ntdll's system-call stub", "rip=%p", (void *)ctx.Rip);
    CHECKV(ctx.Rsp < (ULONG_PTR)&here && (ULONG_PTR)&here - ctx.Rsp < 0x10000, "its stack pointer is just below this frame", "rsp=%p local=%p",
           (void *)ctx.Rsp, (void *)&here);
    g_wait_event = CreateEventW(0, TRUE, FALSE, 0);
    th = CreateThread(0, 0, waiter, 0, 0, 0);
    while (!g_waiter_local) Sleep(1);
    Sleep(30);
    memset(&ctx, 0, sizeof ctx);
    ctx.ContextFlags = CONTEXT_FULL;
    CHECK(GetThreadContext(th, &ctx), "GetThreadContext(a thread blocked in a wait)");
    CHECKV(ctx.Rip >= lo && ctx.Rip < hi && ctx.Rsp < g_waiter_local && g_waiter_local - ctx.Rsp < 0x10000,
           "it is in ntdll with its stack pointer below its own local variable", "rip=%p rsp=%p local=%p", (void *)ctx.Rip, (void *)ctx.Rsp,
           (void *)g_waiter_local);
    SetEvent(g_wait_event);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    CloseHandle(g_wait_event);
    ctx.ContextFlags = 1;                                 /* no CONTEXT_AMD64 bit */
    SetLastError(0);
    CHECK(!GetThreadContext(GetCurrentThread(), &ctx) && GetLastError() == ERROR_INVALID_PARAMETER, "context flags without CONTEXT_AMD64 are invalid");
    wc.ContextFlags = WOW64_CONTEXT_CONTROL;
    SetLastError(0);
    CHECK(!Wow64GetThreadContext(GetCurrentThread(), &wc) && GetLastError() == ERROR_INVALID_PARAMETER, "a native thread has no WOW64 context");
}

/* ---------------------------------------------------------------- InitOnce */
static INIT_ONCE g_once_wait = INIT_ONCE_STATIC_INIT;
static volatile LPVOID g_once_seen;
static DWORD WINAPI once_waiter(LPVOID p)
{
    BOOL pending = TRUE;
    LPVOID ctx = 0;
    (void)p;
    if (InitOnceBeginInitialize(&g_once_wait, 0, &pending, &ctx) && !pending) g_once_seen = ctx;
    return 0;
}

static void test_initonce(void)
{
    INIT_ONCE o = INIT_ONCE_STATIC_INIT, a = INIT_ONCE_STATIC_INIT, f = INIT_ONCE_STATIC_INIT;
    BOOL pending = FALSE;
    LPVOID ctx = 0;
    HANDLE th;
    SetLastError(0);
    CHECK(!InitOnceBeginInitialize(&o, INIT_ONCE_CHECK_ONLY, &pending, &ctx) && GetLastError() == ERROR_GEN_FAILURE, "CHECK_ONLY before initialisation is ERROR_GEN_FAILURE");
    CHECK(InitOnceBeginInitialize(&o, 0, &pending, &ctx) && pending, "the first caller must initialise (pending)");
    SetLastError(0);
    CHECK(!InitOnceComplete(&o, 0, (LPVOID)0x1001) && GetLastError() == ERROR_INVALID_PARAMETER, "a context with its low bits set is invalid");
    CHECK(InitOnceComplete(&o, 0, (LPVOID)0x1000), "InitOnceComplete");
    CHECK(InitOnceBeginInitialize(&o, 0, &pending, &ctx) && !pending && ctx == (LPVOID)0x1000, "later callers get the context");
    CHECK(InitOnceBeginInitialize(&o, INIT_ONCE_CHECK_ONLY, &pending, &ctx) && !pending && ctx == (LPVOID)0x1000, "CHECK_ONLY after completion");
    SetLastError(0);
    CHECK(!InitOnceComplete(&o, 0, 0) && GetLastError() == ERROR_GEN_FAILURE, "completing twice fails");

    CHECK(InitOnceBeginInitialize(&f, 0, &pending, &ctx) && pending && InitOnceComplete(&f, INIT_ONCE_INIT_FAILED, 0), "a failed initialisation");
    CHECK(InitOnceBeginInitialize(&f, 0, &pending, &ctx) && pending, "... lets the next caller try again");
    InitOnceComplete(&f, 0, 0);

    CHECK(InitOnceBeginInitialize(&a, INIT_ONCE_ASYNC, &pending, &ctx) && pending, "async: the first caller initialises");
    CHECK(InitOnceBeginInitialize(&a, INIT_ONCE_ASYNC, &pending, &ctx) && pending, "async: so may a second one, in parallel");
    SetLastError(0);
    CHECK(!InitOnceBeginInitialize(&a, 0, &pending, &ctx) && GetLastError() == ERROR_INVALID_PARAMETER, "a synchronous call during async initialisation is invalid");
    CHECK(InitOnceComplete(&a, INIT_ONCE_ASYNC, (LPVOID)0x2000), "async: the first completion wins");
    SetLastError(0);
    CHECK(!InitOnceComplete(&a, INIT_ONCE_ASYNC, (LPVOID)0x3000), "async: a second completion fails");
    CHECK(InitOnceBeginInitialize(&a, INIT_ONCE_CHECK_ONLY, &pending, &ctx) && ctx == (LPVOID)0x2000, "... and the first context stays");

    CHECK(InitOnceBeginInitialize(&g_once_wait, 0, &pending, &ctx) && pending, "sync: this thread initialises");
    th = CreateThread(0, 0, once_waiter, 0, 0, 0);
    Sleep(50);
    CHECK(WaitForSingleObject(th, 0) == WAIT_TIMEOUT, "a second thread waits while initialisation runs");
    InitOnceComplete(&g_once_wait, 0, (LPVOID)0x4000);
    CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0 && g_once_seen == (LPVOID)0x4000, "... and gets the context when it completes");
    CloseHandle(th);
}

/* ---------------------------------------------------------------- packages, WER */
static void test_packages_wer(void)
{
    WCHAR buf[64];
    UINT32 len = 64, count = 5, blen = 7;
    CHECK(GetPackagePathByFullName(L"Microsoft.Test_1.0.0.0_x64__8wekyb3d8bbwe", &len, buf) == ERROR_NOT_FOUND, "no package is installed (ERROR_NOT_FOUND)");
    CHECK(GetPackagePathByFullName(L"Microsoft.Test_1.0.0.0_x64__8wekyb3d8bbwe", 0, buf) == ERROR_INVALID_PARAMETER, "NULL length is invalid");
    CHECK(GetPackagesByPackageFamily(L"Microsoft.Test_8wekyb3d8bbwe", &count, 0, &blen, 0) == ERROR_SUCCESS && count == 0 && blen == 0,
          "a package family has no packages");
    CHECK(GetPackagesByPackageFamily(L"nounderscore", &count, 0, &blen, 0) == ERROR_INVALID_PARAMETER, "a malformed family name is invalid");
    CHECK(WerRegisterRuntimeExceptionModule(L"C:\\SHZ\\TESTS\\handler.dll", (PVOID)1) == S_OK, "WerRegisterRuntimeExceptionModule");
    CHECK(WerRegisterRuntimeExceptionModule(L"C:\\SHZ\\TESTS\\handler.dll", (PVOID)1) == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), "registering twice");
    CHECK(WerUnregisterRuntimeExceptionModule(L"C:\\SHZ\\TESTS\\handler.dll", (PVOID)1) == S_OK, "WerUnregisterRuntimeExceptionModule");
    CHECK(WerUnregisterRuntimeExceptionModule(L"C:\\SHZ\\TESTS\\handler.dll", (PVOID)1) == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "unregistering twice");
    CHECK(WerRegisterRuntimeExceptionModule(0, 0) == E_INVALIDARG, "a NULL path is E_INVALIDARG");
}

/* ---------------------------------------------------------------- heaps */
static HANDLE g_locked_heap;
static volatile LONG g_heap_thread_done;
static DWORD WINAPI heap_user(LPVOID p) { void *b = HeapAlloc(g_locked_heap, 0, 32); (void)p; HeapFree(g_locked_heap, 0, b); InterlockedExchange(&g_heap_thread_done, 1); return 0; }

static void test_heaps(void)
{
    HANDLE heaps[64], h2 = HeapCreate(0, 0, 0), h3 = HeapCreate(0, 0, 0), th;
    DWORD n, n2, i;
    int has_proc = 0, has_h2 = 0, busy = 0, mine = 0, regions = 0;
    PROCESS_HEAP_ENTRY e;
    void *b[3];
    ULONG v;
    struct { ULONG version, flags; } opt = { 1, 0 };
    n = GetProcessHeaps(64, heaps);
    for (i = 0; i < n && i < 64; ++i) { has_proc |= heaps[i] == GetProcessHeap(); has_h2 |= heaps[i] == h2; }
    CHECK(n >= 3 && has_proc && has_h2, "GetProcessHeaps lists the process heap and new heaps");
    CHECK(HeapDestroy(h2) && (n2 = GetProcessHeaps(0, 0)) == n - 1, "HeapDestroy removes a heap from the list");
    SetLastError(0);
    CHECK(!HeapDestroy(GetProcessHeap()), "the process heap cannot be destroyed");

    b[0] = HeapAlloc(h3, 0, 100); b[1] = HeapAlloc(h3, 0, 200); b[2] = HeapAlloc(h3, 0, 300);
    e.lpData = 0;
    while (HeapWalk(h3, &e)) {
        if (e.wFlags & PROCESS_HEAP_REGION) ++regions;
        else if (e.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
            ++busy;
            for (i = 0; i < 3; ++i) if (e.lpData == b[i] && e.cbData == 100 * (i + 1)) ++mine;
        }
    }
    CHECK(GetLastError() == ERROR_NO_MORE_ITEMS, "HeapWalk ends with ERROR_NO_MORE_ITEMS");
    CHECKV(regions >= 1 && busy == 3 && mine == 3, "HeapWalk: a region and exactly the three blocks with their sizes", "regions=%d busy=%d mine=%d", regions, busy, mine);
    HeapFree(h3, 0, b[1]);
    busy = 0;
    e.lpData = 0;
    while (HeapWalk(h3, &e)) if (e.wFlags & PROCESS_HEAP_ENTRY_BUSY) ++busy;
    CHECK(busy == 2, "after a free, two busy blocks remain");
    CHECK(HeapCompact(h3, 0) >= 200, "HeapCompact reports the largest free block");

    CHECK(HeapLock(h3), "HeapLock");
    b[1] = HeapAlloc(h3, 0, 64);
    CHECK(b[1] != NULL, "the thread holding the lock can still allocate (the lock is recursive)");
    g_locked_heap = h3;
    th = CreateThread(0, 0, heap_user, 0, 0, 0);
    Sleep(50);
    CHECK(!g_heap_thread_done, "another thread waits for the lock");
    CHECK(HeapUnlock(h3), "HeapUnlock");
    CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0 && g_heap_thread_done, "... then the other thread gets the heap");
    CloseHandle(th);
    SetLastError(0);
    CHECK(!HeapUnlock(h3), "HeapUnlock without the lock fails");

    v = 2;
    SetLastError(0);
    CHECK(!HeapSetInformation(h3, HeapCompatibilityInformation, &v, sizeof v) && GetLastError() == ERROR_NOT_SUPPORTED,
          "this heap is not a low-fragmentation heap (ERROR_NOT_SUPPORTED)");
    v = 0;
    CHECK(HeapSetInformation(h3, HeapCompatibilityInformation, &v, sizeof v), "HeapCompatibilityInformation 0 (standard heap)");
    {
        ULONG q = 99;
        SIZE_T need = 0;
        CHECK(HeapQueryInformation(h3, HeapCompatibilityInformation, &q, sizeof q, &need) && q == 0 && need == sizeof q,
              "HeapQueryInformation(HeapCompatibilityInformation) reports the standard heap (0), size 4");
        q = 99;
        need = 0;
        SetLastError(0);
        CHECK(!HeapQueryInformation(h3, HeapCompatibilityInformation, &q, 2, &need) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && need == sizeof q && q == 99,
              "... a short buffer is ERROR_INSUFFICIENT_BUFFER with the needed size, buffer untouched");
        SetLastError(0);
        CHECK(!HeapQueryInformation(h3, (HEAP_INFORMATION_CLASS)3, &q, sizeof q, &need) && GetLastError() == ERROR_INVALID_PARAMETER,
              "... a set-only class (HeapOptimizeResources) cannot be queried");
        CHECK(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "HeapQueryInformation") != NULL, "HeapQueryInformation resolves through GetProcAddress (dxcompiler.dll imports it)");
    }
    CHECK(HeapSetInformation(0, (HEAP_INFORMATION_CLASS)3, &opt, sizeof opt), "HeapOptimizeResources {1, 0}");
    opt.version = 2;
    SetLastError(0);
    CHECK(!HeapSetInformation(0, (HEAP_INFORMATION_CLASS)3, &opt, sizeof opt) && GetLastError() == ERROR_INVALID_PARAMETER, "HeapOptimizeResources version 2 is invalid");
    HeapDestroy(h3);
    /* last: from here on a corrupt heap operation would end this process */
    CHECK(HeapSetInformation(0, HeapEnableTerminationOnCorruption, 0, 0), "HeapEnableTerminationOnCorruption");
}

/* SetThreadDescription / GetThreadDescription (Windows 10 1607+): HRESULT_FROM_NT codes, LocalAlloc'd result, empty string
 * for a thread without a description, readable through any handle to the thread, NULL clears. */
WINBASEAPI HRESULT WINAPI SetThreadDescription(HANDLE, PCWSTR);
WINBASEAPI HRESULT WINAPI GetThreadDescription(HANDLE, PWSTR *);
/* RegisterApplicationRestart family: recorded, validated, reported back (no WER service restarts anything). */
static void test_restart(void)
{
    WCHAR buf[64];
    DWORD n = 64, fl = 77;
    static WCHAR big[1100];
    int i;
    HRESULT hr = GetApplicationRestartSettings(GetCurrentProcess(), buf, &n, &fl);
    CHECKV(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "GetApplicationRestartSettings before any registration: ERROR_NOT_FOUND", "hr=%lx", (long)hr);
    hr = UnregisterApplicationRestart();
    CHECKV(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "UnregisterApplicationRestart without a registration: ERROR_NOT_FOUND", "hr=%lx", (long)hr);
    CHECK(RegisterApplicationRestart(L"--restart --x", 4 | 8) == S_OK, "RegisterApplicationRestart(cmd, NO_PATCH|NO_REBOOT)");
    n = 64; fl = 0;
    hr = GetApplicationRestartSettings(GetCurrentProcess(), buf, &n, &fl);
    CHECKV(hr == S_OK && fl == 12 && n == 14 && k32t_weq(buf, L"--restart --x"), "GetApplicationRestartSettings returns command line (size includes the NUL) and flags", "hr=%lx n=%lu fl=%lu", (long)hr, (unsigned long)n, (unsigned long)fl);
    n = 5;
    hr = GetApplicationRestartSettings(GetCurrentProcess(), buf, &n, &fl);
    CHECKV(hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) && n == 14, "a short buffer: ERROR_INSUFFICIENT_BUFFER and the needed size", "hr=%lx n=%lu", (long)hr, (unsigned long)n);
    CHECK(RegisterApplicationRestart(L"x", 16) == E_INVALIDARG, "an unknown flag bit is E_INVALIDARG");
    for (i = 0; i < 1025; ++i) big[i] = L'a';
    big[1025] = 0;
    CHECK(RegisterApplicationRestart(big, 0) == E_INVALIDARG, "a command line over RESTART_MAX_CMD_LINE (1024) is E_INVALIDARG");
    big[1024] = 0;
    CHECK(RegisterApplicationRestart(big, 0) == S_OK, "exactly 1024 characters are accepted");
    CHECK(RegisterApplicationRestart(0, 0) == S_OK, "a NULL command line is an empty one");
    n = 64;
    CHECK(GetApplicationRestartSettings(GetCurrentProcess(), buf, &n, &fl) == S_OK && n == 1 && buf[0] == 0 && fl == 0, "... reported back empty");
    CHECK(UnregisterApplicationRestart() == S_OK, "UnregisterApplicationRestart");
    n = 64;
    CHECK(GetApplicationRestartSettings(GetCurrentProcess(), buf, &n, &fl) == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "... after which nothing is registered");
    CHECK(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "RegisterApplicationRestart") != 0, "the name resolves through GetProcAddress (Chromium looks it up)");
}

static DWORD WINAPI desc_worker(LPVOID arg) { return (DWORD)(ULONG_PTR)arg; }
static void test_description(void)
{
    PWSTR s = (PWSTR)1;
    HRESULT hr;
    HANDLE th;
    DWORD tid;
    static WCHAR big[40000];
    int i;
    hr = GetThreadDescription(GetCurrentThread(), &s);
    CHECKV(hr == S_OK && s && s[0] == 0, "GetThreadDescription of an unnamed thread is S_OK with an empty string", "hr=%lx", (long)hr);
    if (s) LocalFree(s);
    hr = SetThreadDescription(GetCurrentThread(), L"shz-main \u00e9");
    CHECKV(hr == S_OK, "SetThreadDescription on the current thread", "hr=%lx", (long)hr);
    s = 0;
    hr = GetThreadDescription(GetCurrentThread(), &s);
    CHECKV(hr == S_OK && s && k32t_weq(s, L"shz-main \u00e9"), "GetThreadDescription returns the text just set", "hr=%lx", (long)hr);
    if (s) LocalFree(s);
    th = CreateThread(0, 0, desc_worker, (LPVOID)7, CREATE_SUSPENDED, &tid);
    CHECK(th != 0, "worker thread created suspended");
    hr = SetThreadDescription(th, L"shz-worker");
    CHECKV(hr == S_OK, "SetThreadDescription through another thread's handle", "hr=%lx", (long)hr);
    s = 0;
    hr = GetThreadDescription(th, &s);
    CHECKV(hr == S_OK && s && k32t_weq(s, L"shz-worker"), "... read back through that handle", "hr=%lx", (long)hr);
    if (s) LocalFree(s);
    s = 0;
    hr = GetThreadDescription(GetCurrentThread(), &s);
    CHECK(hr == S_OK && s && k32t_weq(s, L"shz-main \u00e9"), "the current thread's own description is unchanged");
    if (s) LocalFree(s);
    hr = SetThreadDescription(th, NULL);
    s = 0;
    CHECKV(hr == S_OK && GetThreadDescription(th, &s) == S_OK && s && s[0] == 0, "SetThreadDescription(NULL) clears it", "hr=%lx", (long)hr);
    if (s) LocalFree(s);
    ResumeThread(th);
    CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0, "worker exited");
    CloseHandle(th);
    hr = SetThreadDescription((HANDLE)(ULONG_PTR)0x7fff1, L"x");
    CHECKV(hr == (HRESULT)0xD0000008, "SetThreadDescription on a bad handle is HRESULT_FROM_NT(STATUS_INVALID_HANDLE)", "hr=%lx", (long)hr);
    s = (PWSTR)1;
    hr = GetThreadDescription((HANDLE)(ULONG_PTR)0x7fff1, &s);
    CHECKV(hr == (HRESULT)0xD0000008 && s == 0, "GetThreadDescription on a bad handle: same code, *desc NULL", "hr=%lx", (long)hr);
    for (i = 0; i < 39999; ++i) big[i] = L'a';
    big[39999] = 0;
    hr = SetThreadDescription(GetCurrentThread(), big);
    CHECKV(hr == (HRESULT)0xD000000D, "a 39999-char description exceeds a UNICODE_STRING: HRESULT_FROM_NT(STATUS_INVALID_PARAMETER)", "hr=%lx", (long)hr);
    big[32767] = 0;
    hr = SetThreadDescription(GetCurrentThread(), big);
    s = 0;
    CHECKV(hr == S_OK && GetThreadDescription(GetCurrentThread(), &s) == S_OK && s && k32t_wlen(s) == 32767, "a 32767-char description (65534 bytes) is accepted and read back whole", "hr=%lx len=%d", (long)hr, s ? k32t_wlen(s) : -1);
    if (s) LocalFree(s);
    SetThreadDescription(GetCurrentThread(), L"t_k32_proc main");
}

/* ---------------------------------------------------------------- checked time-query rights and retained child totals
 * Additional component checks; the original test bodies and main sequence are
 * preserved. No CPU-work threshold or timing ratio is required here. */
typedef struct {
    FILETIME creation, exit, kernel, user;
    ULONG64 cycles;
    DWORD handles;
    BOOL wow64;
} tq_values;
typedef struct { ULONG64 before; tq_values value; ULONG64 after; } tq_guard;
static const char *const tq_names[6] = {
    "GetProcessTimes", "GetThreadTimes", "QueryProcessCycleTime",
    "QueryThreadCycleTime", "GetProcessHandleCount", "IsWow64Process"
};
#define TQ_SENTINEL 0x5a5a5a5a5a5a5a5aull

static HANDLE tq_target(unsigned kind, HANDLE process, HANDLE thread)
{
    return kind == 1 || kind == 3 ? thread : process;
}
static BOOL tq_get(unsigned kind, HANDLE handle, tq_values *v)
{
    switch (kind) {
    case 0: return GetProcessTimes(handle, &v->creation, &v->exit, &v->kernel, &v->user);
    case 1: return GetThreadTimes(handle, &v->creation, &v->exit, &v->kernel, &v->user);
    case 2: return QueryProcessCycleTime(handle, &v->cycles);
    case 3: return QueryThreadCycleTime(handle, &v->cycles);
    case 4: return GetProcessHandleCount(handle, &v->handles);
    default: return IsWow64Process(handle, &v->wow64);
    }
}
static void tq_success(unsigned kind, HANDLE handle)
{
    tq_guard out;
    tq_values expected;
    BOOL ok, measured;
    memset(&out, 0x5a, sizeof out);
    expected = out.value;
    ok = tq_get(kind, handle, &out.value);
    if (kind < 2) {
        expected.creation = out.value.creation; expected.exit = out.value.exit;
        expected.kernel = out.value.kernel; expected.user = out.value.user;
        measured = ft_u64(out.value.creation) != 0 && ft_u64(out.value.creation) != TQ_SENTINEL &&
                   ft_u64(out.value.exit) == 0 && ft_u64(out.value.kernel) != TQ_SENTINEL &&
                   ft_u64(out.value.user) != TQ_SENTINEL;
    } else if (kind < 4) {
        expected.cycles = out.value.cycles;
        measured = out.value.cycles != TQ_SENTINEL;
    } else if (kind == 4) {
        expected.handles = out.value.handles;
        measured = out.value.handles != 0x5a5a5a5a;
    } else {
        expected.wow64 = out.value.wow64;
        measured = out.value.wow64 == FALSE; /* this fixture is a native x64 image */
    }
    CHECKV(ok && measured, "one independent query right permits the real getter",
           "%s handle=%p error=%lu", tq_names[kind], handle, (unsigned long)GetLastError());
    CHECKV(out.before == TQ_SENTINEL && out.after == TQ_SENTINEL &&
           !memcmp(&out.value, &expected, sizeof expected),
           "the getter writes only its documented output fields",
           "%s handle=%p", tq_names[kind], handle);
}
static void tq_refusal(unsigned kind, HANDLE handle, DWORD error)
{
    tq_guard out, before;
    memset(&out, 0x5a, sizeof out); before = out;
    SetLastError(0);
    CHECKV(!tq_get(kind, handle, &out.value) && GetLastError() == error &&
           !memcmp(&out, &before, sizeof out),
           "a refused getter reports the contract error and preserves every output byte",
           "%s handle=%p error=%lu expected=%lu", tq_names[kind], handle,
           (unsigned long)GetLastError(), (unsigned long)error);
}
static void tq_affinity_get(HANDLE handle)
{
    struct { DWORD_PTR before, process, system, after; } out;
    memset(&out, 0x5a, sizeof out);
    CHECK(GetProcessAffinityMask(handle, &out.process, &out.system) &&
          out.process == 1 && out.system == 1 &&
          out.before == (DWORD_PTR)TQ_SENTINEL && out.after == (DWORD_PTR)TQ_SENTINEL,
          "either process query right reads exactly the real UP affinity masks");
}
static void tq_affinity_refusal(HANDLE handle, DWORD error)
{
    struct { DWORD_PTR before, process, system, after; } out, before;
    memset(&out, 0x5a, sizeof out); before = out;
    SetLastError(0);
    CHECK(!GetProcessAffinityMask(handle, &out.process, &out.system) &&
          GetLastError() == error && !memcmp(&out, &before, sizeof out),
          "refused affinity getter preserves both masks and adjacent bytes");
}
static void tq_affinity_set_refusal(HANDLE handle, DWORD_PTR mask, DWORD error)
{
    SetLastError(0);
    CHECKV(!SetProcessAffinityMask(handle, mask) && GetLastError() == error,
           "affinity setter refuses unsupported masks or missing target rights",
           "handle=%p mask=%llu error=%lu expected=%lu", handle, (ULONGLONG)mask,
           (unsigned long)GetLastError(), (unsigned long)error);
}
static void tq_affinity_null(HANDLE handle, unsigned missing)
{
    DWORD_PTR process = (DWORD_PTR)TQ_SENTINEL, system = (DWORD_PTR)TQ_SENTINEL;
    SetLastError(0);
    CHECK(!GetProcessAffinityMask(handle, missing == 0 || missing == 2 ? NULL : &process,
                                 missing == 1 || missing == 2 ? NULL : &system) &&
          GetLastError() == ERROR_INVALID_PARAMETER &&
          process == (DWORD_PTR)TQ_SENTINEL && system == (DWORD_PTR)TQ_SENTINEL,
          "NULL affinity output is ERROR_INVALID_PARAMETER with other output preserved");
}

static void tq_retained_child(void)
{
    static const WCHAR child_name[] = L"T_HELLO.EXE";
    struct { ULONG64 before; WCHAR path[MAX_PATH]; ULONG64 after; } name;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE process[2] = {NULL, NULL}, thread[2] = {NULL, NULL}, set_only = NULL;
    const DWORD process_rights[2] = {PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION};
    const DWORD thread_rights[2] = {THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION};
    tq_values pt[2], tt[2];
    BOOL pt_ok[2], tt_ok[2], pc_ok[2], tc_ok[2], configured, resumed, natural;
    DWORD n, at, i, kind, process_wait = WAIT_FAILED, thread_wait = WAIT_FAILED, process_code = 0, thread_code = 0;
    memset(&name, 0x5a, sizeof name);
    n = GetModuleFileNameW(NULL, name.path, MAX_PATH);
    CHECK(n > 0 && n < MAX_PATH && name.path[n] == 0 &&
          name.before == TQ_SENTINEL && name.after == TQ_SENTINEL,
          "capture the complete sibling-fixture path within guarded bounds");
    if (!n || n >= MAX_PATH || name.path[n] != 0) return;
    at = n;
    while (at && name.path[at - 1] != '\\' && name.path[at - 1] != '/') --at;
    CHECK(at > 0 && at + sizeof child_name / sizeof child_name[0] <= MAX_PATH,
          "the existing T_HELLO name including its NUL fits the original directory");
    if (!at || at + sizeof child_name / sizeof child_name[0] > MAX_PATH) return;
    for (i = 0; i < sizeof child_name / sizeof child_name[0]; ++i) name.path[at + i] = child_name[i];
    CHECK(name.before == TQ_SENTINEL && name.after == TQ_SENTINEL &&
          name.path[at + sizeof child_name / sizeof child_name[0] - 1] == 0,
          "bounded child-name replacement preserves path guards and terminates");
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    natural = CreateProcessW(name.path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    CHECK(natural, "create the existing sole-thread exit-seven fixture suspended");
    if (!natural) return;
    natural = FALSE;
    for (i = 0; i < 2; ++i) {
        process[i] = OpenProcess(process_rights[i], FALSE, pi.dwProcessId);
        CHECK(process[i] != NULL, "open one independent child process query right before dispatch");
        thread[i] = OpenThread(thread_rights[i], FALSE, pi.dwThreadId);
        CHECK(thread[i] != NULL, "open one independent primary-thread query right before dispatch");
    }
    set_only = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pi.dwProcessId);
    CHECK(set_only != NULL, "open the child SET-only process handle before dispatch");
    if (!process[0] || !process[1] || !thread[0] || !thread[1] || !set_only) goto cleanup;
    configured = SetProcessAffinityMask(set_only, 1);
    CHECK(configured, "SET-only child handle accepts mask one before first dispatch");
    if (!configured) goto cleanup;
    for (i = 0; i < 2; ++i)
        for (kind = 0; kind < 6; ++kind) tq_success(kind, tq_target(kind, process[i], thread[i]));
    resumed = ResumeThread(pi.hThread) == 1;
    CHECK(resumed, "resume the suspended child exactly once");
    if (!resumed) goto cleanup;
    process_wait = WaitForSingleObject(pi.hProcess, 5000);
    CHECK(process_wait == WAIT_OBJECT_0, "the real child process finishes within a bounded wait");
    thread_wait = WaitForSingleObject(pi.hThread, 5000);
    CHECK(thread_wait == WAIT_OBJECT_0, "the real primary thread also finishes before final aggregation");
    if (process_wait != WAIT_OBJECT_0 || thread_wait != WAIT_OBJECT_0) goto cleanup;
    configured = GetExitCodeProcess(pi.hProcess, &process_code) && process_code == 7;
    CHECK(configured, "the existing child retains its natural process exit-seven result");
    resumed = GetExitCodeThread(pi.hThread, &thread_code) && thread_code == 7;
    CHECK(resumed, "the retained primary thread reports the same natural exit-seven result");
    natural = configured && resumed;
    if (!natural) goto cleanup;
    memset(pt, 0, sizeof pt); memset(tt, 0, sizeof tt);
    for (i = 0; i < 2; ++i) {
        pt_ok[i] = GetProcessTimes(process[i], &pt[i].creation, &pt[i].exit, &pt[i].kernel, &pt[i].user);
        CHECK(pt_ok[i], "an independent query right reads retained final process times");
        tt_ok[i] = GetThreadTimes(thread[i], &tt[i].creation, &tt[i].exit, &tt[i].kernel, &tt[i].user);
        CHECK(tt_ok[i], "an independent query right reads retained primary-thread times");
        pc_ok[i] = QueryProcessCycleTime(process[i], &pt[i].cycles);
        CHECK(pc_ok[i], "an independent query right reads retained process cycles");
        tc_ok[i] = QueryThreadCycleTime(thread[i], &tt[i].cycles);
        CHECK(tc_ok[i], "an independent query right reads retained primary-thread cycles");
        CHECK(pt_ok[i] && tt_ok[i] && ft_u64(pt[i].kernel) == ft_u64(tt[i].kernel) &&
              ft_u64(pt[i].user) == ft_u64(tt[i].user),
              "the naturally exited sole-thread process has exactly its primary-thread CPU totals");
        CHECK(pc_ok[i] && tc_ok[i] && pt[i].cycles == tt[i].cycles,
              "the naturally exited sole-thread process has exactly its primary-thread cycle total");
        CHECK(pt_ok[i] && tt_ok[i] && ft_u64(pt[i].creation) != 0 && ft_u64(tt[i].creation) != 0 &&
              ft_u64(pt[i].exit) >= ft_u64(pt[i].creation) && ft_u64(tt[i].exit) >= ft_u64(tt[i].creation),
              "both retained objects report completed lifetimes without a CPU-work threshold");
    }
    CHECK(pt_ok[0] && pt_ok[1] && tt_ok[0] && tt_ok[1] && pc_ok[0] && pc_ok[1] && tc_ok[0] && tc_ok[1] &&
          !memcmp(&pt[0], &pt[1], sizeof pt[0]) && !memcmp(&tt[0], &tt[1], sizeof tt[0]),
          "QUERY and LIMITED-only handles return identical immutable final totals");
cleanup:
    /* Never count forced or failed cleanup as natural exit or as final totals. */
    if (process_wait != WAIT_OBJECT_0 || thread_wait != WAIT_OBJECT_0) {
        CHECK(TerminateProcess(pi.hProcess, 99), "terminate a failed child only for bounded cleanup");
        CHECK(WaitForSingleObject(pi.hProcess, 2000) == WAIT_OBJECT_0, "failed child process cleanup is bounded");
        CHECK(WaitForSingleObject(pi.hThread, 2000) == WAIT_OBJECT_0, "failed primary-thread cleanup is bounded");
    }
    for (i = 0; i < 2; ++i) {
        if (thread[i]) CHECK(CloseHandle(thread[i]), "close the retained child thread query handle");
        if (process[i]) CHECK(CloseHandle(process[i]), "close the retained child process query handle");
    }
    if (set_only) CHECK(CloseHandle(set_only), "close the child SET-only process handle");
    CHECK(CloseHandle(pi.hThread), "close the original child primary-thread handle");
    CHECK(CloseHandle(pi.hProcess), "close the original child process handle");
}

static void test_query_rights_and_retained_times(void)
{
    const DWORD process_rights[2] = {PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION};
    const DWORD thread_rights[2] = {THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION};
    const HANDLE invalid = (HANDLE)(ULONG_PTR)0x7ffffffc;
    HANDLE process[2] = {NULL, NULL}, thread[2] = {NULL, NULL}, ps = NULL, ts = NULL, event = NULL, oldp, oldt;
    DWORD before = 0, count = 0, i, kind;
    BOOL closed_p, closed_t;
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &before), "capture the real handle count before query-right fixtures");
    for (i = 0; i < 2; ++i) {
        process[i] = OpenProcess(process_rights[i], FALSE, GetCurrentProcessId());
        CHECK(process[i] != NULL, "open one independent process query right");
        thread[i] = OpenThread(thread_rights[i], FALSE, GetCurrentThreadId());
        CHECK(thread[i] != NULL, "open one independent thread query right");
    }
    ps = OpenProcess(PROCESS_SET_INFORMATION, FALSE, GetCurrentProcessId());
    CHECK(ps != NULL, "open a SET-only process handle for getter refusal and affinity setting");
    ts = OpenThread(THREAD_SET_INFORMATION, FALSE, GetCurrentThreadId());
    CHECK(ts != NULL, "open a SET-only thread handle for getter refusal");
    if (!process[0] || !process[1] || !thread[0] || !thread[1] || !ps || !ts) goto cleanup;
    CHECK(GetProcessHandleCount(process[1], &count) && count == before + 6,
          "LIMITED-only process info accounts for exactly the six real opened handles");
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(event != NULL, "create a real counted event beside the restricted query handles");
    CHECK(GetProcessHandleCount(process[1], &count) && count == before + 7,
          "the protected handle count increases by exactly one for that event");
    if (event) {
        BOOL closed = CloseHandle(event);
        CHECK(closed, "close the counted event");
        if (closed) event = NULL;
        else goto cleanup;
    }
    CHECK(GetProcessHandleCount(process[0], &count) && count == before + 6,
          "closing the event restores the real protected process handle count");
    for (i = 0; i < 2; ++i) {
        for (kind = 0; kind < 6; ++kind) tq_success(kind, tq_target(kind, process[i], thread[i]));
        tq_affinity_get(process[i]);
        tq_affinity_set_refusal(process[i], 1, ERROR_ACCESS_DENIED);
    }
    for (kind = 0; kind < 6; ++kind) tq_refusal(kind, tq_target(kind, ps, ts), ERROR_ACCESS_DENIED);
    tq_affinity_refusal(ps, ERROR_ACCESS_DENIED);
    CHECK(SetProcessAffinityMask(ps, 1), "SET-only process handle permits the idempotent actual UP mask");
    tq_affinity_set_refusal(ps, 0, ERROR_INVALID_PARAMETER);
    tq_affinity_set_refusal(ps, 2, ERROR_INVALID_PARAMETER);
    tq_affinity_set_refusal(ps, (DWORD_PTR)1 << 63, ERROR_INVALID_PARAMETER);
    tq_affinity_get(process[1]);
    for (i = 0; i < 4; ++i) {
        for (kind = 0; kind < 6; ++kind)
            tq_success(kind, (HANDLE)((ULONG_PTR)tq_target(kind, process[0], thread[0]) | i));
        tq_affinity_get((HANDLE)((ULONG_PTR)process[0] | i));
        CHECK(SetProcessAffinityMask((HANDLE)((ULONG_PTR)ps | i), 1),
              "affinity setter accepts the two defined real process-handle tag bits");
    }
    for (kind = 0; kind < 6; ++kind) {
        tq_refusal(kind, (HANDLE)((ULONG_PTR)tq_target(kind, process[0], thread[0]) | (ULONG_PTR)(1ull << 32)),
                   ERROR_INVALID_HANDLE);
        tq_refusal(kind, tq_target(kind, thread[0], process[0]), ERROR_INVALID_HANDLE);
        tq_refusal(kind, invalid, ERROR_INVALID_HANDLE);
    }
    tq_affinity_refusal(thread[0], ERROR_INVALID_HANDLE);
    tq_affinity_set_refusal(ts, 1, ERROR_INVALID_HANDLE);
    tq_affinity_refusal((HANDLE)((ULONG_PTR)process[0] | (ULONG_PTR)(1ull << 32)), ERROR_INVALID_HANDLE);
    tq_affinity_set_refusal((HANDLE)((ULONG_PTR)ps | (ULONG_PTR)(1ull << 32)), 1, ERROR_INVALID_HANDLE);
    tq_affinity_refusal(invalid, ERROR_INVALID_HANDLE);
    tq_affinity_set_refusal(invalid, 1, ERROR_INVALID_HANDLE);
    for (i = 0; i < 3; ++i) tq_affinity_null(process[0], i);
    SetLastError(0);
    CHECK(!QueryProcessCycleTime(process[0], NULL) && GetLastError() == ERROR_INVALID_PARAMETER,
          "NULL process-cycle output is explicitly invalid");
    SetLastError(0);
    CHECK(!QueryThreadCycleTime(thread[0], NULL) && GetLastError() == ERROR_INVALID_PARAMETER,
          "NULL thread-cycle output is explicitly invalid");
    SetLastError(0);
    CHECK(!GetProcessHandleCount(process[0], NULL) && GetLastError() == ERROR_INVALID_PARAMETER,
          "NULL process-handle-count output is explicitly invalid");
    SetLastError(0);
    CHECK(!IsWow64Process(process[0], NULL) && GetLastError() == ERROR_INVALID_PARAMETER,
          "NULL Wow64 output is explicitly invalid");
    oldp = process[0]; oldt = thread[0];
    closed_p = CloseHandle(oldp); CHECK(closed_p, "close the real QUERY-only process handle");
    closed_t = CloseHandle(oldt); CHECK(closed_t, "close the real QUERY-only thread handle");
    if (closed_p) process[0] = NULL;
    if (closed_t) thread[0] = NULL;
    if (closed_p && closed_t) {
        /* No handle allocation between close and these refusal checks. */
        for (kind = 0; kind < 6; ++kind) tq_refusal(kind, tq_target(kind, oldp, oldt), ERROR_INVALID_HANDLE);
        tq_affinity_refusal(oldp, ERROR_INVALID_HANDLE);
        tq_affinity_set_refusal(oldp, 1, ERROR_INVALID_HANDLE);
    }
cleanup:
    if (event) CHECK(CloseHandle(event), "close a counted event after failed setup");
    for (i = 0; i < 2; ++i) {
        if (thread[i]) CHECK(CloseHandle(thread[i]), "close the independent thread query handle");
        if (process[i]) CHECK(CloseHandle(process[i]), "close the independent process query handle");
    }
    if (ts) CHECK(CloseHandle(ts), "close the SET-only thread handle");
    if (ps) CHECK(CloseHandle(ps), "close the SET-only process handle");
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &count) && count == before,
          "all query-right fixture handles are released");
    tq_retained_child();
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &count) && count == before,
          "all natural or failed-child fixture handles are released");
}

/* ---------------------------------------------------------------- strict QUERY and loaded-image snapshots
 * Native class 0 is used only to locate a real child's PEB; it proves no
 * access policy. Class 18 below is the private loaded-module subset, not a
 * generic section-backed file provider or native Windows 98 acceptance. */
LONG NTAPI NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
LONG NTAPI NtShzQueryK32(ULONG, HANDLE, PVOID, ULONG, PULONG);
typedef struct {
    LONG64 exit_status;
    ULONG64 peb, affinity;
    LONG64 base_priority;
    ULONG64 pid, parent_pid;
} fq_process_basic;
typedef struct { ULONG64 address; ULONG pid, reserved; char path[256]; } fq_mapped_packet;
typedef union { PROCESS_MITIGATION_DEP_POLICY dep; ULONG64 options[2]; DWORD flags; } fq_policy_value;
typedef struct { ULONG64 before; fq_policy_value value; ULONG64 after; } fq_policy_guard;
typedef struct { ULONG64 before; WCHAR text[400]; ULONG64 after; } fq_name_guard;
_Static_assert(sizeof(fq_process_basic) == 48, "the existing native process-basic packet is 48 bytes");
_Static_assert(sizeof(fq_mapped_packet) == 272, "the private mapped-image packet is 272 bytes");
_Static_assert(offsetof(fq_mapped_packet, path) == 16, "the path follows address, PID and reserved fields");
#define FQ_SENTINEL 0x5a5a5a5a5a5a5a5aull
#define FQ_POISON_ERROR 0x13579u
static void test_strict_process_queries(void);

static int fq_narrow_tail(const char *path, const char *tail)
{
    size_t n = 0, len = strlen(tail), i;
    while (n < 256 && path[n]) ++n;
    if (n == 256 || n < len) return 0;
    for (i = 0; i < len; ++i) {
        unsigned char a = (unsigned char)path[n - len + i], b = (unsigned char)tail[i];
        if (a >= 'a' && a <= 'z') a -= 32;
        if (b >= 'a' && b <= 'z') b -= 32;
        if (a != b) return 0;
    }
    return 1;
}

static int fq_name_bounds(const fq_name_guard *name, DWORD written)
{
    fq_name_guard expected;
    if (written > 400) return 0;
    memset(&expected, 0x5a, sizeof expected);
    memcpy(expected.text, name->text, written * sizeof(WCHAR));
    return !memcmp(name, &expected, sizeof expected);
}

static void fq_policy_success(HANDLE process)
{
    static const PROCESS_MITIGATION_POLICY policies[4] = {
        ProcessDEPPolicy, ProcessASLRPolicy, ProcessMitigationOptionsMask, ProcessMitigationOptionsMask
    };
    static const SIZE_T lengths[4] = {sizeof(PROCESS_MITIGATION_DEP_POLICY), sizeof(DWORD), 8, 16};
    unsigned i;
    for (i = 0; i < 4; ++i) {
        fq_policy_guard out, expected;
        BOOL ok;
        memset(&out, 0x5a, sizeof out);
        expected = out;
        memset(&expected.value, 0, lengths[i]);
        if (policies[i] == ProcessDEPPolicy) {
            expected.value.dep.Enable = 1;
            expected.value.dep.Permanent = TRUE;
        }
        ok = GetProcessMitigationPolicy(process, policies[i], &out.value, lengths[i]);
        CHECK(ok, "full QUERY permits the existing DEP/ASLR/options reporting subset");
        CHECK(!memcmp(&out, &expected, sizeof out),
              "mitigation reporting writes only its exact size and preserves poisoned guards");
    }
}

static void fq_policy_refusal(HANDLE process, DWORD error)
{
    static const PROCESS_MITIGATION_POLICY policies[4] = {
        ProcessDEPPolicy, ProcessASLRPolicy, ProcessMitigationOptionsMask, ProcessMitigationOptionsMask
    };
    static const SIZE_T lengths[4] = {sizeof(PROCESS_MITIGATION_DEP_POLICY), sizeof(DWORD), 8, 16};
    unsigned i;
    for (i = 0; i < 4; ++i) {
        fq_policy_guard out, original;
        memset(&out, 0x5a, sizeof out); original = out;
        SetLastError(FQ_POISON_ERROR);
        CHECK(!GetProcessMitigationPolicy(process, policies[i], &out.value, lengths[i]) &&
              GetLastError() == error && !memcmp(&out, &original, sizeof out),
              "refused mitigation query reports its handle/right error without changing output");
    }
}

static void fq_policy_bad_inputs(HANDLE process)
{
    static const PROCESS_MITIGATION_POLICY policies[4] = {
        ProcessDEPPolicy, ProcessMitigationOptionsMask, ProcessMitigationOptionsMask, ProcessMitigationOptionsMask
    };
    static const SIZE_T lengths[4] = {sizeof(PROCESS_MITIGATION_DEP_POLICY) - 1, 7, 15, 17};
    fq_policy_guard out, original;
    unsigned i;
    for (i = 0; i < 4; ++i) {
        memset(&out, 0x5a, sizeof out); original = out;
        SetLastError(FQ_POISON_ERROR);
        CHECK(!GetProcessMitigationPolicy(process, policies[i], &out.value, lengths[i]) &&
              GetLastError() == ERROR_INVALID_PARAMETER && !memcmp(&out, &original, sizeof out),
              "wrong DEP/options lengths preserve the entire output");
    }
    memset(&out, 0x5a, sizeof out); original = out;
    SetLastError(FQ_POISON_ERROR);
    CHECK(!GetProcessMitigationPolicy(process, (PROCESS_MITIGATION_POLICY)-1, &out.value, 8) &&
          GetLastError() == ERROR_INVALID_PARAMETER && !memcmp(&out, &original, sizeof out),
          "an unknown mitigation policy refuses without manufacturing a capability");
    SetLastError(FQ_POISON_ERROR);
    CHECK(!GetProcessMitigationPolicy(process, ProcessDEPPolicy, NULL, sizeof(PROCESS_MITIGATION_DEP_POLICY)) &&
          GetLastError() == ERROR_INVALID_PARAMETER, "a NULL mitigation output is refused on a valid QUERY handle");
}

static DWORD fq_name_success(HANDLE process, LPVOID address, const char *tail, const WCHAR *same, fq_name_guard *saved)
{
    fq_name_guard name;
    DWORD n;
    BOOL valid;
    memset(&name, 0x5a, sizeof name);
    n = K32GetMappedFileNameW(process, address, name.text, 400);
    valid = n > 0 && n < 400 && name.text[n] == 0 && (DWORD)k32t_wlen(name.text) == n &&
            wstarts(name.text, "\\Device\\HarddiskVolume") && wieq_tail(name.text, tail) &&
            (!same || k32t_weq(name.text, same));
    CHECK(valid, "an actual loaded-image address resolves to its complete native mapped name");
    CHECK(fq_name_bounds(&name, n < 400 && n ? n + 1 : 0),
          "mapped-name success preserves everything beyond the string and its NUL");
    if (saved) *saved = name;
    return valid ? n : 0;
}

static void fq_name_refusal(HANDLE process, LPVOID address, DWORD error)
{
    fq_name_guard name, original;
    memset(&name, 0x5a, sizeof name); original = name;
    SetLastError(FQ_POISON_ERROR);
    CHECK(K32GetMappedFileNameW(process, address, name.text, 400) == 0 &&
          GetLastError() == error && !memcmp(&name, &original, sizeof name),
          "refused mapped-name query preserves the complete poisoned buffer");
}

static void fq_name_sizes(HANDLE process, LPVOID address, const fq_name_guard *full, DWORD n)
{
    DWORD sizes[3] = {1, n, n + 1}, i;
    for (i = 0; i < 3; ++i) {
        fq_name_guard name;
        DWORD got, capacity = sizes[i], copied = capacity <= n ? capacity - 1 : n;
        memset(&name, 0x5a, sizeof name);
        SetLastError(FQ_POISON_ERROR);
        got = K32GetMappedFileNameW(process, address, name.text, capacity);
        CHECK(got == (capacity <= n ? capacity : n) &&
              (capacity > n || GetLastError() == ERROR_INSUFFICIENT_BUFFER) &&
              !memcmp(name.text, full->text, copied * sizeof(WCHAR)) && name.text[copied] == 0,
              "size one, name length and name length plus NUL follow documented truncation rules");
        CHECK(fq_name_bounds(&name, copied + 1), "truncation/exact-fit writes stay within the requested capacity");
    }
}

static void fq_query_gate(HANDLE process, BOOL permitted)
{
    ULONG length = 0x5a5a5a5au;
    LONG status = NtShzQueryK32(17, process, NULL, 0, &length);
    CHECK(permitted ? status == 0 && length == 0 :
          status == (LONG)0xc0000022u && length == 0x5a5a5a5au,
          "the zero-payload private gate independently requires full QUERY");
}

static void fq_packet_success(HANDLE process, LPVOID address, DWORD pid, BOOL empty, const char *tail)
{
    struct { ULONG64 before; fq_mapped_packet value; ULONG64 after; } out;
    ULONG length = 0x5a5a5a5au;
    LONG status;
    memset(&out, 0x5a, sizeof out); out.value.address = (ULONG64)(ULONG_PTR)address;
    status = NtShzQueryK32(18, process, &out.value, sizeof out.value, &length);
    CHECK(status == 0 && length == 272 && out.value.address == (ULONG64)(ULONG_PTR)address &&
          out.value.pid == pid && out.value.reserved == 0 &&
          (empty ? out.value.path[0] == 0 : fq_narrow_tail(out.value.path, tail)),
          "private image snapshot returns exact size, captured identity and the supported path state");
    CHECK(out.before == FQ_SENTINEL && out.after == FQ_SENTINEL,
          "the fixed image snapshot preserves packet guards");
}

static void fq_packet_refusal(HANDLE process, LPVOID address)
{
    struct { ULONG64 before; fq_mapped_packet value; ULONG64 after; } out, original;
    ULONG length = 0x5a5a5a5au;
    memset(&out, 0x5a, sizeof out); out.value.address = (ULONG64)(ULONG_PTR)address; original = out;
    CHECK(NtShzQueryK32(18, process, &out.value, sizeof out.value, &length) == (LONG)0xc0000022u &&
          length == 0x5a5a5a5au && !memcmp(&out, &original, sizeof out),
          "private image snapshot denies insufficient rights before modifying its packet");
}

static void fq_remote_child(void)
{
    static const WCHAR child_name[] = L"T_HELLO.EXE";
    struct { ULONG64 before; WCHAR path[MAX_PATH]; ULONG64 after; } name;
    struct { ULONG64 before; fq_process_basic value; ULONG64 after; } basic;
    struct { ULONG64 before, address, after; } image;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE query = NULL, limited = NULL;
    DWORD n, at, i, original_count = 0, final_count = 0, pw = WAIT_FAILED, tw = WAIT_FAILED, pc = 0, tc = 0;
    ULONG required = 0;
    SIZE_T read = 0;
    LONG status;
    BOOL created, natural;
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &original_count),
          "capture the parent handle count before the remote fixture");
    memset(&name, 0x5a, sizeof name);
    n = GetModuleFileNameW(NULL, name.path, MAX_PATH);
    CHECK(n > 0 && n < MAX_PATH && name.path[n] == 0 &&
          name.before == FQ_SENTINEL && name.after == FQ_SENTINEL,
          "capture the existing sibling directory within guarded bounds");
    if (!n || n >= MAX_PATH || name.path[n] != 0) return;
    at = n;
    while (at && name.path[at - 1] != '\\' && name.path[at - 1] != '/') --at;
    CHECK(at > 0 && at + sizeof child_name / sizeof child_name[0] <= MAX_PATH,
          "the existing child filename including NUL fits the original directory");
    if (!at || at + sizeof child_name / sizeof child_name[0] > MAX_PATH) return;
    for (i = 0; i < sizeof child_name / sizeof child_name[0]; ++i) name.path[at + i] = child_name[i];
    CHECK(name.before == FQ_SENTINEL && name.after == FQ_SENTINEL &&
          name.path[at + sizeof child_name / sizeof child_name[0] - 1] == 0,
          "child-path replacement stays bounded and terminated");
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    created = CreateProcessW(name.path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    CHECK(created, "create the existing natural exit-seven child suspended for a real remote address");
    if (!created) return;
    query = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pi.dwProcessId);
    CHECK(query != NULL, "hold a separate QUERY-only handle to the real child");
    limited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.dwProcessId);
    CHECK(limited != NULL, "hold a separate LIMITED-only handle to the same child");
    if (!query || !limited) goto cleanup;
    /* This pre-existing class only locates the child PEB. Its access policy is
     * outside this slice; the subsequent strict APIs use the separate handles. */
    memset(&basic, 0x5a, sizeof basic);
    status = NtQueryInformationProcess(pi.hProcess, 0, &basic.value, sizeof basic.value, &required);
    CHECK(status == 0 && required == 48 && basic.before == FQ_SENTINEL && basic.after == FQ_SENTINEL &&
          basic.value.pid == pi.dwProcessId && basic.value.peb != 0 &&
          basic.value.peb <= (ULONG64)(ULONG_PTR)-1 - 0x10,
          "the original full handle supplies the real child PEB through the exact 48-byte native query");
    if (status || required != 48 || basic.value.pid != pi.dwProcessId || !basic.value.peb ||
        basic.value.peb > (ULONG64)(ULONG_PTR)-1 - 0x10) goto cleanup;
    memset(&image, 0x5a, sizeof image);
    created = ReadProcessMemory(pi.hProcess, (LPCVOID)(ULONG_PTR)(basic.value.peb + 0x10),
                                &image.address, sizeof image.address, &read);
    CHECK(created && read == 8 && image.address != 0 && image.before == FQ_SENTINEL && image.after == FQ_SENTINEL,
          "actual full-READ PEB readback supplies eight guarded bytes of the child image base");
    if (!created || read != 8 || !image.address) goto cleanup;
    fq_name_success(query, (LPVOID)(ULONG_PTR)image.address, "T_HELLO.EXE", NULL, NULL);
    fq_packet_success(query, (LPVOID)(ULONG_PTR)image.address, pi.dwProcessId, FALSE, "T_HELLO.EXE");
    fq_name_refusal(limited, (LPVOID)(ULONG_PTR)image.address, ERROR_ACCESS_DENIED);
    fq_policy_success(query);
    fq_policy_refusal(limited, ERROR_ACCESS_DENIED);
    created = ResumeThread(pi.hThread) == 1;
    CHECK(created, "resume the suspended mapped-image fixture exactly once");
    if (!created) goto cleanup;
    pw = WaitForSingleObject(pi.hProcess, 5000);
    CHECK(pw == WAIT_OBJECT_0, "the real remote process finishes within its bounded wait");
    tw = WaitForSingleObject(pi.hThread, 5000);
    CHECK(tw == WAIT_OBJECT_0, "the real primary thread also finishes before retained image checks");
    if (pw != WAIT_OBJECT_0 || tw != WAIT_OBJECT_0) goto cleanup;
    created = GetExitCodeProcess(pi.hProcess, &pc) && pc == 7;
    CHECK(created, "the remote process exits naturally with the existing fixture's result seven");
    natural = GetExitCodeThread(pi.hThread, &tc) && tc == 7;
    CHECK(natural, "the retained primary thread independently confirms natural exit seven");
    if (!created || !natural) goto cleanup;
    fq_packet_success(query, (LPVOID)(ULONG_PTR)image.address, pi.dwProcessId, TRUE, NULL);
    fq_name_refusal(query, (LPVOID)(ULONG_PTR)image.address, ERROR_FILE_INVALID);
    fq_policy_success(query);
    fq_policy_refusal(limited, ERROR_ACCESS_DENIED);
    fq_packet_refusal(limited, (LPVOID)(ULONG_PTR)image.address);
cleanup:
    /* Forced cleanup is never credited as a natural exit or a retained query. */
    if (pw != WAIT_OBJECT_0 || tw != WAIT_OBJECT_0) {
        CHECK(TerminateProcess(pi.hProcess, 99), "terminate only a failed remote fixture for cleanup");
        CHECK(WaitForSingleObject(pi.hProcess, 2000) == WAIT_OBJECT_0, "failed remote process cleanup remains bounded");
        CHECK(WaitForSingleObject(pi.hThread, 2000) == WAIT_OBJECT_0, "failed remote primary-thread cleanup remains bounded");
    }
    if (limited) CHECK(CloseHandle(limited), "close the child's independent LIMITED-only handle");
    if (query) CHECK(CloseHandle(query), "close the child's independent QUERY-only handle");
    CHECK(CloseHandle(pi.hThread), "close the original child primary-thread handle");
    CHECK(CloseHandle(pi.hProcess), "close the original child full process handle");
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &final_count) && final_count == original_count,
          "remote fixture cleanup restores the exact parent handle count");
}

static void test_strict_process_queries(void)
{
    static const DWORD rights[5] = {PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
                                    PROCESS_SET_INFORMATION, PROCESS_VM_READ,
                                    PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION};
    HANDLE handles[5] = {NULL, NULL, NULL, NULL, NULL}, closed = NULL;
    LPVOID image;
    fq_name_guard full, name;
    DWORD before = 0, count = 0, n, i;
    BOOL closed_ok;
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &before), "capture the handle count before strict-query checks");
    for (i = 0; i < 5; ++i) {
        handles[i] = OpenProcess(rights[i], FALSE, GetCurrentProcessId());
        CHECK(handles[i] != NULL, "open the exact independent or combined process-query right");
    }
    if (!handles[0] || !handles[1] || !handles[2] || !handles[3] || !handles[4]) goto cleanup;
    CHECK(GetProcessHandleCount(handles[1], &count) && count == before + 5,
          "modern class 3 retains LIMITED-only success and counts the five real handles");
    image = (LPVOID)GetModuleHandleW(NULL);
    CHECK(image != NULL, "obtain the actual current executable image handle");
    if (!image) goto cleanup;
    fq_policy_success(handles[0]); fq_policy_success(handles[4]);
    for (i = 1; i < 4; ++i) {
        fq_policy_refusal(handles[i], ERROR_ACCESS_DENIED);
        fq_name_refusal(handles[i], image, ERROR_ACCESS_DENIED);
        fq_query_gate(handles[i], FALSE);
        fq_packet_refusal(handles[i], image);
    }
    fq_query_gate(handles[0], TRUE); fq_query_gate(handles[4], TRUE);
    fq_packet_success(handles[0], image, GetCurrentProcessId(), FALSE, "T_K32_PROC.EXE");
    n = fq_name_success(handles[0], image, "T_K32_PROC.EXE", NULL, &full);
    fq_name_success(handles[0], (LPVOID)(ULONG_PTR)&test_strict_process_queries,
                    "T_K32_PROC.EXE", n ? full.text : NULL, NULL);
    fq_name_success(handles[4], image, "T_K32_PROC.EXE", n ? full.text : NULL, NULL);
    if (n) fq_name_sizes(handles[0], image, &full, n);
    for (i = 0; i < 4; ++i) {
        HANDLE tagged = (HANDLE)((ULONG_PTR)handles[0] | i);
        fq_policy_success(tagged);
        fq_name_success(tagged, image, "T_K32_PROC.EXE", n ? full.text : NULL, NULL);
    }
    fq_policy_refusal(GetCurrentThread(), ERROR_INVALID_HANDLE);
    fq_name_refusal(GetCurrentThread(), image, ERROR_INVALID_HANDLE);
    fq_policy_refusal((HANDLE)((ULONG_PTR)handles[0] | (1ull << 32)), ERROR_INVALID_HANDLE);
    fq_name_refusal((HANDLE)((ULONG_PTR)handles[0] | (1ull << 32)), image, ERROR_INVALID_HANDLE);
    fq_policy_refusal((HANDLE)(ULONG_PTR)0x7ffc, ERROR_INVALID_HANDLE);
    fq_name_refusal((HANDLE)(ULONG_PTR)0x7ffc, image, ERROR_INVALID_HANDLE);
    closed = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    CHECK(closed != NULL, "open a handle solely for immediate closed-handle refusal");
    if (closed) {
        closed_ok = CloseHandle(closed);
        CHECK(closed_ok, "close the strict-query handle before any handle value can be reused");
        if (closed_ok) {
            fq_policy_refusal(closed, ERROR_INVALID_HANDLE);
            fq_name_refusal(closed, image, ERROR_INVALID_HANDLE);
            closed = NULL;
        }
    }
    fq_policy_bad_inputs(handles[0]);
    memset(&name, 0x5a, sizeof name);
    SetLastError(FQ_POISON_ERROR);
    CHECK(K32GetMappedFileNameW(handles[0], image, name.text, 0) == 0 &&
          GetLastError() == ERROR_INVALID_PARAMETER && fq_name_bounds(&name, 0),
          "zero mapped-name capacity refuses without changing output");
    SetLastError(FQ_POISON_ERROR);
    CHECK(K32GetMappedFileNameW(handles[0], image, NULL, 400) == 0 &&
          GetLastError() == ERROR_INVALID_PARAMETER, "a NULL mapped-name buffer is refused on a valid QUERY handle");
    fq_remote_child();
cleanup:
    if (closed) CHECK(CloseHandle(closed), "close the temporary handle after a failed closed-handle check");
    for (i = 0; i < 5; ++i)
        if (handles[i]) CHECK(CloseHandle(handles[i]), "close each independent strict-query test handle");
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &count) && count == before,
          "all strict-query and remote handles are closed with exact count restoration");
}



/* ---------------------------------------------------------------- held live-memory queries
 * Modern query rights and the existing UP memory subset only. The preceding
 * 620 checks are preserved; physical allocator races remain host controls. */
#define MQ_STATUS_INVALID_HANDLE ((LONG)0xc0000008u)
#define MQ_STATUS_TYPE_MISMATCH ((LONG)0xc0000024u)
#define MQ_STATUS_ACCESS_DENIED ((LONG)0xc0000022u)
#define MQ_STATUS_TERMINATING ((LONG)0xc000010au)
#define MQ_STATUS_SHORT_BUFFER ((LONG)0xc0000023u)
#define MQ_STATUS_BAD_LENGTH ((LONG)0xc0000004u)
#define MQ_LENGTH_POISON 0x5a5a5a5au

typedef struct {
    ULONG64 before;
    union { PROCESS_MEMORY_COUNTERS base; PROCESS_MEMORY_COUNTERS_EX ex; } value;
    BYTE tail[16];
    ULONG64 after;
} mq_counter_guard;
typedef struct { ULONG64 before; APP_MEMORY_INFORMATION value; ULONG64 after; } mq_app_guard;
typedef struct { ULONG64 before, value[5]; BYTE tail[16]; ULONG64 after; } mq_raw_guard;
typedef struct {
    ULONG64 before;
    PSAPI_WORKING_SET_EX_INFORMATION value;
    BYTE tail[16];
    ULONG64 after;
} mq_ws_guard;
typedef struct { ULONG before, value, after; } mq_length_guard;

static BOOL mq_edges(const void *buffer, SIZE_T size, SIZE_T begin, SIZE_T changed)
{
    const BYTE *bytes = buffer;
    SIZE_T i;
    for (i = 0; i < size; ++i)
        if ((i < begin || i >= begin + changed) && bytes[i] != 0x5a) return FALSE;
    return TRUE;
}
static ULONG_PTR mq_page_flags(DWORD protection, BOOL locked)
{
    /* A private resident page has one owner, no sharing or NUMA extension. */
    return 3u | ((ULONG_PTR)protection << 4) | (locked ? (ULONG_PTR)1 << 22 : 0);
}
static BOOL mq_capture_memory(HANDLE process, ULONG64 result[5])
{
    mq_raw_guard out;
    mq_length_guard length;
    LONG status;
    BOOL ok;
    memset(&out, 0x5a, sizeof out);
    memset(&length, 0x5a, sizeof length);
    status = NtShzQueryK32(8, process, out.value, sizeof out.value, &length.value);
    ok = status == 0 && length.value == 40 &&
         mq_edges(&out, sizeof out, sizeof out.before, sizeof out.value) &&
         mq_edges(&length, sizeof length, sizeof length.before, sizeof length.value);
    CHECK(ok, "private memory query returns exactly forty guarded bytes and required length");
    if (ok) memcpy(result, out.value, sizeof out.value);
    return ok;
}
static void mq_memory_success(HANDLE process, ULONG64 minimum_commit)
{
    mq_counter_guard out;
    mq_app_guard app;
    ULONG64 raw[5];
    BOOL ok;
    memset(&out, 0x5a, sizeof out);
    ok = K32GetProcessMemoryInfo(process, &out.value.base, sizeof(PROCESS_MEMORY_COUNTERS));
    CHECK(ok && out.value.base.cb == sizeof(PROCESS_MEMORY_COUNTERS) &&
          out.value.base.PeakWorkingSetSize >= out.value.base.WorkingSetSize &&
          out.value.base.PagefileUsage >= minimum_commit &&
          out.value.base.PeakPagefileUsage >= out.value.base.PagefileUsage,
          "modern memory QUERY or LIMITED returns the guarded base counter subset without VM_READ");
    CHECK(mq_edges(&out, sizeof out, sizeof out.before, sizeof(PROCESS_MEMORY_COUNTERS)),
          "base memory counters preserve the EX portion and every surrounding poisoned byte");
    memset(&out, 0x5a, sizeof out);
    ok = K32GetProcessMemoryInfo(process, &out.value.base, sizeof(PROCESS_MEMORY_COUNTERS_EX));
    CHECK(ok && out.value.ex.cb == sizeof(PROCESS_MEMORY_COUNTERS_EX) &&
          out.value.ex.PrivateUsage == out.value.ex.PagefileUsage &&
          out.value.ex.PagefileUsage >= minimum_commit &&
          out.value.ex.PeakPagefileUsage >= out.value.ex.PagefileUsage &&
          out.value.ex.PeakWorkingSetSize >= out.value.ex.WorkingSetSize,
          "the unchanged EX memory subset reports private commit and valid peak relations");
    CHECK(mq_edges(&out, sizeof out, sizeof out.before, sizeof(PROCESS_MEMORY_COUNTERS_EX)),
          "EX memory counters preserve the oversized tail and poisoned guards");
    memset(&app, 0x5a, sizeof app);
    ok = GetProcessInformation(process, ProcessAppMemoryInfo, &app.value, sizeof app.value);
    CHECK(ok && app.value.PrivateCommitUsage >= minimum_commit &&
          app.value.TotalCommitUsage == app.value.PrivateCommitUsage &&
          app.value.PeakPrivateCommitUsage >= app.value.PrivateCommitUsage,
          "LIMITED-compatible AppMemoryInfo preserves its private-commit reporting subset");
    CHECK(mq_edges(&app, sizeof app, sizeof app.before, sizeof app.value),
          "AppMemoryInfo changes only its exact guarded structure");
    ok = mq_capture_memory(process, raw);
    CHECK(ok && raw[2] >= raw[1] && raw[3] >= minimum_commit && raw[4] >= raw[3],
          "the live private memory snapshot retains its actual counter relations");
    /* AppMemoryInfo queries Q8 and Q7 separately; no joint atomicity is asserted. */
}
static void mq_memory_refusal(HANDLE process, LONG expected_status, DWORD expected_error)
{
    mq_counter_guard out;
    mq_app_guard app;
    mq_raw_guard raw;
    mq_length_guard length;
    memset(&out, 0x5a, sizeof out);
    SetLastError(0x5a5a);
    CHECK(!K32GetProcessMemoryInfo(process, &out.value.base, sizeof(PROCESS_MEMORY_COUNTERS_EX)) &&
          GetLastError() == expected_error && mq_edges(&out, sizeof out, 0, 0),
          "refused memory counters preserve the complete poisoned output and report the handle or right error");
    memset(&app, 0x5a, sizeof app);
    SetLastError(0x5a5a);
    CHECK(!GetProcessInformation(process, ProcessAppMemoryInfo, &app.value, sizeof app.value) &&
          GetLastError() == expected_error && mq_edges(&app, sizeof app, 0, 0),
          "refused AppMemoryInfo preserves its complete guarded output");
    memset(&raw, 0x5a, sizeof raw);
    memset(&length, 0x5a, sizeof length);
    CHECK(NtShzQueryK32(8, process, raw.value, sizeof raw.value, &length.value) == expected_status &&
          mq_edges(&raw, sizeof raw, 0, 0) && mq_edges(&length, sizeof length, 0, 0),
          "private memory refusal preserves both output and optional required length");
}
static void mq_ws_success(HANDLE process, PVOID address, ULONG_PTR flags)
{
    mq_ws_guard out;
    mq_length_guard length;
    BOOL ok;
    memset(&out, 0x5a, sizeof out);
    out.value.VirtualAddress = address;
    ok = K32QueryWorkingSetEx(process, &out.value, sizeof out.value);
    CHECK(ok && out.value.VirtualAddress == address && out.value.VirtualAttributes.Flags == flags &&
          mq_edges(&out, sizeof out, sizeof out.before, sizeof out.value),
          "full QUERY returns the independently expected page state within one guarded entry");
    memset(&out, 0x5a, sizeof out);
    memset(&length, 0x5a, sizeof length);
    out.value.VirtualAddress = address;
    CHECK(NtShzQueryK32(9, process, &out.value, sizeof out.value, &length.value) == 0 &&
          length.value == 16 && out.value.VirtualAddress == address && out.value.VirtualAttributes.Flags == flags &&
          mq_edges(&out, sizeof out, sizeof out.before, sizeof out.value) &&
          mq_edges(&length, sizeof length, sizeof length.before, sizeof length.value),
          "private working-set query preserves the address and writes exactly sixteen bytes plus required length");
}
static void mq_ws_refusal(HANDLE process, PVOID address, LONG expected_status, DWORD expected_error)
{
    mq_ws_guard out, original;
    mq_length_guard length;
    memset(&out, 0x5a, sizeof out);
    out.value.VirtualAddress = address;
    original = out;
    SetLastError(0x5a5a);
    CHECK(!K32QueryWorkingSetEx(process, &out.value, sizeof out.value) &&
          GetLastError() == expected_error && memcmp(&out, &original, sizeof out) == 0,
          "refused working-set query preserves its input address, poisoned attributes and guards");
    memset(&length, 0x5a, sizeof length);
    CHECK(NtShzQueryK32(9, process, &out.value, sizeof out.value, &length.value) == expected_status &&
          memcmp(&out, &original, sizeof out) == 0 && mq_edges(&length, sizeof length, 0, 0),
          "private working-set refusal preserves the whole entry and optional length");
}
static void mq_buffer_checks(HANDLE process, PVOID address)
{
    mq_raw_guard raw;
    mq_counter_guard counter;
    mq_ws_guard ws, original;
    mq_length_guard length;
    const ULONG short_lengths[2] = {0, 39}, bad_lengths[3] = {0, 15, 17};
    unsigned i;
    for (i = 0; i < 2; ++i) {
        memset(&raw, 0x5a, sizeof raw);
        memset(&length, 0x5a, sizeof length);
        CHECK(NtShzQueryK32(8, process, raw.value, short_lengths[i], &length.value) == MQ_STATUS_SHORT_BUFFER &&
              length.value == 40 && mq_edges(&raw, sizeof raw, 0, 0) &&
              mq_edges(&length, sizeof length, sizeof length.before, sizeof length.value),
              "a short private memory buffer receives required forty without an output write");
    }
    memset(&raw, 0x5a, sizeof raw);
    memset(&length, 0x5a, sizeof length);
    CHECK(NtShzQueryK32(8, process, raw.value, sizeof raw.value + sizeof raw.tail, &length.value) == 0 &&
          length.value == 40 && mq_edges(&raw, sizeof raw, sizeof raw.before, sizeof raw.value) &&
          mq_edges(&length, sizeof length, sizeof length.before, sizeof length.value),
          "an oversized private memory buffer keeps its unused tail");
    memset(&counter, 0x5a, sizeof counter);
    SetLastError(0x5a5a);
    CHECK(!K32GetProcessMemoryInfo(process, &counter.value.base, sizeof(PROCESS_MEMORY_COUNTERS) - 1) &&
          GetLastError() == ERROR_INSUFFICIENT_BUFFER && mq_edges(&counter, sizeof counter, 0, 0),
          "the preserved frontend rejects a short base memory buffer without modifying it");
    SetLastError(0x5a5a);
    CHECK(!K32GetProcessMemoryInfo(process, NULL, sizeof(PROCESS_MEMORY_COUNTERS)) &&
          GetLastError() == ERROR_INSUFFICIENT_BUFFER, "the preserved frontend safely rejects NULL memory counters");
    memset(&counter, 0x5a, sizeof counter);
    CHECK(K32GetProcessMemoryInfo(process, &counter.value.base, sizeof counter.value + sizeof counter.tail) &&
          counter.value.ex.cb == sizeof(PROCESS_MEMORY_COUNTERS_EX) &&
          mq_edges(&counter, sizeof counter, sizeof counter.before, sizeof(PROCESS_MEMORY_COUNTERS_EX)),
          "the existing frontend writes only its EX subset even with an oversized public buffer");
    for (i = 0; i < 3; ++i) {
        memset(&ws, 0x5a, sizeof ws);
        memset(&length, 0x5a, sizeof length);
        ws.value.VirtualAddress = address;
        original = ws;
        CHECK(NtShzQueryK32(9, process, &ws.value, bad_lengths[i], &length.value) == MQ_STATUS_BAD_LENGTH &&
              memcmp(&ws, &original, sizeof ws) == 0 && mq_edges(&length, sizeof length, 0, 0),
              "private working-set zero or non-entry lengths refuse without any entry or length write");
    }
    memset(&ws, 0x5a, sizeof ws);
    ws.value.VirtualAddress = address;
    original = ws;
    SetLastError(0x5a5a);
    CHECK(!K32QueryWorkingSetEx(process, &ws.value, 0) && GetLastError() == ERROR_BAD_LENGTH &&
          memcmp(&ws, &original, sizeof ws) == 0, "the unchanged working-set wrapper rejects zero capacity");
    SetLastError(0x5a5a);
    CHECK(!K32QueryWorkingSetEx(process, &ws.value, 15) && GetLastError() == ERROR_BAD_LENGTH &&
          memcmp(&ws, &original, sizeof ws) == 0, "the unchanged working-set wrapper rejects a partial entry");
    SetLastError(0x5a5a);
    CHECK(!K32QueryWorkingSetEx(process, NULL, 16) && GetLastError() == ERROR_BAD_LENGTH,
          "the unchanged working-set wrapper safely rejects NULL entries");
}
static void mq_batch(HANDLE process, BYTE *pages)
{
    struct { ULONG64 before; PSAPI_WORKING_SET_EX_INFORMATION value[4]; BYTE tail[16]; ULONG64 after; } out;
    mq_length_guard length;
    unsigned i, pass;
    BOOL ok;
    const ULONG_PTR expected[4] = {3u | ((ULONG_PTR)PAGE_READONLY << 4),
                                   3u | ((ULONG_PTR)PAGE_READWRITE << 4), 0, 0};
    PVOID addresses[4] = {pages, pages + 4096, pages + 2 * 4096, NULL};
    for (pass = 0; pass < 2; ++pass) {
        memset(&out, 0x5a, sizeof out);
        memset(&length, 0x5a, sizeof length);
        for (i = 0; i < 4; ++i) out.value[i].VirtualAddress = addresses[i];
        ok = pass == 0 ? K32QueryWorkingSetEx(process, out.value, sizeof out.value) :
                        NtShzQueryK32(9, process, out.value, sizeof out.value, &length.value) == 0;
        for (i = 0; i < 4; ++i)
            if (out.value[i].VirtualAddress != addresses[i] || out.value[i].VirtualAttributes.Flags != expected[i]) ok = FALSE;
        CHECK(ok && mq_edges(&out, sizeof out, sizeof out.before, sizeof out.value) &&
              (pass == 0 ? mq_edges(&length, sizeof length, 0, 0) :
               length.value == 64 && mq_edges(&length, sizeof length, sizeof length.before, sizeof length.value)),
              "each complete batch entry reports its independent resident, decommitted or absent page state");
    }
}
static void mq_remote_child(void)
{
    static const WCHAR child_name[] = L"T_HELLO.EXE";
    struct { ULONG64 before; WCHAR path[MAX_PATH]; ULONG64 after; } name;
    struct { ULONG64 before, value, after; } readback;
    struct { ULONG64 before; SIZE_T value; ULONG64 after; } transfer;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE query = NULL, limited = NULL;
    BYTE *remote = NULL, *address = NULL;
    ULONG64 before_memory[5], after_memory[5], pattern = 0x3141592653589793ull;
    DWORD n, at, i, original_count = 0, final_count = 0, old = 0, pc = 0, tc = 0;
    DWORD pw = WAIT_FAILED, tw = WAIT_FAILED;
    BOOL ok;
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &original_count),
          "capture the handle count before the live remote memory fixture");
    memset(&name, 0x5a, sizeof name);
    n = GetModuleFileNameW(NULL, name.path, MAX_PATH);
    CHECK(n > 0 && n < MAX_PATH && name.path[n] == 0 && mq_edges(&name, sizeof name, sizeof name.before, sizeof name.path),
          "obtain the existing sibling directory for the memory child within guarded bounds");
    if (!n || n >= MAX_PATH || name.path[n] != 0) return;
    at = n;
    while (at && name.path[at - 1] != '\\' && name.path[at - 1] != '/') --at;
    CHECK(at && at + sizeof child_name / sizeof child_name[0] <= MAX_PATH,
          "the existing child filename and NUL fit the captured memory-fixture directory");
    if (!at || at + sizeof child_name / sizeof child_name[0] > MAX_PATH) return;
    for (i = 0; i < sizeof child_name / sizeof child_name[0]; ++i) name.path[at + i] = child_name[i];
    CHECK(name.path[at + sizeof child_name / sizeof child_name[0] - 1] == 0 &&
          mq_edges(&name, sizeof name, sizeof name.before, sizeof name.path),
          "memory-fixture child path replacement preserves guards and termination");
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    ok = CreateProcessW(name.path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    CHECK(ok, "create the sole-thread natural exit-seven memory child suspended");
    if (!ok) return;
    query = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pi.dwProcessId);
    CHECK(query != NULL, "hold a separate QUERY-only handle to the live memory child");
    limited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.dwProcessId);
    CHECK(limited != NULL, "hold a separate LIMITED-only handle to the same memory child");
    if (!query || !limited || !mq_capture_memory(query, before_memory)) goto cleanup;
    remote = VirtualAllocEx(pi.hProcess, NULL, 2 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(remote != NULL, "the original full handle allocates two actual remote pages and supplies their real address");
    if (!remote) goto cleanup;
    address = remote;
    ok = mq_capture_memory(query, after_memory);
    CHECK(ok && after_memory[3] == before_memory[3] + 2 * 4096,
          "the suspended child's actual remote allocation increases its private commit by exactly two pages");
    mq_memory_success(query, 2 * 4096);
    mq_memory_success(limited, 2 * 4096);
    mq_ws_success(query, address, 0);
    mq_ws_refusal(limited, address, MQ_STATUS_ACCESS_DENIED, ERROR_ACCESS_DENIED);
    memset(&transfer, 0x5a, sizeof transfer);
    ok = WriteProcessMemory(pi.hProcess, address, &pattern, sizeof pattern, &transfer.value);
    CHECK(ok && transfer.value == 8 && mq_edges(&transfer, sizeof transfer, sizeof transfer.before, sizeof transfer.value),
          "the original full handle touches eight bytes in the real remote allocation");
    if (!ok || transfer.value != 8) goto cleanup;
    memset(&readback, 0x5a, sizeof readback);
    memset(&transfer, 0x5a, sizeof transfer);
    ok = ReadProcessMemory(pi.hProcess, address, &readback.value, sizeof readback.value, &transfer.value);
    CHECK(ok && transfer.value == 8 && readback.value == pattern &&
          mq_edges(&readback, sizeof readback, sizeof readback.before, sizeof readback.value) &&
          mq_edges(&transfer, sizeof transfer, sizeof transfer.before, sizeof transfer.value),
          "full-READ readback verifies the actual remote byte owner and preserves both guards");
    mq_ws_success(query, address, mq_page_flags(PAGE_READWRITE, FALSE));
    ok = VirtualProtectEx(pi.hProcess, address, 4096, PAGE_READONLY, &old);
    CHECK(ok && old == PAGE_READWRITE, "the full mutation handle protects the actual remote page read-only");
    mq_ws_success(query, address, mq_page_flags(PAGE_READONLY, FALSE));
    CHECK(VirtualFreeEx(pi.hProcess, address, 4096, MEM_DECOMMIT),
          "the original full handle decommits the actual touched remote page");
    mq_ws_success(query, address, 0);
    ok = VirtualFreeEx(pi.hProcess, remote, 0, MEM_RELEASE);
    CHECK(ok, "release the real remote reservation before natural child dispatch");
    if (ok) remote = NULL;
    mq_ws_success(query, address, 0);
    ok = ResumeThread(pi.hThread) == 1;
    CHECK(ok, "resume the suspended memory fixture exactly once for natural completion");
    if (!ok) goto cleanup;
    pw = WaitForSingleObject(pi.hProcess, 5000);
    CHECK(pw == WAIT_OBJECT_0, "the remote memory process finishes within its bounded wait");
    tw = WaitForSingleObject(pi.hThread, 5000);
    CHECK(tw == WAIT_OBJECT_0, "the real primary thread finishes before retained memory refusal checks");
    if (pw != WAIT_OBJECT_0 || tw != WAIT_OBJECT_0) goto cleanup;
    ok = GetExitCodeProcess(pi.hProcess, &pc) && pc == 7;
    CHECK(ok, "the memory child process exits naturally with its existing result seven");
    if (!ok) goto cleanup;
    ok = GetExitCodeThread(pi.hThread, &tc) && tc == 7;
    CHECK(ok, "the retained primary thread independently confirms natural memory-child exit seven");
    if (!ok) goto cleanup;
    /* These are chosen live-memory backend refusals, not Windows exit precedence. */
    mq_memory_refusal(query, MQ_STATUS_TERMINATING, ERROR_ACCESS_DENIED);
    mq_memory_refusal(limited, MQ_STATUS_TERMINATING, ERROR_ACCESS_DENIED);
    mq_ws_refusal(query, address, MQ_STATUS_TERMINATING, ERROR_ACCESS_DENIED);
    mq_ws_refusal(limited, address, MQ_STATUS_ACCESS_DENIED, ERROR_ACCESS_DENIED);
cleanup:
    if (remote && pw != WAIT_OBJECT_0)
        CHECK(VirtualFreeEx(pi.hProcess, remote, 0, MEM_RELEASE), "release any failed live memory-child allocation");
    if (pw != WAIT_OBJECT_0 || tw != WAIT_OBJECT_0) {
        CHECK(TerminateProcess(pi.hProcess, 99), "terminate a failed memory child only for separate cleanup");
        CHECK(WaitForSingleObject(pi.hProcess, 2000) == WAIT_OBJECT_0, "failed memory-child process cleanup stays bounded");
        CHECK(WaitForSingleObject(pi.hThread, 2000) == WAIT_OBJECT_0, "failed memory-child primary-thread cleanup stays bounded");
    }
    if (limited) CHECK(CloseHandle(limited), "close the memory child's independent LIMITED handle");
    if (query) CHECK(CloseHandle(query), "close the memory child's independent QUERY handle");
    CHECK(CloseHandle(pi.hThread), "close the original memory-child primary-thread handle");
    CHECK(CloseHandle(pi.hProcess), "close the original full memory-child process handle");
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &final_count) && final_count == original_count,
          "live memory-child cleanup restores the exact original parent handle count");
}
static void test_held_memory_queries(void)
{
    static const DWORD rights[7] = {PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        PROCESS_SET_INFORMATION, PROCESS_VM_READ | PROCESS_SET_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ};
    HANDLE handles[7] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL}, thread = NULL, closed = NULL;
    BYTE *pages = NULL;
    DWORD before = 0, count = 0, old = 0;
    unsigned i, tag;
    BOOL ok, locked = FALSE;
    HANDLE bad[5];
    LONG statuses[5] = {MQ_STATUS_TYPE_MISMATCH, MQ_STATUS_TYPE_MISMATCH,
                       MQ_STATUS_INVALID_HANDLE, MQ_STATUS_INVALID_HANDLE, MQ_STATUS_INVALID_HANDLE};
    CHECK(sizeof(PROCESS_MEMORY_COUNTERS) == 72 && sizeof(PROCESS_MEMORY_COUNTERS_EX) == 80 &&
          sizeof(APP_MEMORY_INFORMATION) == 32 && sizeof(PSAPI_WORKING_SET_EX_INFORMATION) == 16 &&
          sizeof(((mq_raw_guard *)0)->value) == 40,
          "the real Win64 counter, app-memory and entry schemas match the unchanged private widths");
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &before), "capture the handle count before held-memory tests");
    for (i = 0; i < 7; ++i) {
        handles[i] = OpenProcess(rights[i], FALSE, GetCurrentProcessId());
        CHECK(handles[i] != NULL, "open each independently selected memory-query right combination");
        if (!handles[i]) goto cleanup;
    }
    thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, GetCurrentThreadId());
    CHECK(thread != NULL, "open a real thread handle for the memory-query wrong-type control");
    if (!thread) goto cleanup;
    pages = VirtualAlloc(NULL, 4 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(pages != NULL, "allocate four actual private pages for memory-query state checks");
    if (!pages) goto cleanup;
    mq_ws_success(handles[0], pages, 0);
    for (i = 0; i < 7; ++i) {
        if (i == 0 || i == 1 || i == 2 || i == 6) mq_memory_success(handles[i], 4 * 4096);
        else mq_memory_refusal(handles[i], MQ_STATUS_ACCESS_DENIED, ERROR_ACCESS_DENIED);
        if (i == 0 || i == 2) mq_ws_success(handles[i], pages, 0);
        else mq_ws_refusal(handles[i], pages, MQ_STATUS_ACCESS_DENIED, ERROR_ACCESS_DENIED);
    }
    ((volatile BYTE *)pages)[0] = 0x39;
    CHECK(((volatile BYTE *)pages)[0] == 0x39, "actually touch the first private page before its resident query");
    mq_ws_success(handles[0], pages, mq_page_flags(PAGE_READWRITE, FALSE));
    ok = VirtualProtect(pages, 4096, PAGE_READONLY, &old);
    CHECK(ok && old == PAGE_READWRITE, "protect the touched current-process page read-only");
    mq_ws_success(handles[0], pages, mq_page_flags(PAGE_READONLY, FALSE));
    locked = VirtualLock(pages + 4096, 4096);
    CHECK(locked, "VirtualLock actually commits residency and locking of the second private page");
    mq_ws_success(handles[0], pages + 4096, mq_page_flags(PAGE_READWRITE, TRUE));
    ok = VirtualUnlock(pages + 4096, 4096);
    CHECK(ok, "release the actual second-page lock before checking its unlocked state");
    if (ok) locked = FALSE;
    mq_ws_success(handles[0], pages + 4096, mq_page_flags(PAGE_READWRITE, FALSE));
    ((volatile BYTE *)pages)[2 * 4096] = 0x73;
    CHECK(((volatile BYTE *)pages)[2 * 4096] == 0x73, "actually touch a third private page before decommit");
    mq_ws_success(handles[0], pages + 2 * 4096, mq_page_flags(PAGE_READWRITE, FALSE));
    CHECK(VirtualFree(pages + 2 * 4096, 4096, MEM_DECOMMIT), "decommit the real resident third private page");
    mq_ws_success(handles[0], pages + 2 * 4096, 0);
    mq_batch(handles[0], pages);
    mq_buffer_checks(handles[0], pages);
    for (tag = 0; tag < 4; ++tag) {
        HANDLE tagged = (HANDLE)(((ULONG_PTR)handles[0] & ~(ULONG_PTR)3) | tag);
        mq_memory_success(tagged, 3 * 4096);
        mq_ws_success(tagged, pages, mq_page_flags(PAGE_READONLY, FALSE));
    }
    bad[0] = thread; bad[1] = GetCurrentThread(); bad[2] = NULL;
    bad[3] = (HANDLE)((ULONG_PTR)handles[0] | ((ULONG_PTR)1 << 32));
    bad[4] = (HANDLE)(ULONG_PTR)0x7fff1;
    for (i = 0; i < 5; ++i) {
        mq_memory_refusal(bad[i], statuses[i], ERROR_INVALID_HANDLE);
        mq_ws_refusal(bad[i], pages, statuses[i], ERROR_INVALID_HANDLE);
    }
    closed = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    CHECK(closed != NULL, "open one memory-query handle solely for immediate closed-handle refusal");
    if (closed) {
        ok = CloseHandle(closed);
        CHECK(ok, "close the temporary memory-query handle before any handle slot can be reused");
        if (ok) {
            HANDLE stale = closed;
            closed = NULL;
            mq_memory_refusal(stale, MQ_STATUS_INVALID_HANDLE, ERROR_INVALID_HANDLE);
            mq_ws_refusal(stale, pages, MQ_STATUS_INVALID_HANDLE, ERROR_INVALID_HANDLE);
        }
    }
    mq_remote_child();
cleanup:
    if (locked) CHECK(VirtualUnlock(pages + 4096, 4096), "release a remaining page lock after a failed fixture");
    if (pages) CHECK(VirtualFree(pages, 0, MEM_RELEASE), "release the current-process memory fixture reservation");
    if (thread) CHECK(CloseHandle(thread), "close the wrong-type memory-query thread handle");
    if (closed) CHECK(CloseHandle(closed), "close any failed temporary memory-query handle");
    for (i = 0; i < 7; ++i)
        if (handles[i]) CHECK(CloseHandle(handles[i]), "close each independently held memory-query handle");
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &count) && count == before,
          "held-memory tests release every fixture page and restore the exact parent handle count");
}
/* ---------------------------------------------------------------- held settings, modern rights and retained scalar metadata
 * Append-only Kernel64 subset: stored settings have no demonstrated boost,
 * eviction or power-policy effect. The preceding 866 checks remain intact.
 * Query19 is independently full-QUERY; query12 retains boost/group validation.
 * Natural exit and bounded churn do not prove a particular TCB slot was reused;
 * the separate host fixture exercises actual thread_object_detach and reuse. */
/* Normal-success count: 551 added = 409 current/right/buffer/restore checks
 * + 142 natural-child/retained/churn/close checks; total 866 + 551 = 1417.
 * Failure-only forced cleanup is deliberately outside this success count. */
LONG NTAPI NtShzSetK32(ULONG, HANDLE, PVOID, ULONG);
#define QS_DENIED ((LONG)0xc0000022u)
#define QS_INVALID_HANDLE ((LONG)0xc0000008u)
#define QS_TYPE_MISMATCH ((LONG)0xc0000024u)
#define QS_ACCESS_VIOLATION ((LONG)0xc0000005u)
#define QS_INVALID_PARAMETER ((LONG)0xc000000du)
#define QS_SHORT ((LONG)0xc0000023u)
#define QS_PROCESS_EXITED ((LONG)0xc000010au)
#define QS_THREAD_EXITED ((LONG)0xc000004bu)
typedef struct { ULONG64 before; ULONG value[4]; BYTE tail[16]; ULONG64 after; } qs_raw_guard;
typedef struct { ULONG before, value, after; } qs_length_guard;
typedef struct { ULONG64 before; MEMORY_PRIORITY_INFORMATION value; ULONG64 after; } qs_memory_guard;
typedef struct { ULONG64 before; THREAD_PTS value; ULONG64 after; } qs_power_guard;
typedef struct { ULONG64 before; BOOL value; ULONG64 after; } qs_bool_guard;
typedef struct { ULONG64 before; GROUP_AFFINITY value; ULONG64 after; } qs_group_guard;

static DWORD qs_error(LONG status)
{
    return status == QS_DENIED || status == QS_PROCESS_EXITED || status == QS_THREAD_EXITED ?
           ERROR_ACCESS_DENIED : ERROR_INVALID_HANDLE;
}
static void qs_raw_query(ULONG selector, HANDLE h, LONG status, const ULONG *expected, ULONG words)
{
    qs_raw_guard out;
    qs_length_guard length;
    BOOL ok;
    memset(&out, 0x5a, sizeof out); memset(&length, 0x5a, sizeof length);
    ok = NtShzQueryK32(selector, h, out.value, words * 4, &length.value) == status;
    if (!status) ok = ok && length.value == words * 4 && memcmp(out.value, expected, words * 4) == 0 &&
        mq_edges(&out, sizeof out, sizeof out.before, words * 4) &&
        mq_edges(&length, sizeof length, sizeof length.before, sizeof length.value);
    else ok = ok && mq_edges(&out, sizeof out, 0, 0) && mq_edges(&length, sizeof length, 0, 0);
    CHECK(ok, "private settings query uses its literal expected words or preserves both poisoned outputs on refusal");
}
static void qs_process_query(HANDLE h, LONG status, const ULONG expected[3])
{
    qs_memory_guard memory;
    qs_power_guard power;
    BOOL ok;
    qs_raw_query(13, h, status, expected, 3);
    memset(&memory, 0x5a, sizeof memory); SetLastError(0x5a5a);
    ok = GetProcessInformation(h, ProcessMemoryPriority, &memory.value, sizeof memory.value);
    CHECK(status ? !ok && GetLastError() == qs_error(status) && mq_edges(&memory, sizeof memory, 0, 0) :
          ok && memory.value.MemoryPriority == expected[0] &&
          mq_edges(&memory, sizeof memory, sizeof memory.before, sizeof memory.value),
          "process memory getter enforces query rights and writes only its four-byte stored value");
    memset(&power, 0x5a, sizeof power); power.value.Version = 1; SetLastError(0x5a5a);
    ok = GetProcessInformation(h, ProcessPowerThrottling, &power.value, sizeof power.value);
    CHECK(status ? !ok && GetLastError() == qs_error(status) && power.value.Version == 1 &&
          mq_edges(&power, sizeof power, sizeof power.before, 4) :
          ok && power.value.Version == 1 && power.value.ControlMask == expected[1] &&
          power.value.StateMask == expected[2] &&
          mq_edges(&power, sizeof power, sizeof power.before, sizeof power.value),
          "process power getter reports the literal stored pair and preserves rejected output");
}
static void qs_thread_query(HANDLE h, LONG legacy_status, LONG strict_status, const ULONG expected[4])
{
    qs_memory_guard memory;
    qs_power_guard power;
    qs_bool_guard boost;
    qs_group_guard group;
    BOOL ok;
    qs_raw_query(12, h, legacy_status, expected, 4);
    qs_raw_query(19, h, strict_status, expected, 4);
    memset(&boost, 0x5a, sizeof boost); SetLastError(0x5a5a);
    ok = GetThreadPriorityBoost(h, &boost.value);
    CHECK(legacy_status ? !ok && GetLastError() == qs_error(legacy_status) && mq_edges(&boost, sizeof boost, 0, 0) :
          ok && boost.value == (expected[0] != 0) &&
          mq_edges(&boost, sizeof boost, sizeof boost.before, sizeof boost.value),
          "boost getter retains QUERY or LIMITED and its normalized stored boolean");
    memset(&memory, 0x5a, sizeof memory); SetLastError(0x5a5a);
    ok = GetThreadInformation(h, THREAD_MEMORY_PRIORITY_CLASS, &memory.value, sizeof memory.value);
    CHECK(strict_status ? !ok && GetLastError() == qs_error(strict_status) && mq_edges(&memory, sizeof memory, 0, 0) :
          ok && memory.value.MemoryPriority == expected[1] &&
          mq_edges(&memory, sizeof memory, sizeof memory.before, sizeof memory.value),
          "thread memory getter uses direct full-QUERY settings and preserves a denied four-byte output");
    memset(&power, 0x5a, sizeof power); power.value.Version = 1; SetLastError(0x5a5a);
    ok = GetThreadInformation(h, THREAD_POWER_THROTTLING_CLASS, &power.value, sizeof power.value);
    CHECK(strict_status ? !ok && GetLastError() == qs_error(strict_status) && power.value.Version == 1 &&
          mq_edges(&power, sizeof power, sizeof power.before, 4) :
          ok && power.value.Version == 1 && power.value.ControlMask == expected[2] &&
          power.value.StateMask == expected[3] &&
          mq_edges(&power, sizeof power, sizeof power.before, sizeof power.value),
          "the retained local thread-power getter uses strict QUERY with its unchanged twelve-byte schema");
    memset(&group, 0x5a, sizeof group); SetLastError(0x5a5a);
    ok = GetThreadGroupAffinity(h, &group.value);
    CHECK(legacy_status ? !ok && GetLastError() == qs_error(legacy_status) && mq_edges(&group, sizeof group, 0, 0) :
          ok && group.value.Mask == 1 && group.value.Group == 0 && group.value.Reserved[0] == 0 &&
          group.value.Reserved[1] == 0 && group.value.Reserved[2] == 0 &&
          mq_edges(&group, sizeof group, sizeof group.before, sizeof group.value),
          "the indirect legacy settings consumer admits QUERY or LIMITED and reports only the actual CPU0 group");
}
static void qs_set_refusal(HANDLE h, BOOL thread, LONG status)
{
    ULONG value[2] = {3, 1};
    MEMORY_PRIORITY_INFORMATION memory = {3};
    THREAD_PTS power = {1, 1, 1};
    BOOL ok;
    if (thread) {
        CHECK(NtShzSetK32(2, h, value, 4) == status, "raw boost mutation refuses missing rights or departed ownership");
        SetLastError(0x5a5a); ok = SetThreadPriorityBoost(h, TRUE);
        CHECK(!ok && GetLastError() == qs_error(status), "public boost refusal preserves the backend status translation");
    }
    CHECK(NtShzSetK32(thread ? 3 : 9, h, value, 4) == status,
          "raw memory settings mutation refuses the selected handle before changing metadata");
    SetLastError(0x5a5a);
    ok = thread ? SetThreadInformation(h, THREAD_MEMORY_PRIORITY_CLASS, &memory, sizeof memory) :
                  SetProcessInformation(h, ProcessMemoryPriority, &memory, sizeof memory);
    CHECK(!ok && GetLastError() == qs_error(status), "public memory settings mutation translates the selected refusal");
    CHECK(NtShzSetK32(thread ? 8 : 10, h, value, 8) == status,
          "raw power settings mutation refuses the selected handle without storing either word");
    SetLastError(0x5a5a);
    ok = thread ? SetThreadInformation(h, THREAD_POWER_THROTTLING_CLASS, &power, sizeof power) :
                  SetProcessInformation(h, ProcessPowerThrottling, &power, sizeof power);
    CHECK(!ok && GetLastError() == qs_error(status), "public power mutation translates refusal after valid frontend checks");
}
static void qs_denied_widths(HANDLE h, BOOL thread)
{
    const ULONG process_ops[2] = {9, 10}, thread_ops[3] = {2, 3, 8};
    const ULONG *ops = thread ? thread_ops : process_ops;
    ULONG value[3] = {0, 0xabcdef01u, 0x12345678u};
    unsigned i, j;
    for (i = 0; i < (thread ? 3u : 2u); ++i) {
        ULONG width = ops[i] == 8 || ops[i] == 10 ? 8 : 4;
        ULONG lengths[4] = {0, width - 1, width, width + 4};
        for (j = 0; j < 4; ++j)
            CHECK(NtShzSetK32(ops[i], h, value, lengths[j]) == QS_DENIED,
                  "selected setter rights precede zero, short, invalid-value and oversized safe payloads");
    }
}
static void qs_buffers(HANDLE process, HANDLE thread)
{
    const ULONG selectors[3] = {13, 12, 19}, widths[3] = {12, 16, 16};
    qs_raw_guard out;
    qs_length_guard length;
    unsigned i, j;
    for (i = 0; i < 3; ++i) {
        HANDLE h = i == 0 ? process : thread;
        ULONG short_lengths[2] = {0, widths[i] - 1};
        for (j = 0; j < 2; ++j) {
            memset(&out, 0x5a, sizeof out); memset(&length, 0x5a, sizeof length);
            CHECK(NtShzQueryK32(selectors[i], h, out.value, short_lengths[j], &length.value) == QS_SHORT &&
                  length.value == widths[i] && mq_edges(&out, sizeof out, 0, 0) &&
                  mq_edges(&length, sizeof length, sizeof length.before, sizeof length.value),
                  "short settings output receives its exact required width without scalar or guard writes");
        }
        memset(&out, 0x5a, sizeof out); memset(&length, 0x5a, sizeof length);
        CHECK(NtShzQueryK32(selectors[i], h, out.value, sizeof out.value + sizeof out.tail, &length.value) == 0 &&
              length.value == widths[i] && mq_edges(&out, sizeof out, sizeof out.before, widths[i]) &&
              mq_edges(&length, sizeof length, sizeof length.before, sizeof length.value),
              "oversized settings output changes only its twelve or sixteen bytes and required length");
        memset(&out, 0x5a, sizeof out);
        CHECK(NtShzQueryK32(selectors[i], h, out.value, widths[i], NULL) == 0 &&
              mq_edges(&out, sizeof out, sizeof out.before, widths[i]),
              "settings query accepts an absent optional ReturnLength without widening its output");
    }
}
static void qs_public_contracts(HANDLE process, HANDLE thread)
{
    qs_memory_guard memory;
    qs_power_guard power;
    unsigned kind, i;
    const DWORD sizes[2] = {3, 5}, power_sizes[2] = {11, 13};
    for (kind = 0; kind < 2; ++kind) {
        HANDLE h = kind ? thread : process;
        BOOL ok;
        SetLastError(0x5a5a);
        ok = kind ? GetThreadInformation(h, THREAD_MEMORY_PRIORITY_CLASS, NULL, 4) :
                    GetProcessInformation(h, ProcessMemoryPriority, NULL, 4);
        CHECK(!ok && GetLastError() == ERROR_INVALID_PARAMETER, "NULL public memory output retains its parameter refusal");
        SetLastError(0x5a5a);
        ok = kind ? SetThreadInformation(h, THREAD_MEMORY_PRIORITY_CLASS, NULL, 4) :
                    SetProcessInformation(h, ProcessMemoryPriority, NULL, 4);
        CHECK(!ok && GetLastError() == ERROR_INVALID_PARAMETER, "NULL public memory input retains its parameter refusal");
        for (i = 0; i < 2; ++i) {
            memset(&memory, 0x5a, sizeof memory); SetLastError(0x5a5a);
            ok = kind ? GetThreadInformation(h, THREAD_MEMORY_PRIORITY_CLASS, &memory.value, sizes[i]) :
                        GetProcessInformation(h, ProcessMemoryPriority, &memory.value, sizes[i]);
            CHECK(!ok && GetLastError() == ERROR_BAD_LENGTH && mq_edges(&memory, sizeof memory, 0, 0),
                  "public memory getter rejects both sides of exact four bytes without output writes");
            SetLastError(0x5a5a);
            ok = kind ? SetThreadInformation(h, THREAD_MEMORY_PRIORITY_CLASS, &memory.value, sizes[i]) :
                        SetProcessInformation(h, ProcessMemoryPriority, &memory.value, sizes[i]);
            CHECK(!ok && GetLastError() == ERROR_BAD_LENGTH && mq_edges(&memory, sizeof memory, 0, 0),
                  "public memory setter preserves its exact-size validation before kernel rights");
        }
        for (i = 0; i < 2; ++i) {
            memory.value.MemoryPriority = i ? 6 : 0; SetLastError(0x5a5a);
            ok = kind ? SetThreadInformation(h, THREAD_MEMORY_PRIORITY_CLASS, &memory.value, 4) :
                        SetProcessInformation(h, ProcessMemoryPriority, &memory.value, 4);
            CHECK(!ok && GetLastError() == ERROR_INVALID_PARAMETER,
                  "admitted SET memory priority refuses zero and six rather than storing an invented value");
        }
        SetLastError(0x5a5a);
        ok = kind ? GetThreadInformation(h, THREAD_POWER_THROTTLING_CLASS, NULL, 12) :
                    GetProcessInformation(h, ProcessPowerThrottling, NULL, 12);
        CHECK(!ok && GetLastError() == ERROR_INVALID_PARAMETER, "NULL public power output retains parameter precedence");
        SetLastError(0x5a5a);
        ok = kind ? SetThreadInformation(h, THREAD_POWER_THROTTLING_CLASS, NULL, 12) :
                    SetProcessInformation(h, ProcessPowerThrottling, NULL, 12);
        CHECK(!ok && GetLastError() == ERROR_INVALID_PARAMETER, "NULL public power input retains parameter precedence");
        for (i = 0; i < 2; ++i) {
            memset(&power, 0x5a, sizeof power); power.value.Version = 1; SetLastError(0x5a5a);
            ok = kind ? GetThreadInformation(h, THREAD_POWER_THROTTLING_CLASS, &power.value, power_sizes[i]) :
                        GetProcessInformation(h, ProcessPowerThrottling, &power.value, power_sizes[i]);
            CHECK(!ok && GetLastError() == ERROR_BAD_LENGTH && power.value.Version == 1 &&
                  mq_edges(&power, sizeof power, sizeof power.before, 4),
                  "public power getter rejects short and long twelve-byte layouts without output changes");
            SetLastError(0x5a5a);
            ok = kind ? SetThreadInformation(h, THREAD_POWER_THROTTLING_CLASS, &power.value, power_sizes[i]) :
                        SetProcessInformation(h, ProcessPowerThrottling, &power.value, power_sizes[i]);
            CHECK(!ok && GetLastError() == ERROR_BAD_LENGTH,
                  "public power setter checks its exact twelve-byte layout before backend rights");
            memset(&power, 0x5a, sizeof power); power.value.Version = i ? 2 : 0; SetLastError(0x5a5a);
            ok = kind ? GetThreadInformation(h, THREAD_POWER_THROTTLING_CLASS, &power.value, 12) :
                        GetProcessInformation(h, ProcessPowerThrottling, &power.value, 12);
            CHECK(!ok && GetLastError() == ERROR_INVALID_PARAMETER && power.value.Version == (i ? 2u : 0u) &&
                  mq_edges(&power, sizeof power, sizeof power.before, 4),
                  "public power getter rejects a non-one version without replacing its poisoned masks");
            SetLastError(0x5a5a);
            ok = kind ? SetThreadInformation(h, THREAD_POWER_THROTTLING_CLASS, &power.value, 12) :
                        SetProcessInformation(h, ProcessPowerThrottling, &power.value, 12);
            CHECK(!ok && GetLastError() == ERROR_INVALID_PARAMETER, "public power setter preserves non-one version refusal");
        }
        for (i = 0; i < 2; ++i) {
            power.value.Version = 1;
            power.value.ControlMask = i ? 0 : (kind ? 2 : 8);
            power.value.StateMask = i ? 1 : 0; SetLastError(0x5a5a);
            ok = kind ? SetThreadInformation(h, THREAD_POWER_THROTTLING_CLASS, &power.value, 12) :
                        SetProcessInformation(h, ProcessPowerThrottling, &power.value, 12);
            CHECK(!ok && GetLastError() == ERROR_INVALID_PARAMETER,
                  "public power stores refuse unknown control bits and state bits outside control");
        }
    }
    SetLastError(0x5a5a);
    CHECK(!GetThreadPriorityBoost(thread, NULL) && GetLastError() == ERROR_INVALID_PARAMETER,
          "boost getter retains safe NULL output validation");
    SetLastError(0x5a5a);
    CHECK(!GetThreadGroupAffinity(thread, NULL) && GetLastError() == ERROR_INVALID_PARAMETER,
          "indirect group-affinity consumer retains safe NULL validation");
    SetLastError(0x5a5a);
    CHECK(!Wow64GetThreadContext(thread, NULL) && GetLastError() == ERROR_NOACCESS,
          "unsupported WOW64 context wrapper retains its safe NULL refusal");
    memset(&memory, 0x5a, sizeof memory); SetLastError(0x5a5a);
    CHECK(!GetThreadInformation(thread, 1, &memory.value, 4) && GetLastError() == ERROR_INVALID_PARAMETER &&
          mq_edges(&memory, sizeof memory, 0, 0), "absolute-CPU settings getter remains unsupported");
    SetLastError(0x5a5a);
    CHECK(!SetThreadInformation(thread, 2, &memory.value, 4) && GetLastError() == ERROR_NOT_SUPPORTED,
          "dynamic-code thread settings remain explicitly unsupported");
}
static void qs_store_literals(HANDLE process, HANDLE thread)
{
    MEMORY_PRIORITY_INFORMATION memory = {2};
    THREAD_PTS power = {1, 5, 1};
    CHECK(SetProcessInformation(process, ProcessMemoryPriority, &memory, 4), "SET-only process handle stores literal priority two");
    CHECK(SetProcessInformation(process, ProcessPowerThrottling, &power, 12), "SET-only process handle stores literal power five/one");
    CHECK(SetThreadPriorityBoost(thread, TRUE), "full SET thread handle stores disabled boost without QUERY");
    memory.MemoryPriority = 3;
    CHECK(SetThreadInformation(thread, THREAD_MEMORY_PRIORITY_CLASS, &memory, 4), "SET-only thread handle stores literal priority three");
    power.ControlMask = power.StateMask = 1;
    CHECK(SetThreadInformation(thread, THREAD_POWER_THROTTLING_CLASS, &power, 12), "SET-only thread handle stores literal power one/one");
}
static void qs_raw_widths(HANDLE process, HANDLE thread, HANDLE process_query, HANDLE thread_query)
{
    const ULONG ops[5] = {9, 10, 2, 3, 8};
    const ULONG widths[5] = {4, 8, 4, 4, 8};
    const ULONG wild_process[3] = {2, 0x80000005u, 0xdeadbeefu};
    const ULONG wild_thread[4] = {1, 3, 0x80000001u, 0x76543210u};
    ULONG value[3];
    unsigned i, j;
    for (i = 0; i < 5; ++i) {
        HANDLE h = i < 2 ? process : thread;
        value[0] = ops[i] == 9 ? 2 : ops[i] == 3 ? 3 : ops[i] == 10 ? 5 : 1;
        value[1] = 1; value[2] = 0x13572468u;
        for (j = 0; j < 2; ++j)
            CHECK(NtShzSetK32(ops[i], h, value, j ? widths[i] - 1 : 0) == QS_ACCESS_VIOLATION,
                  "admitted private setter retains zero and short payload ACCESS_VIOLATION");
        CHECK(NtShzSetK32(ops[i], h, value, widths[i] + 4) == 0,
              "oversized private setter consumes only its existing four or eight bytes");
    }
    for (i = 0; i < 2; ++i) {
        value[0] = i ? 6 : 0;
        CHECK(NtShzSetK32(9, process, value, 4) == QS_INVALID_PARAMETER, "raw process memory priority rejects zero and six");
        CHECK(NtShzSetK32(3, thread, value, 4) == QS_INVALID_PARAMETER, "raw thread memory priority rejects zero and six");
    }
    value[0] = 7;
    CHECK(NtShzSetK32(2, thread, value, 4) == 0, "raw nonzero boost value normalizes to the stored boolean");
    CHECK(NtShzSetK32(10, process, (PVOID)(wild_process + 1), 8) == 0,
          "raw process power keeps its existing unvalidated two-word metadata contract");
    CHECK(NtShzSetK32(8, thread, (PVOID)(wild_thread + 2), 8) == 0,
          "raw thread power keeps its existing unvalidated two-word metadata contract");
    qs_process_query(process_query, 0, wild_process);
    qs_thread_query(thread_query, 0, 0, wild_thread);
    qs_store_literals(process, thread);
}
static void qs_wow64_consumer(HANDLE thread, DWORD error)
{
    struct { ULONG64 before; WOW64_CONTEXT value; ULONG64 after; } out;
    memset(&out, 0x5a, sizeof out); SetLastError(0x5a5a);
    CHECK(!Wow64GetThreadContext(thread, &out.value) && GetLastError() == error && mq_edges(&out, sizeof out, 0, 0),
          "WOW64 indirect settings validation is rights-aware but still supplies no native x86 context");
}
static void qs_natural_child(void)
{
    static const WCHAR child_name[] = L"T_HELLO.EXE";
    const ULONG expected_process[3] = {3, 4, 4}, expected_thread[4] = {1, 1, 1, 0};
    const DWORD process_rights[3] = {PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION};
    const DWORD thread_rights[4] = {THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
                                 THREAD_SET_INFORMATION, THREAD_SET_LIMITED_INFORMATION};
    struct { ULONG64 before; WCHAR value[MAX_PATH]; ULONG64 after; } path;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE process[3] = {NULL, NULL, NULL}, thread[4] = {NULL, NULL, NULL, NULL};
    MEMORY_PRIORITY_INFORMATION memory = {3};
    THREAD_PTS power = {1, 4, 4};
    ULONG boost = 1;
    DWORD count = 0, after = 0, n, at, pc = 0, tc = 0, pw = WAIT_FAILED, tw = WAIT_FAILED;
    unsigned i;
    BOOL ok;
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &count), "capture the exact parent handle count before retained settings");
    memset(&path, 0x5a, sizeof path); n = GetModuleFileNameW(NULL, path.value, MAX_PATH);
    CHECK(n && n < MAX_PATH && path.value[n] == 0 && mq_edges(&path, sizeof path, sizeof path.before, sizeof path.value),
          "capture the existing fixture directory with bounded guarded path storage");
    if (!n || n >= MAX_PATH || path.value[n] != 0) return;
    at = n; while (at && path.value[at - 1] != '\\' && path.value[at - 1] != '/') --at;
    CHECK(at && at + sizeof child_name / sizeof child_name[0] <= MAX_PATH, "natural settings child name and NUL fit MAX_PATH");
    if (!at || at + sizeof child_name / sizeof child_name[0] > MAX_PATH) return;
    for (i = 0; i < sizeof child_name / sizeof child_name[0]; ++i) path.value[at + i] = child_name[i];
    CHECK(path.value[at + sizeof child_name / sizeof child_name[0] - 1] == 0 &&
          mq_edges(&path, sizeof path, sizeof path.before, sizeof path.value), "child path replacement preserves both guards");
    memset(&si, 0, sizeof si); si.cb = sizeof si; memset(&pi, 0, sizeof pi);
    ok = CreateProcessW(path.value, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    CHECK(ok, "create only the existing natural exit-seven fixture suspended for real settings mutation");
    if (!ok) return;
    for (i = 0; i < 3; ++i) {
        process[i] = OpenProcess(process_rights[i], FALSE, pi.dwProcessId);
        CHECK(process[i] != NULL, "hold each distinct settings right on the real child process");
        if (!process[i]) goto cleanup;
    }
    for (i = 0; i < 4; ++i) {
        thread[i] = OpenThread(thread_rights[i], FALSE, pi.dwThreadId);
        CHECK(thread[i] != NULL, "hold each distinct settings right on the child's actual primary thread");
        if (!thread[i]) goto cleanup;
    }
    CHECK(SetProcessInformation(process[2], ProcessMemoryPriority, &memory, 4), "store nondefault child process priority three");
    CHECK(SetProcessInformation(process[2], ProcessPowerThrottling, &power, 12), "store nondefault child process power four/four");
    CHECK(SetThreadPriorityBoost(thread[3], TRUE), "SET_LIMITED alone stores nondefault child boost disable");
    memory.MemoryPriority = 1;
    CHECK(SetThreadInformation(thread[2], THREAD_MEMORY_PRIORITY_CLASS, &memory, 4), "store distinct child thread memory priority one");
    power.ControlMask = 1; power.StateMask = 0;
    CHECK(SetThreadInformation(thread[2], THREAD_POWER_THROTTLING_CLASS, &power, 12), "store distinct child thread power one/zero");
    qs_process_query(process[0], 0, expected_process); qs_process_query(process[1], 0, expected_process);
    qs_thread_query(thread[0], 0, 0, expected_thread); qs_thread_query(thread[1], 0, QS_DENIED, expected_thread);
    qs_process_query(process[2], QS_DENIED, expected_process);
    qs_thread_query(thread[2], QS_DENIED, QS_DENIED, expected_thread);
    qs_thread_query(thread[3], QS_DENIED, QS_DENIED, expected_thread);
    ok = ResumeThread(pi.hThread) == 1;
    CHECK(ok, "resume the settings fixture exactly once for its natural existing exit");
    if (!ok) goto cleanup;
    pw = WaitForSingleObject(pi.hProcess, 5000); CHECK(pw == WAIT_OBJECT_0, "natural settings child process finishes within five seconds");
    tw = WaitForSingleObject(pi.hThread, 5000); CHECK(tw == WAIT_OBJECT_0, "natural settings primary thread finishes before retained assertions");
    if (pw != WAIT_OBJECT_0 || tw != WAIT_OBJECT_0) goto cleanup;
    ok = GetExitCodeProcess(pi.hProcess, &pc) && pc == 7;
    CHECK(ok, "the retained process confirms natural exit seven rather than forced cleanup");
    if (!ok) goto cleanup;
    ok = GetExitCodeThread(pi.hThread, &tc) && tc == 7;
    CHECK(ok, "the independently retained primary thread confirms the same natural exit seven");
    if (!ok) goto cleanup;
    qs_process_query(process[0], 0, expected_process); qs_process_query(process[1], 0, expected_process);
    qs_thread_query(thread[0], 0, 0, expected_thread); qs_thread_query(thread[1], 0, QS_DENIED, expected_thread);
    qs_set_refusal(process[2], FALSE, QS_PROCESS_EXITED);
    qs_set_refusal(thread[2], TRUE, QS_THREAD_EXITED);
    CHECK(NtShzSetK32(2, thread[3], &boost, 4) == QS_THREAD_EXITED,
          "SET_LIMITED boost refuses the naturally departed real thread");
    SetLastError(0x5a5a);
    CHECK(!SetThreadPriorityBoost(thread[3], TRUE) && GetLastError() == ERROR_ACCESS_DENIED,
          "public retained SET_LIMITED boost translates THREAD_IS_TERMINATING");
    qs_set_refusal(process[0], FALSE, QS_DENIED); qs_set_refusal(thread[0], TRUE, QS_DENIED);
    for (i = 0; i < 4; ++i) {
        HANDLE churn = CreateThread(NULL, 0, quick_thread, NULL, 0, NULL);
        DWORD wait = WAIT_FAILED, code = 0;
        CHECK(churn != NULL, "create one of exactly four bounded post-exit churn threads");
        if (!churn) continue;
        wait = WaitForSingleObject(churn, 5000);
        CHECK(wait == WAIT_OBJECT_0, "each churn thread completes within its checked bounded wait");
        CHECK(wait == WAIT_OBJECT_0 && GetExitCodeThread(churn, &code) && code == 7,
              "each churn control has its own natural exit seven, without claiming a specific slot reuse");
        if (wait != WAIT_OBJECT_0) {
            CHECK(TerminateThread(churn, 99), "failed churn termination is separate cleanup with no natural-success credit");
            CHECK(WaitForSingleObject(churn, 2000) == WAIT_OBJECT_0, "failed churn cleanup has its own bounded wait");
        }
        CHECK(CloseHandle(churn), "close each completed or separately cleaned churn handle");
    }
    qs_thread_query(thread[0], 0, 0, expected_thread); qs_thread_query(thread[1], 0, QS_DENIED, expected_thread);
    qs_set_refusal(thread[2], TRUE, QS_THREAD_EXITED);
    qs_process_query(process[0], 0, expected_process);
cleanup:
    if (pw != WAIT_OBJECT_0 || tw != WAIT_OBJECT_0) {
        CHECK(TerminateProcess(pi.hProcess, 99), "failed settings child termination is separate cleanup only");
        CHECK(WaitForSingleObject(pi.hProcess, 2000) == WAIT_OBJECT_0, "failed settings process cleanup has a checked bounded wait");
        CHECK(WaitForSingleObject(pi.hThread, 2000) == WAIT_OBJECT_0, "failed settings primary-thread cleanup has a checked bounded wait");
    }
    for (i = 0; i < 4; ++i) if (thread[i]) CHECK(CloseHandle(thread[i]), "close every independent retained settings thread handle");
    for (i = 0; i < 3; ++i) if (process[i]) CHECK(CloseHandle(process[i]), "close every independent retained settings process handle");
    CHECK(CloseHandle(pi.hThread), "close the original natural settings primary-thread handle");
    CHECK(CloseHandle(pi.hProcess), "close the original natural settings process handle");
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &after) && after == count,
          "retained settings and four bounded churn controls restore the exact parent handle count");
}
static void test_held_settings(void)
{
    const DWORD process_rights[4] = {PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SET_INFORMATION, PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION};
    const DWORD thread_rights[5] = {THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
        THREAD_SET_INFORMATION, THREAD_SET_LIMITED_INFORMATION, THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION};
    const ULONG expected_process[3] = {2, 5, 1}, expected_thread[4] = {1, 3, 1, 1};
    HANDLE process[4] = {NULL, NULL, NULL, NULL}, thread[5] = {NULL, NULL, NULL, NULL, NULL};
    HANDLE closed_process = NULL, closed_thread = NULL, bad_process[5], bad_thread[5];
    ULONG saved_process[3] = {0}, saved_thread[4] = {0}, restored_process[3], restored_thread[4], length = 0, value[2] = {3, 1};
    LONG status, bad_status[5] = {QS_TYPE_MISMATCH, QS_TYPE_MISMATCH, QS_INVALID_HANDLE, QS_INVALID_HANDLE, QS_INVALID_HANDLE};
    MEMORY_PRIORITY_INFORMATION memory = {3};
    THREAD_PTS power = {1, 1, 1};
    DWORD before = 0, after = 0;
    unsigned i, tag;
    BOOL saved = FALSE, ok;
    CHECK(sizeof(MEMORY_PRIORITY_INFORMATION) == 4 && sizeof(THREAD_PTS) == 12 &&
          sizeof(PROCESS_POWER_THROTTLING_STATE) == 12 && sizeof(ULONG) == 4 &&
          THREAD_SET_LIMITED_INFORMATION == 0x400 && THREAD_QUERY_LIMITED_INFORMATION == 0x800,
          "actual public settings schemas and independent literal LIMITED rights match the selected ABI");
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &before), "capture the parent handle count before held settings");
    status = NtShzQueryK32(13, GetCurrentProcess(), saved_process, sizeof saved_process, &length);
    CHECK(status == 0 && length == 12, "capture original process settings solely for restoration on every changed-current path");
    if (status || length != 12) goto cleanup;
    length = 0; status = NtShzQueryK32(12, GetCurrentThread(), saved_thread, sizeof saved_thread, &length);
    CHECK(status == 0 && length == 16, "capture original thread settings solely for restoration without using them as a test oracle");
    if (status || length != 16) goto cleanup;
    saved = TRUE;
    for (i = 0; i < 4; ++i) {
        process[i] = OpenProcess(process_rights[i], FALSE, GetCurrentProcessId());
        CHECK(process[i] != NULL, "open independent process QUERY, LIMITED, SET and combined-query settings handles");
        if (!process[i]) goto cleanup;
    }
    for (i = 0; i < 5; ++i) {
        thread[i] = OpenThread(thread_rights[i], FALSE, GetCurrentThreadId());
        CHECK(thread[i] != NULL, "open independent thread QUERY, LIMITED, SET, SET_LIMITED and combined-query handles");
        if (!thread[i]) goto cleanup;
    }
    qs_store_literals(process[2], thread[2]);
    for (i = 0; i < 4; ++i) qs_process_query(process[i], i == 2 ? QS_DENIED : 0, expected_process);
    for (i = 0; i < 5; ++i)
        qs_thread_query(thread[i], i == 2 || i == 3 ? QS_DENIED : 0,
                        i == 0 || i == 4 ? 0 : QS_DENIED, expected_thread);
    for (i = 0; i < 4; ++i) if (i != 2) qs_set_refusal(process[i], FALSE, QS_DENIED);
    for (i = 0; i < 5; ++i) if (i != 2 && i != 3) qs_set_refusal(thread[i], TRUE, QS_DENIED);
    qs_denied_widths(process[0], FALSE); qs_denied_widths(thread[0], TRUE);
    CHECK(SetThreadPriorityBoost(thread[3], TRUE), "SET_LIMITED-only boost mutation succeeds without SET or QUERY");
    CHECK(NtShzSetK32(3, thread[3], value, 4) == QS_DENIED, "SET_LIMITED does not authorize raw thread memory mutation");
    SetLastError(0x5a5a);
    CHECK(!SetThreadInformation(thread[3], THREAD_MEMORY_PRIORITY_CLASS, &memory, 4) && GetLastError() == ERROR_ACCESS_DENIED,
          "SET_LIMITED does not authorize public thread memory mutation");
    CHECK(NtShzSetK32(8, thread[3], value, 8) == QS_DENIED, "SET_LIMITED does not authorize raw thread power mutation");
    SetLastError(0x5a5a);
    CHECK(!SetThreadInformation(thread[3], THREAD_POWER_THROTTLING_CLASS, &power, 12) && GetLastError() == ERROR_ACCESS_DENIED,
          "SET_LIMITED does not authorize public thread power mutation");
    qs_process_query(process[0], 0, expected_process); qs_thread_query(thread[0], 0, 0, expected_thread);
    qs_buffers(process[0], thread[0]); qs_public_contracts(process[2], thread[2]);
    qs_raw_widths(process[2], thread[2], process[0], thread[0]);
    qs_process_query(GetCurrentProcess(), 0, expected_process); qs_thread_query(GetCurrentThread(), 0, 0, expected_thread);
    qs_wow64_consumer(thread[0], ERROR_INVALID_PARAMETER);
    qs_wow64_consumer(thread[1], ERROR_INVALID_PARAMETER);
    qs_wow64_consumer(thread[2], ERROR_ACCESS_DENIED);
    for (tag = 0; tag < 4; ++tag) {
        qs_process_query((HANDLE)(((ULONG_PTR)process[0] & ~(ULONG_PTR)3) | tag), 0, expected_process);
        qs_thread_query((HANDLE)(((ULONG_PTR)thread[0] & ~(ULONG_PTR)3) | tag), 0, 0, expected_thread);
    }
    bad_process[0] = thread[0]; bad_process[1] = GetCurrentThread(); bad_process[2] = NULL;
    bad_process[3] = (HANDLE)((ULONG_PTR)process[0] | ((ULONG_PTR)1 << 32)); bad_process[4] = (HANDLE)(ULONG_PTR)0x7fff1;
    bad_thread[0] = process[0]; bad_thread[1] = GetCurrentProcess(); bad_thread[2] = NULL;
    bad_thread[3] = (HANDLE)((ULONG_PTR)thread[0] | ((ULONG_PTR)1 << 32)); bad_thread[4] = (HANDLE)(ULONG_PTR)0x7fff1;
    for (i = 0; i < 5; ++i) {
        qs_process_query(bad_process[i], bad_status[i], expected_process);
        qs_thread_query(bad_thread[i], bad_status[i], bad_status[i], expected_thread);
        qs_set_refusal(bad_process[i], FALSE, bad_status[i]); qs_set_refusal(bad_thread[i], TRUE, bad_status[i]);
    }
    closed_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, GetCurrentProcessId());
    CHECK(closed_process != NULL, "open a process settings handle solely for immediate close refusal");
    if (closed_process) {
        HANDLE old = closed_process;
        ok = CloseHandle(closed_process); CHECK(ok, "close the process settings handle before any slot republication");
        if (ok) { closed_process = NULL; qs_process_query(old, QS_INVALID_HANDLE, expected_process); qs_set_refusal(old, FALSE, QS_INVALID_HANDLE); }
    }
    closed_thread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, FALSE, GetCurrentThreadId());
    CHECK(closed_thread != NULL, "open a thread settings handle solely for immediate close refusal");
    if (closed_thread) {
        HANDLE old = closed_thread;
        ok = CloseHandle(closed_thread); CHECK(ok, "close the thread settings handle before any slot republication");
        if (ok) { closed_thread = NULL; qs_thread_query(old, QS_INVALID_HANDLE, QS_INVALID_HANDLE, expected_thread); qs_set_refusal(old, TRUE, QS_INVALID_HANDLE); }
    }
    qs_process_query(process[0], 0, expected_process); qs_thread_query(thread[0], 0, 0, expected_thread);
    qs_natural_child();
cleanup:
    if (saved) {
        CHECK(NtShzSetK32(9, GetCurrentProcess(), saved_process, 4) == 0, "restore original current process memory metadata");
        CHECK(NtShzSetK32(10, GetCurrentProcess(), saved_process + 1, 8) == 0, "restore original current process power words exactly");
        CHECK(NtShzSetK32(2, GetCurrentThread(), saved_thread, 4) == 0, "restore original current thread boost boolean");
        CHECK(NtShzSetK32(3, GetCurrentThread(), saved_thread + 1, 4) == 0, "restore original current thread memory metadata");
        CHECK(NtShzSetK32(8, GetCurrentThread(), saved_thread + 2, 8) == 0, "restore original current thread power words exactly");
        CHECK(NtShzQueryK32(13, GetCurrentProcess(), restored_process, sizeof restored_process, NULL) == 0 &&
              memcmp(restored_process, saved_process, sizeof saved_process) == 0, "verify exact restoration of all original process settings");
        CHECK(NtShzQueryK32(12, GetCurrentThread(), restored_thread, sizeof restored_thread, NULL) == 0 &&
              memcmp(restored_thread, saved_thread, sizeof saved_thread) == 0, "verify exact restoration of all original thread settings");
    }
    if (closed_thread) CHECK(CloseHandle(closed_thread), "close a failed temporary thread settings handle");
    if (closed_process) CHECK(CloseHandle(closed_process), "close a failed temporary process settings handle");
    for (i = 0; i < 5; ++i) if (thread[i]) CHECK(CloseHandle(thread[i]), "close every independently selected thread settings handle");
    for (i = 0; i < 4; ++i) if (process[i]) CHECK(CloseHandle(process[i]), "close every independently selected process settings handle");
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &after) && after == before,
          "settings tests restore current metadata and the exact original parent handle count");
}
int main(void)
{
    test_restart();
    test_description();
    test_times();
    test_counts_priority();
    test_mitigation();
    test_debugbreak();
    test_names_toolhelp();
    test_memory_info();
    test_residency();
    test_context();
    test_initonce();
    test_packages_wer();
    test_heaps();
    test_query_rights_and_retained_times();
    test_strict_process_queries();
    test_held_memory_queries();
    test_held_settings();
    return k32t_finish("t_k32_proc");
}
