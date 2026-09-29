/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 process / thread / memory information: CPU times and cycles, thread reclamation, priority and information classes,
 * mitigation policies, toolhelp, PSAPI (image names, mapped files, memory counters, working set), VirtualLock / Discard / Prefetch,
 * thread contexts, DebugBreak, InitOnce, heaps. Expectations are the documented Win32 semantics or relations between independent
 * measurements (e.g. a page this program touched must be in its working set), never values read back from the implementation.
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
    CHECK(!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_END), "PROCESS_MODE_BACKGROUND_END outside background mode fails");
    CHECK_ERR(ERROR_PROCESS_MODE_NOT_BACKGROUND, "... with ERROR_PROCESS_MODE_NOT_BACKGROUND");
    CHECK(SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN), "PROCESS_MODE_BACKGROUND_BEGIN");
    SetLastError(0);
    CHECK(!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN), "a second BEGIN fails");
    CHECK_ERR(ERROR_PROCESS_MODE_ALREADY_BACKGROUND, "... with ERROR_PROCESS_MODE_ALREADY_BACKGROUND");
    CHECK(GetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &mp, sizeof mp) && mp.MemoryPriority == MEMORY_PRIORITY_VERY_LOW,
          "background mode runs at very low memory priority");
    CHECK(SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_END), "PROCESS_MODE_BACKGROUND_END");
    CHECK(GetPriorityClass(GetCurrentProcess()) == NORMAL_PRIORITY_CLASS, "background mode leaves the priority class alone");

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
    CHECK(HeapSetInformation(0, (HEAP_INFORMATION_CLASS)3, &opt, sizeof opt), "HeapOptimizeResources {1, 0}");
    opt.version = 2;
    SetLastError(0);
    CHECK(!HeapSetInformation(0, (HEAP_INFORMATION_CLASS)3, &opt, sizeof opt) && GetLastError() == ERROR_INVALID_PARAMETER, "HeapOptimizeResources version 2 is invalid");
    HeapDestroy(h3);
    /* last: from here on a corrupt heap operation would end this process */
    CHECK(HeapSetInformation(0, HeapEnableTerminationOnCorruption, 0, 0), "HeapEnableTerminationOnCorruption");
}

int main(void)
{
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
    return k32t_finish("t_k32_proc");
}
