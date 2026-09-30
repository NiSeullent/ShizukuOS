/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: process and thread information over the Kernel64 accounting calls (NtShzQueryK32 / NtShzSetK32,
 * kernel64/sysk32_proc.c): CPU times and cycles, handle counts, priority class and boost settings, process / thread
 * information classes, mitigation policies, toolhelp snapshots, PSAPI memory and mapped-file queries, thread contexts,
 * sessions, packages and WER registration.
 *
 * What the numbers mean here (all measured, none invented):
 *  - Times: 1 ms scheduler ticks charged to the interrupted thread (user or kernel mode), cycles: TSC while the thread ran.
 *  - Priority class, priority boost, memory priority and power throttling are stored per process / thread and reported
 *    back; the round-robin scheduler of Kernel64 does not act on any of them (there is nothing to boost or throttle).
 *  - Mitigation policies: DEP is reported on (Kernel64 maps data pages non-executable for every process and it cannot be
 *    turned off); nothing else is enforced, so every other policy reads all-zero and asking to enable one fails with
 *    ERROR_NOT_SUPPORTED.
 *  - There is one session. Its id is the one in the PEB (SessionId), for every process.
 *  - There are no packaged (AppX) applications and no Windows Error Reporting service: package queries find nothing, and
 *    registered WER runtime exception modules are kept in a list that nothing will ever call.
 */
#include "k32.h"
#include <tlhelp32.h>
#include <psapi.h>

typedef struct { ULONG64 create, exit, kernel, user, cycles; } k32_times;

static void to_ft(ULONG64 v, LPFILETIME ft) { if (ft) { ft->dwLowDateTime = (DWORD)v; ft->dwHighDateTime = (DWORD)(v >> 32); } }

static BOOL fail_st(NTSTATUS st) { k32_nt_error(st); return FALSE; }
static BOOL fail_err(DWORD e) { shz_set_last_error(e); return FALSE; }

/* ---------------------------------------------------------------- times and cycles */
K32API BOOL WINAPI GetProcessTimes(HANDLE h, LPFILETIME creation, LPFILETIME exit, LPFILETIME kernel, LPFILETIME user)
{
    k32_times t;
    NTSTATUS st = NtShzQueryK32(K32Q_PROCESS_TIMES, h, &t, sizeof t, 0);
    if (st) return fail_st(st);
    to_ft(t.create, creation); to_ft(t.exit, exit); to_ft(t.kernel, kernel); to_ft(t.user, user);
    return TRUE;
}

K32API BOOL WINAPI GetThreadTimes(HANDLE h, LPFILETIME creation, LPFILETIME exit, LPFILETIME kernel, LPFILETIME user)
{
    k32_times t;
    NTSTATUS st = NtShzQueryK32(K32Q_THREAD_TIMES, h, &t, sizeof t, 0);
    if (st) return fail_st(st);
    to_ft(t.create, creation); to_ft(t.exit, exit); to_ft(t.kernel, kernel); to_ft(t.user, user);
    return TRUE;
}

K32API BOOL WINAPI QueryProcessCycleTime(HANDLE h, PULONG64 cycles)
{
    k32_times t;
    NTSTATUS st;
    if (!cycles) return fail_err(ERROR_INVALID_PARAMETER);
    st = NtShzQueryK32(K32Q_PROCESS_TIMES, h, &t, sizeof t, 0);
    if (st) return fail_st(st);
    *cycles = t.cycles;
    return TRUE;
}

K32API BOOL WINAPI QueryThreadCycleTime(HANDLE h, PULONG64 cycles)
{
    k32_times t;
    NTSTATUS st;
    if (!cycles) return fail_err(ERROR_INVALID_PARAMETER);
    st = NtShzQueryK32(K32Q_THREAD_TIMES, h, &t, sizeof t, 0);
    if (st) return fail_st(st);
    *cycles = t.cycles;
    return TRUE;
}

/* {handles, threads, pid, parent pid, priority class, 0} */
static BOOL process_info(HANDLE h, ULONG v[6])
{
    NTSTATUS st = NtShzQueryK32(K32Q_PROCESS_INFO, h, v, 6 * sizeof(ULONG), 0);
    if (st) return fail_st(st);
    return TRUE;
}

K32API BOOL WINAPI GetProcessHandleCount(HANDLE h, PDWORD count)
{
    ULONG v[6];
    if (!count) return fail_err(ERROR_INVALID_PARAMETER);
    if (!process_info(h, v)) return FALSE;
    *count = v[0];
    return TRUE;
}

K32API BOOL WINAPI IsWow64Process(HANDLE h, PBOOL wow64)
{
    ULONG v[6];
    if (!wow64) return fail_err(ERROR_INVALID_PARAMETER);
    if (!process_info(h, v)) return FALSE;
    *wow64 = FALSE;                                       /* every Kernel64 process is a native x64 process */
    return TRUE;
}

/* ---------------------------------------------------------------- priority class and boost */
static volatile LONG g_background;                        /* PROCESS_MODE_BACKGROUND_BEGIN .. END (the calling process) */

static BOOL is_self(HANDLE h)
{
    ULONG v[6];
    if (h == GetCurrentProcess()) return TRUE;
    return NtShzQueryK32(K32Q_PROCESS_INFO, h, v, sizeof v, 0) == 0 && v[2] == GetCurrentProcessId();
}

K32API DWORD WINAPI GetPriorityClass(HANDLE h)
{
    ULONG v[6];
    if (!process_info(h, v)) return 0;
    return v[4];
}

K32API BOOL WINAPI SetPriorityClass(HANDLE h, DWORD cls)
{
    ULONG v = cls;
    NTSTATUS st;
    if (cls == PROCESS_MODE_BACKGROUND_BEGIN || cls == PROCESS_MODE_BACKGROUND_END) {
        if (!is_self(h)) return fail_err(ERROR_INVALID_PARAMETER);         /* background mode applies to the caller only */
        if (cls == PROCESS_MODE_BACKGROUND_BEGIN) {
            if (InterlockedCompareExchange(&g_background, 1, 0) != 0) return fail_err(ERROR_PROCESS_MODE_ALREADY_BACKGROUND);
        } else if (InterlockedCompareExchange(&g_background, 0, 1) != 1) {
            return fail_err(ERROR_PROCESS_MODE_NOT_BACKGROUND);
        }
        return TRUE;
    }
    st = NtShzSetK32(K32S_PRIORITY_CLASS, h, &v, sizeof v);
    if (st) return fail_st(st);
    return TRUE;
}

K32API BOOL WINAPI GetThreadPriorityBoost(HANDLE h, PBOOL disabled)
{
    ULONG s[4];
    NTSTATUS st;
    if (!disabled) return fail_err(ERROR_INVALID_PARAMETER);
    st = NtShzQueryK32(K32Q_THREAD_SETTINGS, h, s, sizeof s, 0);
    if (st) return fail_st(st);
    *disabled = s[0] != 0;
    return TRUE;
}

K32API BOOL WINAPI SetThreadPriorityBoost(HANDLE h, BOOL disable)
{
    ULONG v = disable != 0;
    NTSTATUS st = NtShzSetK32(K32S_THREAD_BOOST, h, &v, sizeof v);
    if (st) return fail_st(st);
    return TRUE;
}

/* ---------------------------------------------------------------- thread descriptions (Windows 10 1607+) */
/* Both return HRESULT_FROM_NT(status): 0 on success, 0xD0000008 for a bad handle, 0xD000000D for a text longer than a
 * UNICODE_STRING can carry (65534 bytes), as on Windows. The text lives in the kernel's thread record (kernel64/sysk32_proc.c),
 * so any process holding a thread handle reads it, and it ends with the thread. */
static HRESULT hr_from_nt(NTSTATUS st) { return st ? (HRESULT)(st | 0x10000000) : S_OK; }

K32API HRESULT WINAPI SetThreadDescription(HANDLE h, PCWSTR desc)
{
    SIZE_T n = 0;
    if (desc) while (desc[n]) ++n;
    if (n * sizeof(WCHAR) > 65534) return hr_from_nt(STATUS_INVALID_PARAMETER);
    return hr_from_nt(NtShzSetK32(K32S_THREAD_NAME, h, (PVOID)desc, (ULONG)(n * sizeof(WCHAR))));
}

K32API HRESULT WINAPI GetThreadDescription(HANDLE h, PWSTR *desc)
{
    ULONG bytes = 0;
    WCHAR *s;
    NTSTATUS st;
    if (!desc) return hr_from_nt(STATUS_INVALID_PARAMETER);
    *desc = 0;
    st = NtShzQueryK32(K32Q_THREAD_NAME, h, 0, 0, &bytes);
    if (st && st != STATUS_BUFFER_TOO_SMALL) return hr_from_nt(st);
    s = LocalAlloc(LMEM_FIXED, bytes + sizeof(WCHAR));
    if (!s) return hr_from_nt(STATUS_NO_MEMORY);
    if (bytes) {
        ULONG got = 0;
        st = NtShzQueryK32(K32Q_THREAD_NAME, h, s, bytes, &got);
        if (st == STATUS_BUFFER_TOO_SMALL) {                /* grew between the two calls: report what fits */
            got = bytes;
            st = 0;
        }
        if (st) { LocalFree(s); return hr_from_nt(st); }
        bytes = got < bytes ? got : bytes;
    }
    s[bytes / sizeof(WCHAR)] = 0;
    *desc = s;
    return S_OK;
}

/* ---------------------------------------------------------------- process / thread information classes */
#define THROTTLE_VALID (PROCESS_POWER_THROTTLING_EXECUTION_SPEED | 0x4)   /* EXECUTION_SPEED, IGNORE_TIMER_RESOLUTION */

K32API BOOL WINAPI GetProcessInformation(HANDLE h, PROCESS_INFORMATION_CLASS cls, LPVOID info, DWORD size)
{
    ULONG s[3];
    NTSTATUS st;
    if (!info) return fail_err(ERROR_INVALID_PARAMETER);
    switch ((int)cls) {
    case ProcessMemoryPriority:
        if (size != sizeof(MEMORY_PRIORITY_INFORMATION)) return fail_err(ERROR_BAD_LENGTH);
        if ((st = NtShzQueryK32(K32Q_PROCESS_SETTINGS, h, s, sizeof s, 0))) return fail_st(st);
        /* background mode runs the process at very low memory priority (documented for PROCESS_MODE_BACKGROUND_BEGIN) */
        ((MEMORY_PRIORITY_INFORMATION *)info)->MemoryPriority = g_background && is_self(h) ? MEMORY_PRIORITY_VERY_LOW : s[0];
        return TRUE;
    case ProcessAppMemoryInfo: {
        struct { ULONG64 total, freep, commit, peak_commit, kheap_total, kheap_used; ULONG procs, threads, handles, pad; } sys;
        ULONG64 m[5];
        APP_MEMORY_INFORMATION *a = info;
        if (size != sizeof *a) return fail_err(ERROR_BAD_LENGTH);
        if ((st = NtShzQueryK32(K32Q_PROCESS_MEMORY, h, m, sizeof m, 0))) return fail_st(st);
        if ((st = NtShzQueryK32(K32Q_SYSTEM_PERF, 0, &sys, sizeof sys, 0))) return fail_st(st);
        a->AvailableCommit = sys.total * 4096 > sys.commit ? sys.total * 4096 - sys.commit : 0;   /* no page file: RAM is the limit */
        a->PrivateCommitUsage = m[3];
        a->PeakPrivateCommitUsage = m[4];
        a->TotalCommitUsage = m[3];
        return TRUE;
    }
    case ProcessPowerThrottling: {
        PROCESS_POWER_THROTTLING_STATE *p = info;
        if (size != sizeof *p) return fail_err(ERROR_BAD_LENGTH);
        if (p->Version != PROCESS_POWER_THROTTLING_CURRENT_VERSION) return fail_err(ERROR_INVALID_PARAMETER);
        if ((st = NtShzQueryK32(K32Q_PROCESS_SETTINGS, h, s, sizeof s, 0))) return fail_st(st);
        p->ControlMask = s[1];
        p->StateMask = s[2];
        return TRUE;
    }
    case ProcessProtectionLevelInfo: {
        ULONG v[6];
        if (size != sizeof(PROCESS_PROTECTION_LEVEL_INFORMATION)) return fail_err(ERROR_BAD_LENGTH);
        if (!process_info(h, v)) return FALSE;
        ((PROCESS_PROTECTION_LEVEL_INFORMATION *)info)->ProtectionLevel = PROTECTION_LEVEL_NONE;   /* no protected processes */
        return TRUE;
    }
    case ProcessMachineTypeInfo: {
        PROCESS_MACHINE_INFORMATION *m = info;
        ULONG v[6];
        if (size != sizeof *m) return fail_err(ERROR_BAD_LENGTH);
        if (!process_info(h, v)) return FALSE;
        memset(m, 0, sizeof *m);
        m->ProcessMachine = IMAGE_FILE_MACHINE_AMD64;
        m->MachineAttributes = UserEnabled | KernelEnabled;
        return TRUE;
    }
    default:
        return fail_err(ERROR_INVALID_PARAMETER);
    }
}

K32API BOOL WINAPI SetProcessInformation(HANDLE h, PROCESS_INFORMATION_CLASS cls, LPVOID info, DWORD size)
{
    NTSTATUS st;
    if (!info) return fail_err(ERROR_INVALID_PARAMETER);
    switch ((int)cls) {
    case ProcessMemoryPriority: {
        ULONG v;
        if (size != sizeof(MEMORY_PRIORITY_INFORMATION)) return fail_err(ERROR_BAD_LENGTH);
        v = ((MEMORY_PRIORITY_INFORMATION *)info)->MemoryPriority;
        if ((st = NtShzSetK32(K32S_PROCESS_MEM_PRIORITY, h, &v, sizeof v))) return fail_st(st);
        return TRUE;
    }
    case ProcessPowerThrottling: {
        const PROCESS_POWER_THROTTLING_STATE *p = info;
        ULONG v[2];
        if (size != sizeof *p) return fail_err(ERROR_BAD_LENGTH);
        if (p->Version != PROCESS_POWER_THROTTLING_CURRENT_VERSION || (p->ControlMask & ~THROTTLE_VALID) ||
            (p->StateMask & ~p->ControlMask))
            return fail_err(ERROR_INVALID_PARAMETER);
        v[0] = p->ControlMask; v[1] = p->StateMask;
        if ((st = NtShzSetK32(K32S_PROCESS_POWER, h, v, sizeof v))) return fail_st(st);
        return TRUE;
    }
    default:
        return fail_err(ERROR_INVALID_PARAMETER);
    }
}

/* THREAD_INFORMATION_CLASS (processthreadsapi.h of newer SDKs) */
#define SHZ_ThreadMemoryPriority 0
#define SHZ_ThreadAbsoluteCpuPriority 1
#define SHZ_ThreadDynamicCodePolicy 2
#define SHZ_ThreadPowerThrottling 3
typedef struct { ULONG Version, ControlMask, StateMask; } SHZ_THREAD_POWER_THROTTLING_STATE;

K32API BOOL WINAPI GetThreadInformation(HANDLE h, THREAD_INFORMATION_CLASS cls_, LPVOID info, DWORD size)
{
    ULONG s[4];
    NTSTATUS st;
    const int cls = (int)cls_;
    if (!info) return fail_err(ERROR_INVALID_PARAMETER);
    switch (cls) {
    case SHZ_ThreadMemoryPriority:
        if (size != sizeof(MEMORY_PRIORITY_INFORMATION)) return fail_err(ERROR_BAD_LENGTH);
        if ((st = NtShzQueryK32(K32Q_THREAD_SETTINGS, h, s, sizeof s, 0))) return fail_st(st);
        ((MEMORY_PRIORITY_INFORMATION *)info)->MemoryPriority = s[1];
        return TRUE;
    case SHZ_ThreadPowerThrottling: {
        SHZ_THREAD_POWER_THROTTLING_STATE *p = info;
        if (size != sizeof *p) return fail_err(ERROR_BAD_LENGTH);
        if (p->Version != 1) return fail_err(ERROR_INVALID_PARAMETER);
        if ((st = NtShzQueryK32(K32Q_THREAD_SETTINGS, h, s, sizeof s, 0))) return fail_st(st);
        p->ControlMask = s[2];
        p->StateMask = s[3];
        return TRUE;
    }
    default:
        return fail_err(ERROR_INVALID_PARAMETER);
    }
}

K32API BOOL WINAPI SetThreadInformation(HANDLE h, THREAD_INFORMATION_CLASS cls_, LPVOID info, DWORD size)
{
    NTSTATUS st;
    const int cls = (int)cls_;
    if (!info) return fail_err(ERROR_INVALID_PARAMETER);
    switch (cls) {
    case SHZ_ThreadMemoryPriority: {
        ULONG v;
        if (size != sizeof(MEMORY_PRIORITY_INFORMATION)) return fail_err(ERROR_BAD_LENGTH);
        v = ((MEMORY_PRIORITY_INFORMATION *)info)->MemoryPriority;
        if ((st = NtShzSetK32(K32S_THREAD_MEM_PRIORITY, h, &v, sizeof v))) return fail_st(st);
        return TRUE;
    }
    case SHZ_ThreadPowerThrottling: {
        const SHZ_THREAD_POWER_THROTTLING_STATE *p = info;
        ULONG v[2];
        if (size != sizeof *p) return fail_err(ERROR_BAD_LENGTH);
        if (p->Version != 1 || (p->ControlMask & ~1u) || (p->StateMask & ~p->ControlMask)) return fail_err(ERROR_INVALID_PARAMETER);
        v[0] = p->ControlMask; v[1] = p->StateMask;
        if ((st = NtShzSetK32(K32S_THREAD_POWER, h, v, sizeof v))) return fail_st(st);
        return TRUE;
    }
    case SHZ_ThreadDynamicCodePolicy:
        /* THREAD_DYNAMIC_CODE_ALLOW opts a thread out of a process dynamic-code policy; no such policy can be in force here */
        return fail_err(ERROR_NOT_SUPPORTED);
    default:
        return fail_err(ERROR_INVALID_PARAMETER);
    }
}

/* ---------------------------------------------------------------- mitigation policies */
static DWORD policy_size(PROCESS_MITIGATION_POLICY p)
{
    switch ((int)p) {
    case ProcessDEPPolicy: return sizeof(PROCESS_MITIGATION_DEP_POLICY);
    case ProcessMitigationOptionsMask: return 0;           /* variable: one or two ULONG64 */
    default: return (int)p >= 0 && (int)p < MaxProcessMitigationPolicy ? sizeof(DWORD) : (DWORD)-1;
    }
}

K32API BOOL WINAPI GetProcessMitigationPolicy(HANDLE h, PROCESS_MITIGATION_POLICY policy, PVOID buf, SIZE_T len)
{
    ULONG v[6];
    const DWORD want = policy_size(policy);
    if (!buf || want == (DWORD)-1) return fail_err(ERROR_INVALID_PARAMETER);
    if (!process_info(h, v)) return FALSE;
    if (policy == ProcessMitigationOptionsMask) {         /* the mitigation options this system can apply: none */
        if (len != 8 && len != 16) return fail_err(ERROR_INVALID_PARAMETER);
        memset(buf, 0, len);
        return TRUE;
    }
    if (len != want) return fail_err(ERROR_INVALID_PARAMETER);
    memset(buf, 0, len);
    if (policy == ProcessDEPPolicy) {                    /* NX is always on for x64 processes, and permanently so */
        ((PROCESS_MITIGATION_DEP_POLICY *)buf)->Enable = 1;
        ((PROCESS_MITIGATION_DEP_POLICY *)buf)->Permanent = TRUE;
    }
    return TRUE;
}

K32API BOOL WINAPI SetProcessMitigationPolicy(PROCESS_MITIGATION_POLICY policy, PVOID buf, SIZE_T len)
{
    const DWORD want = policy_size(policy);
    if (!buf || want == (DWORD)-1 || want == 0 || len != want) return fail_err(ERROR_INVALID_PARAMETER);
    if (policy == ProcessDEPPolicy) {
        const PROCESS_MITIGATION_DEP_POLICY *d = buf;
        return d->Enable ? TRUE : fail_err(ERROR_NOT_SUPPORTED);         /* already on; x64 DEP cannot be turned off */
    }
    if (*(const DWORD *)buf == 0) return TRUE;            /* nothing asked for: nothing to enforce */
    return fail_err(ERROR_NOT_SUPPORTED);                 /* Kernel64 cannot enforce this mitigation */
}

/* ---------------------------------------------------------------- shutdown parameters */
static DWORD g_shutdown_level = 0x280, g_shutdown_flags;

K32API BOOL WINAPI SetProcessShutdownParameters(DWORD level, DWORD flags)
{
    if (level > 0x4ff || (flags & ~(DWORD)SHUTDOWN_NORETRY)) return fail_err(ERROR_INVALID_PARAMETER);
    g_shutdown_level = level;
    g_shutdown_flags = flags;
    return TRUE;
}

K32API BOOL WINAPI GetProcessShutdownParameters(LPDWORD level, LPDWORD flags)
{
    if (!level || !flags) return fail_err(ERROR_INVALID_PARAMETER);
    *level = g_shutdown_level;
    *flags = g_shutdown_flags;
    return TRUE;
}

/* ---------------------------------------------------------------- debugging */
K32API BOOL WINAPI CheckRemoteDebuggerPresent(HANDLE h, PBOOL present)
{
    ULONG v[6];
    if (!h || !present) return fail_err(ERROR_INVALID_PARAMETER);
    if (!process_info(h, v)) return FALSE;
    *present = FALSE;                                     /* Kernel64 has no debug objects: no process can have a debugger attached */
    return TRUE;
}

K32API VOID WINAPI DebugBreak(void) { __asm__ volatile("int3"); }

/* ---------------------------------------------------------------- sessions */
#define PEB_SESSION_ID(peb) (*(ULONG *)((peb) + 0x2c0))

static BOOL pid_exists(DWORD pid)
{
    struct { ULONG pid, ppid, threads, cls; char name[32]; } list[64];
    ULONG need = 0, i;
    NTSTATUS st;
    if (pid == GetCurrentProcessId()) return TRUE;
    st = NtShzQueryK32(K32Q_PROCESS_LIST, 0, list, sizeof list, &need);
    if (st) return FALSE;
    for (i = 0; i < need / sizeof list[0]; ++i)
        if (list[i].pid == pid) return TRUE;
    return FALSE;
}

K32API BOOL WINAPI ProcessIdToSessionId(DWORD pid, DWORD *session)
{
    if (!session) return fail_err(ERROR_INVALID_PARAMETER);
    if (!pid_exists(pid)) return fail_err(ERROR_INVALID_PARAMETER);
    *session = PEB_SESSION_ID(shz_peb());                 /* one session holds every process */
    return TRUE;
}

K32API DWORD WINAPI WTSGetActiveConsoleSessionId(void) { return PEB_SESSION_ID(shz_peb()); }

/* ---------------------------------------------------------------- image names */
static BOOL image_path(HANDLE h, char *path, ULONG cap)
{
    NTSTATUS st = NtShzQueryK32(K32Q_IMAGE_PATH, h, path, cap, 0);
    if (st) return fail_st(st);
    return TRUE;
}

/* Loader paths are "\SHZ\TESTS\X.EXE" (volume C:) or "D:\dir\X.EXE" (another volume) -> "C:\SHZ\TESTS\X.EXE" (Win32) or
 * "\Device\HarddiskVolume1\SHZ\TESTS\X.EXE" (native; k32_volume.c numbering) */
static int format_path(const char *kpath, int native, WCHAR *out, int cap)
{
    WCHAR dev[32];
    char full[400];
    size_t n = 0, i, dl;
    char letter = 'C';
    if (kpath[0] && kpath[1] == ':') { letter = (char)(kpath[0] & ~0x20); kpath += 2; }
    if (native) {
        dl = k32_volume_device((WCHAR)letter, dev);
        for (i = 0; i < dl; ++i) full[n++] = (char)dev[i];
    } else {
        full[n++] = letter; full[n++] = ':';
    }
    for (i = 0; kpath[i] && n + 1 < sizeof full; ++i) full[n++] = kpath[i];
    full[n] = 0;
    return k32_utf8_to_wide(full, -1, out, cap);            /* includes the NUL; 0 if it does not fit */
}

K32API BOOL WINAPI QueryFullProcessImageNameW(HANDLE h, DWORD flags, LPWSTR buf, PDWORD size)
{
    char kpath[300];
    WCHAR tmp[400];
    int n;
    if (!buf || !size || (flags & ~(DWORD)PROCESS_NAME_NATIVE)) return fail_err(ERROR_INVALID_PARAMETER);
    if (!image_path(h, kpath, sizeof kpath)) return FALSE;
    n = format_path(kpath, (flags & PROCESS_NAME_NATIVE) != 0, tmp, 400);
    if (n <= 0) return fail_err(ERROR_INSUFFICIENT_BUFFER);
    if ((DWORD)n > *size) return fail_err(ERROR_INSUFFICIENT_BUFFER);
    memcpy(buf, tmp, (size_t)n * sizeof(WCHAR));
    *size = (DWORD)n - 1;
    return TRUE;
}

K32API BOOL WINAPI QueryFullProcessImageNameA(HANDLE h, DWORD flags, LPSTR buf, PDWORD size)
{
    WCHAR w[400];
    DWORD n = 400;
    int len;
    if (!buf || !size) return fail_err(ERROR_INVALID_PARAMETER);
    if (!QueryFullProcessImageNameW(h, flags, w, &n)) return FALSE;
    len = k32_wide_to_utf8(w, (int)n + 1, buf, (int)*size);
    if (len <= 0) return fail_err(ERROR_INSUFFICIENT_BUFFER);
    *size = (DWORD)len - 1;
    return TRUE;
}

/* ---------------------------------------------------------------- toolhelp snapshots
 * A snapshot is a copy of the kernel's process list and/or one process' module list taken at creation. Its handle is a real
 * kernel object (an event), so CloseHandle and DuplicateHandle behave; kernel32 keeps the snapshot data next to the handle value
 * and releases it when CloseHandle closes that handle. */
typedef struct { ULONG pid, ppid, threads, cls; char name[32]; } k_proc;
typedef struct { ULONG64 base, size; char name[48]; char path[128]; } k_mod;
typedef struct snap {
    struct snap *next;
    HANDLE h;
    DWORD owner_pid;
    k_proc *procs; ULONG nprocs, proc_pos;
    k_mod *mods; ULONG nmods, mod_pos;
} snap_t;

static snap_t *g_snaps;
static SRWLOCK g_snap_lock = SRWLOCK_INIT;

static PVOID query_list(ULONG cls, HANDLE arg, ULONG elem, ULONG *count)
{
    ULONG need = 0;
    PVOID buf = 0;
    NTSTATUS st;
    int tries;
    for (tries = 0; tries < 4; ++tries) {                 /* the list may grow between the size query and the copy */
        st = NtShzQueryK32(cls, arg, buf, need, &need);
        if (st == 0) { *count = need / elem; return buf ? buf : RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, 16); }
        if (st != STATUS_BUFFER_TOO_SMALL) { if (buf) RtlFreeHeap(ShzProcessHeap(), 0, buf); k32_nt_error(st); return 0; }
        if (buf) RtlFreeHeap(ShzProcessHeap(), 0, buf);
        need += 4 * elem;
        buf = RtlAllocateHeap(ShzProcessHeap(), 0, need);
        if (!buf) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    }
    if (buf) RtlFreeHeap(ShzProcessHeap(), 0, buf);
    shz_set_last_error(ERROR_BAD_LENGTH);
    return 0;
}

static void snap_free(snap_t *s)
{
    if (s->procs) RtlFreeHeap(ShzProcessHeap(), 0, s->procs);
    if (s->mods) RtlFreeHeap(ShzProcessHeap(), 0, s->mods);
    RtlFreeHeap(ShzProcessHeap(), 0, s);
}

K32API HANDLE WINAPI CreateToolhelp32Snapshot(DWORD flags, DWORD pid)
{
    snap_t *s = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, sizeof *s);
    if (!s) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; }
    if (!pid) pid = GetCurrentProcessId();
    s->owner_pid = pid;
    if (flags & TH32CS_SNAPPROCESS) {
        s->procs = query_list(K32Q_PROCESS_LIST, 0, sizeof(k_proc), &s->nprocs);
        if (!s->procs) { snap_free(s); return INVALID_HANDLE_VALUE; }
    }
    if (flags & (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)) {
        s->mods = query_list(K32Q_MODULE_LIST, (HANDLE)(ULONG_PTR)(pid == GetCurrentProcessId() ? 0 : pid), sizeof(k_mod), &s->nmods);
        if (!s->mods) {
            if (GetLastError() == ERROR_MR_MID_NOT_FOUND) shz_set_last_error(ERROR_INVALID_PARAMETER);    /* no such process */
            snap_free(s);
            return INVALID_HANDLE_VALUE;
        }
    }
    s->h = CreateEventW(0, TRUE, FALSE, 0);
    if (!s->h) { snap_free(s); return INVALID_HANDLE_VALUE; }
    AcquireSRWLockExclusive(&g_snap_lock);
    s->next = g_snaps;
    g_snaps = s;
    ReleaseSRWLockExclusive(&g_snap_lock);
    return s->h;
}

/* Called by CloseHandle before the handle goes away. */
void k32_snapshot_closing(HANDLE h)
{
    snap_t **pp, *s = 0;
    AcquireSRWLockExclusive(&g_snap_lock);
    for (pp = &g_snaps; *pp; pp = &(*pp)->next)
        if ((*pp)->h == h) { s = *pp; *pp = s->next; break; }
    ReleaseSRWLockExclusive(&g_snap_lock);
    if (s) snap_free(s);
}

static snap_t *snap_find(HANDLE h)
{
    snap_t *s;
    for (s = g_snaps; s; s = s->next) if (s->h == h) return s;
    return 0;
}

static BOOL process_entry(HANDLE h, LPPROCESSENTRY32W pe, int first)
{
    snap_t *s;
    const k_proc *k;
    BOOL ok = FALSE;
    if (!pe || pe->dwSize < sizeof *pe) return fail_err(ERROR_BAD_LENGTH);
    AcquireSRWLockExclusive(&g_snap_lock);
    s = snap_find(h);
    if (!s) { ReleaseSRWLockExclusive(&g_snap_lock); return fail_err(ERROR_INVALID_HANDLE); }
    if (first) s->proc_pos = 0;
    if (s->proc_pos < s->nprocs) {
        k = &s->procs[s->proc_pos++];
        pe->cntUsage = 0;
        pe->th32ProcessID = k->pid;
        pe->th32DefaultHeapID = 0;
        pe->th32ModuleID = 0;
        pe->cntThreads = k->threads;
        pe->th32ParentProcessID = k->ppid;
        pe->pcPriClassBase = k->cls == IDLE_PRIORITY_CLASS ? 4 : k->cls == BELOW_NORMAL_PRIORITY_CLASS ? 6 : k->cls == ABOVE_NORMAL_PRIORITY_CLASS ? 10
                           : k->cls == HIGH_PRIORITY_CLASS ? 13 : k->cls == REALTIME_PRIORITY_CLASS ? 24 : 8;
        pe->dwFlags = 0;
        if (!k32_utf8_to_wide(k->name, -1, pe->szExeFile, MAX_PATH)) pe->szExeFile[0] = 0;
        ok = TRUE;
    }
    ReleaseSRWLockExclusive(&g_snap_lock);
    return ok ? TRUE : fail_err(ERROR_NO_MORE_FILES);
}

K32API BOOL WINAPI Process32FirstW(HANDLE h, LPPROCESSENTRY32W pe) { return process_entry(h, pe, 1); }
K32API BOOL WINAPI Process32NextW(HANDLE h, LPPROCESSENTRY32W pe) { return process_entry(h, pe, 0); }

static BOOL module_entry(HANDLE h, LPMODULEENTRY32W me, int first)
{
    snap_t *s;
    const k_mod *k;
    BOOL ok = FALSE;
    if (!me || me->dwSize < sizeof *me) return fail_err(ERROR_BAD_LENGTH);
    AcquireSRWLockExclusive(&g_snap_lock);
    s = snap_find(h);
    if (!s) { ReleaseSRWLockExclusive(&g_snap_lock); return fail_err(ERROR_INVALID_HANDLE); }
    if (first) s->mod_pos = 0;
    if (s->mod_pos < s->nmods) {
        WCHAR path[300];
        k = &s->mods[s->mod_pos++];
        me->th32ModuleID = 1;
        me->th32ProcessID = s->owner_pid;
        me->GlblcntUsage = 0xffff;
        me->ProccntUsage = 0xffff;
        me->modBaseAddr = (BYTE *)(ULONG_PTR)k->base;
        me->modBaseSize = (DWORD)k->size;
        me->hModule = (HMODULE)(ULONG_PTR)k->base;
        if (!k32_utf8_to_wide(k->name, -1, me->szModule, MAX_MODULE_NAME32 + 1)) me->szModule[0] = 0;
        if (format_path(k->path, 0, path, 300) > 0 && k32_wlen(path) < MAX_PATH) memcpy(me->szExePath, path, (k32_wlen(path) + 1) * sizeof(WCHAR));
        else me->szExePath[0] = 0;
        ok = TRUE;
    }
    ReleaseSRWLockExclusive(&g_snap_lock);
    return ok ? TRUE : fail_err(ERROR_NO_MORE_FILES);
}

K32API BOOL WINAPI Module32FirstW(HANDLE h, LPMODULEENTRY32W me) { return module_entry(h, me, 1); }
K32API BOOL WINAPI Module32NextW(HANDLE h, LPMODULEENTRY32W me) { return module_entry(h, me, 0); }

/* ---------------------------------------------------------------- PSAPI */
K32API DWORD WINAPI K32GetMappedFileNameW(HANDLE h, LPVOID addr, LPWSTR buf, DWORD size)
{
    ULONG v[6], count = 0, i;
    k_mod *mods;
    WCHAR path[400];
    DWORD n = 0;
    if (!buf || !size) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (!process_info(h, v)) return 0;
    mods = query_list(K32Q_MODULE_LIST, (HANDLE)(ULONG_PTR)(v[2] == GetCurrentProcessId() ? 0 : v[2]), sizeof(k_mod), &count);
    if (!mods) return 0;
    for (i = 0; i < count; ++i)
        if ((ULONG_PTR)addr >= mods[i].base && (ULONG_PTR)addr < mods[i].base + mods[i].size) break;
    if (i < count && format_path(mods[i].path, 1, path, 400) > 0) {
        n = (DWORD)k32_wlen(path);
        if (n >= size) n = size - 1;                      /* truncated, like Windows */
        memcpy(buf, path, n * sizeof(WCHAR));
        buf[n] = 0;
    }
    RtlFreeHeap(ShzProcessHeap(), 0, mods);
    if (i < count) return n;
    if (v[2] == GetCurrentProcessId()) {
        MEMORY_BASIC_INFORMATION mbi;
        /* no file is mapped there: free address space (STATUS_INVALID_ADDRESS) or private memory (STATUS_FILE_INVALID) */
        if (VirtualQuery(addr, &mbi, sizeof mbi) && mbi.State == MEM_FREE) { shz_set_last_error(ERROR_UNEXP_NET_ERR); return 0; }
    }
    shz_set_last_error(ERROR_FILE_INVALID);
    return 0;
}

K32API BOOL WINAPI K32GetPerformanceInfo(PPERFORMANCE_INFORMATION pi, DWORD cb)
{
    struct { ULONG64 total, freep, commit, peak_commit, kheap_total, kheap_used; ULONG procs, threads, handles, pad; } s;
    NTSTATUS st;
    if (!pi || cb < sizeof *pi) return fail_err(ERROR_BAD_LENGTH);
    if ((st = NtShzQueryK32(K32Q_SYSTEM_PERF, 0, &s, sizeof s, 0))) return fail_st(st);
    memset(pi, 0, sizeof *pi);
    pi->cb = sizeof *pi;
    pi->CommitTotal = (SIZE_T)(s.commit / 4096);
    pi->CommitLimit = (SIZE_T)s.total;                   /* no page file: committed memory is backed by RAM only */
    pi->CommitPeak = (SIZE_T)(s.peak_commit / 4096);
    pi->PhysicalTotal = (SIZE_T)s.total;
    pi->PhysicalAvailable = (SIZE_T)s.freep;
    pi->SystemCache = 0;                                  /* no file cache: file data lives in the RAM file system */
    pi->KernelNonpaged = (SIZE_T)((s.kheap_used + 4095) / 4096);
    pi->KernelPaged = 0;                                  /* Kernel64 never pages */
    pi->KernelTotal = pi->KernelNonpaged;
    pi->PageSize = 4096;
    pi->HandleCount = s.handles;
    pi->ProcessCount = s.procs;
    pi->ThreadCount = s.threads;
    return TRUE;
}

K32API BOOL WINAPI K32GetProcessMemoryInfo(HANDLE h, PPROCESS_MEMORY_COUNTERS pmc, DWORD cb)
{
    ULONG64 m[5];
    NTSTATUS st;
    if (!pmc || cb < sizeof(PROCESS_MEMORY_COUNTERS)) return fail_err(ERROR_INSUFFICIENT_BUFFER);
    if ((st = NtShzQueryK32(K32Q_PROCESS_MEMORY, h, m, sizeof m, 0))) return fail_st(st);
    memset(pmc, 0, cb >= sizeof(PROCESS_MEMORY_COUNTERS_EX) ? sizeof(PROCESS_MEMORY_COUNTERS_EX) : sizeof(PROCESS_MEMORY_COUNTERS));
    pmc->cb = cb >= sizeof(PROCESS_MEMORY_COUNTERS_EX) ? sizeof(PROCESS_MEMORY_COUNTERS_EX) : sizeof(PROCESS_MEMORY_COUNTERS);
    pmc->PageFaultCount = (DWORD)m[0];
    pmc->WorkingSetSize = (SIZE_T)m[1];
    pmc->PeakWorkingSetSize = (SIZE_T)m[2];
    pmc->PagefileUsage = (SIZE_T)m[3];                    /* commit charge: private committed bytes */
    pmc->PeakPagefileUsage = (SIZE_T)m[4];
    /* Quota pool usage stays 0: Kernel64 charges no pool quota to processes. */
    if (cb >= sizeof(PROCESS_MEMORY_COUNTERS_EX)) ((PROCESS_MEMORY_COUNTERS_EX *)pmc)->PrivateUsage = (SIZE_T)m[3];
    return TRUE;
}

K32API BOOL WINAPI K32QueryWorkingSetEx(HANDLE h, PVOID pv, DWORD cb)
{
    NTSTATUS st;
    if (!pv || !cb || cb % sizeof(PSAPI_WORKING_SET_EX_INFORMATION)) return fail_err(ERROR_BAD_LENGTH);
    if ((st = NtShzQueryK32(K32Q_WORKING_SET_EX, h, pv, cb, 0))) return fail_st(st);
    return TRUE;
}

/* ---------------------------------------------------------------- thread context */
K32API BOOL WINAPI GetThreadContext(HANDLE h, LPCONTEXT ctx)
{
    NTSTATUS st;
    if (!ctx) return fail_err(ERROR_NOACCESS);
    st = NtGetContextThread(h, ctx);
    if (st) return fail_st(st);
    return TRUE;
}

K32API BOOL WINAPI Wow64GetThreadContext(HANDLE h, PWOW64_CONTEXT ctx)
{
    ULONG s[4];
    NTSTATUS st;
    if (!ctx) return fail_err(ERROR_NOACCESS);
    if ((st = NtShzQueryK32(K32Q_THREAD_SETTINGS, h, s, sizeof s, 0))) return fail_st(st);
    return fail_err(ERROR_INVALID_PARAMETER);             /* a native x64 thread has no WOW64 (x86) context */
}

K32API BOOL WINAPI IsThreadAFiber(void)
{
    /* TEB.SameTebFlags (0x17ee) bit 2 is HasFiberData. ConvertThreadToFiber does not exist in this kernel32, so it is never set,
     * but the flag is what Windows reports and what is read here. */
    return (*(const USHORT *)(shz_teb() + 0x17ee) & 4) != 0;
}

/* ---------------------------------------------------------------- packages (none are installed) */
K32API LONG WINAPI GetPackagePathByFullName(PCWSTR full_name, UINT32 *len, PWSTR path)
{
    (void)path;
    if (!full_name || !full_name[0] || !len) return ERROR_INVALID_PARAMETER;
    return ERROR_NOT_FOUND;
}

K32API LONG WINAPI GetPackagesByPackageFamily(PCWSTR family, UINT32 *count, PWSTR *full_names, UINT32 *buf_len, WCHAR *buf)
{
    const WCHAR *p;
    (void)full_names; (void)buf;
    if (!family || !count || !buf_len) return ERROR_INVALID_PARAMETER;
    for (p = family; *p && *p != '_'; ++p) { }
    if (p == family || !*p || !p[1]) return ERROR_INVALID_PARAMETER;     /* a family name is "<name>_<publisher id>" */
    *count = 0;
    *buf_len = 0;
    return ERROR_SUCCESS;
}

/* ---------------------------------------------------------------- WER runtime exception modules */
#define WER_MAX_MODULES 16
static struct { WCHAR path[MAX_PATH]; PVOID ctx; int used; } g_wer[WER_MAX_MODULES];
static SRWLOCK g_wer_lock = SRWLOCK_INIT;

static int weq(const WCHAR *a, const WCHAR *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }

/* RegisterApplicationRestart / UnregisterApplicationRestart / GetApplicationRestartSettings (Windows Vista+). There is no Windows
 * Error Reporting service to restart the program after a crash, so the registration is only recorded (and reported back), as the
 * WER runtime exception modules below are: the HRESULTs, limits and validation follow the documentation. */
#define RESTART_MAX_CMD_LINE 1024
#define RESTART_NO_CRASH 1
#define RESTART_NO_HANG 2
#define RESTART_NO_PATCH 4
#define RESTART_NO_REBOOT 8
static SRWLOCK g_restart_lock = SRWLOCK_INIT;
static int g_restart_set;
static DWORD g_restart_flags;
static WCHAR g_restart_cmd[RESTART_MAX_CMD_LINE + 1];

K32API HRESULT WINAPI RegisterApplicationRestart(PCWSTR cmd, DWORD flags)
{
    size_t n = cmd ? k32_wlen(cmd) : 0;
    if (flags & ~15u) return E_INVALIDARG;
    if (n > RESTART_MAX_CMD_LINE) return E_INVALIDARG;
    AcquireSRWLockExclusive(&g_restart_lock);
    if (n) memcpy(g_restart_cmd, cmd, n * sizeof(WCHAR));
    g_restart_cmd[n] = 0;
    g_restart_flags = flags;
    g_restart_set = 1;
    ReleaseSRWLockExclusive(&g_restart_lock);
    return S_OK;
}

K32API HRESULT WINAPI UnregisterApplicationRestart(void)
{
    HRESULT hr = S_OK;
    AcquireSRWLockExclusive(&g_restart_lock);
    if (!g_restart_set) hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    g_restart_set = 0;
    ReleaseSRWLockExclusive(&g_restart_lock);
    return hr;
}

K32API HRESULT WINAPI GetApplicationRestartSettings(HANDLE process, PWSTR cmd, PDWORD size, PDWORD flags)
{
    HRESULT hr = S_OK;
    DWORD n;
    if (!size || (!cmd && *size)) return E_INVALIDARG;
    if (process != GetCurrentProcess() && GetProcessId(process) != GetCurrentProcessId()) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);   /* another process' registration is not kept */
    AcquireSRWLockShared(&g_restart_lock);
    if (!g_restart_set) hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    else {
        n = (DWORD)k32_wlen(g_restart_cmd) + 1;
        if (*size < n) { *size = n; hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER); }
        else {
            memcpy(cmd, g_restart_cmd, n * sizeof(WCHAR));
            *size = n;
            if (flags) *flags = g_restart_flags;
        }
    }
    ReleaseSRWLockShared(&g_restart_lock);
    return hr;
}

K32API HRESULT WINAPI WerRegisterRuntimeExceptionModule(PCWSTR dll, PVOID ctx)
{
    int i, slot = -1;
    size_t n;
    if (!dll || !dll[0] || (n = k32_wlen(dll)) >= MAX_PATH) return E_INVALIDARG;
    AcquireSRWLockExclusive(&g_wer_lock);
    for (i = 0; i < WER_MAX_MODULES; ++i) {
        if (g_wer[i].used && g_wer[i].ctx == ctx && weq(g_wer[i].path, dll)) { ReleaseSRWLockExclusive(&g_wer_lock); return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS); }
        if (!g_wer[i].used && slot < 0) slot = i;
    }
    if (slot < 0) { ReleaseSRWLockExclusive(&g_wer_lock); return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA); }
    memcpy(g_wer[slot].path, dll, (n + 1) * sizeof(WCHAR));
    g_wer[slot].ctx = ctx;
    g_wer[slot].used = 1;
    ReleaseSRWLockExclusive(&g_wer_lock);
    return S_OK;
}

K32API HRESULT WINAPI WerUnregisterRuntimeExceptionModule(PCWSTR dll, PVOID ctx)
{
    int i;
    if (!dll) return E_INVALIDARG;
    AcquireSRWLockExclusive(&g_wer_lock);
    for (i = 0; i < WER_MAX_MODULES; ++i)
        if (g_wer[i].used && g_wer[i].ctx == ctx && weq(g_wer[i].path, dll)) {
            g_wer[i].used = 0;
            ReleaseSRWLockExclusive(&g_wer_lock);
            return S_OK;
        }
    ReleaseSRWLockExclusive(&g_wer_lock);
    return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}
