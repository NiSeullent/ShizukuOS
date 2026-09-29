/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: processor topology, firmware, computer names, product and version checks, power state and power requests.
 *
 *  - Processors: Kernel64 runs on one logical processor (the boot CPU; no other CPU is started), in one group, one NUMA node,
 *    one package. Cache descriptors are what CPUID reports (deterministic cache parameters, leaf 4 on Intel or 0x8000001D on AMD,
 *    else AMD's legacy leaves 0x80000005/6); if the CPU reports none, none are listed.
 *  - Version: the OS version the loader wrote into the PEB (the 10.0 build 22631 profile), workstation product type, no service
 *    pack, no suites. GetProductInfo reports PRODUCT_UNDEFINED: this is not an edition of Windows.
 *  - Power: there is no ACPI battery / AC driver, so the power status is "unknown" in every field. Power requests and
 *    SetThreadExecutionState are recorded and reported back; nothing puts this system to sleep, so there is nothing for them to
 *    prevent.
 */
#include "k32.h"

static BOOL fail_err(DWORD e) { shz_set_last_error(e); return FALSE; }

/* ---------------------------------------------------------------- processors */
#define SHZ_ALL_GROUPS 0xffff

static DWORD processor_count(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
}

K32API DWORD WINAPI GetActiveProcessorCount(WORD group)
{
    if (group != 0 && group != SHZ_ALL_GROUPS) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return processor_count();
}

K32API DWORD WINAPI GetMaximumProcessorCount(WORD group)
{
    if (group != 0 && group != SHZ_ALL_GROUPS) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return processor_count();                             /* no processor can be added while the system runs */
}

K32API WORD WINAPI GetMaximumProcessorGroupCount(void) { return 1; }

K32API DWORD WINAPI GetCurrentProcessorNumber(void) { return 0; }       /* every thread runs on logical processor 0 */

K32API BOOL WINAPI GetThreadGroupAffinity(HANDLE h, PGROUP_AFFINITY ga)
{
    ULONG s[4];
    NTSTATUS st;
    if (!ga) return fail_err(ERROR_INVALID_PARAMETER);
    st = NtShzQueryK32(K32Q_THREAD_SETTINGS, h, s, sizeof s, 0);   /* validates the thread handle */
    if (st) { k32_nt_error(st); return FALSE; }
    memset(ga, 0, sizeof *ga);
    ga->Mask = 1;
    ga->Group = 0;
    return TRUE;
}

typedef struct { BYTE level, assoc; WORD line; DWORD size; int type; } cache_t;   /* type: PROCESSOR_CACHE_TYPE */

static void cpuid(unsigned leaf, unsigned sub, unsigned r[4])
{
    __asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(leaf), "c"(sub));
}

/* Deterministic cache parameters (Intel leaf 4 / AMD leaf 0x8000001D share the format). */
static unsigned det_caches(unsigned leaf, cache_t *out, unsigned cap)
{
    unsigned n = 0, i, r[4];
    for (i = 0; i < 16 && n < cap; ++i) {
        unsigned t;
        cpuid(leaf, i, r);
        t = r[0] & 31;
        if (!t) break;
        if (t > 3) continue;
        out[n].level = (BYTE)((r[0] >> 5) & 7);
        out[n].assoc = (r[0] & 0x200) ? 0xff : (BYTE)(((r[1] >> 22) & 0x3ff) + 1);             /* 0xff: fully associative */
        out[n].line = (WORD)((r[1] & 0xfff) + 1);
        out[n].size = (((r[1] >> 22) & 0x3ff) + 1) * (((r[1] >> 12) & 0x3ff) + 1) * ((r[1] & 0xfff) + 1) * (r[2] + 1);
        out[n].type = t == 1 ? CacheData : t == 2 ? CacheInstruction : CacheUnified;
        ++n;
    }
    return n;
}

static BYTE amd_assoc(unsigned code)                     /* leaf 0x80000006 associativity encoding */
{
    static const BYTE map[16] = { 0, 1, 2, 0, 4, 0, 8, 0, 16, 0, 32, 48, 64, 96, 128, 0xff };
    return map[code & 15];
}

static unsigned cpu_caches(cache_t *out, unsigned cap)
{
    unsigned r[4], max, maxext, n;
    char vendor[13];
    cpuid(0, 0, r);
    max = r[0];
    memcpy(vendor, &r[1], 4); memcpy(vendor + 4, &r[3], 4); memcpy(vendor + 8, &r[2], 4); vendor[12] = 0;
    cpuid(0x80000000u, 0, r);
    maxext = r[0];
    if (!memcmp(vendor, "GenuineIntel", 12) && max >= 4 && (n = det_caches(4, out, cap))) return n;
    if (maxext >= 0x8000001du) {
        cpuid(0x80000001u, 0, r);
        if ((r[2] >> 22) & 1 && (n = det_caches(0x8000001du, out, cap))) return n;               /* TOPOEXT */
    }
    if (max >= 4 && memcmp(vendor, "AuthenticAMD", 12) && (n = det_caches(4, out, cap))) return n;
    n = 0;
    if (maxext >= 0x80000005u && n + 2 <= cap) {           /* AMD legacy: L1 data (ECX) and instruction (EDX) */
        cpuid(0x80000005u, 0, r);
        if (r[2] >> 24) { out[n].level = 1; out[n].assoc = (BYTE)(r[2] >> 16); out[n].line = (WORD)(r[2] & 0xff); out[n].size = (r[2] >> 24) * 1024; out[n].type = CacheData; ++n; }
        if (r[3] >> 24) { out[n].level = 1; out[n].assoc = (BYTE)(r[3] >> 16); out[n].line = (WORD)(r[3] & 0xff); out[n].size = (r[3] >> 24) * 1024; out[n].type = CacheInstruction; ++n; }
    }
    if (maxext >= 0x80000006u && n + 2 <= cap) {
        cpuid(0x80000006u, 0, r);
        if (r[2] >> 16) { out[n].level = 2; out[n].assoc = amd_assoc(r[2] >> 12); out[n].line = (WORD)(r[2] & 0xff); out[n].size = (r[2] >> 16) * 1024; out[n].type = CacheUnified; ++n; }
        if (r[3] >> 18) { out[n].level = 3; out[n].assoc = amd_assoc(r[3] >> 12); out[n].line = (WORD)(r[3] & 0xff); out[n].size = (r[3] >> 18) * 512 * 1024; out[n].type = CacheUnified; ++n; }
    }
    return n;
}

K32API BOOL WINAPI GetLogicalProcessorInformation(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buf, PDWORD len)
{
    cache_t c[16];
    const unsigned nc = cpu_caches(c, 16), total = 3 + nc;
    unsigned i, k = 0;
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION e[3 + 16];
    if (!len) return fail_err(ERROR_INVALID_PARAMETER);
    if (*len < total * sizeof e[0] || !buf) { *len = total * (DWORD)sizeof e[0]; return fail_err(ERROR_INSUFFICIENT_BUFFER); }
    memset(e, 0, sizeof e);
    e[k].ProcessorMask = 1; e[k].Relationship = RelationProcessorCore; e[k].ProcessorCore.Flags = 0; ++k;   /* no SMT sibling */
    e[k].ProcessorMask = 1; e[k].Relationship = RelationNumaNode; e[k].NumaNode.NodeNumber = 0; ++k;
    for (i = 0; i < nc; ++i, ++k) {
        e[k].ProcessorMask = 1; e[k].Relationship = RelationCache;
        e[k].Cache.Level = c[i].level; e[k].Cache.Associativity = c[i].assoc; e[k].Cache.LineSize = c[i].line;
        e[k].Cache.Size = c[i].size; e[k].Cache.Type = (PROCESSOR_CACHE_TYPE)c[i].type;
    }
    e[k].ProcessorMask = 1; e[k].Relationship = RelationProcessorPackage; ++k;
    memcpy(buf, e, k * sizeof e[0]);
    *len = k * (DWORD)sizeof e[0];
    return TRUE;
}

/* SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX records, built byte by byte in the documented x64 layout:
 * {DWORD Relationship; DWORD Size; union at +8}; GROUP_AFFINITY = {KAFFINITY Mask; WORD Group; WORD Reserved[3]} (16 bytes). */
static void put_affinity(BYTE *p) { ULONG64 m = 1; memcpy(p, &m, 8); memset(p + 8, 0, 8); }

static unsigned ex_record(BYTE *out, int rel, const cache_t *c)
{
    unsigned size;
    DWORD r = (DWORD)rel;
    switch (rel) {
    case RelationProcessorCore: case RelationProcessorPackage:
        size = 8 + 24 + 16;                                /* Flags, EfficiencyClass, Reserved[20], GroupCount, GroupMask[1] */
        if (out) { memset(out, 0, size); *(WORD *)(out + 8 + 22) = 1; put_affinity(out + 8 + 24); }
        break;
    case RelationNumaNode:
        size = 8 + 24 + 16;                                /* NodeNumber, Reserved[18], GroupCount, GroupMask */
        if (out) { memset(out, 0, size); *(WORD *)(out + 8 + 22) = 1; put_affinity(out + 8 + 24); }
        break;
    case RelationCache:
        size = 8 + 32 + 16;                                /* Level, Associativity, LineSize, CacheSize, Type, Reserved[18], GroupCount, GroupMask */
        if (out) {
            memset(out, 0, size);
            out[8] = c->level; out[9] = c->assoc; *(WORD *)(out + 10) = c->line; *(DWORD *)(out + 12) = c->size;
            *(DWORD *)(out + 16) = (DWORD)c->type; *(WORD *)(out + 8 + 30) = 1; put_affinity(out + 8 + 32);
        }
        break;
    case RelationGroup:
        size = 8 + 24 + 48;                                /* MaximumGroupCount, ActiveGroupCount, Reserved[20], GroupInfo[1] */
        if (out) {
            memset(out, 0, size);
            *(WORD *)(out + 8) = 1; *(WORD *)(out + 10) = 1;
            out[8 + 24] = 1; out[8 + 25] = 1;              /* MaximumProcessorCount, ActiveProcessorCount */
            { ULONG64 m = 1; memcpy(out + 8 + 24 + 40, &m, 8); }                       /* ActiveProcessorMask */
        }
        break;
    default:
        return 0;
    }
    if (out) { memcpy(out, &r, 4); memcpy(out + 4, &size, 4); }
    return size;
}

K32API BOOL WINAPI GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP rel, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX buf, PDWORD len)
{
    cache_t c[16];
    const unsigned nc = cpu_caches(c, 16);
    const int want = (int)rel;
    static const int order[] = { RelationProcessorCore, RelationNumaNode, RelationCache, RelationProcessorPackage, RelationGroup };
    unsigned need = 0, pass, i, j, off;
    BYTE *out = (BYTE *)buf;
    if (!len) return fail_err(ERROR_INVALID_PARAMETER);
    if (want != RelationAll && (want < RelationProcessorCore || want > 7)) return fail_err(ERROR_INVALID_PARAMETER);
    for (pass = 0; pass < 2; ++pass) {
        off = 0;
        for (i = 0; i < sizeof order / sizeof order[0]; ++i) {
            if (want != RelationAll && want != order[i]) continue;
            if (order[i] == RelationCache) {
                for (j = 0; j < nc; ++j) off += ex_record(pass ? out + off : 0, RelationCache, &c[j]);
            } else {
                off += ex_record(pass ? out + off : 0, order[i], 0);
            }
        }
        if (!pass) {
            need = off;
            if (!buf || *len < need) { *len = need; return fail_err(ERROR_INSUFFICIENT_BUFFER); }
        }
    }
    *len = need;
    return TRUE;
}

/* ---------------------------------------------------------------- firmware, names, product, version */
K32API BOOL WINAPI GetFirmwareType(PFIRMWARE_TYPE type)
{
    ULONG v = 0;
    NTSTATUS st;
    if (!type) return fail_err(ERROR_INVALID_PARAMETER);
    st = NtShzQueryK32(K32Q_FIRMWARE, 0, &v, sizeof v, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    *type = (FIRMWARE_TYPE)v;
    return TRUE;
}

/* The host name is the computer name (the name the loader exports as COMPUTERNAME and the registry holds); no DNS domain is
 * configured, so the domain is empty and the fully qualified name is the host name. */
K32API BOOL WINAPI GetComputerNameExW(COMPUTER_NAME_FORMAT fmt, LPWSTR buf, LPDWORD size)
{
    WCHAR name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n = MAX_COMPUTERNAME_LENGTH + 1;
    const WCHAR *src;
    DWORD len;
    if (!size) return fail_err(ERROR_INVALID_PARAMETER);
    switch ((int)fmt) {
    case ComputerNameNetBIOS: case ComputerNameDnsHostname: case ComputerNameDnsFullyQualified:
    case ComputerNamePhysicalNetBIOS: case ComputerNamePhysicalDnsHostname: case ComputerNamePhysicalDnsFullyQualified:
        if (!GetComputerNameW(name, &n)) return FALSE;
        src = name;
        break;
    case ComputerNameDnsDomain: case ComputerNamePhysicalDnsDomain:
        name[0] = 0;
        src = name;
        break;
    default:
        return fail_err(ERROR_INVALID_PARAMETER);
    }
    len = (DWORD)k32_wlen(src);
    if (!buf || *size < len + 1) { *size = len + 1; return fail_err(ERROR_MORE_DATA); }
    memcpy(buf, src, (len + 1) * sizeof(WCHAR));
    *size = len;
    return TRUE;
}

K32API BOOL WINAPI GetProductInfo(DWORD os_major, DWORD os_minor, DWORD sp_major, DWORD sp_minor, PDWORD type)
{
    (void)os_major; (void)os_minor; (void)sp_major; (void)sp_minor;
    if (!type) return fail_err(ERROR_INVALID_PARAMETER);
    *type = PRODUCT_UNDEFINED;                            /* not a Windows edition */
    return TRUE;
}

/* VerSetConditionMask: kernel32 forwards it to ntdll (as on Windows), see ntdll_main.c. */

static int cmp_cond(ULONGLONG cur, ULONGLONG want, unsigned cond)
{
    switch (cond) {
    case VER_EQUAL: return cur == want;
    case VER_GREATER: return cur > want;
    case VER_GREATER_EQUAL: return cur >= want;
    case VER_LESS: return cur < want;
    case VER_LESS_EQUAL: return cur <= want;
    default: return -1;
    }
}

static unsigned cond_of(ULONGLONG mask, DWORD bit)
{
    unsigned i = 0;
    while (!(bit & 1)) { bit >>= 1; ++i; }
    return (unsigned)((mask >> (3 * i)) & 7);
}

K32API BOOL WINAPI VerifyVersionInfoW(LPOSVERSIONINFOEXW vi, DWORD type, DWORDLONG mask)
{
    const uint64_t peb = shz_peb();
    const ULONG major = PEB_OS_MAJOR(peb), minor = PEB_OS_MINOR(peb), build = PEB_OS_BUILD(peb), platform = PEB_OS_PLATFORM(peb);
    const WORD csd = *(const WORD *)(peb + 0x122);        /* PEB.OSCSDVersion: service pack major in the high byte */
    const ULONG cur[4] = { major, minor, (ULONG)(csd >> 8), (ULONG)(csd & 0xff) };
    static const DWORD comp_bit[4] = { VER_MAJORVERSION, VER_MINORVERSION, VER_SERVICEPACKMAJOR, VER_SERVICEPACKMINOR };
    ULONG req[4];
    unsigned i, last = 0;
    int r;
    if (!vi || !type || !mask) return fail_err(ERROR_BAD_ARGUMENTS);
    req[0] = vi->dwMajorVersion; req[1] = vi->dwMinorVersion; req[2] = vi->wServicePackMajor; req[3] = vi->wServicePackMinor;
    if (type & VER_PRODUCT_TYPE) {
        if ((r = cmp_cond(VER_NT_WORKSTATION, vi->wProductType, cond_of(mask, VER_PRODUCT_TYPE))) < 0) return fail_err(ERROR_BAD_ARGUMENTS);
        if (!r) return fail_err(ERROR_OLD_WIN_VERSION);
    }
    if (type & VER_SUITENAME) {                           /* no suite is present */
        const unsigned c = cond_of(mask, VER_SUITENAME);
        if (c != VER_AND && c != VER_OR) return fail_err(ERROR_BAD_ARGUMENTS);
        if (vi->wSuiteMask) return fail_err(ERROR_OLD_WIN_VERSION);
    }
    if (type & VER_PLATFORMID) {
        if ((r = cmp_cond(platform, vi->dwPlatformId, cond_of(mask, VER_PLATFORMID))) < 0) return fail_err(ERROR_BAD_ARGUMENTS);
        if (!r) return fail_err(ERROR_OLD_WIN_VERSION);
    }
    if (type & VER_BUILDNUMBER) {
        if ((r = cmp_cond(build, vi->dwBuildNumber, cond_of(mask, VER_BUILDNUMBER))) < 0) return fail_err(ERROR_BAD_ARGUMENTS);
        if (!r) return fail_err(ERROR_OLD_WIN_VERSION);
    }
    /* major.minor.spmajor.spminor compare as one hierarchical value: the first component that differs decides with its
     * condition (a component without a condition takes the one of the component before it); all equal: equality decides. */
    for (i = 0; i < 4; ++i) {
        unsigned c;
        if (!(type & comp_bit[i])) continue;
        c = cond_of(mask, comp_bit[i]);
        if (!c) c = last;
        if (!c) return fail_err(ERROR_BAD_ARGUMENTS);
        last = c;
        if (cur[i] != req[i]) {
            if ((r = cmp_cond(cur[i], req[i], c)) < 0) return fail_err(ERROR_BAD_ARGUMENTS);
            return r ? TRUE : fail_err(ERROR_OLD_WIN_VERSION);
        }
    }
    if (last && !cmp_cond(0, 0, last)) return fail_err(ERROR_OLD_WIN_VERSION);    /* all equal but strictly greater/less asked */
    return TRUE;
}

/* ---------------------------------------------------------------- power */
K32API BOOL WINAPI GetSystemPowerStatus(LPSYSTEM_POWER_STATUS ps)
{
    if (!ps) return fail_err(ERROR_INVALID_PARAMETER);
    ps->ACLineStatus = 255;                               /* unknown: no AC adapter driver */
    ps->BatteryFlag = 255;                                /* unknown: no battery driver */
    ps->BatteryLifePercent = 255;
    ps->SystemStatusFlag = 0;                             /* battery saver off */
    ps->BatteryLifeTime = (DWORD)-1;
    ps->BatteryFullLifeTime = (DWORD)-1;
    return TRUE;
}

/* SetThreadExecutionState: the calling thread's continuous state lives in a TLS slot of kernel32. */
#ifndef ES_AWAYMODE_REQUIRED
#define ES_AWAYMODE_REQUIRED 0x00000040
#endif
static DWORD g_exec_tls = TLS_OUT_OF_INDEXES;
static INIT_ONCE g_exec_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK exec_tls_init(PINIT_ONCE o, PVOID p, PVOID *c) { (void)o; (void)p; (void)c; g_exec_tls = TlsAlloc(); return g_exec_tls != TLS_OUT_OF_INDEXES; }

K32API EXECUTION_STATE WINAPI SetThreadExecutionState(EXECUTION_STATE flags)
{
    const DWORD valid = ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_AWAYMODE_REQUIRED | ES_CONTINUOUS;
    DWORD prev;
    if ((flags & ~valid) || !InitOnceExecuteOnce(&g_exec_once, exec_tls_init, 0, 0)) return 0;
    prev = (DWORD)(ULONG_PTR)TlsGetValue(g_exec_tls) | ES_CONTINUOUS;          /* previous state always carries ES_CONTINUOUS */
    if (flags & ES_CONTINUOUS) TlsSetValue(g_exec_tls, (PVOID)(ULONG_PTR)(flags & ~ES_CONTINUOUS));
    return prev;
}

/* Power requests: a request is a kernel event (so CloseHandle works) plus per-type counts kept by kernel32. */
#define POWER_TYPES 4                                     /* DisplayRequired, SystemRequired, AwayModeRequired, ExecutionRequired */
typedef struct preq { struct preq *next; HANDLE h; LONG count[POWER_TYPES]; } preq_t;
static preq_t *g_preqs;
static SRWLOCK g_preq_lock = SRWLOCK_INIT;
typedef struct { ULONG Version; DWORD Flags; PVOID a, b; } shz_reason_context;       /* REASON_CONTEXT prefix */

K32API HANDLE WINAPI PowerCreateRequest(PREASON_CONTEXT ctx)
{
    const shz_reason_context *rc = (const shz_reason_context *)ctx;
    preq_t *r;
    if (!rc || rc->Version != 0 || (rc->Flags != 1 && rc->Flags != 2)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    r = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, sizeof *r);
    if (!r) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; }
    r->h = CreateEventW(0, TRUE, FALSE, 0);
    if (!r->h) { RtlFreeHeap(ShzProcessHeap(), 0, r); return INVALID_HANDLE_VALUE; }
    AcquireSRWLockExclusive(&g_preq_lock);
    r->next = g_preqs;
    g_preqs = r;
    ReleaseSRWLockExclusive(&g_preq_lock);
    return r->h;
}

static BOOL power_change(HANDLE h, int type, int delta)
{
    preq_t *r;
    BOOL ok = FALSE;
    if (type < 0 || type >= POWER_TYPES) return fail_err(ERROR_INVALID_PARAMETER);
    AcquireSRWLockExclusive(&g_preq_lock);
    for (r = g_preqs; r && r->h != h; r = r->next) { }
    if (r && (delta > 0 || r->count[type] > 0)) { r->count[type] += delta; ok = TRUE; }
    ReleaseSRWLockExclusive(&g_preq_lock);
    if (!r) return fail_err(ERROR_INVALID_HANDLE);
    return ok ? TRUE : fail_err(ERROR_INVALID_PARAMETER);             /* clearing a request type that is not set */
}

K32API BOOL WINAPI PowerSetRequest(HANDLE h, POWER_REQUEST_TYPE type) { return power_change(h, (int)type, 1); }
K32API BOOL WINAPI PowerClearRequest(HANDLE h, POWER_REQUEST_TYPE type) { return power_change(h, (int)type, -1); }

void k32_power_request_closing(HANDLE h)
{
    preq_t **pp, *r = 0;
    AcquireSRWLockExclusive(&g_preq_lock);
    for (pp = &g_preqs; *pp; pp = &(*pp)->next)
        if ((*pp)->h == h) { r = *pp; *pp = r->next; break; }
    ReleaseSRWLockExclusive(&g_preq_lock);
    if (r) RtlFreeHeap(ShzProcessHeap(), 0, r);
}
