/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: time, code-page conversion, system information and small utilities.
 * The system code page is 65001 (UTF-8); other code pages are reported as invalid instead of
 * being approximated. */
#include "k32.h"

int k32_utf8_to_wide(const char *s, int n, WCHAR *w, int cap);
int k32_wide_to_utf8(const WCHAR *w, int n, char *s, int cap);

/* ---------------------------------------------------------------- time */
static ULONGLONG uptime_ns(void)
{
    LARGE_INTEGER c, f;
    NtQueryPerformanceCounter(&c, &f);
    return (ULONGLONG)c.QuadPart;
}
K32API ULONGLONG WINAPI GetTickCount64(void) { return uptime_ns() / 1000000ull; }

/* Interrupt time: 100 ns units since boot, from the same clock as QueryPerformanceCounter. The machine never sleeps or
 * hibernates, so the unbiased time (which excludes sleep) equals it; the non-precise variants return the same value. */
K32API VOID WINAPI QueryInterruptTimePrecise(PULONGLONG t) { *t = uptime_ns() / 100ull; }
K32API VOID WINAPI QueryInterruptTime(PULONGLONG t) { *t = uptime_ns() / 100ull; }
K32API VOID WINAPI QueryUnbiasedInterruptTimePrecise(PULONGLONG t) { *t = uptime_ns() / 100ull; }
K32API BOOL WINAPI QueryUnbiasedInterruptTime(PULONGLONG t)
{
    if (!t) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    *t = uptime_ns() / 100ull;
    return TRUE;
}

/* CompareObjectHandles: TRUE when both handles (pseudo handles included) refer to the same kernel object. */
K32API BOOL WINAPI CompareObjectHandles(HANDLE a, HANDLE b)
{
    ULONG got = 0;
    return NtShzQueryK32(K32Q_SAME_OBJECT, a, &b, sizeof b, &got) == 0;   /* STATUS_NOT_SAME_OBJECT otherwise; no last error */
}
K32API DWORD WINAPI GetTickCount(void) { return (DWORD)GetTickCount64(); }
K32API BOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER *c)
{
    LARGE_INTEGER f;
    NtQueryPerformanceCounter(c, &f);
    return TRUE;
}
K32API BOOL WINAPI QueryPerformanceFrequency(LARGE_INTEGER *f)
{
    LARGE_INTEGER c;
    NtQueryPerformanceCounter(&c, f);
    return TRUE;
}
K32API VOID WINAPI GetSystemTimeAsFileTime(LPFILETIME ft)
{
    LARGE_INTEGER t;
    NtQuerySystemTime(&t);
    ft->dwLowDateTime = (DWORD)t.QuadPart;
    ft->dwHighDateTime = (DWORD)(t.QuadPart >> 32);
}
K32API VOID WINAPI GetSystemTimePreciseAsFileTime(LPFILETIME ft) { GetSystemTimeAsFileTime(ft); }

static const int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
static int leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

K32API BOOL WINAPI FileTimeToSystemTime(const FILETIME *ft, LPSYSTEMTIME st)
{
    ULONGLONG t = ((ULONGLONG)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
    ULONGLONG ms = t / 10000, days;
    int y = 1601, m;
    if (t >= 0x8000000000000000ull) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    days = ms / 86400000ull;
    st->wMilliseconds = (WORD)(ms % 1000);
    st->wSecond = (WORD)(ms / 1000 % 60);
    st->wMinute = (WORD)(ms / 60000 % 60);
    st->wHour = (WORD)(ms / 3600000 % 24);
    st->wDayOfWeek = (WORD)((days + 1) % 7);                    /* 1601-01-01 was a Monday */
    for (;;) {
        const ULONGLONG yd = leap(y) ? 366 : 365;
        if (days < yd) break;
        days -= yd;
        ++y;
    }
    for (m = 0; m < 12; ++m) {
        ULONGLONG md = (ULONGLONG)mdays[m] + (m == 1 && leap(y));
        if (days < md) break;
        days -= md;
    }
    st->wYear = (WORD)y;
    st->wMonth = (WORD)(m + 1);
    st->wDay = (WORD)(days + 1);
    return TRUE;
}
K32API BOOL WINAPI SystemTimeToFileTime(const SYSTEMTIME *st, LPFILETIME ft)
{
    ULONGLONG days = 0;
    int y, m;
    if (st->wYear < 1601 || st->wMonth < 1 || st->wMonth > 12 || st->wDay < 1) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (y = 1601; y < st->wYear; ++y) days += leap(y) ? 366 : 365;
    for (m = 0; m < st->wMonth - 1; ++m) days += (ULONGLONG)mdays[m] + (m == 1 && leap(st->wYear));
    if (st->wDay > mdays[st->wMonth - 1] + (st->wMonth == 2 && leap(st->wYear))) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    days += st->wDay - 1;
    {
        const ULONGLONG t = (((days * 24 + st->wHour) * 60 + st->wMinute) * 60 + st->wSecond) * 1000ull + st->wMilliseconds;
        ft->dwLowDateTime = (DWORD)(t * 10000);
        ft->dwHighDateTime = (DWORD)((t * 10000) >> 32);
    }
    return TRUE;
}
K32API VOID WINAPI GetSystemTime(LPSYSTEMTIME st) { FILETIME ft; GetSystemTimeAsFileTime(&ft); FileTimeToSystemTime(&ft, st); }
K32API VOID WINAPI GetLocalTime(LPSYSTEMTIME st) { GetSystemTime(st); }          /* the platform clock is UTC; no time zone database */
K32API DWORD WINAPI GetTimeZoneInformation(LPTIME_ZONE_INFORMATION tz)
{
    memset(tz, 0, sizeof *tz);
    tz->StandardName[0] = 'U'; tz->StandardName[1] = 'T'; tz->StandardName[2] = 'C';
    return TIME_ZONE_ID_UNKNOWN;
}
K32API BOOL WINAPI SetSystemTime(const SYSTEMTIME *st) { (void)st; shz_set_last_error(ERROR_ACCESS_DENIED); return FALSE; }

/* ---------------------------------------------------------------- code pages */
K32API UINT WINAPI GetACP(void) { return 65001; }
K32API UINT WINAPI GetOEMCP(void) { return 65001; }
K32API BOOL WINAPI IsValidCodePage(UINT cp) { return cp == 65001 || cp == 0 || cp == 1 || cp == 20127; }
K32API BOOL WINAPI GetCPInfo(UINT cp, LPCPINFO info)
{
    if (!IsValidCodePage(cp)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(info, 0, sizeof *info);
    info->MaxCharSize = cp == 20127 ? 1 : 4;
    info->DefaultChar[0] = '?';
    return TRUE;
}

K32API int WINAPI MultiByteToWideChar(UINT cp, DWORD flags, LPCCH s, int n, LPWSTR w, int cap)
{
    int r;
    if (!s || !n || (cp != 65001 && cp != 0 && cp != 1 && cp != 20127 && cp != 65000)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (n < 0) { n = 0; while (s[n]) ++n; ++n; }
    if (flags & MB_ERR_INVALID_CHARS) {                           /* validate strictly */
        int i = 0;
        while (i < n) {
            unsigned char c = (unsigned char)s[i];
            int len = c < 0x80 ? 1 : (c & 0xe0) == 0xc0 ? 2 : (c & 0xf0) == 0xe0 ? 3 : (c & 0xf8) == 0xf0 ? 4 : 0;
            int k;
            if (!len || i + len > n || (len == 2 && c < 0xc2)) { shz_set_last_error(ERROR_NO_UNICODE_TRANSLATION); return 0; }
            for (k = 1; k < len; ++k) if (((unsigned char)s[i + k] & 0xc0) != 0x80) { shz_set_last_error(ERROR_NO_UNICODE_TRANSLATION); return 0; }
            i += len;
        }
    }
    if (!cap) {                                                   /* size query */
        WCHAR tmp[4096];
        int total = 0, off = 0;
        while (off < n) {
            int chunk = n - off > 1000 ? 1000 : n - off;
            while (chunk > 1 && chunk < n - off && ((unsigned char)s[off + chunk] & 0xc0) == 0x80) --chunk;   /* do not split a sequence */
            r = k32_utf8_to_wide(s + off, chunk, tmp, 4096);
            total += r;
            off += chunk;
        }
        return total;
    }
    r = k32_utf8_to_wide(s, n, w, cap);
    if (!r) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    return r;
}
K32API int WINAPI WideCharToMultiByte(UINT cp, DWORD flags, LPCWCH w, int n, LPSTR s, int cap, LPCCH def, LPBOOL used)
{
    int r;
    (void)flags; (void)def;
    if (used) *used = FALSE;
    if (!w || !n || (cp != 65001 && cp != 0 && cp != 1 && cp != 65000)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (n < 0) { n = 0; while (w[n]) ++n; ++n; }
    if (!cap) {
        char tmp[4096];
        int total = 0, off = 0;
        while (off < n) {
            int chunk = n - off > 1000 ? 1000 : n - off;
            if (chunk < n - off && w[off + chunk - 1] >= 0xd800 && w[off + chunk - 1] < 0xdc00) --chunk;
            r = k32_wide_to_utf8(w + off, chunk, tmp, sizeof tmp);
            total += r;
            off += chunk;
        }
        return total;
    }
    r = k32_wide_to_utf8(w, n, s, cap);
    if (!r) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    return r;
}

/* ---------------------------------------------------------------- strings */
K32API int WINAPI lstrlenA(LPCSTR s) { int n = 0; while (s && s[n]) ++n; return n; }
K32API int WINAPI lstrlenW(LPCWSTR s) { int n = 0; while (s && s[n]) ++n; return n; }
K32API LPSTR WINAPI lstrcpyA(LPSTR d, LPCSTR s) { char *r = d; while ((*d++ = *s++)) { } return r; }
K32API LPWSTR WINAPI lstrcpyW(LPWSTR d, LPCWSTR s) { WCHAR *r = d; while ((*d++ = *s++)) { } return r; }
K32API int WINAPI lstrcmpA(LPCSTR a, LPCSTR b) { while (*a && *a == *b) { ++a; ++b; } return (unsigned char)*a - (unsigned char)*b; }
K32API int WINAPI lstrcmpiA(LPCSTR a, LPCSTR b)
{
    for (;; ++a, ++b) {
        int x = (unsigned char)*a, y = (unsigned char)*b;
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y || !x) return x - y;
    }
}
K32API int WINAPI CompareStringOrdinal(LPCWCH a, int an, LPCWCH b, int bn, BOOL ignore_case)
{
    int i;
    if (an < 0) an = lstrlenW(a);
    if (bn < 0) bn = lstrlenW(b);
    for (i = 0; i < an && i < bn; ++i) {
        WCHAR x = a[i], y = b[i];
        if (ignore_case) { if (x >= 'a' && x <= 'z') x -= 32; if (y >= 'a' && y <= 'z') y -= 32; }
        if (x != y) return x < y ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
    }
    return an == bn ? CSTR_EQUAL : an < bn ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
}

/* ---------------------------------------------------------------- system information */
K32API VOID WINAPI GetSystemInfo(LPSYSTEM_INFO si)
{
    memset(si, 0, sizeof *si);
    si->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
    si->dwPageSize = 4096;
    si->lpMinimumApplicationAddress = (LPVOID)0x10000;
    si->lpMaximumApplicationAddress = (LPVOID)0x7ffffffeffffull;
    si->dwActiveProcessorMask = 1;
    si->dwNumberOfProcessors = 1;
    si->dwProcessorType = 8664;
    si->dwAllocationGranularity = 65536;
    si->wProcessorLevel = 6;
}
K32API VOID WINAPI GetNativeSystemInfo(LPSYSTEM_INFO si) { GetSystemInfo(si); }
K32API BOOL WINAPI GlobalMemoryStatusEx(LPMEMORYSTATUSEX m)
{
    struct { ULONG64 total_pages, free_pages; } q;
    if (NtQuerySystemInformation(0x100, &q, sizeof q, 0)) { shz_set_last_error(ERROR_GEN_FAILURE); return FALSE; }
    memset(m, 0, sizeof *m);
    m->dwLength = sizeof *m;
    m->dwMemoryLoad = q.total_pages ? (DWORD)((q.total_pages - q.free_pages) * 100 / q.total_pages) : 0;
    m->ullTotalPhys = q.total_pages * 4096;
    m->ullAvailPhys = q.free_pages * 4096;
    m->ullTotalVirtual = 0x7ffffffe0000ull;
    m->ullAvailVirtual = 0x7ffffffe0000ull;
    m->ullTotalPageFile = m->ullTotalPhys;
    m->ullAvailPageFile = m->ullAvailPhys;
    return TRUE;
}
K32API BOOL WINAPI IsProcessorFeaturePresent(DWORD f)
{
    unsigned a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    switch (f) {
    case PF_MMX_INSTRUCTIONS_AVAILABLE: return (d >> 23) & 1;
    case PF_XMMI_INSTRUCTIONS_AVAILABLE: return (d >> 25) & 1;
    case PF_XMMI64_INSTRUCTIONS_AVAILABLE: return (d >> 26) & 1;
    case PF_SSE3_INSTRUCTIONS_AVAILABLE: return c & 1;
    case PF_COMPARE_EXCHANGE_DOUBLE: return (d >> 8) & 1;
    case PF_COMPARE_EXCHANGE128: return (c >> 13) & 1;
    case PF_PAE_ENABLED: return 1;
    case PF_NX_ENABLED: return 1;
    case PF_FASTFAIL_AVAILABLE: return 0;
    default: return 0;                                            /* unknown features are reported as absent */
    }
}
/* GetVersionExW lies the way Windows 8.1+ lies: the version it reports depends on the supportedOS GUIDs in the
 * application manifest (RT_MANIFEST resource of the main image). With the Windows 10 GUID the true version (the PEB's,
 * what RtlGetVersion reports) is returned; with the Windows 8.1 GUID 6.3 (9600); with none 6.2 (9200). Chromium's
 * manifest carries the Windows 10 GUID and its base::win::OSInfo trusts GetVersionEx. The manifest is scanned once per
 * process, as raw bytes (UTF-8 or UTF-16, either GUID case). */
static int manifest_has_guid(const BYTE *m, DWORD n, const char *guid)
{
    DWORD i;
    unsigned k, len = 0;
    while (guid[len]) ++len;
    for (i = 0; i + len <= n; ++i) {
        for (k = 0; k < len; ++k) { char c = (char)m[i + k]; if (c >= 'A' && c <= 'Z') c = (char)(c + 32); if (c != guid[k]) break; }
        if (k == len) return 1;
        if (i + 2 * len <= n) {                                        /* UTF-16LE */
            for (k = 0; k < len; ++k) { char c = (char)m[i + 2 * k]; if (m[i + 2 * k + 1]) break; if (c >= 'A' && c <= 'Z') c = (char)(c + 32); if (c != guid[k]) break; }
            if (k == len) return 1;
        }
    }
    return 0;
}

#define K32_INTRESOURCE(i) ((LPCWSTR)(ULONG_PTR)(WORD)(i))
static void k32_manifest_version(DWORD *major, DWORD *minor, DWORD *build)
{
    static DWORD cached[3];
    if (!cached[0]) {
        DWORD v[3] = { 6, 2, 9200 };
        HMODULE exe = GetModuleHandleW(0);
        HRSRC r = exe ? FindResourceW(exe, K32_INTRESOURCE(1), K32_INTRESOURCE(24)) : 0;     /* RT_MANIFEST, CREATEPROCESS_MANIFEST_RESOURCE_ID */
        if (!r && exe) r = FindResourceW(exe, K32_INTRESOURCE(2), K32_INTRESOURCE(24));    /* ISOLATIONAWARE_MANIFEST_RESOURCE_ID */
        if (r) {
            const BYTE *m = LockResource(LoadResource(exe, r));
            const DWORD n = SizeofResource(exe, r);
            if (m && n) {
                const uint64_t peb = shz_peb();
                if (manifest_has_guid(m, n, "8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a")) {         /* Windows 10 / 11 */
                    v[0] = PEB_OS_MAJOR(peb); v[1] = PEB_OS_MINOR(peb); v[2] = PEB_OS_BUILD(peb);
                } else if (manifest_has_guid(m, n, "1f676c76-80e1-4239-95bb-83d0f6d0da78")) {  /* Windows 8.1 */
                    v[0] = 6; v[1] = 3; v[2] = 9600;
                }
            }
        }
        shz_set_last_error(0);
        cached[1] = v[1]; cached[2] = v[2]; cached[0] = v[0];
    }
    *major = cached[0]; *minor = cached[1]; *build = cached[2];
}

K32API BOOL WINAPI GetVersionExW(LPOSVERSIONINFOW v)
{
    if (v->dwOSVersionInfoSize < sizeof(OSVERSIONINFOW)) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    k32_manifest_version(&v->dwMajorVersion, &v->dwMinorVersion, &v->dwBuildNumber);
    v->dwPlatformId = VER_PLATFORM_WIN32_NT;
    v->szCSDVersion[0] = 0;
    if (v->dwOSVersionInfoSize >= sizeof(OSVERSIONINFOEXW)) {
        LPOSVERSIONINFOEXW x = (LPOSVERSIONINFOEXW)v;
        x->wServicePackMajor = 0; x->wServicePackMinor = 0; x->wSuiteMask = 0; x->wProductType = VER_NT_WORKSTATION; x->wReserved = 0;
    }
    return TRUE;
}
K32API BOOL WINAPI GetComputerNameW(LPWSTR buf, LPDWORD n)
{
    static const WCHAR name[] = { 'S','H','Z','-','K','6','4', 0 };
    if (*n < 8) { *n = 8; shz_set_last_error(ERROR_BUFFER_OVERFLOW); return FALSE; }
    memcpy(buf, name, sizeof name);
    *n = 7;
    return TRUE;
}
K32API BOOL WINAPI GetProcessAffinityMask(HANDLE p, PDWORD_PTR pm, PDWORD_PTR sm) { (void)p; *pm = 1; *sm = 1; return TRUE; }
K32API DWORD_PTR WINAPI SetThreadAffinityMask(HANDLE t, DWORD_PTR m)
{
    struct { LONG64 exit_status; ULONG64 teb, pid, tid, aff; LONG prio, base; } b;
    NTSTATUS st = NtQueryInformationThread(t, 0, &b, sizeof b, 0);
    if (st) { k32_nt_error(st); return 0; }
    st = NtSetInformationThread(t, 4, &m, sizeof m);
    if (st) { k32_nt_error(st); return 0; }
    return (DWORD_PTR)b.aff;
}
