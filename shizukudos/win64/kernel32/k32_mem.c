/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: virtual memory, heaps, module loading and process environment. */
#include "k32.h"

int k32_utf8_to_wide(const char *s, int n, WCHAR *w, int cap);
int k32_wide_to_utf8(const WCHAR *w, int n, char *s, int cap);

/* ---------------------------------------------------------------- virtual memory */
K32API LPVOID WINAPI VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD prot)
{
    PVOID base = addr;
    SIZE_T sz = size;
    NTSTATUS st = NtAllocateVirtualMemory(CURRENT_PROCESS, &base, 0, &sz, type, prot);
    if (st) { k32_nt_error(st); return 0; }
    return base;
}
K32API LPVOID WINAPI VirtualAllocEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD type, DWORD prot)
{
    PVOID base = addr;
    SIZE_T sz = size;
    NTSTATUS st = NtAllocateVirtualMemory(proc, &base, 0, &sz, type, prot);
    if (st) { k32_nt_error(st); return 0; }
    return base;
}
K32API BOOL WINAPI VirtualFree(LPVOID addr, SIZE_T size, DWORD type)
{
    PVOID base = addr;
    SIZE_T sz = size;
    NTSTATUS st = NtFreeVirtualMemory(CURRENT_PROCESS, &base, &sz, type);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
K32API BOOL WINAPI VirtualProtect(LPVOID addr, SIZE_T size, DWORD prot, PDWORD old)
{
    PVOID base = addr;
    SIZE_T sz = size;
    ULONG o = 0;
    NTSTATUS st = NtProtectVirtualMemory(CURRENT_PROCESS, &base, &sz, prot, &o);
    if (st) { k32_nt_error(st); return FALSE; }
    if (old) *old = o;
    return TRUE;
}
K32API SIZE_T WINAPI VirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T len)
{
    SIZE_T ret = 0;
    NTSTATUS st;
    if (len < sizeof *mbi) { shz_set_last_error(ERROR_BAD_LENGTH); return 0; }
    st = NtQueryVirtualMemory(CURRENT_PROCESS, (PVOID)addr, 0, mbi, sizeof *mbi, &ret);
    if (st) { k32_nt_error(st); return 0; }
    return sizeof *mbi;
}
K32API BOOL WINAPI FlushInstructionCache(HANDLE p, LPCVOID a, SIZE_T n) { (void)p; (void)a; (void)n; return TRUE; }   /* x86 keeps I/D coherent */

/* ---------------------------------------------------------------- heaps */
K32API HANDLE WINAPI GetProcessHeap(void) { return ShzProcessHeap(); }
K32API HANDLE WINAPI HeapCreate(DWORD flags, SIZE_T init, SIZE_T max)
{
    PVOID h = RtlCreateHeap(flags, 0, max, init, 0, 0);
    if (!h) shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    return h;
}
K32API BOOL WINAPI HeapDestroy(HANDLE h) { if (RtlDestroyHeap(h)) return TRUE; shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
K32API LPVOID WINAPI HeapAlloc(HANDLE h, DWORD flags, SIZE_T size)
{
    PVOID p = RtlAllocateHeap(h, flags, size);
    if (!p) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); if (flags & HEAP_GENERATE_EXCEPTIONS) RaiseException(STATUS_NO_MEMORY, 0, 0, 0); }
    return p;
}
K32API LPVOID WINAPI HeapReAlloc(HANDLE h, DWORD flags, LPVOID p, SIZE_T size)
{
    PVOID n = RtlReAllocateHeap(h, flags, p, size);
    if (!n) shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    return n;
}
K32API BOOL WINAPI HeapFree(HANDLE h, DWORD flags, LPVOID p)
{
    if (!RtlFreeHeap(h, flags, p)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}
K32API SIZE_T WINAPI HeapSize(HANDLE h, DWORD flags, LPCVOID p) { return RtlSizeHeap(h, flags, (PVOID)p); }
K32API BOOL WINAPI HeapValidate(HANDLE h, DWORD flags, LPCVOID p) { return RtlValidateHeap(h, flags, (PVOID)p); }

/* ---------------------------------------------------------------- heap enumeration and settings (ntdll heap) */
ULONG NTAPI RtlGetProcessHeaps(ULONG, PVOID *);
SIZE_T NTAPI RtlCompactHeap(PVOID, ULONG);
BOOLEAN NTAPI RtlLockHeap(PVOID);
BOOLEAN NTAPI RtlUnlockHeap(PVOID);
NTSTATUS NTAPI RtlWalkHeap(PVOID, PVOID);

K32API DWORD WINAPI GetProcessHeaps(DWORD n, PHANDLE heaps) { return RtlGetProcessHeaps(n, (PVOID *)heaps); }

K32API SIZE_T WINAPI HeapCompact(HANDLE h, DWORD flags)
{
    SIZE_T n;
    if (!RtlValidateHeap(h, 0, 0)) { shz_set_last_error(ERROR_INVALID_HANDLE); return 0; }
    n = RtlCompactHeap(h, flags);
    if (!n) shz_set_last_error(NO_ERROR);                  /* documented: no free block at all is not an error */
    return n;
}

K32API BOOL WINAPI HeapLock(HANDLE h) { if (RtlLockHeap(h)) return TRUE; shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
K32API BOOL WINAPI HeapUnlock(HANDLE h)
{
    if (RtlUnlockHeap(h)) return TRUE;
    shz_set_last_error(RtlValidateHeap(h, 0, 0) ? ERROR_NOT_OWNER : ERROR_INVALID_HANDLE);
    return FALSE;
}

/* RTL_HEAP_WALK_ENTRY (ntdll) <-> PROCESS_HEAP_ENTRY */
typedef struct {
    PVOID DataAddress; SIZE_T DataSize; UCHAR OverheadBytes, SegmentIndex; USHORT Flags;
    union { struct { SIZE_T Settable; USHORT TagIndex, BackTraceIndex; ULONG Reserved[2]; } Block;
            struct { ULONG CommittedSize, UnCommittedSize; PVOID FirstEntry, LastEntry; } Segment; } u;
} rtl_walk_entry;

K32API BOOL WINAPI HeapWalk(HANDLE h, LPPROCESS_HEAP_ENTRY e)
{
    rtl_walk_entry r;
    NTSTATUS st;
    if (!e) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(&r, 0, sizeof r);
    r.DataAddress = e->lpData;
    st = RtlWalkHeap(h, &r);
    if (st == (NTSTATUS)0x8000001A) { shz_set_last_error(ERROR_NO_MORE_ITEMS); return FALSE; }      /* STATUS_NO_MORE_ENTRIES */
    if (st) { k32_nt_error(st); return FALSE; }
    memset(e, 0, sizeof *e);
    e->lpData = r.DataAddress;
    e->cbData = (DWORD)r.DataSize;
    e->cbOverhead = r.OverheadBytes;
    e->iRegionIndex = r.SegmentIndex;
    if (r.Flags & 2) {
        e->wFlags = PROCESS_HEAP_REGION;
        e->Region.dwCommittedSize = r.u.Segment.CommittedSize;
        e->Region.dwUnCommittedSize = r.u.Segment.UnCommittedSize;
        e->Region.lpFirstBlock = r.u.Segment.FirstEntry;
        e->Region.lpLastBlock = r.u.Segment.LastEntry;
    } else if (r.Flags & 1) {
        e->wFlags = PROCESS_HEAP_ENTRY_BUSY;
    }
    return TRUE;
}

K32API BOOL WINAPI HeapSetInformation(HANDLE h, HEAP_INFORMATION_CLASS cls, PVOID info, SIZE_T len)
{
    NTSTATUS st = (NTSTATUS)RtlSetHeapInformation(h, cls, info, len);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- page residency (kernel64/sysk32_proc.c) */
static NTSTATUS range_op(HANDLE proc, ULONG cls, LPCVOID addr, SIZE_T size)
{
    ULONG64 r[2];
    r[0] = (ULONG64)(ULONG_PTR)addr;
    r[1] = size;
    return NtShzSetK32(cls, proc, r, sizeof r);
}

/* Returns a Win32 error code (not through GetLastError). The pages stay committed; their contents are gone (zero on next touch). */
K32API DWORD WINAPI DiscardVirtualMemory(PVOID addr, SIZE_T size)
{
    NTSTATUS st;
    if (!addr || !size) return ERROR_INVALID_PARAMETER;
    st = range_op(GetCurrentProcess(), K32S_DISCARD, addr, size);
    return st ? RtlNtStatusToDosError(st) : ERROR_SUCCESS;
}

K32API BOOL WINAPI PrefetchVirtualMemory(HANDLE proc, ULONG_PTR n, PWIN32_MEMORY_RANGE_ENTRY ranges, ULONG flags)
{
    ULONG_PTR i;
    if (flags || !n || !ranges) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < n; ++i) {
        NTSTATUS st = range_op(proc, K32S_PREFETCH, ranges[i].VirtualAddress, ranges[i].NumberOfBytes);
        if (st) { k32_nt_error(st); return FALSE; }
    }
    return TRUE;
}

K32API BOOL WINAPI VirtualLock(LPVOID addr, SIZE_T size)
{
    NTSTATUS st = range_op(GetCurrentProcess(), K32S_LOCK, addr, size);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI VirtualUnlock(LPVOID addr, SIZE_T size)
{
    NTSTATUS st = range_op(GetCurrentProcess(), K32S_UNLOCK, addr, size);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* Global and Local memory (fixed and movable) live in k32_gmem.c. */

/* ---------------------------------------------------------------- modules */
static HMODULE find_module_w(LPCWSTR name)
{
    SHZ_UNICODE_STRING us;
    PVOID h = 0;
    NTSTATUS st;
    RtlInitUnicodeString(&us, name);
    st = LdrGetDllHandle(0, 0, &us, &h);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}
K32API HMODULE WINAPI GetModuleHandleW(LPCWSTR name)
{
    if (!name) return PEB_IMAGE_BASE(shz_peb());
    return find_module_w(name);
}
K32API HMODULE WINAPI GetModuleHandleA(LPCSTR name)
{
    WCHAR w[260];
    if (!name) return PEB_IMAGE_BASE(shz_peb());
    if (k32_utf8_to_wide(name, -1, w, 260) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return find_module_w(w);
}
K32API HMODULE WINAPI LoadLibraryW(LPCWSTR name)
{
    SHZ_UNICODE_STRING us;
    PVOID h = 0;
    NTSTATUS st;
    RtlInitUnicodeString(&us, name);
    st = LdrLoadDll(0, 0, &us, &h);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}
K32API HMODULE WINAPI LoadLibraryA(LPCSTR name)
{
    WCHAR w[260];
    if (k32_utf8_to_wide(name, -1, w, 260) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return LoadLibraryW(w);
}
/* Search flags (LOAD_LIBRARY_SEARCH_*, LOAD_WITH_ALTERED_SEARCH_PATH) reach the loader through LdrLoadDll's first
 * parameter as (flags << 1) | 1 (ntdll/ldr_search.c). IGNORE_CODE_AUTHZ_LEVEL and SAFE_CURRENT_DIRS change nothing
 * here (no AppLocker; the current directory is already searched after the system directories); SYSTEM32_NO_FORWARDER
 * means SYSTEM32. Data-file and image-resource mappings, DONT_RESOLVE_DLL_REFERENCES and REQUIRE_SIGNED_TARGET are not
 * implemented and fail with ERROR_NOT_SUPPORTED. */
K32API HMODULE WINAPI LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
    const DWORD search = LOAD_WITH_ALTERED_SEARCH_PATH | 0x1f00u;
    const DWORD ignored = 0x10u | 0x2000u;                  /* IGNORE_CODE_AUTHZ_LEVEL, SAFE_CURRENT_DIRS */
    SHZ_UNICODE_STRING us;
    PVOID h = 0;
    NTSTATUS st;
    if (file || !name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & 0x4000u) flags = (flags & ~0x4000u) | 0x800u;  /* SYSTEM32_NO_FORWARDER */
    if (flags & ~(search | ignored)) { shz_set_last_error(ERROR_NOT_SUPPORTED); return 0; }
    if ((flags & LOAD_WITH_ALTERED_SEARCH_PATH) && (flags & 0x1f00u)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    flags &= search;
    RtlInitUnicodeString(&us, name);
    st = LdrLoadDll(flags ? (PWSTR)(ULONG_PTR)(((ULONG_PTR)flags << 1) | 1) : 0, 0, &us, &h);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}
K32API HMODULE WINAPI LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags)
{
    WCHAR w[260];
    if (k32_utf8_to_wide(name, -1, w, 260) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return LoadLibraryExW(w, file, flags);
}
K32API BOOL WINAPI FreeLibrary(HMODULE m)
{
    NTSTATUS st = LdrUnloadDll(m);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
K32API FARPROC WINAPI GetProcAddress(HMODULE m, LPCSTR name)
{
    PVOID addr = 0;
    NTSTATUS st;
    if ((uintptr_t)name < 0x10000) {
        st = LdrGetProcedureAddress(m, 0, (ULONG)(uintptr_t)name, &addr);
    } else {
        struct { USHORT Length, MaximumLength; PCHAR Buffer; } as;
        USHORT n = 0;
        while (name[n]) ++n;
        as.Length = n; as.MaximumLength = n + 1; as.Buffer = (PCHAR)name;
        st = LdrGetProcedureAddress(m, &as, 0, &addr);
    }
    if (st) { k32_nt_error(st == STATUS_ENTRYPOINT_NOT_FOUND || st == STATUS_ORDINAL_NOT_FOUND ? STATUS_ENTRYPOINT_NOT_FOUND : st); return 0; }
    return (FARPROC)addr;
}

static SHZ_LDR_ENTRY *entry_for(HMODULE m)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList, *l;
    if (!m) m = PEB_IMAGE_BASE(shz_peb());
    for (l = head->Flink; l != head; l = l->Flink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InLoadOrderLinks);
        if (e->DllBase == m) return e;
    }
    return 0;
}
K32API DWORD WINAPI GetModuleFileNameW(HMODULE m, LPWSTR buf, DWORD cap)
{
    SHZ_LDR_ENTRY *e = entry_for(m);
    DWORD n;
    if (!e) { shz_set_last_error(ERROR_MOD_NOT_FOUND); return 0; }
    n = e->FullDllName.Length / 2;
    if (n >= cap) { if (cap) { memcpy(buf, e->FullDllName.Buffer, (cap - 1) * sizeof(WCHAR)); buf[cap - 1] = 0; } shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return cap; }
    memcpy(buf, e->FullDllName.Buffer, n * sizeof(WCHAR));
    buf[n] = 0;
    return n;
}
K32API DWORD WINAPI GetModuleFileNameA(HMODULE m, LPSTR buf, DWORD cap)
{
    WCHAR w[300];
    DWORD n = GetModuleFileNameW(m, w, 300);
    int r;
    if (!n) return 0;
    r = k32_wide_to_utf8(w, (int)n + 1, buf, (int)cap);
    if (r <= 0) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return cap; }
    return (DWORD)r - 1;
}

/* ---------------------------------------------------------------- command line, environment, startup info */
K32API LPWSTR WINAPI GetCommandLineW(void)
{
    const uint8_t *params = PEB_PARAMS(shz_peb());
    return *(LPWSTR *)(params + 0x78);
}
K32API LPSTR WINAPI GetCommandLineA(void)
{
    static char *cache;
    if (!cache) {
        LPWSTR w = GetCommandLineW();
        size_t n = k32_wlen(w);
        char *c = RtlAllocateHeap(ShzProcessHeap(), 0, n * 3 + 1);
        if (!c) return 0;
        k32_wide_to_utf8(w, (int)n + 1, c, (int)(n * 3 + 1));
        cache = c;
    }
    return cache;
}

static WCHAR *g_env;                                  /* private copy once the environment is modified */
static WCHAR *env_block(void)
{
    if (g_env) return g_env;
    return *(WCHAR **)(PEB_PARAMS(shz_peb()) + 0x80);
}
K32API LPWCH WINAPI GetEnvironmentStringsW(void) { return env_block(); }
K32API BOOL WINAPI FreeEnvironmentStringsW(LPWCH p) { (void)p; return TRUE; }
K32API DWORD WINAPI GetEnvironmentVariableW(LPCWSTR name, LPWSTR buf, DWORD cap)
{
    const WCHAR *e = env_block();
    size_t nl = k32_wlen(name);
    while (*e) {
        size_t i;
        for (i = 0; i < nl && (e[i] | 32) == (name[i] | 32) && e[i]; ++i) { }
        if (i == nl && e[nl] == '=') {
            size_t vl = k32_wlen(e + nl + 1);
            if (cap <= vl) return (DWORD)vl + 1;
            memcpy(buf, e + nl + 1, (vl + 1) * sizeof(WCHAR));
            return (DWORD)vl;
        }
        e += k32_wlen(e) + 1;
    }
    shz_set_last_error(ERROR_ENVVAR_NOT_FOUND);
    return 0;
}
K32API DWORD WINAPI GetEnvironmentVariableA(LPCSTR name, LPSTR buf, DWORD cap)
{
    WCHAR wn[128], wv[1024];
    DWORD n;
    if (k32_utf8_to_wide(name, -1, wn, 128) <= 0) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    n = GetEnvironmentVariableW(wn, wv, 1024);
    if (!n || n >= 1024) return n;
    {
        int r = k32_wide_to_utf8(wv, (int)n + 1, buf, (int)cap);
        if (r <= 0) return n * 3 + 1;
        return (DWORD)r - 1;
    }
}
static int wcschr_eq(const WCHAR *s, WCHAR c) { for (; *s; ++s) if (*s == c) return 1; return 0; }

K32API BOOL WINAPI SetEnvironmentVariableW(LPCWSTR name, LPCWSTR value)
{
    const WCHAR *e = env_block();
    size_t total = 0, nl = k32_wlen(name), vl = value ? k32_wlen(value) : 0, o = 0;
    WCHAR *n;
    const WCHAR *p;
    if (!nl || wcschr_eq(name, '=')) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (p = e; *p; p += k32_wlen(p) + 1) total += k32_wlen(p) + 1;
    n = RtlAllocateHeap(ShzProcessHeap(), 0, (total + nl + vl + 4) * sizeof(WCHAR));
    if (!n) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    for (p = e; *p; p += k32_wlen(p) + 1) {
        size_t i;
        for (i = 0; i < nl && (p[i] | 32) == (name[i] | 32); ++i) { }
        if (i == nl && p[nl] == '=') continue;                       /* replaced or deleted */
        memcpy(n + o, p, (k32_wlen(p) + 1) * sizeof(WCHAR));
        o += k32_wlen(p) + 1;
    }
    if (value) {
        memcpy(n + o, name, nl * sizeof(WCHAR)); o += nl;
        n[o++] = '=';
        memcpy(n + o, value, (vl + 1) * sizeof(WCHAR)); o += vl + 1;
    }
    n[o] = 0;
    g_env = n;                                                       /* the previous block is leaked deliberately: GetEnvironmentStrings users may hold it */
    return TRUE;
}
K32API BOOL WINAPI SetEnvironmentVariableA(LPCSTR name, LPCSTR value)
{
    WCHAR wn[128], wv[1024];
    if (k32_utf8_to_wide(name, -1, wn, 128) <= 0) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (value && k32_utf8_to_wide(value, -1, wv, 1024) <= 0) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    return SetEnvironmentVariableW(wn, value ? wv : 0);
}
K32API VOID WINAPI GetStartupInfoW(LPSTARTUPINFOW si)
{
    const uint8_t *params = PEB_PARAMS(shz_peb());
    memset(si, 0, sizeof *si);
    si->cb = sizeof *si;
    si->dwFlags = STARTF_USESTDHANDLES;
    si->hStdInput = *(HANDLE *)(params + 0x20);
    si->hStdOutput = *(HANDLE *)(params + 0x28);
    si->hStdError = *(HANDLE *)(params + 0x30);
}
K32API VOID WINAPI GetStartupInfoA(LPSTARTUPINFOA si)
{
    STARTUPINFOW w;
    GetStartupInfoW(&w);
    memset(si, 0, sizeof *si);
    si->cb = sizeof *si;
    si->dwFlags = w.dwFlags;
    si->hStdInput = w.hStdInput; si->hStdOutput = w.hStdOutput; si->hStdError = w.hStdError;
}

/* ---------------------------------------------------------------- process creation */
K32API BOOL WINAPI CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit,
                                  DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    SHZ_UNICODE_STRING image, cmdline;
    WCHAR path[300], nt[320];
    HANDLE hp = 0, ht = 0;
    NTSTATUS st;
    struct { LONG64 es; ULONG64 peb, aff; LONG64 prio; ULONG64 pid, ppid; } b;
    struct { LONG64 es; ULONG64 teb, pid, tid, aff; LONG prio, base; } tb;
    (void)pa; (void)ta; (void)inherit; (void)env; (void)dir; (void)si;
    if (flags & (CREATE_SUSPENDED | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) { shz_set_last_error(ERROR_NOT_SUPPORTED); return FALSE; }
    if (app) {
        size_t n = k32_wlen(app);
        if (n >= 299) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
        memcpy(path, app, (n + 1) * sizeof(WCHAR));
    } else if (cmd) {                                        /* first token of the command line */
        size_t i = 0, o = 0;
        if (cmd[0] == '"') { i = 1; while (cmd[i] && cmd[i] != '"' && o < 299) path[o++] = cmd[i++]; }
        else while (cmd[i] && cmd[i] != ' ' && o < 299) path[o++] = cmd[i++];
        path[o] = 0;
        {
            size_t k = o; int dot = 0;
            while (k) { --k; if (path[k] == '.') { dot = 1; break; } if (path[k] == '\\') break; }
            if (!dot && o + 4 < 299) { path[o++] = '.'; path[o++] = 'e'; path[o++] = 'x'; path[o++] = 'e'; path[o] = 0; }
        }
    } else { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = k32_dos_to_nt(path, nt, 320);
    if (st) { k32_nt_error(st); return FALSE; }
    image.Buffer = nt + 4;                                   /* the kernel takes DOS-style paths */
    image.Length = (USHORT)((k32_wlen(nt) - 4) * 2);
    image.MaximumLength = image.Length + 2;
    if (cmd) { RtlInitUnicodeString(&cmdline, cmd); }
    st = NtCreateProcessEx(&hp, &ht, &image, cmd ? &cmdline : 0, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    memset(pi, 0, sizeof *pi);
    pi->hProcess = hp;
    pi->hThread = ht;
    if (NtQueryInformationProcess(hp, 0, &b, sizeof b, 0) == 0) pi->dwProcessId = (DWORD)b.pid;
    if (NtQueryInformationThread(ht, 0, &tb, sizeof tb, 0) == 0) pi->dwThreadId = (DWORD)tb.tid;
    return TRUE;
}
K32API BOOL WINAPI CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit,
                                  DWORD flags, LPVOID env, LPCSTR dir, LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
    WCHAR wapp[300], wcmd[600], wdir[300];
    (void)si;
    if (app && k32_utf8_to_wide(app, -1, wapp, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    if (cmd && k32_utf8_to_wide(cmd, -1, wcmd, 600) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    if (dir && k32_utf8_to_wide(dir, -1, wdir, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return CreateProcessW(app ? wapp : 0, cmd ? wcmd : 0, pa, ta, inherit, flags, env, dir ? wdir : 0, 0, pi);
}
