/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: virtual memory, heaps, module loading and process environment. */
#include "k32.h"

#define ShzProcessHeap() (*(PVOID *)(shz_peb() + 0x30))

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
K32API BOOL WINAPI HeapDestroy(HANDLE h) { return RtlDestroyHeap(h); }
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

/* Fixed-memory Local and Global allocations only; movable memory (LMEM_MOVEABLE) is not implemented. */
K32API HLOCAL WINAPI LocalAlloc(UINT flags, SIZE_T size)
{
    if (flags & LMEM_MOVEABLE) { shz_set_last_error(ERROR_NOT_SUPPORTED); return 0; }
    return HeapAlloc(ShzProcessHeap(), (flags & LMEM_ZEROINIT) ? HEAP_ZERO_MEMORY : 0, size);
}
K32API HLOCAL WINAPI LocalFree(HLOCAL p) { return HeapFree(ShzProcessHeap(), 0, p) ? 0 : p; }
K32API HLOCAL WINAPI LocalReAlloc(HLOCAL p, SIZE_T size, UINT flags) { return HeapReAlloc(ShzProcessHeap(), (flags & LMEM_ZEROINIT) ? HEAP_ZERO_MEMORY : 0, p, size); }
K32API HGLOBAL WINAPI GlobalAlloc(UINT flags, SIZE_T size)
{
    if (flags & GMEM_MOVEABLE) { shz_set_last_error(ERROR_NOT_SUPPORTED); return 0; }
    return HeapAlloc(ShzProcessHeap(), (flags & GMEM_ZEROINIT) ? HEAP_ZERO_MEMORY : 0, size);
}
K32API HGLOBAL WINAPI GlobalFree(HGLOBAL p) { return HeapFree(ShzProcessHeap(), 0, p) ? 0 : p; }

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
K32API HMODULE WINAPI LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
    (void)file;
    if (flags & ~(DWORD)(LOAD_WITH_ALTERED_SEARCH_PATH | LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)) {
        shz_set_last_error(ERROR_NOT_SUPPORTED);            /* AS_DATAFILE, IGNORE_CODE_AUTHZ_LEVEL ... are not implemented */
        return 0;
    }
    return LoadLibraryW(name);
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
