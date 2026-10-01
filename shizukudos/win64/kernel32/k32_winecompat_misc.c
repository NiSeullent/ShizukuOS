/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: miscellaneous Win32 functions called by the DLLs ported from Wine (wineport) that the rest of kernel32
 * does not provide: CompareFileTime, IsBad*Ptr (answered from VirtualQuery instead of probing with exceptions), the
 * delay-load resolver (ResolveDelayLoadedAPI, DelayLoadFailureHook), IsWow64Process2 and SearchPath.
 * (FormatMessage, ExpandEnvironmentStrings, GetTempFileName, GetFileAttributesEx, GetFileTime, IsWow64Process and the
 * local file time conversions are kernel32's own: k32_fmt.c, k32_volume.c, k32_fileinfo.c, k32_procinfo.c, k32_tz.c.)
 */
#include "k32_winecompat.h"

/* ---------------------------------------------------------------- time */
K32API LONG WINAPI CompareFileTime(const FILETIME *a, const FILETIME *b)
{
    ULONGLONG x, y;
    if (!a || !b) return 0;
    x = ((ULONGLONG)a->dwHighDateTime << 32) | a->dwLowDateTime;
    y = ((ULONGLONG)b->dwHighDateTime << 32) | b->dwLowDateTime;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* ---------------------------------------------------------------- pointers */
static BOOL range_ok(const void *p, UINT_PTR n, BOOL write)
{
    const BYTE *a = p, *end;
    MEMORY_BASIC_INFORMATION mbi;
    if (!n) return TRUE;
    if (!p) return FALSE;
    end = a + n;
    if (end < a) return FALSE;
    while (a < end) {
        DWORD prot;
        if (!VirtualQuery(a, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT) return FALSE;
        prot = mbi.Protect & 0xff;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return FALSE;
        if (write && !(prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) return FALSE;
        if (!write && !(prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                PAGE_EXECUTE_WRITECOPY))) return FALSE;
        a = (const BYTE *)mbi.BaseAddress + mbi.RegionSize;
    }
    return TRUE;
}
K32API BOOL WINAPI IsBadReadPtr(const void *p, UINT_PTR n) { return !range_ok(p, n, FALSE); }
K32API BOOL WINAPI IsBadWritePtr(LPVOID p, UINT_PTR n) { return !range_ok(p, n, TRUE); }
K32API BOOL WINAPI IsBadCodePtr(FARPROC p) { return !range_ok((const void *)p, 1, FALSE); }
K32API BOOL WINAPI IsBadStringPtrA(LPCSTR s, UINT_PTR max)
{
    UINT_PTR i;
    if (!max) return FALSE;
    for (i = 0; i < max; ++i) {
        if (i == 0 || !(((UINT_PTR)(s + i)) & 0xfff)) if (!range_ok(s + i, 1, FALSE)) return TRUE;
        if (!s[i]) break;
    }
    return FALSE;
}
K32API BOOL WINAPI IsBadStringPtrW(LPCWSTR s, UINT_PTR max)
{
    UINT_PTR i;
    if (!max) return FALSE;
    for (i = 0; i < max; ++i) {
        if (i == 0 || !(((UINT_PTR)(s + i)) & 0xfff)) if (!range_ok(s + i, sizeof(WCHAR), FALSE)) return TRUE;
        if (!s[i]) break;
    }
    return FALSE;
}



/* ---------------------------------------------------------------- delay-load resolution */
typedef struct {
    DWORD Attributes, DllNameRVA, ModuleHandleRVA, ImportAddressTableRVA, ImportNameTableRVA, BoundImportAddressTableRVA,
          UnloadInformationTableRVA, TimeDateStamp;
} SHZ_DELAYLOAD_DESCRIPTOR;

static ULONGLONG __attribute__((ms_abi)) delay_fail_mod(void) { SetLastError(ERROR_MOD_NOT_FOUND); return 0; }
static ULONGLONG __attribute__((ms_abi)) delay_fail_proc(void) { SetLastError(ERROR_PROC_NOT_FOUND); return 0; }

/* Called when a delay-loaded DLL or function is missing: report it and hand back a stub that fails with
 * ERROR_MOD_NOT_FOUND / ERROR_PROC_NOT_FOUND and returns 0, so the calling API reports failure. */
K32API PVOID WINAPI DelayLoadFailureHook(LPCSTR dll, LPCSTR proc)
{
    char msg[200];
    int k = 0;
    const char *parts[4] = { "kernel32: delay load of ", dll ? dll : "?", !IS_INTRESOURCE(proc) ? "!" : "", "" };
    unsigned i;
    for (i = 0; i < 3; ++i) { const char *s = parts[i]; while (*s && k < 150) msg[k++] = *s++; }
    if (!IS_INTRESOURCE(proc)) { const char *s = proc; while (*s && k < 190) msg[k++] = *s++; }
    msg[k++] = ' '; msg[k++] = 'f'; msg[k++] = 'a'; msg[k++] = 'i'; msg[k++] = 'l'; msg[k++] = 'e'; msg[k++] = 'd';
    msg[k++] = '\n'; msg[k] = 0;
    OutputDebugStringA(msg);
    return (PVOID)(dll && GetModuleHandleA(dll) ? delay_fail_proc : delay_fail_mod);
}

typedef PVOID (WINAPI *delay_sys_hook)(LPCSTR, LPCSTR);

/* Modern linker delay thunks can live in read-only image pages. Serialize
 * these short patch transactions so two resolvers cannot restore each other's
 * temporary protection. Never hold this lock across a loader call or hook. */
static RTL_SRWLOCK delay_patch_lock;

static BOOL delay_read_module(HMODULE *slot, HMODULE *module)
{
    BOOL ok;
    if (((ULONG_PTR)slot & (sizeof(PVOID) - 1)) != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    RtlAcquireSRWLockExclusive(&delay_patch_lock);
    ok = range_ok(slot, sizeof *slot, FALSE);
    if (ok) *module = *slot;
    else SetLastError(ERROR_NOACCESS);
    RtlReleaseSRWLockExclusive(&delay_patch_lock);
    return ok;
}

static BOOL delay_patch_pointer(PVOID *target, PVOID value, BOOL compare_null, PVOID *previous, BOOL *committed)
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD protection, writable, old = 0, ignored;
    BOOL changed = FALSE, ok = FALSE;
    if (committed) *committed = FALSE;
    if (((ULONG_PTR)target & (sizeof(PVOID) - 1)) != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    RtlAcquireSRWLockExclusive(&delay_patch_lock);
    if (!VirtualQuery(target, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT ||
        !range_ok(target, sizeof *target, FALSE)) {
        SetLastError(ERROR_NOACCESS);
        goto done;
    }
    protection = mbi.Protect & 0xff;
    if (protection == PAGE_READONLY || protection == PAGE_EXECUTE_READ) {
        writable = (protection == PAGE_EXECUTE_READ ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE) |
                   (mbi.Protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE));
        if (!VirtualProtect(target, sizeof *target, writable, &old)) goto done;
        changed = TRUE;
    } else if (!range_ok(target, sizeof *target, TRUE)) {
        SetLastError(ERROR_NOACCESS);
        goto done;
    }
    if (compare_null) *previous = InterlockedCompareExchangePointer(target, value, NULL);
    else InterlockedExchangePointer(target, value);
    if (committed) *committed = TRUE;
    ok = TRUE;
    if (changed && !VirtualProtect(target, sizeof *target, old, &ignored)) ok = FALSE;
done:
    RtlReleaseSRWLockExclusive(&delay_patch_lock);
    return ok;
}

K32API PVOID WINAPI ResolveDelayLoadedAPI(PVOID base, const SHZ_DELAYLOAD_DESCRIPTOR *desc, PVOID dll_hook, delay_sys_hook sys_hook,
                                          PIMAGE_THUNK_DATA thunk, ULONG flags)
{
    BYTE *b = base;
    BOOL rva;
    if (!base || !desc || !thunk || flags) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    rva = desc->Attributes & 1;
#define PTR(v) ((void *)(rva ? b + (v) : (BYTE *)(ULONG_PTR)(v)))
    const char *dll = PTR(desc->DllNameRVA);
    HMODULE *slot = PTR(desc->ModuleHandleRVA), mod;
    IMAGE_THUNK_DATA *iat = PTR(desc->ImportAddressTableRVA), *names = PTR(desc->ImportNameTableRVA);
    ULONG_PTR index = thunk - iat;
    LPCSTR proc;
    PVOID fn = NULL;
#undef PTR
    (void)dll_hook;
    if (IMAGE_SNAP_BY_ORDINAL(names[index].u1.Ordinal)) proc = (LPCSTR)(ULONG_PTR)IMAGE_ORDINAL(names[index].u1.Ordinal);
    else proc = (const char *)((IMAGE_IMPORT_BY_NAME *)(rva ? b + names[index].u1.AddressOfData
                                                           : (BYTE *)(ULONG_PTR)names[index].u1.AddressOfData))->Name;
    if (!delay_read_module(slot, &mod)) return NULL;
    if (!mod) {
        if ((mod = LoadLibraryA(dll))) {
            HMODULE prev = NULL;
            BOOL committed;
            if (!delay_patch_pointer((PVOID *)slot, mod, TRUE, (PVOID *)&prev, &committed)) {
                DWORD error = GetLastError();
                /* A successful publication owns this module reference even
                 * when restoration fails. Do not leave a dangling slot. */
                if (!committed || prev) FreeLibrary(mod);
                SetLastError(error);
                return NULL;
            }
            if (prev) { FreeLibrary(mod); mod = prev; }
        }
    }
    if (mod) fn = (PVOID)GetProcAddress(mod, proc);
    if (!fn) fn = sys_hook ? sys_hook(dll, proc) : DelayLoadFailureHook(dll, proc);
    if (fn && !delay_patch_pointer((PVOID *)&thunk->u1.Function, fn, FALSE, NULL, NULL)) return NULL;
    return fn;
}

/* ---------------------------------------------------------------- WOW64: this system runs 64-bit processes only */
K32API BOOL WINAPI IsWow64Process2(HANDLE process, USHORT *machine, USHORT *native)
{
    (void)process;
    if (!machine) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *machine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (native) *native = IMAGE_FILE_MACHINE_AMD64;
    return TRUE;
}

/* ---------------------------------------------------------------- SearchPath */
/* Default order (SearchPathW with a NULL path, safe search mode): the application directory, the system directory,
 * the Windows directory, the current directory, then PATH. The extension is appended when the name has none. */
static BOOL try_candidate(const WCHAR *dir, size_t dlen, const WCHAR *name, const WCHAR *ext, WCHAR *out, DWORD cap,
                          DWORD *need, WCHAR **filepart)
{
    WCHAR buf[MAX_PATH * 2];
    size_t n = 0, i;
    DWORD attr, full;
    for (i = 0; i < dlen && n < MAX_PATH; ++i) buf[n++] = dir[i];
    if (n && buf[n - 1] != '\\' && buf[n - 1] != '/') buf[n++] = '\\';
    for (i = 0; name[i] && n < MAX_PATH * 2 - 8; ++i) buf[n++] = name[i];
    for (i = 0; ext && ext[i] && n < MAX_PATH * 2 - 1; ++i) buf[n++] = ext[i];
    buf[n] = 0;
    attr = GetFileAttributesW(buf);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) return FALSE;
    full = GetFullPathNameW(buf, cap, out, filepart);
    *need = full;
    return TRUE;
}

K32API DWORD WINAPI SearchPathW(LPCWSTR path, LPCWSTR name, LPCWSTR ext, DWORD cap, LPWSTR out, LPWSTR *filepart)
{
    WCHAR dirs[4][MAX_PATH], env[2048];
    const WCHAR *use_ext = NULL, *p;
    DWORD need = 0, n, i;
    if (!name || !*name) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    for (p = name; *p; ++p) { }
    while (p > name && p[-1] != '.' && p[-1] != '\\' && p[-1] != '/') --p;
    if (!(p > name && p[-1] == '.')) use_ext = ext;
    /* a name with a directory part is only looked up as given */
    for (p = name; *p; ++p) if (*p == '\\' || *p == '/' || *p == ':') break;
    if (*p) {
        if (try_candidate(L"", 0, name, use_ext, out, cap, &need, filepart)) return need;
        SetLastError(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    if (path) {
        const WCHAR *s = path;
        while (*s) {
            const WCHAR *e = s;
            while (*e && *e != ';') ++e;
            if (e > s && try_candidate(s, e - s, name, use_ext, out, cap, &need, filepart)) return need;
            s = *e ? e + 1 : e;
        }
        SetLastError(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    n = GetModuleFileNameW(NULL, dirs[0], MAX_PATH);
    while (n && dirs[0][n - 1] != '\\') --n;
    dirs[0][n] = 0;
    GetSystemDirectoryW(dirs[1], MAX_PATH);
    GetWindowsDirectoryW(dirs[2], MAX_PATH);
    GetCurrentDirectoryW(MAX_PATH, dirs[3]);
    for (i = 0; i < 4; ++i)
        if (dirs[i][0] && try_candidate(dirs[i], lstrlenW(dirs[i]), name, use_ext, out, cap, &need, filepart)) return need;
    if (GetEnvironmentVariableW(L"PATH", env, ARRAYSIZE(env)))
        return SearchPathW(env, name, ext, cap, out, filepart);
    SetLastError(ERROR_FILE_NOT_FOUND);
    return 0;
}

K32API DWORD WINAPI SearchPathA(LPCSTR path, LPCSTR name, LPCSTR ext, DWORD cap, LPSTR out, LPSTR *filepart)
{
    WCHAR wpath[2048], wname[MAX_PATH], wext[16], wout[MAX_PATH];
    DWORD r;
    if (!name) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (path) MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, ARRAYSIZE(wpath));
    MultiByteToWideChar(CP_ACP, 0, name, -1, wname, MAX_PATH);
    if (ext) MultiByteToWideChar(CP_ACP, 0, ext, -1, wext, ARRAYSIZE(wext));
    r = SearchPathW(path ? wpath : NULL, wname, ext ? wext : NULL, MAX_PATH, wout, NULL);
    if (!r || r > MAX_PATH) return r;
    r = (DWORD)WideCharToMultiByte(CP_ACP, 0, wout, -1, NULL, 0, NULL, NULL);
    if (r > cap) return r;
    WideCharToMultiByte(CP_ACP, 0, wout, -1, out, cap, NULL, NULL);
    if (filepart) {
        char *s = out, *last = NULL;
        for (; *s; ++s) if (*s == '\\') last = s;
        *filepart = last ? last + 1 : out;
    }
    return r - 1;
}
