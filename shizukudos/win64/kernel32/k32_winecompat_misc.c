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
    DWORD saved_error = GetLastError(), error = 0, protection, writable, old = 0, ignored;
    PVOID prior;
    BOOL changed = FALSE, ok = FALSE;
    if (committed) *committed = FALSE;
    if (((ULONG_PTR)target & (sizeof(PVOID) - 1)) != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    RtlAcquireSRWLockExclusive(&delay_patch_lock);
    if (!VirtualQuery(target, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT ||
        !range_ok(target, sizeof *target, FALSE)) {
        error = ERROR_NOACCESS;
        goto done;
    }
    protection = mbi.Protect & 0xff;
    if (protection == PAGE_READONLY || protection == PAGE_EXECUTE_READ) {
        writable = (protection == PAGE_EXECUTE_READ ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE) |
                   (mbi.Protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE));
        if (!VirtualProtect(target, sizeof *target, writable, &old)) { error = GetLastError(); goto done; }
        changed = TRUE;
    } else if (!range_ok(target, sizeof *target, TRUE)) {
        error = ERROR_NOACCESS;
        goto done;
    }
    prior = compare_null ? InterlockedCompareExchangePointer(target, value, NULL) : InterlockedExchangePointer(target, value);
    if (previous) *previous = prior;
    if (committed) *committed = TRUE;
    if (changed && !VirtualProtect(target, sizeof *target, old, &ignored)) {
        error = GetLastError();
        /* Undo only this transaction's publication while the page is writable.
         * A module reference can be released only when its slot no longer owns
         * it; retain the committed signal if a competing writer prevents undo. */
        if (!compare_null || !prior) {
            PVOID undone = InterlockedCompareExchangePointer(target, prior, value);
            if (undone == value && committed) *committed = FALSE;
        }
        VirtualProtect(target, sizeof *target, old, &ignored);
        goto done;
    }
    ok = TRUE;
done:
    RtlReleaseSRWLockExclusive(&delay_patch_lock);
    SetLastError(ok ? saved_error : error);
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
    DWORD failure_error = 0;
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
        } else failure_error = GetLastError();
    }
    if (mod) {
        fn = (PVOID)GetProcAddress(mod, proc);
        if (!fn) failure_error = GetLastError();
    }
    if (!fn) fn = sys_hook ? sys_hook(dll, proc) : DelayLoadFailureHook(dll, proc);
    if (failure_error) SetLastError(failure_error);
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

/* SearchPathW/A and SetSearchPathMode live in k32_search_path.c. */
