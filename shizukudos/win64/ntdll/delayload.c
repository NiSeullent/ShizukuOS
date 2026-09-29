/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll: delay-load import resolution (LdrResolveDelayLoadedAPI, LdrResolveDelayLoadsFromDll), exported from kernel32
 * as ResolveDelayLoadedAPI / ResolveDelayLoadsFromDll.
 *
 * A delay-load import is not bound by the loader: the compiler puts each such call behind a stub that, on the first
 * call, invokes the image's delay-load helper (__delayLoadHelper2). Since Windows 8 that helper calls the exported
 * ResolveDelayLoadedAPI, which loads the target DLL (if not already), resolves the one thunk and writes the function
 * pointer into the IAT so later calls go direct. This is that routine.
 *
 * Layout facts (public: learn.microsoft.com "IMAGE_DELAYLOAD_DESCRIPTOR", "Linker support for delay-loaded DLLs",
 * winnt.h / delayloadhandler.h in the mingw-w64 headers): the descriptor's Rva* fields are RVAs from the image base
 * (Attributes.RvaBased == 1). ImportAddressTableRVA and ImportNameTableRVA are parallel arrays of IMAGE_THUNK_DATA64;
 * the INT entry is IMAGE_ORDINAL_FLAG64 | ordinal, or an RVA to an IMAGE_IMPORT_BY_NAME. The thunk to resolve is
 * identified by its index in the IAT (ThunkAddress - ImportAddressTable).
 */
#include "nt.h"
#include <delayloadhandler.h>

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ull
#define DL_DONT_RESOLVE_DLL_REFERENCES 0x00000001u      /* Flags bit the caller sets to skip the failure hook */

NTSTATUS NTAPI LdrLoadDll(PWSTR, PULONG, SHZ_UNICODE_STRING *, PVOID *);
NTSTATUS NTAPI LdrGetProcedureAddress(PVOID, const void *, ULONG, PVOID *);
NTSTATUS NTAPI LdrGetDllHandle(PWSTR, PULONG, SHZ_UNICODE_STRING *, PVOID *);
extern void ShzLoaderLock(void), ShzLoaderUnlock(void);
VOID NTAPI RtlRaiseException(PEXCEPTION_RECORD);

typedef struct { USHORT Length, MaximumLength; PCHAR Buffer; } SHZ_ANSI_STRING;

/* Widen an ASCII/UTF-8 DLL name into a UNICODE_STRING (delay-load names are plain ASCII). */
static void ansi_to_unicode(SHZ_UNICODE_STRING *u, WCHAR *buf, size_t cap, const char *s)
{
    size_t n = 0;
    while (s[n] && n + 1 < cap) { buf[n] = (WCHAR)(unsigned char)s[n]; ++n; }
    buf[n] = 0;
    u->Buffer = buf;
    u->Length = (USHORT)(n * sizeof(WCHAR));
    u->MaximumLength = (USHORT)((n + 1) * sizeof(WCHAR));
}

/* Ensures the descriptor's module handle slot holds a loaded module; returns it (or 0 and sets *st). */
static PVOID ensure_module(const uint8_t *base, PCIMAGE_DELAYLOAD_DESCRIPTOR d, NTSTATUS *st)
{
    PVOID *handle_slot = (PVOID *)(base + d->ModuleHandleRVA);
    const char *dll = (const char *)(base + d->DllNameRVA);
    WCHAR w[256];
    SHZ_UNICODE_STRING u;
    PVOID h;
    *st = STATUS_SUCCESS;
    h = *handle_slot;
    if (h) return h;
    ansi_to_unicode(&u, w, 256, dll);
    if (!LdrGetDllHandle(0, 0, &u, &h) && h) { *handle_slot = h; return h; }
    *st = LdrLoadDll(0, 0, &u, &h);
    if (*st) return 0;
    *handle_slot = h;
    return h;
}

/* Resolves the single thunk `thunk` of descriptor `desc` in image `ParentModuleBase`, writing the IAT slot. */
SHZ_EXPORT PVOID NTAPI LdrResolveDelayLoadedAPI(PVOID ParentModuleBase, PCIMAGE_DELAYLOAD_DESCRIPTOR desc,
                                                PDELAYLOAD_FAILURE_DLL_CALLBACK dll_hook, PVOID system_hook,
                                                PIMAGE_THUNK_DATA thunk, ULONG flags)
{
    const uint8_t *base = ParentModuleBase;
    IMAGE_THUNK_DATA64 *iat = (IMAGE_THUNK_DATA64 *)(base + desc->ImportAddressTableRVA);
    const IMAGE_THUNK_DATA64 *int_tbl = (const IMAGE_THUNK_DATA64 *)(base + desc->ImportNameTableRVA);
    const long index = (IMAGE_THUNK_DATA64 *)thunk - iat;
    NTSTATUS st;
    PVOID module, proc = 0;
    ULONGLONG want;
    SHZ_ANSI_STRING name;
    DELAYLOAD_INFO info;
    (void)system_hook;
    ShzLoaderLock();
    module = ensure_module(base, desc, &st);
    if (!module) { ShzLoaderUnlock(); goto failed_dll; }
    if (index < 0) { ShzLoaderUnlock(); st = STATUS_INVALID_PARAMETER; goto failed; }
    want = int_tbl[index].u1.Ordinal;
    if (want & IMAGE_ORDINAL_FLAG64) {
        st = LdrGetProcedureAddress(module, 0, (ULONG)(want & 0xffff), &proc);
    } else {
        const IMAGE_IMPORT_BY_NAME *ibn = (const IMAGE_IMPORT_BY_NAME *)(base + (DWORD)want);
        USHORT n = 0;
        while (ibn->Name[n]) ++n;
        name.Buffer = (PCHAR)ibn->Name;
        name.Length = n;
        name.MaximumLength = (USHORT)(n + 1);
        st = LdrGetProcedureAddress(module, &name, 0, &proc);
    }
    ShzLoaderUnlock();
    if (st || !proc) goto failed;
    iat[index].u1.Function = (ULONGLONG)(uintptr_t)proc;               /* later calls go direct */
    return proc;

failed_dll:
    /* Give the image's failure hook a chance to substitute the DLL, exactly like the Windows helper. */
    if (dll_hook && !(flags & DL_DONT_RESOLVE_DLL_REFERENCES)) {
        memset(&info, 0, sizeof info);
        info.Size = sizeof info;
        info.DelayloadDescriptor = desc;
        info.ThunkAddress = thunk;
        info.TargetDllName = (LPCSTR)(base + desc->DllNameRVA);
        info.LastError = (ULONG)RtlNtStatusToDosError(st);
        proc = dll_hook(1 /* dliFailLoadLib */, &info);
        if (proc) return proc;
    }
    goto raise;
failed:
    if (dll_hook && !(flags & DL_DONT_RESOLVE_DLL_REFERENCES)) {
        memset(&info, 0, sizeof info);
        info.Size = sizeof info;
        info.DelayloadDescriptor = desc;
        info.ThunkAddress = thunk;
        info.TargetDllName = (LPCSTR)(base + desc->DllNameRVA);
        info.TargetModuleBase = module;
        info.LastError = (ULONG)RtlNtStatusToDosError(st);
        want = ((const IMAGE_THUNK_DATA64 *)(base + desc->ImportNameTableRVA))[index >= 0 ? index : 0].u1.Ordinal;
        if (want & IMAGE_ORDINAL_FLAG64) info.TargetApiDescriptor.Description.Ordinal = (ULONG)(want & 0xffff);
        else { info.TargetApiDescriptor.ImportDescribedByName = 1;
               info.TargetApiDescriptor.Description.Name = (LPCSTR)((const IMAGE_IMPORT_BY_NAME *)(base + (DWORD)want))->Name; }
        proc = dll_hook(DELAYLOAD_GPA_FAILURE, &info);
        if (proc) { if (index >= 0) iat[index].u1.Function = (ULONGLONG)(uintptr_t)proc; return proc; }
    }
raise:
    {
        EXCEPTION_RECORD rec;
        memset(&rec, 0, sizeof rec);
        rec.ExceptionCode = (DWORD)(st == STATUS_DLL_NOT_FOUND ? 0xC06D007Eu /* VcppException DLL_NOT_FOUND */ : 0xC06D007Fu /* PROC_NOT_FOUND */);
        rec.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
        rec.NumberParameters = 1;
        rec.ExceptionInformation[0] = (ULONG_PTR)(base + desc->DllNameRVA);
        RtlRaiseException(&rec);
    }
    return 0;
}

/* Resolves every delay-load thunk whose DLL is `TargetDllName` in image `ParentModuleBase`. Used when a module is
 * pinned/forwarded so that its delay imports become bound immediately. Returns STATUS_SUCCESS, or the first failure. */
SHZ_EXPORT NTSTATUS NTAPI LdrResolveDelayLoadsFromDll(PVOID ParentModuleBase, LPCSTR TargetDllName, ULONG Flags)
{
    const uint8_t *base = ParentModuleBase;
    const IMAGE_DOS_HEADER *dos = ParentModuleBase;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_DATA_DIRECTORY *dd;
    const IMAGE_DELAYLOAD_DESCRIPTOR *d;
    (void)Flags;
    if (!base || !TargetDllName || dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_PARAMETER;
    nt = (const IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (!dd->VirtualAddress || !dd->Size) return STATUS_SUCCESS;
    for (d = (const IMAGE_DELAYLOAD_DESCRIPTOR *)(base + dd->VirtualAddress); d->DllNameRVA; ++d) {
        const char *dll = (const char *)(base + d->DllNameRVA);
        unsigned i;
        int match = 1;
        for (i = 0; dll[i] || TargetDllName[i]; ++i) {                 /* case-insensitive ASCII compare */
            char a = dll[i], b = TargetDllName[i];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = 0; break; }
        }
        if (!match) continue;
        {
            IMAGE_THUNK_DATA64 *iat = (IMAGE_THUNK_DATA64 *)(base + d->ImportAddressTableRVA);
            const IMAGE_THUNK_DATA64 *intt = (const IMAGE_THUNK_DATA64 *)(base + d->ImportNameTableRVA);
            unsigned k;
            for (k = 0; intt[k].u1.Ordinal; ++k)
                if (!LdrResolveDelayLoadedAPI(ParentModuleBase, d, 0, 0, (PIMAGE_THUNK_DATA)&iat[k], Flags))
                    return STATUS_ENTRYPOINT_NOT_FOUND;
        }
        return STATUS_SUCCESS;
    }
    return STATUS_SUCCESS;
}
