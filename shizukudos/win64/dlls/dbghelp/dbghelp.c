/* SPDX-License-Identifier: GPL-2.0-only
 * dbghelp.dll - the symbol handler, stack walker and minidump writer, over what this system really has: the loaded
 * modules of a process (kernel32 K32EnumProcessModules / K32GetModuleInformation / K32GetModuleFileNameExW, i.e. the
 * kernel's module list), their PE export tables and CodeView records read from the process (ReadProcessMemory for
 * another process), the x64 unwind tables (ntdll RtlLookupFunctionEntry / RtlVirtualUnwind) and the process/thread
 * information kernel32 exports. There are no PDB files here, so:
 *
 *   SymInitialize / SymCleanup       one symbol table per process handle (a second SymInitialize for the same process
 *                                    fails with ERROR_INVALID_PARAMETER, as on Windows); fInvadeProcess loads the module
 *                                    list at once, otherwise modules are found on first use (SYMOPT_DEFERRED_LOADS).
 *   SymSetOptions / SymGetOptions    the global SYMOPT_* word (default SYMOPT_UNDNAME).
 *   Sym{Get,Set}SearchPath{,W}       stored per process; the default is _NT_SYMBOL_PATH, else ".".
 *   SymGetModuleBase64, SymGetModuleInfo64/W64, EnumerateLoadedModules64/W64, SymRefreshModuleList
 *                                    from the process' module list; the CodeView RSDS record gives PdbSig70/PdbAge and
 *                                    LoadedPdbName (never matched: no PDB is on disk), SymType is SymExport when the
 *                                    module has an export table, else SymNone.
 *   SymFromAddr/W, SymGetSymFromAddr64   the nearest preceding export of the module (SYMFLAG_EXPORT, SymTagPublicSymbol),
 *                                    which is exactly what dbghelp reports for a module without symbols.
 *   SymGetLineFromAddr64/W64         no line information exists: FALSE, ERROR_INVALID_ADDRESS (dbghelp's own code for it).
 *   SymFunctionTableAccess64         the RUNTIME_FUNCTION of an address (the module's exception directory; for another
 *                                    process a copy read from it, valid until the next call, as documented).
 *   StackWalk64                      x64 unwinding of the calling process with RtlVirtualUnwind through the caller's
 *                                    FunctionTableAccess/GetModuleBase routines; the CONTEXT is advanced frame by frame.
 *                                    Another process' stack cannot be unwound with the unwind data mapped in this one:
 *                                    FALSE, ERROR_NOT_SUPPORTED.
 *   SymSrvGetFileIndexInfo/W         the indexing data of a PE file on disk (timestamp, SizeOfImage, RSDS guid/age/pdb).
 *   UnDecorateSymbolName/W           an undecorated (C) name is copied unchanged, as dbghelp does. MSVC-decorated names
 *                                    ("?...") need the full C++ type grammar, which is not implemented: 0, ERROR_NOT_SUPPORTED.
 *   MiniDumpWriteDump                a minidump of the calling process: SystemInfo, ThreadList (the calling thread, or the
 *                                    thread named by ExceptionParam when it is the calling one, with its CONTEXT and stack),
 *                                    ModuleList (with VS_FIXEDFILEINFO and the CodeView record), MemoryList (that stack),
 *                                    Exception (from ExceptionParam) and MiscInfo streams. The kernel exposes no thread
 *                                    enumeration, so other threads are not in the dump; MINIDUMP_TYPE bits beyond
 *                                    MiniDumpNormal are accepted, the header Flags record what was written (MiniDumpNormal).
 *                                    Another process: FALSE, ERROR_NOT_SUPPORTED. User streams are written; callbacks are
 *                                    not invoked (ERROR_NOT_SUPPORTED when a CallbackParam is given).
 */
#define WIN32_LEAN_AND_MEAN
/* mingw's dbghelp.h declares every function DECLSPEC_IMPORT unconditionally; this file defines them, so the
 * "redeclared without dllimport" note is expected and silenced here only. */
#pragma GCC diagnostic ignored "-Wattributes"
#define PSAPI_VERSION 2                         /* the K32* names kernel32 exports */
#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <string.h>

#ifndef DLLAPI
#define DLLAPI __declspec(dllexport)
#endif

#define SYMTAG_PUBLIC_SYMBOL 10
LONG NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW);          /* ntdll */

static ULONG_PTR teb_qword(unsigned off)         /* GS:[off] of this thread's TEB (mingw's NtCurrentTeb trips -Warray-bounds) */
{
    ULONG_PTR v;
    __asm__ volatile("movq %%gs:(%1), %0" : "=r"(v) : "r"((ULONG_PTR)off));
    return v;
}
#define TEB_STACK_BASE 0x08
#define TEB_SELF 0x30
#define ERROR_INVALID_ADDRESS_ 487

typedef struct sym_module {
    DWORD64 base;
    DWORD size, timestamp, checksum, nexports, export_dir_rva, export_dir_size, machine;
    int has_cv;
    GUID pdb_guid;
    DWORD pdb_age;
    char pdb[MAX_PATH];
    WCHAR image[MAX_PATH];
    char name[32];
} sym_module;

typedef struct sym_process {
    struct sym_process *next;
    HANDLE h;
    DWORD pid;
    int is_self;
    WCHAR search[1024];
    sym_module *mods;
    unsigned nmods, cap;
    /* SymFunctionTableAccess64 for another process: the exception directory of the last module asked for */
    DWORD64 ft_base;
    RUNTIME_FUNCTION *ft;
    unsigned ft_count;
} sym_process;

static SRWLOCK g_lock = SRWLOCK_INIT;
static sym_process *g_procs;
static DWORD g_options = SYMOPT_UNDNAME;

static size_t wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

static void narrow(const WCHAR *w, char *out, size_t cap)
{
    size_t i;
    for (i = 0; i + 1 < cap && w[i]; ++i) out[i] = w[i] < 128 ? (char)w[i] : '?';
    out[i] = 0;
}

static void widen(const char *a, WCHAR *out, size_t cap)
{
    size_t i;
    for (i = 0; i + 1 < cap && a[i]; ++i) out[i] = (WCHAR)(unsigned char)a[i];
    out[i] = 0;
}

static sym_process *find_process(HANDLE h)              /* g_lock held */
{
    sym_process *p;
    DWORD pid = GetProcessId(h);
    for (p = g_procs; p; p = p->next)
        if (p->h == h || (pid && p->pid == pid)) return p;
    return 0;
}

static int read_mem(const sym_process *p, DWORD64 addr, void *buf, SIZE_T n)
{
    SIZE_T got = 0;
    if (p->is_self) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)(ULONG_PTR)addr, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS)) return 0;
        if ((ULONG_PTR)addr + n > (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize) {      /* may span regions: check the rest */
            MEMORY_BASIC_INFORMATION m2;
            ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            while (next < (ULONG_PTR)addr + n) {
                if (!VirtualQuery((LPCVOID)next, &m2, sizeof m2) || m2.State != MEM_COMMIT || (m2.Protect & PAGE_NOACCESS)) return 0;
                next = (ULONG_PTR)m2.BaseAddress + m2.RegionSize;
            }
        }
        memcpy(buf, (const void *)(ULONG_PTR)addr, n);
        return 1;
    }
    return ReadProcessMemory(p->h, (LPCVOID)(ULONG_PTR)addr, buf, n, &got) && got == n;
}

/* Fills the PE-derived fields of a module from the image in the process. */
static void describe_module(const sym_process *p, sym_module *m)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    const IMAGE_DATA_DIRECTORY *dd;
    unsigned i;
    m->nexports = 0; m->has_cv = 0; m->timestamp = 0; m->checksum = 0;
    if (!read_mem(p, m->base, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return;
    if (!read_mem(p, m->base + dos.e_lfanew, &nt, sizeof nt) || nt.Signature != IMAGE_NT_SIGNATURE) return;
    m->timestamp = nt.FileHeader.TimeDateStamp;
    m->checksum = nt.OptionalHeader.CheckSum;
    m->machine = nt.FileHeader.Machine;
    if (!m->size) m->size = nt.OptionalHeader.SizeOfImage;
    dd = &nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dd->VirtualAddress && dd->Size >= sizeof(IMAGE_EXPORT_DIRECTORY)) {
        IMAGE_EXPORT_DIRECTORY ed;
        if (read_mem(p, m->base + dd->VirtualAddress, &ed, sizeof ed)) {
            m->nexports = ed.NumberOfFunctions;
            m->export_dir_rva = dd->VirtualAddress;
            m->export_dir_size = dd->Size;
        }
    }
    dd = &nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (dd->VirtualAddress && dd->Size >= sizeof(IMAGE_DEBUG_DIRECTORY)) {
        for (i = 0; i < dd->Size / sizeof(IMAGE_DEBUG_DIRECTORY) && i < 16; ++i) {
            IMAGE_DEBUG_DIRECTORY dbg;
            if (!read_mem(p, m->base + dd->VirtualAddress + i * sizeof dbg, &dbg, sizeof dbg)) break;
            if (dbg.Type == IMAGE_DEBUG_TYPE_CODEVIEW && dbg.SizeOfData >= 24 && dbg.AddressOfRawData) {
                struct { DWORD sig; GUID guid; DWORD age; } cv;
                if (read_mem(p, m->base + dbg.AddressOfRawData, &cv, sizeof cv) && cv.sig == 0x53445352u /* 'RSDS' */) {
                    DWORD n = dbg.SizeOfData - 24;
                    if (n >= sizeof m->pdb) n = sizeof m->pdb - 1;
                    m->has_cv = 1;
                    m->pdb_guid = cv.guid;
                    m->pdb_age = cv.age;
                    if (!read_mem(p, m->base + dbg.AddressOfRawData + 24, m->pdb, n)) n = 0;
                    m->pdb[n] = 0;
                }
                break;
            }
        }
    }
}

static void module_short_name(sym_module *m)
{
    const WCHAR *s = m->image, *last = s;
    size_t i, n;
    for (; *s; ++s) if (*s == '\\' || *s == '/') last = s + 1;
    for (n = 0; last[n] && last[n] != '.'; ++n) ;
    if (n >= sizeof m->name) n = sizeof m->name - 1;
    for (i = 0; i < n; ++i) m->name[i] = last[i] < 128 ? (char)last[i] : '?';
    m->name[n] = 0;
}

/* Re-reads the process' module list (K32EnumProcessModules). g_lock held exclusive. */
static int refresh_modules(sym_process *p)
{
    HMODULE mods[512];
    DWORD needed = 0, n, i;
    if (!K32EnumProcessModules(p->h, mods, sizeof mods, &needed)) return 0;
    n = needed / sizeof(HMODULE);
    if (n > 512) n = 512;
    if (p->cap < n) {
        sym_module *nm = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n * sizeof *nm);
        if (!nm) return 0;
        if (p->mods) HeapFree(GetProcessHeap(), 0, p->mods);
        p->mods = nm;
        p->cap = n;
    }
    p->nmods = 0;
    for (i = 0; i < n; ++i) {
        sym_module *m = &p->mods[p->nmods];
        MODULEINFO mi;
        memset(m, 0, sizeof *m);
        m->base = (DWORD64)(ULONG_PTR)mods[i];
        if (K32GetModuleInformation(p->h, mods[i], &mi, sizeof mi)) m->size = mi.SizeOfImage;
        if (!K32GetModuleFileNameExW(p->h, mods[i], m->image, MAX_PATH)) m->image[0] = 0;
        module_short_name(m);
        describe_module(p, m);
        ++p->nmods;
    }
    return 1;
}

static sym_module *module_at(sym_process *p, DWORD64 addr, int refresh)
{
    unsigned i;
    for (i = 0; i < p->nmods; ++i)
        if (addr >= p->mods[i].base && addr - p->mods[i].base < p->mods[i].size) return &p->mods[i];
    if (refresh && refresh_modules(p)) {
        for (i = 0; i < p->nmods; ++i)
            if (addr >= p->mods[i].base && addr - p->mods[i].base < p->mods[i].size) return &p->mods[i];
    }
    return 0;
}

/* ================================================================ options, initialisation */
DLLAPI DWORD WINAPI SymSetOptions(DWORD options) { g_options = options; return options; }
DLLAPI DWORD WINAPI SymGetOptions(void) { return g_options; }

DLLAPI BOOL WINAPI SymInitializeW(HANDLE h, PCWSTR path, BOOL invade)
{
    sym_process *p;
    DWORD pid = GetProcessId(h);
    if (!h || !pid) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    AcquireSRWLockExclusive(&g_lock);
    if (find_process(h)) { ReleaseSRWLockExclusive(&g_lock); SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *p);
    if (!p) { ReleaseSRWLockExclusive(&g_lock); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    p->h = h;
    p->pid = pid;
    p->is_self = pid == GetCurrentProcessId();
    if (path && *path) {
        size_t n = wlen(path);
        if (n >= sizeof p->search / sizeof(WCHAR)) n = sizeof p->search / sizeof(WCHAR) - 1;
        memcpy(p->search, path, n * sizeof(WCHAR));
        p->search[n] = 0;
    } else {
        static const WCHAR env[] = { '_','N','T','_','S','Y','M','B','O','L','_','P','A','T','H', 0 };
        DWORD n = GetEnvironmentVariableW(env, p->search, sizeof p->search / sizeof(WCHAR));
        if (!n || n >= sizeof p->search / sizeof(WCHAR)) { p->search[0] = '.'; p->search[1] = 0; }
    }
    p->next = g_procs;
    g_procs = p;
    if (invade) refresh_modules(p);
    ReleaseSRWLockExclusive(&g_lock);
    return TRUE;
}

DLLAPI BOOL WINAPI SymInitialize(HANDLE h, PCSTR path, BOOL invade)
{
    WCHAR w[1024];
    if (path) widen(path, w, sizeof w / sizeof w[0]);
    return SymInitializeW(h, path ? w : 0, invade);
}

DLLAPI BOOL WINAPI SymCleanup(HANDLE h)
{
    sym_process *p, **pp;
    AcquireSRWLockExclusive(&g_lock);
    for (pp = &g_procs; (p = *pp) != 0; pp = &p->next)
        if (p->h == h || (GetProcessId(h) && p->pid == GetProcessId(h))) { *pp = p->next; break; }
    ReleaseSRWLockExclusive(&g_lock);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (p->mods) HeapFree(GetProcessHeap(), 0, p->mods);
    if (p->ft) HeapFree(GetProcessHeap(), 0, p->ft);
    HeapFree(GetProcessHeap(), 0, p);
    return TRUE;
}

DLLAPI BOOL WINAPI SymRefreshModuleList(HANDLE h)
{
    sym_process *p;
    int ok;
    AcquireSRWLockExclusive(&g_lock);
    p = find_process(h);
    ok = p && refresh_modules(p);
    ReleaseSRWLockExclusive(&g_lock);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    return ok ? TRUE : FALSE;
}

DLLAPI BOOL WINAPI SymSetSearchPathW(HANDLE h, PCWSTR path)
{
    sym_process *p;
    AcquireSRWLockExclusive(&g_lock);
    p = find_process(h);
    if (p) {
        size_t n = path ? wlen(path) : 0;
        if (n >= sizeof p->search / sizeof(WCHAR)) n = sizeof p->search / sizeof(WCHAR) - 1;
        if (path) memcpy(p->search, path, n * sizeof(WCHAR));
        p->search[n] = 0;
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI SymSetSearchPath(HANDLE h, PCSTR path)
{
    WCHAR w[1024];
    if (path) widen(path, w, sizeof w / sizeof w[0]);
    return SymSetSearchPathW(h, path ? w : 0);
}

DLLAPI BOOL WINAPI SymGetSearchPathW(HANDLE h, PWSTR out, DWORD cap)
{
    sym_process *p;
    size_t n = 0;
    if (!out || !cap) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    AcquireSRWLockShared(&g_lock);
    p = find_process(h);
    if (p) {
        n = wlen(p->search);
        if (n < cap) memcpy(out, p->search, (n + 1) * sizeof(WCHAR));
    }
    ReleaseSRWLockShared(&g_lock);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (n >= cap) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI SymGetSearchPath(HANDLE h, PSTR out, DWORD cap)
{
    WCHAR w[1024];
    if (!out || !cap) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!SymGetSearchPathW(h, w, sizeof w / sizeof w[0])) return FALSE;
    if (wlen(w) >= cap) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    narrow(w, out, cap);
    return TRUE;
}

/* ================================================================ modules */
DLLAPI DWORD64 WINAPI SymGetModuleBase64(HANDLE h, DWORD64 addr)
{
    sym_process *p;
    sym_module *m = 0;
    AcquireSRWLockExclusive(&g_lock);
    p = find_process(h);
    if (p) m = module_at(p, addr, 1);
    ReleaseSRWLockExclusive(&g_lock);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    if (!m) { SetLastError(ERROR_MOD_NOT_FOUND); return 0; }
    return m->base;
}

static void fill_module_info_w(const sym_module *m, IMAGEHLP_MODULEW64 *mi, DWORD size)
{
    IMAGEHLP_MODULEW64 full;
    memset(&full, 0, sizeof full);
    full.SizeOfStruct = size;
    full.BaseOfImage = m->base;
    full.ImageSize = m->size;
    full.TimeDateStamp = m->timestamp;
    full.CheckSum = m->checksum;
    full.NumSyms = m->nexports;
    full.SymType = m->nexports ? SymExport : SymNone;
    widen(m->name, full.ModuleName, 32);
    memcpy(full.ImageName, m->image, (wlen(m->image) + 1) * sizeof(WCHAR));
    memcpy(full.LoadedImageName, m->image, (wlen(m->image) + 1) * sizeof(WCHAR));
    if (m->has_cv) {
        full.CVSig = 0x53445352u;
        widen(m->pdb, full.CVData, MAX_PATH * 3);
        widen(m->pdb, full.LoadedPdbName, 256);
        full.PdbSig70 = m->pdb_guid;
        full.PdbAge = m->pdb_age;
        full.PdbUnmatched = TRUE;                     /* the PDB itself is not on this system */
    }
    full.Publics = m->nexports != 0;
    full.MachineType = m->machine;
    memcpy(mi, &full, size);
}

static BOOL module_info(HANDLE h, DWORD64 addr, void *out, DWORD size, int wide)
{
    sym_process *p;
    sym_module *m = 0;
    sym_module copy;
    const DWORD wmin = FIELD_OFFSET(IMAGEHLP_MODULEW64, CVSig), amin = FIELD_OFFSET(IMAGEHLP_MODULE64, CVSig);
    if (!out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (wide ? (size < wmin || size > sizeof(IMAGEHLP_MODULEW64)) : (size < amin || size > sizeof(IMAGEHLP_MODULE64))) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    AcquireSRWLockExclusive(&g_lock);
    p = find_process(h);
    if (p) m = module_at(p, addr, 1);
    if (m) copy = *m;
    ReleaseSRWLockExclusive(&g_lock);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (!m) { SetLastError(ERROR_MOD_NOT_FOUND); return FALSE; }
    if (wide) {
        fill_module_info_w(&copy, out, size);
    } else {
        IMAGEHLP_MODULEW64 w;
        IMAGEHLP_MODULE64 a;
        fill_module_info_w(&copy, &w, sizeof w);
        memset(&a, 0, sizeof a);
        a.SizeOfStruct = size;
        a.BaseOfImage = w.BaseOfImage; a.ImageSize = w.ImageSize; a.TimeDateStamp = w.TimeDateStamp; a.CheckSum = w.CheckSum;
        a.NumSyms = w.NumSyms; a.SymType = w.SymType;
        narrow(w.ModuleName, a.ModuleName, 32); narrow(w.ImageName, a.ImageName, 256); narrow(w.LoadedImageName, a.LoadedImageName, 256);
        narrow(w.LoadedPdbName, a.LoadedPdbName, 256);
        a.CVSig = w.CVSig; narrow(w.CVData, a.CVData, MAX_PATH * 3); a.PdbSig = w.PdbSig; a.PdbSig70 = w.PdbSig70; a.PdbAge = w.PdbAge;
        a.PdbUnmatched = w.PdbUnmatched; a.Publics = w.Publics; a.MachineType = w.MachineType;
        memcpy(out, &a, size);
    }
    return TRUE;
}

DLLAPI BOOL WINAPI SymGetModuleInfoW64(HANDLE h, DWORD64 addr, PIMAGEHLP_MODULEW64 mi)
{ return module_info(h, addr, mi, mi ? mi->SizeOfStruct : 0, 1); }

DLLAPI BOOL WINAPI SymGetModuleInfo64(HANDLE h, DWORD64 addr, PIMAGEHLP_MODULE64 mi)
{ return module_info(h, addr, mi, mi ? mi->SizeOfStruct : 0, 0); }

DLLAPI BOOL WINAPI EnumerateLoadedModulesW64(HANDLE h, PENUMLOADED_MODULES_CALLBACKW64 cb, PVOID ctx)
{
    sym_process tmp, *p;
    sym_module *mods;
    unsigned n, i;
    if (!cb) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    AcquireSRWLockExclusive(&g_lock);
    p = find_process(h);
    if (!p) {                                                  /* works without SymInitialize, on any process handle */
        memset(&tmp, 0, sizeof tmp);
        tmp.h = h; tmp.pid = GetProcessId(h); tmp.is_self = tmp.pid == GetCurrentProcessId();
        p = &tmp;
    }
    if (!refresh_modules(p) && !p->nmods) { ReleaseSRWLockExclusive(&g_lock); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    n = p->nmods;
    mods = HeapAlloc(GetProcessHeap(), 0, (n ? n : 1) * sizeof *mods);
    if (mods) memcpy(mods, p->mods, n * sizeof *mods);
    if (p == &tmp && tmp.mods) HeapFree(GetProcessHeap(), 0, tmp.mods);
    ReleaseSRWLockExclusive(&g_lock);
    if (!mods) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    for (i = 0; i < n; ++i)
        if (!cb(mods[i].image, mods[i].base, mods[i].size, ctx)) break;
    HeapFree(GetProcessHeap(), 0, mods);
    return TRUE;
}

typedef struct { PENUMLOADED_MODULES_CALLBACK64 cb; PVOID ctx; } enum_a;
static BOOL CALLBACK enum_a_thunk(PCWSTR name, DWORD64 base, ULONG size, PVOID ctx)
{
    char a[MAX_PATH];
    narrow(name, a, sizeof a);
    return ((enum_a *)ctx)->cb(a, base, size, ((enum_a *)ctx)->ctx);
}

DLLAPI BOOL WINAPI EnumerateLoadedModules64(HANDLE h, PENUMLOADED_MODULES_CALLBACK64 cb, PVOID ctx)
{
    enum_a e = { cb, ctx };
    if (!cb) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return EnumerateLoadedModulesW64(h, enum_a_thunk, &e);
}

/* ================================================================ symbols (exports) */
/* The nearest export at or below `addr` in module m; returns 1 and the export's address/name. */
static int nearest_export(const sym_process *p, const sym_module *m, DWORD64 addr, DWORD64 *sym_addr, char *name, size_t cap)
{
    IMAGE_EXPORT_DIRECTORY ed;
    DWORD *funcs = 0, *names = 0;
    WORD *ords = 0;
    DWORD i, rva = (DWORD)(addr - m->base), best_rva = 0, best_ord = 0xffffffffu, best_name = 0xffffffffu;
    int found = 0;
    if (!m->export_dir_rva || !read_mem(p, m->base + m->export_dir_rva, &ed, sizeof ed)) return 0;
    if (ed.NumberOfFunctions == 0 || ed.NumberOfFunctions > 65536 || ed.NumberOfNames > 65536) return 0;
    funcs = HeapAlloc(GetProcessHeap(), 0, ed.NumberOfFunctions * sizeof(DWORD));
    names = HeapAlloc(GetProcessHeap(), 0, (ed.NumberOfNames ? ed.NumberOfNames : 1) * sizeof(DWORD));
    ords = HeapAlloc(GetProcessHeap(), 0, (ed.NumberOfNames ? ed.NumberOfNames : 1) * sizeof(WORD));
    if (!funcs || !names || !ords) goto out;
    if (!read_mem(p, m->base + ed.AddressOfFunctions, funcs, ed.NumberOfFunctions * sizeof(DWORD))) goto out;
    if (ed.NumberOfNames && (!read_mem(p, m->base + ed.AddressOfNames, names, ed.NumberOfNames * sizeof(DWORD)) ||
                             !read_mem(p, m->base + ed.AddressOfNameOrdinals, ords, ed.NumberOfNames * sizeof(WORD)))) goto out;
    for (i = 0; i < ed.NumberOfFunctions; ++i) {
        DWORD f = funcs[i];
        if (!f || f > rva) continue;
        if (f >= m->export_dir_rva && f < m->export_dir_rva + m->export_dir_size) continue;      /* a forwarder string */
        if (!found || f > best_rva) { found = 1; best_rva = f; best_ord = i; }
    }
    if (!found) goto out;
    for (i = 0; i < ed.NumberOfNames; ++i) if (ords[i] == best_ord) { best_name = names[i]; break; }
    *sym_addr = m->base + best_rva;
    if (best_name != 0xffffffffu) {
        size_t k = 0;
        for (;;) {
            char c;
            if (!read_mem(p, m->base + best_name + k, &c, 1) || k + 1 >= cap) { name[k] = 0; break; }
            name[k++] = c;
            if (!c) break;
        }
    } else {
        /* an export without a name: dbghelp calls it OrdinalN */
        DWORD o = ed.Base + best_ord;
        char d[12];
        size_t k = 0, j;
        do { d[k++] = (char)('0' + o % 10); o /= 10; } while (o);
        memcpy(name, "Ordinal", 7);
        for (j = 0; j < k && 7 + j + 1 < cap; ++j) name[7 + j] = d[k - 1 - j];
        name[7 + j] = 0;
    }
out:
    if (funcs) HeapFree(GetProcessHeap(), 0, funcs);
    if (names) HeapFree(GetProcessHeap(), 0, names);
    if (ords) HeapFree(GetProcessHeap(), 0, ords);
    return found;
}

static BOOL sym_lookup(HANDLE h, DWORD64 addr, DWORD64 *disp, DWORD64 *sym_addr, DWORD64 *mod_base, char *name, size_t cap)
{
    sym_process *p;
    sym_module *m = 0;
    int ok = 0;
    AcquireSRWLockExclusive(&g_lock);
    p = find_process(h);
    if (p) m = module_at(p, addr, 1);
    if (m) { *mod_base = m->base; ok = nearest_export(p, m, addr, sym_addr, name, cap); }
    ReleaseSRWLockExclusive(&g_lock);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (!m) { SetLastError(ERROR_MOD_NOT_FOUND); return FALSE; }
    if (!ok) { SetLastError(ERROR_INVALID_ADDRESS_); return FALSE; }
    if (disp) *disp = addr - *sym_addr;
    return TRUE;
}

DLLAPI BOOL WINAPI SymFromAddr(HANDLE h, DWORD64 addr, PDWORD64 disp, PSYMBOL_INFO si)
{
    char name[2048];
    DWORD64 sa = 0, mb = 0;
    size_t n;
    if (!si || si->SizeOfStruct != sizeof(SYMBOL_INFO)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!sym_lookup(h, addr, disp, &sa, &mb, name, sizeof name)) return FALSE;
    si->TypeIndex = 0; si->Reserved[0] = si->Reserved[1] = 0; si->info = 0; si->Size = 0;
    si->ModBase = mb; si->Flags = SYMFLAG_EXPORT; si->Value = 0; si->Address = sa; si->Register = 0; si->Scope = 0;
    si->Tag = SYMTAG_PUBLIC_SYMBOL;
    n = strlen(name);
    si->NameLen = (ULONG)n;
    if (si->MaxNameLen) {
        size_t c = n < si->MaxNameLen ? n : si->MaxNameLen - 1;
        memcpy(si->Name, name, c);
        si->Name[c] = 0;
    }
    return TRUE;
}

DLLAPI BOOL WINAPI SymFromAddrW(HANDLE h, DWORD64 addr, PDWORD64 disp, PSYMBOL_INFOW si)
{
    char name[2048];
    DWORD64 sa = 0, mb = 0;
    size_t n;
    if (!si || si->SizeOfStruct != sizeof(SYMBOL_INFOW)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!sym_lookup(h, addr, disp, &sa, &mb, name, sizeof name)) return FALSE;
    si->TypeIndex = 0; si->Reserved[0] = si->Reserved[1] = 0; si->info = 0; si->Size = 0;
    si->ModBase = mb; si->Flags = SYMFLAG_EXPORT; si->Value = 0; si->Address = sa; si->Register = 0; si->Scope = 0;
    si->Tag = SYMTAG_PUBLIC_SYMBOL;
    n = strlen(name);
    si->NameLen = (ULONG)n;
    if (si->MaxNameLen) widen(name, si->Name, si->MaxNameLen);
    return TRUE;
}

DLLAPI BOOL WINAPI SymGetSymFromAddr64(HANDLE h, DWORD64 addr, PDWORD64 disp, PIMAGEHLP_SYMBOL64 sym)
{
    char name[2048];
    DWORD64 sa = 0, mb = 0;
    size_t n;
    if (!sym || sym->SizeOfStruct < FIELD_OFFSET(IMAGEHLP_SYMBOL64, Name)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!sym_lookup(h, addr, disp, &sa, &mb, name, sizeof name)) return FALSE;
    sym->Address = sa;
    sym->Size = 0;
    sym->Flags = SYMFLAG_EXPORT;
    n = strlen(name);
    if (sym->MaxNameLength) {
        size_t c = n < sym->MaxNameLength ? n : sym->MaxNameLength - 1;
        memcpy(sym->Name, name, c);
        sym->Name[c] = 0;
    }
    return TRUE;
}

DLLAPI BOOL WINAPI SymGetLineFromAddr64(HANDLE h, DWORD64 addr, PDWORD disp, PIMAGEHLP_LINE64 line)
{
    sym_process *p;
    sym_module *m = 0;
    if (!line || line->SizeOfStruct != sizeof(IMAGEHLP_LINE64)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (disp) *disp = 0;
    AcquireSRWLockExclusive(&g_lock);
    p = find_process(h);
    if (p) m = module_at(p, addr, 1);
    ReleaseSRWLockExclusive(&g_lock);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    SetLastError(m ? ERROR_INVALID_ADDRESS_ : ERROR_MOD_NOT_FOUND);   /* no line information without a PDB */
    return FALSE;
}

DLLAPI BOOL WINAPI SymGetLineFromAddrW64(HANDLE h, DWORD64 addr, PDWORD disp, PIMAGEHLP_LINEW64 line)
{
    IMAGEHLP_LINE64 l;
    if (!line || line->SizeOfStruct != sizeof(IMAGEHLP_LINEW64)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    l.SizeOfStruct = sizeof l;
    return SymGetLineFromAddr64(h, addr, disp, &l);
}

/* ================================================================ unwind data, stack walk */
DLLAPI PVOID WINAPI SymFunctionTableAccess64(HANDLE h, DWORD64 addr)
{
    sym_process *p;
    sym_module *m = 0;
    PVOID r = 0;
    AcquireSRWLockExclusive(&g_lock);
    p = find_process(h);
    if (p && p->is_self) {
        DWORD64 base = 0;
        r = RtlLookupFunctionEntry(addr, &base, 0);
    } else if (p && (m = module_at(p, addr, 1)) != 0) {
        if (p->ft_base != m->base) {
            IMAGE_DOS_HEADER dos;
            IMAGE_NT_HEADERS64 nt;
            const IMAGE_DATA_DIRECTORY *dd;
            if (p->ft) { HeapFree(GetProcessHeap(), 0, p->ft); p->ft = 0; p->ft_count = 0; }
            p->ft_base = 0;
            if (read_mem(p, m->base, &dos, sizeof dos) && read_mem(p, m->base + dos.e_lfanew, &nt, sizeof nt)) {
                dd = &nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if (dd->VirtualAddress && dd->Size >= sizeof(RUNTIME_FUNCTION) && dd->Size < (1u << 26)) {
                    p->ft = HeapAlloc(GetProcessHeap(), 0, dd->Size);
                    if (p->ft && read_mem(p, m->base + dd->VirtualAddress, p->ft, dd->Size)) {
                        p->ft_count = dd->Size / sizeof(RUNTIME_FUNCTION);
                        p->ft_base = m->base;
                    } else if (p->ft) { HeapFree(GetProcessHeap(), 0, p->ft); p->ft = 0; }
                }
            }
        }
        if (p->ft_base == m->base && p->ft_count) {
            DWORD rva = (DWORD)(addr - m->base);
            unsigned lo = 0, hi = p->ft_count;
            while (lo < hi) {
                unsigned mid = (lo + hi) / 2;
                if (rva < p->ft[mid].BeginAddress) hi = mid;
                else if (rva >= p->ft[mid].EndAddress) lo = mid + 1;
                else { r = &p->ft[mid]; break; }
            }
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    if (!r) SetLastError(m || p->is_self ? ERROR_INVALID_ADDRESS_ : ERROR_MOD_NOT_FOUND);
    return r;
}

static void frame_from_context(STACKFRAME64 *f, const CONTEXT *c)
{
    f->AddrPC.Offset = c->Rip; f->AddrPC.Mode = AddrModeFlat;
    f->AddrFrame.Offset = c->Rbp; f->AddrFrame.Mode = AddrModeFlat;
    f->AddrStack.Offset = c->Rsp; f->AddrStack.Mode = AddrModeFlat;
    f->AddrBStore.Offset = 0; f->AddrBStore.Mode = AddrModeFlat;
    f->Far = FALSE;
}

/* One frame of x64 unwinding of `c` in the calling process, through the caller's routines. 0 = end of stack / failure. */
static int unwind_one(HANDLE h, CONTEXT *c, PFUNCTION_TABLE_ACCESS_ROUTINE64 fta, PGET_MODULE_BASE_ROUTINE64 gmb, PVOID *entry_out)
{
    DWORD64 base;
    RUNTIME_FUNCTION *fe;
    if (!c->Rip) return 0;
    base = gmb ? gmb(h, c->Rip) : SymGetModuleBase64(h, c->Rip);
    fe = fta ? fta(h, c->Rip) : SymFunctionTableAccess64(h, c->Rip);
    if (entry_out) *entry_out = fe;
    if (fe && base) {
        PVOID handler_data = 0;
        DWORD64 establisher = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, base, c->Rip, fe, c, &handler_data, &establisher, 0);
    } else {
        /* a leaf function (no unwind data): the return address is at [Rsp] */
        DWORD64 ret;
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)(ULONG_PTR)c->Rsp, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return 0;
        ret = *(const DWORD64 *)(ULONG_PTR)c->Rsp;
        c->Rip = ret;
        c->Rsp += 8;
    }
    return c->Rip != 0;
}

DLLAPI BOOL WINAPI StackWalk64(DWORD machine, HANDLE h, HANDLE thread, LPSTACKFRAME64 frame, PVOID ctx_,
                               PREAD_PROCESS_MEMORY_ROUTINE64 readmem, PFUNCTION_TABLE_ACCESS_ROUTINE64 fta,
                               PGET_MODULE_BASE_ROUTINE64 gmb, PTRANSLATE_ADDRESS_ROUTINE64 xlat)
{
    CONTEXT *c = ctx_, probe;
    DWORD pid;
    unsigned i;
    (void)thread; (void)readmem; (void)xlat;
    if (machine != IMAGE_FILE_MACHINE_AMD64 || !frame || !c) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    pid = GetProcessId(h);
    if (pid != GetCurrentProcessId()) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    if (frame->Virtual) {                                    /* every call after the first advances the context one frame */
        if (!unwind_one(h, c, fta, gmb, 0)) return FALSE;
    }
    frame_from_context(frame, c);
    frame->Virtual = TRUE;
    frame->FuncTableEntry = fta ? fta(h, c->Rip) : SymFunctionTableAccess64(h, c->Rip);
    /* the return address of this frame: what one more unwind step would make of Rip */
    probe = *c;
    frame->AddrReturn.Offset = unwind_one(h, &probe, fta, gmb, 0) ? probe.Rip : 0;
    frame->AddrReturn.Mode = AddrModeFlat;
    /* the first four stack parameters are in the home slots above the return address of this frame's caller */
    for (i = 0; i < 4; ++i) {
        MEMORY_BASIC_INFORMATION mbi;
        DWORD64 slot = probe.Rsp + i * 8;
        frame->Params[i] = 0;
        if (frame->AddrReturn.Offset && VirtualQuery((LPCVOID)(ULONG_PTR)slot, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT &&
            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            frame->Params[i] = *(const DWORD64 *)(ULONG_PTR)slot;
    }
    return TRUE;
}

/* ================================================================ file index information */
static int file_read(HANDLE f, ULONGLONG off, void *buf, DWORD n)
{
    LARGE_INTEGER li;
    DWORD got = 0;
    li.QuadPart = (LONGLONG)off;
    return SetFilePointerEx(f, li, 0, FILE_BEGIN) && ReadFile(f, buf, n, &got, 0) && got == n;
}

static BOOL index_info(const WCHAR *file, SYMSRV_INDEX_INFOW *info)
{
    HANDLE f;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_SECTION_HEADER sec[96];
    const IMAGE_DATA_DIRECTORY *dd;
    unsigned i, nsec;
    DWORD err = 0;
    f = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) return FALSE;              /* last error from CreateFile */
    if (!file_read(f, 0, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        !file_read(f, dos.e_lfanew, &nt, sizeof nt) || nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) err = ERROR_BAD_EXE_FORMAT;
    if (!err) {
        nsec = nt.FileHeader.NumberOfSections;
        if (nsec > 96 || !file_read(f, dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader, sec, nsec * sizeof sec[0]))
            err = ERROR_BAD_EXE_FORMAT;
    }
    if (err) { CloseHandle(f); SetLastError(err); return FALSE; }
    {
        size_t n = wlen(file);
        if (n > MAX_PATH) n = MAX_PATH;
        memcpy(info->file, file, n * sizeof(WCHAR));
        info->file[n] = 0;
    }
    info->stripped = (nt.FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) != 0;
    info->timestamp = nt.FileHeader.TimeDateStamp;
    info->size = nt.OptionalHeader.SizeOfImage;
    info->sig = nt.FileHeader.TimeDateStamp;
    dd = &nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    for (i = 0; dd->VirtualAddress && i < dd->Size / sizeof(IMAGE_DEBUG_DIRECTORY) && i < 16; ++i) {
        IMAGE_DEBUG_DIRECTORY dbg;
        ULONGLONG off = 0;
        unsigned s;
        for (s = 0; s < nsec; ++s) {
            DWORD rva = dd->VirtualAddress + i * sizeof dbg;
            if (rva >= sec[s].VirtualAddress && rva < sec[s].VirtualAddress + sec[s].SizeOfRawData) { off = sec[s].PointerToRawData + (rva - sec[s].VirtualAddress); break; }
        }
        if (!off || !file_read(f, off, &dbg, sizeof dbg)) break;
        if (dbg.Type == IMAGE_DEBUG_TYPE_CODEVIEW && dbg.SizeOfData >= 24 && dbg.PointerToRawData) {
            struct { DWORD sig; GUID guid; DWORD age; } cv;
            if (file_read(f, dbg.PointerToRawData, &cv, sizeof cv) && cv.sig == 0x53445352u) {
                char pdb[MAX_PATH + 1];
                DWORD n = dbg.SizeOfData - 24;
                if (n > MAX_PATH) n = MAX_PATH;
                info->guid = cv.guid;
                info->age = cv.age;
                if (file_read(f, dbg.PointerToRawData + 24, pdb, n)) { pdb[n] = 0; widen(pdb, info->pdbfile, MAX_PATH + 1); }
            }
            break;
        }
    }
    CloseHandle(f);
    return TRUE;
}

DLLAPI BOOL WINAPI SymSrvGetFileIndexInfoW(PCWSTR file, PSYMSRV_INDEX_INFOW info, DWORD flags)
{
    SYMSRV_INDEX_INFOW tmp;
    (void)flags;
    if (!file || !info || info->sizeofstruct != sizeof *info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(&tmp, 0, sizeof tmp);
    tmp.sizeofstruct = sizeof tmp;
    if (!index_info(file, &tmp)) return FALSE;
    *info = tmp;
    return TRUE;
}

DLLAPI BOOL WINAPI SymSrvGetFileIndexInfo(PCSTR file, PSYMSRV_INDEX_INFO info, DWORD flags)
{
    WCHAR w[MAX_PATH + 1];
    SYMSRV_INDEX_INFOW wi;
    if (!file || !info || info->sizeofstruct != sizeof *info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    widen(file, w, MAX_PATH + 1);
    wi.sizeofstruct = sizeof wi;
    if (!SymSrvGetFileIndexInfoW(w, &wi, flags)) return FALSE;
    memset(info, 0, sizeof *info);
    info->sizeofstruct = sizeof *info;
    narrow(wi.file, info->file, MAX_PATH + 1);
    info->stripped = wi.stripped; info->timestamp = wi.timestamp; info->size = wi.size;
    narrow(wi.dbgfile, info->dbgfile, MAX_PATH + 1); narrow(wi.pdbfile, info->pdbfile, MAX_PATH + 1);
    info->guid = wi.guid; info->sig = wi.sig; info->age = wi.age;
    return TRUE;
}

/* ================================================================ UnDecorateSymbolName */
DLLAPI DWORD WINAPI UnDecorateSymbolName(PCSTR in, PSTR out, DWORD cap, DWORD flags)
{
    size_t n;
    (void)flags;
    if (!in || !out || !cap) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (in[0] == '?') { SetLastError(ERROR_NOT_SUPPORTED); out[0] = 0; return 0; }   /* MSVC C++ decoration: not implemented */
    n = strlen(in);
    if (n >= cap) n = cap - 1;
    memcpy(out, in, n);
    out[n] = 0;
    return (DWORD)n;
}

DLLAPI DWORD WINAPI UnDecorateSymbolNameW(PCWSTR in, PWSTR out, DWORD cap, DWORD flags)
{
    size_t n;
    (void)flags;
    if (!in || !out || !cap) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (in[0] == '?') { SetLastError(ERROR_NOT_SUPPORTED); out[0] = 0; return 0; }
    n = wlen(in);
    if (n >= cap) n = cap - 1;
    memcpy(out, in, n * sizeof(WCHAR));
    out[n] = 0;
    return (DWORD)n;
}

/* ================================================================ MiniDumpWriteDump */
typedef struct { BYTE *p; SIZE_T len, cap; } dumpbuf;

static RVA dump_put(dumpbuf *d, const void *data, SIZE_T n)
{
    RVA at = (RVA)d->len;
    if (d->len + n > d->cap) {
        SIZE_T nc = d->cap ? d->cap * 2 : 65536;
        BYTE *np;
        while (nc < d->len + n) nc *= 2;
        np = HeapAlloc(GetProcessHeap(), 0, nc);
        if (!np) return 0xffffffffu;
        if (d->p) { memcpy(np, d->p, d->len); HeapFree(GetProcessHeap(), 0, d->p); }
        d->p = np; d->cap = nc;
    }
    if (data) memcpy(d->p + d->len, data, n); else memset(d->p + d->len, 0, n);
    d->len += n;
    return at;
}

static void dump_align(dumpbuf *d) { while (d->len & 7) dump_put(d, 0, 1); }

static RVA dump_string(dumpbuf *d, const WCHAR *s)
{
    ULONG32 bytes = (ULONG32)(wlen(s) * sizeof(WCHAR));
    RVA at = dump_put(d, &bytes, 4);
    dump_put(d, s, bytes + sizeof(WCHAR));
    dump_align(d);
    return at;
}

/* VS_FIXEDFILEINFO of a module from its in-memory resource tree (RT_VERSION / 1 / first language). */
static int module_fixed_version(const sym_process *p, const sym_module *m, VS_FIXEDFILEINFO *out)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    const IMAGE_DATA_DIRECTORY *dd;
    DWORD64 rsrc, dir;
    unsigned level;
    if (!read_mem(p, m->base, &dos, sizeof dos) || !read_mem(p, m->base + dos.e_lfanew, &nt, sizeof nt)) return 0;
    dd = &nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (!dd->VirtualAddress || !dd->Size) return 0;
    rsrc = m->base + dd->VirtualAddress;
    dir = rsrc;
    for (level = 0; level < 3; ++level) {
        IMAGE_RESOURCE_DIRECTORY rd;
        unsigned i, total;
        int found = 0;
        if (!read_mem(p, dir, &rd, sizeof rd)) return 0;
        total = rd.NumberOfNamedEntries + rd.NumberOfIdEntries;
        if (total > 4096) return 0;
        for (i = rd.NumberOfNamedEntries; i < total; ++i) {
            IMAGE_RESOURCE_DIRECTORY_ENTRY e;
            if (!read_mem(p, dir + sizeof rd + i * sizeof e, &e, sizeof e)) return 0;
            if (level == 0 && e.Name != 16) continue;               /* RT_VERSION */
            if (level == 1 && e.Name != 1) continue;                /* VS_VERSION_INFO */
            if (level < 2 && !e.DataIsDirectory) return 0;
            if (level == 2 && e.DataIsDirectory) return 0;
            if (level < 2) { dir = rsrc + e.OffsetToDirectory; found = 1; break; }
            {
                IMAGE_RESOURCE_DATA_ENTRY de;
                BYTE hdr[6 + 32 + 4];
                DWORD voff;
                if (!read_mem(p, rsrc + e.OffsetToData, &de, sizeof de) || de.Size < 52 + 40) return 0;
                if (!read_mem(p, m->base + de.OffsetToData, hdr, sizeof hdr)) return 0;
                /* VS_VERSIONINFO: wLength, wValueLength, wType, "VS_VERSION_INFO\0" (16 WCHARs), padding to 4 */
                voff = (6 + 16 * 2 + 3) & ~3u;
                if (*(WORD *)(hdr + 2) < 52) return 0;
                return read_mem(p, m->base + de.OffsetToData + voff, out, sizeof *out) && out->dwSignature == 0xFEEF04BDu;
            }
        }
        if (!found) return 0;
    }
    return 0;
}

DLLAPI BOOL WINAPI MiniDumpWriteDump(HANDLE h, DWORD volatile pid, HANDLE file, MINIDUMP_TYPE type, PMINIDUMP_EXCEPTION_INFORMATION const exc,
                                     PMINIDUMP_USER_STREAM_INFORMATION const user, PMINIDUMP_CALLBACK_INFORMATION const cb)
{
    sym_process tmp;
    dumpbuf d;
    MINIDUMP_HEADER hdr;
    MINIDUMP_DIRECTORY dirs[8];
    /* The SDK marks RtlCaptureContext returns_twice. Preserve state used
     * after capture without disabling the compiler's clobber diagnostics. */
    volatile unsigned ndir = 0;
    unsigned i;
    CONTEXT ctx;
    DWORD tid = GetCurrentThreadId();
    DWORD64 stack_lo, stack_hi;
    RVA ctx_rva, stack_rva;
    int exc_ctx_ok = 0;
    (void)type;
    if (!file || file == INVALID_HANDLE_VALUE) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (cb) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    if (!pid) pid = GetProcessId(h);
    if (pid != GetCurrentProcessId() || (h && GetProcessId(h) != pid)) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    memset(&tmp, 0, sizeof tmp);
    tmp.h = GetCurrentProcess(); tmp.pid = pid; tmp.is_self = 1;
    AcquireSRWLockExclusive(&g_lock);
    refresh_modules(&tmp);
    ReleaseSRWLockExclusive(&g_lock);

    /* the thread whose state is dumped: the one of ExceptionParam when it is this thread, else this thread */
    memset(&ctx, 0, sizeof ctx);
    if (exc && exc->ExceptionPointers && exc->ExceptionPointers->ContextRecord && !exc->ClientPointers) {
        ctx = *exc->ExceptionPointers->ContextRecord;
        exc_ctx_ok = 1;
        if (exc->ThreadId) tid = exc->ThreadId;
    } else {
        RtlCaptureContext(&ctx);
    }
    {
        /* the stack: from Rsp to the top of this thread's stack (TEB StackBase); another thread's stack bounds are not
         * known here, so its dump covers the 64 KiB above its Rsp that are readable */
        MEMORY_BASIC_INFORMATION mbi;
        stack_lo = ctx.Rsp & ~(DWORD64)15;
        if (tid == GetCurrentThreadId()) stack_hi = (DWORD64)teb_qword(TEB_STACK_BASE);
        else stack_hi = stack_lo + 65536;
        if (!VirtualQuery((LPCVOID)(ULONG_PTR)stack_lo, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT) stack_hi = stack_lo;
        else if (stack_hi > (DWORD64)(ULONG_PTR)mbi.BaseAddress + mbi.RegionSize) {
            DWORD64 end = (DWORD64)(ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            while (end < stack_hi && VirtualQuery((LPCVOID)(ULONG_PTR)end, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                end = (DWORD64)(ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            if (end < stack_hi) stack_hi = end;
        }
    }

    memset(&d, 0, sizeof d);
    memset(&hdr, 0, sizeof hdr);
    dump_put(&d, &hdr, sizeof hdr);                              /* placeholder, rewritten at the end */
    memset(dirs, 0, sizeof dirs);
    {
        RVA dir_rva = dump_put(&d, 0, sizeof dirs);              /* placeholder directory (8 entries at most) */
        hdr.StreamDirectoryRva = dir_rva;
    }
    dump_align(&d);

    /* SystemInfoStream */
    {
        MINIDUMP_SYSTEM_INFO si;
        SYSTEM_INFO sysinfo;
        RTL_OSVERSIONINFOW osv;
        static const WCHAR empty[] = { 0 };
        memset(&si, 0, sizeof si);
        GetNativeSystemInfo(&sysinfo);
        si.ProcessorArchitecture = sysinfo.wProcessorArchitecture;
        si.ProcessorLevel = sysinfo.wProcessorLevel;
        si.ProcessorRevision = sysinfo.wProcessorRevision;
        si.NumberOfProcessors = (UCHAR)sysinfo.dwNumberOfProcessors;
        si.ProductType = 1;                                          /* VER_NT_WORKSTATION */
        memset(&osv, 0, sizeof osv);
        osv.dwOSVersionInfoSize = sizeof osv;
        /* the version the kernel put in the PEB (ntdll RtlGetVersion), the same source dbghelp uses on Windows */
        if (RtlGetVersion(&osv) == 0) { si.MajorVersion = osv.dwMajorVersion; si.MinorVersion = osv.dwMinorVersion; si.BuildNumber = osv.dwBuildNumber; si.PlatformId = osv.dwPlatformId; }
        {
            int regs[4] = { 0, 0, 0, 0 };
            __asm__ volatile("cpuid" : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3]) : "a"(0), "c"(0));
            si.Cpu.X86CpuInfo.VendorId[0] = (ULONG32)regs[1]; si.Cpu.X86CpuInfo.VendorId[1] = (ULONG32)regs[3]; si.Cpu.X86CpuInfo.VendorId[2] = (ULONG32)regs[2];
            __asm__ volatile("cpuid" : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3]) : "a"(1), "c"(0));
            si.Cpu.X86CpuInfo.VersionInformation = (ULONG32)regs[0];
            si.Cpu.X86CpuInfo.FeatureInformation = (ULONG32)regs[3];
        }
        si.CSDVersionRva = dump_string(&d, empty);
        dirs[ndir].StreamType = SystemInfoStream;
        dirs[ndir].Location.DataSize = sizeof si;
        dirs[ndir].Location.Rva = dump_put(&d, &si, sizeof si);
        ++ndir;
        dump_align(&d);
    }
    /* the thread context and stack, shared by the thread list and the exception stream */
    ctx_rva = dump_put(&d, &ctx, sizeof ctx);
    dump_align(&d);
    stack_rva = dump_put(&d, (const void *)(ULONG_PTR)stack_lo, (SIZE_T)(stack_hi - stack_lo));
    dump_align(&d);
    /* ThreadListStream */
    {
        MINIDUMP_THREAD_LIST tl;
        MINIDUMP_THREAD th;
        memset(&th, 0, sizeof th);
        th.ThreadId = tid;
        th.SuspendCount = 0;
        th.PriorityClass = GetPriorityClass(GetCurrentProcess());
        th.Priority = (ULONG32)GetThreadPriority(GetCurrentThread());
        th.Teb = tid == GetCurrentThreadId() ? (ULONG64)teb_qword(TEB_SELF) : 0;
        th.Stack.StartOfMemoryRange = stack_lo;
        th.Stack.Memory.DataSize = (ULONG32)(stack_hi - stack_lo);
        th.Stack.Memory.Rva = stack_rva;
        th.ThreadContext.DataSize = sizeof ctx;
        th.ThreadContext.Rva = ctx_rva;
        tl.NumberOfThreads = 1;
        dirs[ndir].StreamType = ThreadListStream;
        dirs[ndir].Location.Rva = dump_put(&d, &tl, sizeof tl);
        dump_put(&d, &th, sizeof th);
        dirs[ndir].Location.DataSize = sizeof tl + sizeof th;
        ++ndir;
        dump_align(&d);
    }
    /* ModuleListStream: names and CodeView records first, then the list */
    {
        RVA *names = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (tmp.nmods ? tmp.nmods : 1) * sizeof(RVA));
        MINIDUMP_LOCATION_DESCRIPTOR *cvs = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (tmp.nmods ? tmp.nmods : 1) * sizeof *cvs);
        MINIDUMP_MODULE_LIST ml;
        if (!names || !cvs) { if (names) HeapFree(GetProcessHeap(), 0, names); if (cvs) HeapFree(GetProcessHeap(), 0, cvs); if (tmp.mods) HeapFree(GetProcessHeap(), 0, tmp.mods); if (d.p) HeapFree(GetProcessHeap(), 0, d.p); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        for (i = 0; i < tmp.nmods; ++i) {
            names[i] = dump_string(&d, tmp.mods[i].image);
            if (tmp.mods[i].has_cv) {
                struct { DWORD sig; GUID guid; DWORD age; } cv = { 0x53445352u, tmp.mods[i].pdb_guid, tmp.mods[i].pdb_age };
                cvs[i].Rva = dump_put(&d, &cv, sizeof cv);
                dump_put(&d, tmp.mods[i].pdb, strlen(tmp.mods[i].pdb) + 1);
                cvs[i].DataSize = (ULONG32)(sizeof cv + strlen(tmp.mods[i].pdb) + 1);
                dump_align(&d);
            }
        }
        ml.NumberOfModules = tmp.nmods;
        dirs[ndir].StreamType = ModuleListStream;
        dirs[ndir].Location.Rva = dump_put(&d, &ml, sizeof ml);
        for (i = 0; i < tmp.nmods; ++i) {
            MINIDUMP_MODULE mm;
            memset(&mm, 0, sizeof mm);
            mm.BaseOfImage = tmp.mods[i].base;
            mm.SizeOfImage = tmp.mods[i].size;
            mm.CheckSum = tmp.mods[i].checksum;
            mm.TimeDateStamp = tmp.mods[i].timestamp;
            mm.ModuleNameRva = names[i];
            module_fixed_version(&tmp, &tmp.mods[i], &mm.VersionInfo);
            mm.CvRecord = cvs[i];
            dump_put(&d, &mm, sizeof mm);
        }
        dirs[ndir].Location.DataSize = (ULONG32)(sizeof ml + tmp.nmods * sizeof(MINIDUMP_MODULE));
        ++ndir;
        dump_align(&d);
        HeapFree(GetProcessHeap(), 0, names);
        HeapFree(GetProcessHeap(), 0, cvs);
    }
    /* MemoryListStream: the dumped stack */
    {
        MINIDUMP_MEMORY_LIST mlst;
        MINIDUMP_MEMORY_DESCRIPTOR md;
        mlst.NumberOfMemoryRanges = 1;
        md.StartOfMemoryRange = stack_lo;
        md.Memory.DataSize = (ULONG32)(stack_hi - stack_lo);
        md.Memory.Rva = stack_rva;
        dirs[ndir].StreamType = MemoryListStream;
        dirs[ndir].Location.Rva = dump_put(&d, &mlst, sizeof mlst);
        dump_put(&d, &md, sizeof md);
        dirs[ndir].Location.DataSize = sizeof mlst + sizeof md;
        ++ndir;
        dump_align(&d);
    }
    /* ExceptionStream */
    if (exc && exc->ExceptionPointers && exc->ExceptionPointers->ExceptionRecord && !exc->ClientPointers) {
        MINIDUMP_EXCEPTION_STREAM es;
        const EXCEPTION_RECORD *er = exc->ExceptionPointers->ExceptionRecord;
        memset(&es, 0, sizeof es);
        es.ThreadId = exc->ThreadId ? exc->ThreadId : tid;
        es.ExceptionRecord.ExceptionCode = er->ExceptionCode;
        es.ExceptionRecord.ExceptionFlags = er->ExceptionFlags;
        es.ExceptionRecord.ExceptionRecord = (ULONG64)(ULONG_PTR)er->ExceptionRecord;
        es.ExceptionRecord.ExceptionAddress = (ULONG64)(ULONG_PTR)er->ExceptionAddress;
        es.ExceptionRecord.NumberParameters = er->NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS ? EXCEPTION_MAXIMUM_PARAMETERS : er->NumberParameters;
        for (i = 0; i < es.ExceptionRecord.NumberParameters; ++i) es.ExceptionRecord.ExceptionInformation[i] = er->ExceptionInformation[i];
        es.ThreadContext.DataSize = exc_ctx_ok ? sizeof ctx : 0;
        es.ThreadContext.Rva = exc_ctx_ok ? ctx_rva : 0;
        dirs[ndir].StreamType = ExceptionStream;
        dirs[ndir].Location.DataSize = sizeof es;
        dirs[ndir].Location.Rva = dump_put(&d, &es, sizeof es);
        ++ndir;
        dump_align(&d);
    }
    /* MiscInfoStream */
    {
        MINIDUMP_MISC_INFO mi;
        FILETIME c, e, k, u;
        memset(&mi, 0, sizeof mi);
        mi.SizeOfInfo = sizeof mi;
        mi.Flags1 = MINIDUMP_MISC1_PROCESS_ID;
        mi.ProcessId = pid;
        if (GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) {
            ULONG64 ct = ((ULONG64)c.dwHighDateTime << 32 | c.dwLowDateTime);
            mi.Flags1 |= MINIDUMP_MISC1_PROCESS_TIMES;
            mi.ProcessCreateTime = (ULONG32)((ct - 116444736000000000ull) / 10000000ull);
            mi.ProcessUserTime = (ULONG32)((((ULONG64)u.dwHighDateTime << 32 | u.dwLowDateTime)) / 10000000ull);
            mi.ProcessKernelTime = (ULONG32)((((ULONG64)k.dwHighDateTime << 32 | k.dwLowDateTime)) / 10000000ull);
        }
        dirs[ndir].StreamType = MiscInfoStream;
        dirs[ndir].Location.DataSize = sizeof mi;
        dirs[ndir].Location.Rva = dump_put(&d, &mi, sizeof mi);
        ++ndir;
        dump_align(&d);
    }
    /* user streams (at most what the directory has room for) */
    if (user && user->UserStreamArray) {
        for (i = 0; i < user->UserStreamCount && ndir < 8; ++i) {
            const MINIDUMP_USER_STREAM *us = &user->UserStreamArray[i];
            dirs[ndir].StreamType = us->Type;
            dirs[ndir].Location.DataSize = us->BufferSize;
            dirs[ndir].Location.Rva = dump_put(&d, us->Buffer, us->BufferSize);
            ++ndir;
            dump_align(&d);
        }
    }
    hdr.Signature = 0x504d444du;                              /* MINIDUMP_SIGNATURE 'PMDM' */
    hdr.Version = MINIDUMP_VERSION;
    hdr.NumberOfStreams = ndir;
    hdr.CheckSum = 0;
    {
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        hdr.TimeDateStamp = (ULONG32)((((ULONG64)now.dwHighDateTime << 32 | now.dwLowDateTime) - 116444736000000000ull) / 10000000ull);
    }
    hdr.Flags = MiniDumpNormal;
    if (d.p) {
        DWORD written = 0;
        BOOL ok;
        memcpy(d.p, &hdr, sizeof hdr);
        memcpy(d.p + hdr.StreamDirectoryRva, dirs, ndir * sizeof dirs[0]);
        ok = WriteFile(file, d.p, (DWORD)d.len, &written, 0) && written == d.len;
        HeapFree(GetProcessHeap(), 0, d.p);
        if (tmp.mods) HeapFree(GetProcessHeap(), 0, tmp.mods);
        return ok;
    }
    if (tmp.mods) HeapFree(GetProcessHeap(), 0, tmp.mods);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
}

/* ================================================================ misc */
DLLAPI LPAPI_VERSION WINAPI ImagehlpApiVersion(void)
{
    static API_VERSION v = { 10, 0, 0, 0 };
    v.MajorVersion = 10; v.MinorVersion = 0; v.Revision = 22631; v.Reserved = 0;
    return &v;
}

DLLAPI LPAPI_VERSION WINAPI ImagehlpApiVersionEx(LPAPI_VERSION app)
{
    (void)app;
    return ImagehlpApiVersion();
}
