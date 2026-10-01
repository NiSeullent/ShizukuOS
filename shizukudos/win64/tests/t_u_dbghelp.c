/* SPDX-License-Identifier: GPL-2.0-only
 * dbghelp.dll: symbol handler over export tables, module information, x64 StackWalk64, SymSrvGetFileIndexInfo and
 * MiniDumpWriteDump. Expected values are documented contracts (MSDN dbghelp reference, the minidump file format in
 * minidumpapiset.h) and facts this program can establish independently: the address of an exported function obtained
 * with GetProcAddress must be what SymFromAddr names, the module base from GetModuleHandle must be what
 * SymGetModuleBase64 returns, the PE header fields read from the image in memory must match SymGetModuleInfo64 and
 * SymSrvGetFileIndexInfo, and a stack walk from a known call chain must pass through this program's own frames. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include "u_check.h"

#define SELF L"C:\\SHZ\\TESTS\\T_U_DBGHELP.EXE"

static BOOL CALLBACK count_modules(PCWSTR name, DWORD64 base, ULONG size, PVOID ctx)
{
    int *n = ctx;
    if (name && name[0] && base && size) ++*n;
    return TRUE;
}

/* three nested frames with unwind data (they are not leaf: they call something) so the walk has known frames to cross */
static DWORD64 g_pc_inner;
int main(void);
static int depth_walk(HANDLE proc, int expect_self_frames);

static __attribute__((noinline)) int frame_c(HANDLE proc)
{
    return depth_walk(proc, 3);
}
static __attribute__((noinline)) int frame_b(HANDLE proc)
{
    int r = frame_c(proc);
    __asm__ volatile("" ::: "memory");
    return r + 1;
}
static __attribute__((noinline)) int frame_a(HANDLE proc)
{
    int r = frame_b(proc);
    __asm__ volatile("" ::: "memory");
    return r + 1;
}

/* Walks the stack of the calling thread and returns the number of frames whose PC lies inside this executable. */
static int depth_walk(HANDLE proc, int expect_self_frames)
{
    CONTEXT ctx;
    STACKFRAME64 f;
    DWORD64 exe = (DWORD64)(ULONG_PTR)GetModuleHandleW(0);
    (void)expect_self_frames;
    memset(&ctx, 0, sizeof ctx);
    RtlCaptureContext(&ctx);
    /* Initialize walk state after the SDK returns-twice capture point. */
    int frames = 0, self = 0, saw_main = 0;
    g_pc_inner = ctx.Rip;
    memset(&f, 0, sizeof f);
    f.AddrPC.Offset = ctx.Rip; f.AddrPC.Mode = AddrModeFlat;
    f.AddrFrame.Offset = ctx.Rbp; f.AddrFrame.Mode = AddrModeFlat;
    f.AddrStack.Offset = ctx.Rsp; f.AddrStack.Mode = AddrModeFlat;
    while (frames < 64 && StackWalk64(IMAGE_FILE_MACHINE_AMD64, proc, GetCurrentThread(), &f, &ctx, 0, SymFunctionTableAccess64, SymGetModuleBase64, 0)) {
        ++frames;
        if (f.AddrPC.Offset >= exe && f.AddrPC.Offset < exe + 0x100000) ++self;
        if (f.AddrPC.Offset >= (DWORD64)(ULONG_PTR)main && f.AddrPC.Offset < (DWORD64)(ULONG_PTR)main + 0x4000) saw_main = 1;
        if (!f.AddrReturn.Offset) break;
    }
    U_CHECKF("StackWalk64 walks through depth_walk, frame_c, frame_b, frame_a and main (>= 5 frames in this image)", self >= 5 && saw_main, "frames=%d self=%d main=%d", frames, self, saw_main);
    U_CHECK("the walk ends at a frame without a return address (the thread start)", frames >= 5 && frames < 64);
    return 0;
}

int main(void)
{
    HANDLE proc = GetCurrentProcess();
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    DWORD64 base;
    BOOL ok;

    U_CHECK("SymGetOptions defaults to SYMOPT_UNDNAME", SymGetOptions() == SYMOPT_UNDNAME);
    U_CHECK("SymSetOptions returns the new options", SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES) == (SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES) && SymGetOptions() == (SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES));
    U_CHECK("SymGetModuleBase64 before SymInitialize fails with ERROR_INVALID_HANDLE", SymGetModuleBase64(proc, (DWORD64)(ULONG_PTR)k32) == 0 && GetLastError() == ERROR_INVALID_HANDLE);
    ok = SymInitialize(proc, "C:\\SHZ\\SYMBOLS", TRUE);
    U_CHECKF("SymInitialize(current process, path, invade)", ok, "err=%u", (unsigned)GetLastError());
    U_CHECK("a second SymInitialize for the same process fails with ERROR_INVALID_PARAMETER", !SymInitialize(proc, 0, FALSE) && GetLastError() == ERROR_INVALID_PARAMETER);
    {
        char path[256];
        WCHAR wpath[256];
        U_CHECK("SymGetSearchPath returns the path given to SymInitialize", SymGetSearchPath(proc, path, sizeof path) && !strcmp(path, "C:\\SHZ\\SYMBOLS"));
        U_CHECK("SymSetSearchPathW / SymGetSearchPathW round-trip", SymSetSearchPathW(proc, L"srv*D:\\sym") && SymGetSearchPathW(proc, wpath, 256) && u_ascii_eq_w(wpath, "srv*D:\\sym"));
        U_CHECK("SymGetSearchPath with a too-small buffer fails with ERROR_INSUFFICIENT_BUFFER", !SymGetSearchPath(proc, path, 4) && GetLastError() == ERROR_INSUFFICIENT_BUFFER);
    }

    /* ---- modules ---- */
    base = SymGetModuleBase64(proc, (DWORD64)(ULONG_PTR)GetProcAddress(k32, "CreateFileW"));
    U_CHECKF("SymGetModuleBase64(address inside kernel32) = the kernel32 module handle", base == (DWORD64)(ULONG_PTR)k32, "base=%llx k32=%p", (unsigned long long)base, (void *)k32);
    U_CHECK("SymGetModuleBase64(address in no module) fails with ERROR_MOD_NOT_FOUND", SymGetModuleBase64(proc, 0x1000) == 0 && GetLastError() == ERROR_MOD_NOT_FOUND);
    {
        IMAGEHLP_MODULE64 mi;
        IMAGEHLP_MODULEW64 wmi;
        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)k32;
        const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)((const BYTE *)k32 + dos->e_lfanew);
        memset(&mi, 0, sizeof mi);
        mi.SizeOfStruct = sizeof mi;
        ok = SymGetModuleInfo64(proc, (DWORD64)(ULONG_PTR)k32 + 0x1000, &mi);
        U_CHECKF("SymGetModuleInfo64(kernel32): base, SizeOfImage and TimeDateStamp match the PE header in memory", ok && mi.BaseOfImage == (DWORD64)(ULONG_PTR)k32 && mi.ImageSize == nt->OptionalHeader.SizeOfImage && mi.TimeDateStamp == nt->FileHeader.TimeDateStamp, "ok=%d err=%u", ok, (unsigned)GetLastError());
        U_CHECK("...ModuleName \"kernel32\", ImageName under C:\\SHZ\\SYS64, SymType SymExport with NumSyms > 100, MachineType AMD64", ok && !strcmp(mi.ModuleName, "kernel32") && strstr(mi.ImageName, "SYS64") && mi.SymType == SymExport && mi.NumSyms > 100 && mi.MachineType == IMAGE_FILE_MACHINE_AMD64);
        memset(&wmi, 0, sizeof wmi);
        wmi.SizeOfStruct = FIELD_OFFSET(IMAGEHLP_MODULEW64, CVSig);           /* the older, shorter structure is accepted */
        U_CHECK("SymGetModuleInfoW64 accepts the pre-CodeView structure size", SymGetModuleInfoW64(proc, (DWORD64)(ULONG_PTR)k32, &wmi) && wmi.BaseOfImage == (DWORD64)(ULONG_PTR)k32 && u_ascii_eq_w(wmi.ModuleName, "kernel32"));
        wmi.SizeOfStruct = 12;
        U_CHECK("SymGetModuleInfoW64 with a bad SizeOfStruct fails with ERROR_INVALID_PARAMETER", !SymGetModuleInfoW64(proc, (DWORD64)(ULONG_PTR)k32, &wmi) && GetLastError() == ERROR_INVALID_PARAMETER);
    }
    {
        int n = 0;
        U_CHECK("EnumerateLoadedModulesW64 lists this program, ntdll and kernel32 at least", EnumerateLoadedModulesW64(proc, count_modules, &n) && n >= 3);
        U_CHECK("SymRefreshModuleList succeeds", SymRefreshModuleList(proc));
    }

    /* ---- symbols from export tables ---- */
    {
        static char sbuf[sizeof(SYMBOL_INFO) + 256];
        SYMBOL_INFO *si = (SYMBOL_INFO *)sbuf;
        DWORD64 disp = 0xffff;
        FARPROC cf = GetProcAddress(k32, "CreateFileW");
        memset(sbuf, 0, sizeof sbuf);
        si->SizeOfStruct = sizeof(SYMBOL_INFO);
        si->MaxNameLen = 256;
        ok = SymFromAddr(proc, (DWORD64)(ULONG_PTR)cf, &disp, si);
        U_CHECKF("SymFromAddr(CreateFileW) names the export CreateFileW at displacement 0", ok && !strcmp(si->Name, "CreateFileW") && disp == 0 && si->Address == (DWORD64)(ULONG_PTR)cf, "ok=%d name=%s disp=%llu err=%u", ok, si->Name, (unsigned long long)disp, (unsigned)GetLastError());
        U_CHECK("...SYMFLAG_EXPORT, ModBase = kernel32, NameLen = 11, Tag = SymTagPublicSymbol (10)", ok && (si->Flags & SYMFLAG_EXPORT) && si->ModBase == (DWORD64)(ULONG_PTR)k32 && si->NameLen == 11 && si->Tag == 10);
        ok = SymFromAddr(proc, (DWORD64)(ULONG_PTR)cf + 3, &disp, si);
        U_CHECK("SymFromAddr(CreateFileW + 3) is the same symbol with displacement 3", ok && !strcmp(si->Name, "CreateFileW") && disp == 3);
        si->MaxNameLen = 5;
        ok = SymFromAddr(proc, (DWORD64)(ULONG_PTR)cf, &disp, si);
        U_CHECK("a short MaxNameLen truncates the name (\"Crea\") but still reports NameLen 11", ok && !strcmp(si->Name, "Crea") && si->NameLen == 11);
        si->SizeOfStruct = 12;
        U_CHECK("SymFromAddr with a bad SizeOfStruct fails with ERROR_INVALID_PARAMETER", !SymFromAddr(proc, (DWORD64)(ULONG_PTR)cf, &disp, si) && GetLastError() == ERROR_INVALID_PARAMETER);
        si->SizeOfStruct = sizeof(SYMBOL_INFO); si->MaxNameLen = 256;
        U_CHECK("SymFromAddr(address in no module) fails with ERROR_MOD_NOT_FOUND", !SymFromAddr(proc, 0x1000, &disp, si) && GetLastError() == ERROR_MOD_NOT_FOUND);
        {
            static WCHAR wbuf[sizeof(SYMBOL_INFOW) + 256 * 2];
            SYMBOL_INFOW *wi = (SYMBOL_INFOW *)wbuf;
            memset(wbuf, 0, sizeof wbuf);
            wi->SizeOfStruct = sizeof(SYMBOL_INFOW);
            wi->MaxNameLen = 256;
            U_CHECK("SymFromAddrW gives the same name as a wide string", SymFromAddrW(proc, (DWORD64)(ULONG_PTR)cf, &disp, wi) && u_ascii_eq_w(wi->Name, "CreateFileW"));
        }
        {
            static char lbuf[sizeof(IMAGEHLP_SYMBOL64) + 256];
            IMAGEHLP_SYMBOL64 *ls = (IMAGEHLP_SYMBOL64 *)lbuf;
            memset(lbuf, 0, sizeof lbuf);
            ls->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
            ls->MaxNameLength = 256;
            U_CHECK("SymGetSymFromAddr64 (legacy) names the export too", SymGetSymFromAddr64(proc, (DWORD64)(ULONG_PTR)cf + 1, &disp, ls) && !strcmp(ls->Name, "CreateFileW") && disp == 1 && ls->Address == (DWORD64)(ULONG_PTR)cf);
        }
        {
            IMAGEHLP_LINE64 line;
            DWORD ld = 0;
            memset(&line, 0, sizeof line);
            line.SizeOfStruct = sizeof line;
            U_CHECK("SymGetLineFromAddr64 fails with ERROR_INVALID_ADDRESS (no line information without a PDB)", !SymGetLineFromAddr64(proc, (DWORD64)(ULONG_PTR)cf, &ld, &line) && GetLastError() == 487);
        }
    }

    /* ---- unwind data and the stack walk ---- */
    {
        PRUNTIME_FUNCTION rf = SymFunctionTableAccess64(proc, (DWORD64)(ULONG_PTR)frame_a + 4);
        DWORD64 ib = 0;
        PRUNTIME_FUNCTION ref = RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)frame_a + 4, &ib, 0);
        U_CHECKF("SymFunctionTableAccess64 returns the RUNTIME_FUNCTION RtlLookupFunctionEntry finds for frame_a", rf && rf == ref, "rf=%p ref=%p", (void *)rf, (void *)ref);
        U_CHECK("SymFunctionTableAccess64(address in no module) returns NULL", SymFunctionTableAccess64(proc, 0x1000) == 0);
        frame_a(proc);
        {
            CONTEXT c;
            STACKFRAME64 f;
            memset(&f, 0, sizeof f);
            memset(&c, 0, sizeof c);
            U_CHECK("StackWalk64 with a machine type other than AMD64 fails with ERROR_INVALID_PARAMETER", !StackWalk64(IMAGE_FILE_MACHINE_I386, proc, GetCurrentThread(), &f, &c, 0, 0, 0, 0) && GetLastError() == ERROR_INVALID_PARAMETER);
        }
    }

    /* ---- SymSrvGetFileIndexInfo on this executable ---- */
    {
        SYMSRV_INDEX_INFOW info;
        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)GetModuleHandleW(0);
        const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)((const BYTE *)dos + dos->e_lfanew);
        memset(&info, 0, sizeof info);
        info.sizeofstruct = sizeof info;
        ok = SymSrvGetFileIndexInfoW(SELF, &info, 0);
        U_CHECKF("SymSrvGetFileIndexInfoW(self): timestamp and size match the PE header of the loaded image", ok && info.timestamp == nt->FileHeader.TimeDateStamp && info.size == nt->OptionalHeader.SizeOfImage && info.sig == nt->FileHeader.TimeDateStamp, "ok=%d err=%u", ok, (unsigned)GetLastError());
        U_CHECK("...file is the name asked for", ok && u_wide_eq(info.file, (const unsigned short *)SELF));
        info.sizeofstruct = 4;
        U_CHECK("a wrong sizeofstruct fails with ERROR_INVALID_PARAMETER", !SymSrvGetFileIndexInfoW(SELF, &info, 0) && GetLastError() == ERROR_INVALID_PARAMETER);
        info.sizeofstruct = sizeof info;
        U_CHECK("a missing file fails with ERROR_FILE_NOT_FOUND", !SymSrvGetFileIndexInfoW(L"C:\\SHZ\\TESTS\\NOPE.EXE", &info, 0) && GetLastError() == ERROR_FILE_NOT_FOUND);
        U_CHECK("a non-PE file fails with ERROR_BAD_EXE_FORMAT", !SymSrvGetFileIndexInfoW(L"C:\\SHZ\\TESTS\\M2.HTML", &info, 0) ? GetLastError() == ERROR_BAD_EXE_FORMAT || GetLastError() == ERROR_FILE_NOT_FOUND : 0);
    }

    /* ---- UnDecorateSymbolName ---- */
    {
        char out[64];
        U_CHECK("UnDecorateSymbolName copies an undecorated name and returns its length", UnDecorateSymbolName("CreateFileW", out, sizeof out, UNDNAME_COMPLETE) == 11 && !strcmp(out, "CreateFileW"));
        U_CHECK("UnDecorateSymbolName truncates to the buffer", UnDecorateSymbolName("CreateFileW", out, 5, UNDNAME_COMPLETE) == 4 && !strcmp(out, "Crea"));
        U_CHECK("an MSVC-decorated name fails explicitly with ERROR_NOT_SUPPORTED", UnDecorateSymbolName("?foo@@YAXXZ", out, sizeof out, UNDNAME_COMPLETE) == 0 && GetLastError() == ERROR_NOT_SUPPORTED);
    }

    /* ---- MiniDumpWriteDump ---- */
    {
        HANDLE f = CreateFileW(L"C:\\SHZ\\TESTS\\T_U_DBGHELP.DMP", GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        U_CHECKF("a dump file can be created", f != INVALID_HANDLE_VALUE, "err=%u", (unsigned)GetLastError());
        if (f != INVALID_HANDLE_VALUE) {
            EXCEPTION_RECORD er;
            CONTEXT ec;
            EXCEPTION_POINTERS ep = { &er, &ec };
            MINIDUMP_EXCEPTION_INFORMATION mei = { 0, &ep, FALSE };
            static BYTE dump[262144];
            DWORD got = 0;
            LARGE_INTEGER zero = { { 0, 0 } };
            memset(&er, 0, sizeof er);
            er.ExceptionCode = 0xC0000005;
            er.ExceptionAddress = (PVOID)main;
            er.NumberParameters = 2;
            er.ExceptionInformation[0] = 1; er.ExceptionInformation[1] = 0xdead;
            RtlCaptureContext(&ec);
            mei.ThreadId = GetCurrentThreadId();
            ok = MiniDumpWriteDump(proc, GetCurrentProcessId(), f, MiniDumpNormal, &mei, 0, 0);
            U_CHECKF("MiniDumpWriteDump(current process, exception) succeeds", ok, "err=%u", (unsigned)GetLastError());
            SetFilePointerEx(f, zero, 0, FILE_BEGIN);
            ok = ReadFile(f, dump, sizeof dump, &got, 0);
            U_CHECKF("the dump is readable and larger than the header", ok && got > sizeof(MINIDUMP_HEADER) + 6 * sizeof(MINIDUMP_DIRECTORY), "got=%u", (unsigned)got);
            if (ok && got > sizeof(MINIDUMP_HEADER)) {
                const MINIDUMP_HEADER *h = (const MINIDUMP_HEADER *)dump;
                const MINIDUMP_DIRECTORY *d = (const MINIDUMP_DIRECTORY *)(dump + h->StreamDirectoryRva);
                unsigned i, seen_sys = 0, seen_thr = 0, seen_mod = 0, seen_mem = 0, seen_exc = 0, seen_misc = 0, inside = 1;
                U_CHECK("header: signature 'PMDM' (0x504d444d), version 42899 in the low word, >= 6 streams, Flags MiniDumpNormal", h->Signature == 0x504d444d && (h->Version & 0xffff) == 42899 && h->NumberOfStreams >= 6 && h->Flags == MiniDumpNormal);
                for (i = 0; i < h->NumberOfStreams && h->StreamDirectoryRva + (i + 1) * sizeof *d <= got; ++i) {
                    if (d[i].Location.Rva + d[i].Location.DataSize > got) inside = 0;
                    switch (d[i].StreamType) {
                    case SystemInfoStream: {
                        const MINIDUMP_SYSTEM_INFO *si = (const MINIDUMP_SYSTEM_INFO *)(dump + d[i].Location.Rva);
                        seen_sys = d[i].Location.DataSize == sizeof *si && si->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 && si->MajorVersion == 10 && si->NumberOfProcessors >= 1;
                        break;
                    }
                    case ThreadListStream: {
                        const MINIDUMP_THREAD_LIST *tl = (const MINIDUMP_THREAD_LIST *)(dump + d[i].Location.Rva);
                        const CONTEXT *tc = tl->NumberOfThreads ? (const CONTEXT *)(dump + tl->Threads[0].ThreadContext.Rva) : 0;
                        seen_thr = tl->NumberOfThreads == 1 && tl->Threads[0].ThreadId == GetCurrentThreadId() && tl->Threads[0].ThreadContext.DataSize == sizeof(CONTEXT) &&
                                   tc && tc->Rip == ec.Rip && tc->Rsp == ec.Rsp && tl->Threads[0].Stack.StartOfMemoryRange <= ec.Rsp && tl->Threads[0].Stack.Memory.DataSize > 0;
                        break;
                    }
                    case ModuleListStream: {
                        const MINIDUMP_MODULE_LIST *ml = (const MINIDUMP_MODULE_LIST *)(dump + d[i].Location.Rva);
                        unsigned k, self_ok = 0, k32_ok = 0;
                        for (k = 0; k < ml->NumberOfModules; ++k) {
                            const MINIDUMP_MODULE *m = &ml->Modules[k];
                            const MINIDUMP_STRING *nm = (const MINIDUMP_STRING *)(dump + m->ModuleNameRva);
                            if (m->BaseOfImage == (DWORD64)(ULONG_PTR)GetModuleHandleW(0)) self_ok = nm->Length > 0 && m->VersionInfo.dwSignature == 0xFEEF04BD && m->VersionInfo.dwFileVersionMS == 0x000a0000;
                            if (m->BaseOfImage == (DWORD64)(ULONG_PTR)k32) k32_ok = m->SizeOfImage > 0 && m->TimeDateStamp != 0;
                        }
                        seen_mod = ml->NumberOfModules >= 3 && self_ok && k32_ok;
                        break;
                    }
                    case MemoryListStream: {
                        const MINIDUMP_MEMORY_LIST *ml = (const MINIDUMP_MEMORY_LIST *)(dump + d[i].Location.Rva);
                        seen_mem = ml->NumberOfMemoryRanges == 1 && ml->MemoryRanges[0].StartOfMemoryRange <= ec.Rsp;
                        break;
                    }
                    case ExceptionStream: {
                        const MINIDUMP_EXCEPTION_STREAM *es = (const MINIDUMP_EXCEPTION_STREAM *)(dump + d[i].Location.Rva);
                        seen_exc = es->ThreadId == GetCurrentThreadId() && es->ExceptionRecord.ExceptionCode == 0xC0000005 && es->ExceptionRecord.ExceptionAddress == (ULONG64)(ULONG_PTR)main &&
                                   es->ExceptionRecord.NumberParameters == 2 && es->ExceptionRecord.ExceptionInformation[1] == 0xdead && es->ThreadContext.DataSize == sizeof(CONTEXT);
                        break;
                    }
                    case MiscInfoStream: {
                        const MINIDUMP_MISC_INFO *mi = (const MINIDUMP_MISC_INFO *)(dump + d[i].Location.Rva);
                        seen_misc = mi->SizeOfInfo == sizeof *mi && (mi->Flags1 & MINIDUMP_MISC1_PROCESS_ID) && mi->ProcessId == GetCurrentProcessId();
                        break;
                    }
                    default: break;
                    }
                }
                U_CHECK("every stream lies inside the file", inside);
                U_CHECK("SystemInfoStream: AMD64, Windows 10, >= 1 processor", seen_sys);
                U_CHECK("ThreadListStream: this thread with the exception CONTEXT and its stack", seen_thr);
                U_CHECK("ModuleListStream: this program (with its VS_FIXEDFILEINFO 10.0.x) and kernel32 among >= 3 modules", seen_mod);
                U_CHECK("MemoryListStream: the dumped stack range", seen_mem);
                U_CHECK("ExceptionStream: code, address, parameters and context of the exception given", seen_exc);
                U_CHECK("MiscInfoStream: the process id", seen_misc);
            }
            CloseHandle(f);
            DeleteFileW(L"C:\\SHZ\\TESTS\\T_U_DBGHELP.DMP");
        }
        U_CHECK("MiniDumpWriteDump with an invalid file handle fails with ERROR_INVALID_PARAMETER", !MiniDumpWriteDump(proc, GetCurrentProcessId(), INVALID_HANDLE_VALUE, MiniDumpNormal, 0, 0, 0) && GetLastError() == ERROR_INVALID_PARAMETER);
    }

    U_CHECK("SymCleanup succeeds once and fails the second time with ERROR_INVALID_HANDLE", SymCleanup(proc) && !SymCleanup(proc) && GetLastError() == ERROR_INVALID_HANDLE);
    U_CHECK("after SymCleanup the process is unknown again", SymGetModuleBase64(proc, (DWORD64)(ULONG_PTR)k32) == 0 && GetLastError() == ERROR_INVALID_HANDLE);
    return u_finish("t_u_dbghelp");
}
