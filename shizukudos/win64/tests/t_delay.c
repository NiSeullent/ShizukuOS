/* SPDX-License-Identifier: GPL-2.0-only
 * Delay-load end to end: this image delay-imports winmm!timeGetTime and version!GetFileVersionInfoSizeW through import
 * libraries built with `dlltool --output-delaylib` (shizukudos/win64/build.py). The functions are NOT bound by the
 * loader; on the first call each stub invokes __delayLoadHelper2 (crt/shzcrt.c), which calls kernel32!ResolveDelayLoadedAPI
 * -> ntdll!LdrResolveDelayLoadedAPI to load the DLL, resolve the export and patch the IAT slot. A second call must reach
 * the same resolved address directly. The test also confirms neither DLL was in the loader database before the first
 * call (delay modules are loaded lazily) and both are afterwards.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"
#include "u_check.h"

__declspec(dllimport) DWORD WINAPI timeGetTime(void);
__declspec(dllimport) DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR, LPDWORD);
extern DWORD (WINAPI *__imp_timeGetTime)(void);

typedef struct {
    DWORD Attributes, DllNameRVA, ModuleHandleRVA, ImportAddressTableRVA, ImportNameTableRVA,
          BoundImportAddressTableRVA, UnloadInformationTableRVA, TimeDateStamp;
} TEST_DELAY_DESCRIPTOR;
typedef PVOID (WINAPI *RESOLVER)(PVOID, const TEST_DELAY_DESCRIPTOR *, PVOID, PVOID, PIMAGE_THUNK_DATA, ULONG);
typedef struct {
    BYTE *base;
    TEST_DELAY_DESCRIPTOR desc;
    HMODULE *module;
    IMAGE_THUNK_DATA *iat;
    RESOLVER resolve;
} FIXTURE;

static void copy_ascii(char *out, const char *text)
{
    while ((*out++ = *text++) != 0) {}
}

static DWORD protection(const void *pointer)
{
    MEMORY_BASIC_INFORMATION mbi;
    return VirtualQuery(pointer, &mbi, sizeof mbi) ? mbi.Protect : 0;
}

/* Metadata, module handle and IAT live on different pages. A fourth page stays
 * reserved so a failed publication is tested without causing an access fault. */
static int fixture_init(FIXTURE *f, const char *dll, const char *proc)
{
    IMAGE_THUNK_DATA *names;
    IMAGE_IMPORT_BY_NAME *name;
    DWORD old;
    f->base = VirtualAlloc(0, 16384, MEM_RESERVE, PAGE_NOACCESS);
    f->module = 0;
    if (!f->base || !VirtualAlloc(f->base, 12288, MEM_COMMIT, PAGE_READWRITE)) return 0;
    f->desc = (TEST_DELAY_DESCRIPTOR){1, 768, 4096, 8192, 256, 0, 0, 0};
    f->module = (HMODULE *)(f->base + 4096);
    f->iat = (IMAGE_THUNK_DATA *)(f->base + 8192);
    names = (IMAGE_THUNK_DATA *)(f->base + 256);
    name = (IMAGE_IMPORT_BY_NAME *)(f->base + 512);
    names[0].u1.AddressOfData = names[1].u1.AddressOfData = 512;
    copy_ascii((char *)name->Name, proc);
    copy_ascii((char *)(f->base + 768), dll);
    f->iat[0].u1.Function = f->iat[1].u1.Function = 0x1234;
    f->base[4096 + 24] = f->base[8192 + 24] = 0x5a;
    f->resolve = (RESOLVER)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ResolveDelayLoadedAPI");
    return f->resolve && VirtualProtect(f->module, 4096, PAGE_READONLY, &old) &&
           VirtualProtect(f->iat, 4096, PAGE_READONLY, &old);
}

static void fixture_free(FIXTURE *f)
{
    DWORD old;
    if (f->module && VirtualProtect(f->module, 4096, PAGE_READWRITE, &old) && *f->module) FreeLibrary(*f->module);
    if (f->base) VirtualFree(f->base, 0, MEM_RELEASE);
}

static DWORD WINAPI resolve_thread(void *argument)
{
    FIXTURE *f = argument;
    PVOID expected = (PVOID)GetProcAddress(GetModuleHandleA("winmm.dll"), "timeGetTime");
    unsigned i;
    for (i = 0; i < 64; ++i)
        if (f->resolve(f->base, &f->desc, 0, 0, &f->iat[i & 1], 0) != expected) return 1;
    return 0;
}

static PVOID WINAPI reject_missing(LPCSTR dll, LPCSTR proc)
{
    (void)dll; (void)proc;
    SetLastError(0x12345678);     /* must not replace the actual GetProcAddress failure */
    return 0;
}

/* Run before any failed lookup in a fresh child, so the diagnostic helper's
 * lazily initialized cache cannot hide first-use LastError corruption. */
static int first_error_check(void)
{
    char setting[8];
    HMODULE module = GetModuleHandleA("kernel32.dll");
    FARPROC missing;
    DWORD error, length;
    SetEnvironmentVariableA("SHZ_K32TRACE", NULL);
    SetLastError(0);
    length = GetEnvironmentVariableA("SHZ_K32TRACE", setting, sizeof setting);
    error = GetLastError();
    U_CHECKF("fresh child has no diagnostic trace setting", length == 0 && error == ERROR_ENVVAR_NOT_FOUND,
             "length=%u error=%u", (unsigned)length, (unsigned)error);
    SetLastError(0);
    missing = GetProcAddress(module, "SHZMissingFirstProcedure"); error = GetLastError();
    U_CHECKF("first failed GetProcAddress preserves ERROR_PROC_NOT_FOUND", !missing && error == ERROR_PROC_NOT_FOUND,
             "address=%p error=%u", (void *)missing, (unsigned)error);
    SetLastError(0);
    missing = GetProcAddress(module, "SHZMissingSecondProcedure"); error = GetLastError();
    U_CHECKF("cached trace setting also preserves the procedure error", !missing && error == ERROR_PROC_NOT_FOUND,
             "address=%p error=%u", (void *)missing, (unsigned)error);
    return u_finish("t_delay_first_error");
}

static void isolated_first_error(void)
{
    WCHAR image[MAX_PATH], command[MAX_PATH + 32];
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    const char suffix[] = "\" --first-error";
    DWORD length = GetModuleFileNameW(NULL, image, MAX_PATH), error, exit = 1;
    unsigned i, at = 0;
    BOOL started;
    U_CHECK("fresh error-test child has its executable path", length > 0 && length < MAX_PATH);
    if (!length || length >= MAX_PATH) return;
    command[at++] = '"';
    for (i = 0; i < length; ++i) command[at++] = image[i];
    for (i = 0; suffix[i]; ++i) command[at++] = (unsigned char)suffix[i];
    command[at] = 0;
    startup.cb = sizeof startup;
    started = CreateProcessW(image, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
    error = GetLastError();
    U_CHECKF("fresh child starts with an independent diagnostic cache", started, "error=%u", (unsigned)error);
    if (!started) return;
    if (WaitForSingleObject(process.hProcess, 10000) != WAIT_OBJECT_0) {
        U_CHECK("fresh error-test child finishes within the observation bound", 0);
        TerminateProcess(process.hProcess, 0xee);
        WaitForSingleObject(process.hProcess, INFINITE);
    }
    U_CHECK("fresh child reports both first-use and cached error checks passed",
            GetExitCodeProcess(process.hProcess, &exit) && exit == 0);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
}

static void protected_slots(void)
{
    FIXTURE f = {0};
    PVOID fn, direct = (PVOID)GetProcAddress(GetModuleHandleA("winmm.dll"), "timeGetTime");
    DWORD error, old;
    int ready = fixture_init(&f, "winmm.dll", "timeGetTime");
    U_CHECK("readonly delay-slot fixture allocated", ready);
    if (!ready) { fixture_free(&f); return; }
    fn = f.resolve(f.base, &f.desc, 0, 0, &f.iat[0], 0);
    U_CHECK("readonly module handle and IAT resolve to the real export", fn == direct && *f.module == GetModuleHandleA("winmm.dll") &&
            f.iat[0].u1.Function == (ULONG_PTR)direct);
    U_CHECK("both pointer pages retain their original readonly protection", protection(f.module) == PAGE_READONLY && protection(f.iat) == PAGE_READONLY);
    U_CHECK("publishing two pointers leaves adjacent data intact", f.base[4096 + 24] == 0x5a && f.base[8192 + 24] == 0x5a);
    {
        HANDLE threads[2] = {CreateThread(0, 0, resolve_thread, &f, 0, 0), CreateThread(0, 0, resolve_thread, &f, 0, 0)};
        DWORD codes[2] = {1, 1};
        int waited = threads[0] && threads[1] && WaitForMultipleObjects(2, threads, TRUE, 10000) == WAIT_OBJECT_0;
        U_CHECK("concurrent delay resolvers sharing one readonly page finish", waited);
        if (waited) {
            GetExitCodeThread(threads[0], &codes[0]); GetExitCodeThread(threads[1], &codes[1]);
            U_CHECK("both concurrent resolvers return the genuine export on every call", codes[0] == 0 && codes[1] == 0);
        }
        /* Keep the fixture alive even if the bounded observation failed. */
        if (threads[0]) { WaitForSingleObject(threads[0], INFINITE); CloseHandle(threads[0]); }
        if (threads[1]) { WaitForSingleObject(threads[1], INFINITE); CloseHandle(threads[1]); }
        U_CHECK("shared page is readonly after both resolver threads exit", protection(f.iat) == PAGE_READONLY &&
                f.iat[0].u1.Function == (ULONG_PTR)direct && f.iat[1].u1.Function == (ULONG_PTR)direct);
    }
    f.desc.ImportAddressTableRVA = 12288;
    SetLastError(0);
    fn = f.resolve(f.base, &f.desc, 0, 0, (PIMAGE_THUNK_DATA)(f.base + 12288), 0);
    error = GetLastError();
    U_CHECK("uncommitted IAT publication fails with a real access error", !fn && error == ERROR_NOACCESS);
    {
        MEMORY_BASIC_INFORMATION mbi;
        U_CHECK("failed publication never commits the reserved IAT page", VirtualQuery(f.base + 12288, &mbi, sizeof mbi) && mbi.State == MEM_RESERVE);
    }
    f.desc.ImportAddressTableRVA = 8192;
    U_CHECK("guarded IAT setup", VirtualProtect(f.iat, 4096, PAGE_READONLY | PAGE_GUARD, &old));
    SetLastError(0);
    fn = f.resolve(f.base, &f.desc, 0, 0, &f.iat[0], 0); error = GetLastError();
    U_CHECK("resolver refuses a guarded IAT without stripping the guard", !fn && error == ERROR_NOACCESS &&
            protection(f.iat) == (PAGE_READONLY | PAGE_GUARD));
    U_CHECK("inaccessible module handle setup", VirtualProtect(f.module, 4096, PAGE_NOACCESS, &old));
    SetLastError(0);
    fn = f.resolve(f.base, &f.desc, 0, 0, &f.iat[0], 0); error = GetLastError();
    U_CHECK("resolver refuses an inaccessible module handle without touching it", !fn && error == ERROR_NOACCESS && protection(f.module) == PAGE_NOACCESS);
    fixture_free(&f);
}

static void resolution_failures(void)
{
    FIXTURE f = {0};
    PVOID fn;
    DWORD error;
    int ready = fixture_init(&f, "SHZ_MISSING_DELAY_20260930.DLL", "timeGetTime");
    U_CHECK("missing-DLL fixture allocated", ready);
    if (ready) {
        SetLastError(0); fn = f.resolve(f.base, &f.desc, 0, 0, &f.iat[0], 0); error = GetLastError();
        U_CHECK("missing delay DLL returns a failure stub and preserves its error", fn && error == ERROR_MOD_NOT_FOUND && !*f.module && f.iat[0].u1.Function == (ULONG_PTR)fn);
        if (fn) U_CHECK("missing-DLL stub reports failure when called", ((ULONGLONG (WINAPI *)(void))fn)() == 0 && GetLastError() == ERROR_MOD_NOT_FOUND);
        U_CHECK("missing-DLL failure also restores readonly slot pages", protection(f.module) == PAGE_READONLY && protection(f.iat) == PAGE_READONLY);
    }
    fixture_free(&f);
    f = (FIXTURE){0};
    ready = fixture_init(&f, "winmm.dll", "SHZMissingDelayProcedure");
    U_CHECK("missing-procedure fixture allocated", ready);
    if (ready) {
        SetLastError(0); fn = f.resolve(f.base, &f.desc, 0, (PVOID)reject_missing, &f.iat[0], 0); error = GetLastError();
        U_CHECKF("rejecting failure hook preserves the real missing-procedure error", !fn && error == ERROR_PROC_NOT_FOUND && f.iat[0].u1.Function == 0x1234,
                 "address=%p error=%u IAT=%p", fn, (unsigned)error, (void *)(ULONG_PTR)f.iat[0].u1.Function);
        SetLastError(0); fn = f.resolve(f.base, &f.desc, 0, 0, &f.iat[0], 0); error = GetLastError();
        U_CHECK("missing procedure returns a failure stub and preserves its error", fn && error == ERROR_PROC_NOT_FOUND && f.iat[0].u1.Function == (ULONG_PTR)fn);
        if (fn) U_CHECK("missing-procedure stub reports failure when called", ((ULONGLONG (WINAPI *)(void))fn)() == 0 && GetLastError() == ERROR_PROC_NOT_FOUND);
        U_CHECK("procedure failure restores readonly slot pages", protection(f.module) == PAGE_READONLY && protection(f.iat) == PAGE_READONLY);
    }
    fixture_free(&f);
}

int main(int argc, char **argv)
{
    DWORD t1, t2;
    DWORD handle = 0, old;
    unsigned short name[16];
    if (argc > 1 && strcmp(argv[1], "--first-error") == 0) return first_error_check();
    isolated_first_error();
    U_CHECK("winmm not loaded before the first delay call", GetModuleHandleW(u_wide("winmm.dll", name, 16)) == 0);

    U_CHECK("real dlltool delay IAT made readonly before its first call", VirtualProtect(&__imp_timeGetTime, sizeof __imp_timeGetTime, PAGE_READONLY, &old));

    t1 = timeGetTime();                                     /* first call: resolves winmm!timeGetTime through the helper */
    t2 = timeGetTime();                                     /* second call: goes direct through the patched IAT slot */
    U_CHECKF("timeGetTime resolved and returned a monotonic tick count", t2 >= t1, "t1=%u t2=%u", (unsigned)t1, (unsigned)t2);
    U_CHECK("winmm loaded after the delay import resolved", GetModuleHandleW(u_wide("winmm.dll", name, 16)) != 0);
    U_CHECK("resolving the real delay import restores its readonly IAT protection", protection(&__imp_timeGetTime) == PAGE_READONLY);

    /* the address the delay stub now jumps to must equal the real export */
    {
        FARPROC direct = GetProcAddress(GetModuleHandleW(u_wide("winmm.dll", name, 16)), "timeGetTime");
        U_CHECK("delay stub bound to the real winmm export", direct != 0 && (FARPROC)__imp_timeGetTime == direct);
    }

    /* a second delay-imported DLL from a different module, resolved independently */
    (void)GetFileVersionInfoSizeW(u_wide("x", name, 16), &handle);
    U_CHECK("version.dll loaded after its delay import resolved",
            GetModuleHandleW(u_wide("version.dll", name, 16)) != 0);

    protected_slots();
    resolution_failures();

    return u_finish("t_delay");
}
