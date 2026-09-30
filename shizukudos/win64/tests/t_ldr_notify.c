/* SPDX-License-Identifier: GPL-2.0-only
 * LdrRegisterDllNotification / LdrUnregisterDllNotification (ntdll/ldr_search.c). Chromium's module database registers one. A
 * callback gets reason LOADED (1) for each module a run-time load maps (after its DllMain(PROCESS_ATTACH) ran), in registration
 * order, and nothing for a module that was already loaded or after unregistering. Expectations follow the documented
 * LDR_DLL_NOTIFICATION_DATA layout and the loader's own module list (GetModuleHandleW), not the implementation's bookkeeping. */
#include "k32test.h"

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } USTR;
typedef struct { ULONG Flags; const USTR *FullDllName, *BaseDllName; PVOID DllBase; ULONG SizeOfImage; } NOTIFY_DATA;
typedef VOID (NTAPI *NOTIFY_FN)(ULONG reason, const NOTIFY_DATA *data, PVOID ctx);
LONG NTAPI LdrRegisterDllNotification(ULONG, NOTIFY_FN, PVOID, PVOID *);
LONG NTAPI LdrUnregisterDllNotification(PVOID);

#define STATUS_INVALID_PARAMETER_ ((LONG)0xC000000D)
#define MAXEV 16
typedef struct { ULONG reason; PVOID base; ULONG size; WCHAR name[40]; int attached; int lock_held; PVOID ctx; } EVENT;
static EVENT g_ev[MAXEV];
static volatile int g_n;

static int ieq(const WCHAR *a, const WCHAR *b)
{
    while (*a && *b) { WCHAR x = *a++, y = *b++; if (x >= 'A' && x <= 'Z') x += 32; if (y >= 'A' && y <= 'Z') y += 32; if (x != y) return 0; }
    return *a == *b;
}

static VOID NTAPI cb(ULONG reason, const NOTIFY_DATA *d, PVOID ctx)
{
    EVENT *e;
    int i, n;
    if (g_n >= MAXEV) return;
    e = &g_ev[g_n++];
    e->reason = reason; e->base = d->DllBase; e->size = d->SizeOfImage; e->ctx = ctx;
    n = d->BaseDllName->Length / 2;
    if (n > 39) n = 39;
    for (i = 0; i < n; ++i) e->name[i] = d->BaseDllName->Buffer[i];
    e->name[n] = 0;
    e->attached = -1;
    if (ieq(e->name, L"modtest.dll")) {     /* the module's own state, read from inside the callback */
        FARPROC f = GetProcAddress((HMODULE)d->DllBase, "ModtestAttached");
        if (f) e->attached = ((int (WINAPI *)(void))(void *)f)();
    }
    {   /* the loader lock is held: PEB.LoaderLock->OwningThread is this thread */
        BYTE *peb;
        __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));                            /* TEB.ProcessEnvironmentBlock */
        RTL_CRITICAL_SECTION *cs = *(RTL_CRITICAL_SECTION **)(peb + 0x110);          /* PEB.LoaderLock */
        e->lock_held = cs && cs->OwningThread == (HANDLE)(ULONG_PTR)GetCurrentThreadId();
    }
}

static int count_named(const WCHAR *name, ULONG reason, PVOID ctx)
{
    int i, c = 0;
    for (i = 0; i < g_n; ++i) if (g_ev[i].reason == reason && g_ev[i].ctx == ctx && ieq(g_ev[i].name, name)) ++c;
    return c;
}

int main(void)
{
    PVOID ck1 = 0, ck2 = 0, junk = 0;
    HMODULE m, w;
    int i, before;
    CHECK(LdrRegisterDllNotification(1, cb, 0, &junk) == STATUS_INVALID_PARAMETER_, "non-zero Flags are invalid");
    CHECK(LdrRegisterDllNotification(0, 0, 0, &junk) == STATUS_INVALID_PARAMETER_, "a NULL callback is invalid");
    CHECK(LdrRegisterDllNotification(0, cb, 0, 0) == STATUS_INVALID_PARAMETER_, "a NULL cookie pointer is invalid");
    CHECK(LdrUnregisterDllNotification(0) == STATUS_INVALID_PARAMETER_, "unregistering NULL is invalid");
    CHECK(LdrRegisterDllNotification(0, cb, (PVOID)0x11, &ck1) == 0 && ck1, "register #1 (context 0x11)");
    CHECK(LdrRegisterDllNotification(0, cb, (PVOID)0x22, &ck2) == 0 && ck2 && ck2 != ck1, "register #2 (context 0x22) gets another cookie");
    CHECK(GetModuleHandleW(L"modtest.dll") == 0, "modtest.dll is not loaded yet");
    CHECK(g_n == 0, "registering itself reports nothing");
    m = LoadLibraryW(L"modtest.dll");
    CHECKV(m != 0, "LoadLibraryW(modtest.dll)", "err %lu", (unsigned long)GetLastError());
    CHECKV(count_named(L"modtest.dll", 1, (PVOID)0x11) == 1 && count_named(L"modtest.dll", 1, (PVOID)0x22) == 1, "each registration got exactly one LOADED for modtest.dll, with its own context", "events %d", g_n);
    for (i = 0; i < g_n; ++i)
        if (ieq(g_ev[i].name, L"modtest.dll")) {
            CHECK(g_ev[i].base == (PVOID)m, "DllBase is the module handle LoadLibrary returned");
            CHECK(g_ev[i].size >= 0x1000 && (g_ev[i].size & 0xfff) == 0, "SizeOfImage is a page multiple");
            CHECK(g_ev[i].attached == 1, "DllMain(DLL_PROCESS_ATTACH) had already run when the callback fired");
            CHECK(g_ev[i].lock_held, "the loader lock is held during the callback");
            break;
        }
    {   /* registration order: #1 before #2 for the same load */
        int first1 = -1, first2 = -1;
        for (i = 0; i < g_n; ++i) { if (g_ev[i].ctx == (PVOID)0x11 && first1 < 0) first1 = i; if (g_ev[i].ctx == (PVOID)0x22 && first2 < 0) first2 = i; }
        CHECK(first1 >= 0 && first2 > first1, "callbacks run in registration order");
    }
    for (i = 0; i < g_n; ++i) {
        HMODULE h = GetModuleHandleW(g_ev[i].name);
        if (h != (HMODULE)g_ev[i].base) { CHECKV(0, "every reported module is in the loader's list with that base", "%ls", g_ev[i].name); break; }
    }
    before = g_n;
    CHECK(LoadLibraryW(L"modtest.dll") == m && g_n == before, "loading an already loaded module reports nothing");
    CHECK(LdrUnregisterDllNotification(ck1) == 0, "unregister #1");
    CHECK(LdrUnregisterDllNotification(ck1) == STATUS_INVALID_PARAMETER_, "unregistering it twice is invalid");
    before = g_n;
    CHECK(GetModuleHandleW(L"winmm.dll") == 0, "winmm.dll is not loaded yet");
    w = LoadLibraryW(L"winmm.dll");
    CHECK(w != 0, "LoadLibraryW(winmm.dll)");
    CHECKV(count_named(L"winmm.dll", 1, (PVOID)0x22) == 1 && count_named(L"winmm.dll", 1, (PVOID)0x11) == 0 && g_n > before,
           "only registration #2 is told about winmm.dll", "events %d -> %d", before, g_n);
    CHECK(LdrUnregisterDllNotification(ck2) == 0, "unregister #2");
    before = g_n;
    CHECK(LoadLibraryW(L"version.dll") != 0 && g_n == before, "with nothing registered no callback runs");
    CHECK(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrRegisterDllNotification") != 0 && GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrUnregisterDllNotification") != 0,
          "both names resolve through GetProcAddress (Chromium looks LdrRegisterDllNotification up)");
    return k32t_finish("t_ldr_notify");
}
