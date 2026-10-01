/* SPDX-License-Identifier: GPL-2.0-only: test-only real importer DLL. */
#include "loader_fixture.h"
__declspec(dllimport) ULONG WINAPI LoaderBValue(void);
__declspec(dllimport) ULONG WINAPI LoaderBAttached(void);
__declspec(dllimport) void WINAPI LoaderBConfigure(loader_fixture_trace *);
static loader_fixture_trace *trace;
static ULONG attached, recursive_init_free;
__declspec(dllexport) ULONG WINAPI LoaderAAttached(void) { return attached; }
__declspec(dllexport) ULONG WINAPI LoaderAInitFree(void) { return recursive_init_free; }
__declspec(dllexport) ULONG WINAPI LoaderADependency(void) { return LoaderBValue() + LoaderBAttached(); }
__declspec(dllexport) void WINAPI LoaderAConfigure(loader_fixture_trace *p) { trace = p; LoaderBConfigure(p); }
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        ++attached;
        recursive_init_free = FreeLibrary(instance); /* actual provider must reject retirement during this callback */
    }
    if (reason == DLL_PROCESS_DETACH && trace) {
        if (reserved) ++trace->reserved_nonnull;
        trace->dependency_value = LoaderBValue(); /* dependency remains mapped through every detach */
        trace->recursive_free_succeeded = FreeLibrary(instance);
        if (trace->count < 16) trace->order[trace->count++] = 1;
    }
    return TRUE;
}
