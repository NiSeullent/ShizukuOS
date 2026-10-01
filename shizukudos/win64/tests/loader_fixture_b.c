/* SPDX-License-Identifier: GPL-2.0-only: test-only real dependency DLL. */
#include "loader_fixture.h"
static loader_fixture_trace *trace;
static ULONG attached;
__declspec(dllexport) ULONG WINAPI LoaderBValue(void) { return 77; }
__declspec(dllexport) ULONG WINAPI LoaderBAttached(void) { return attached; }
__declspec(dllexport) void WINAPI LoaderBConfigure(loader_fixture_trace *p) { trace = p; }
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    if (reason == DLL_PROCESS_ATTACH) ++attached;
    if (reason == DLL_PROCESS_DETACH && trace) {
        if (reserved) ++trace->reserved_nonnull;
        if (trace->count < 16) trace->order[trace->count++] = 2;
    }
    return TRUE;
}
