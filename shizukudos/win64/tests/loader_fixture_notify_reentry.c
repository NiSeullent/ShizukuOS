/* SPDX-License-Identifier: GPL-2.0-only: DllMain retires a real unrelated old tail. */
#include <windows.h>
static HMODULE prior, leaf;
static ULONG attached, retired;
__declspec(dllexport) ULONG WINAPI LoaderNotifyReentryAttached(void) { return attached; }
__declspec(dllexport) ULONG WINAPI LoaderNotifyPriorRetired(void) { return retired; }
__declspec(dllexport) HMODULE WINAPI LoaderNotifyPrior(void) { return prior; }
__declspec(dllexport) HMODULE WINAPI LoaderNotifyLeaf(void) { return leaf; }
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        ++attached;
        prior = GetModuleHandleW(L"loader_fixture_b.dll");
        retired = prior && FreeLibrary(prior);
        /* The nested load has its own notification batch and one explicit
         * reference, transferred to the guest's real cleanup after this load. */
        leaf = LoadLibraryW(L"loader_fixture_notify_leaf.dll");
    }
    return TRUE;
}
