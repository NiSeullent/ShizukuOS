/* SPDX-License-Identifier: GPL-2.0-only: real recursive-load notification fixture. */
#include <windows.h>
static ULONG attached;
__declspec(dllexport) ULONG WINAPI LoaderNotifyLeafAttached(void) { return attached; }
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) ++attached;
    return TRUE;
}
