/* SPDX-License-Identifier: GPL-2.0-only
 * Regression module for the extra-DLL mechanism (win64/build.py build_modules): built from dlls/<name>/, packed at
 * \\SHZ\\SYS64\\modtest.dll, loaded by the Kernel64 loader from an import table, DllMain(DLL_PROCESS_ATTACH) run. */
#include "nt.h"
static volatile int attached;
DLLAPI int WINAPI ModtestAdd(int a, int b) { return a + b; }
DLLAPI int WINAPI ModtestAttached(void) { return attached; }
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res)
{
    (void)h; (void)res;
    if (reason == DLL_PROCESS_ATTACH) attached = 1;
    return TRUE;
}
