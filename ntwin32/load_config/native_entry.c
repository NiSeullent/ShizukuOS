/* SPDX-License-Identifier: GPL-2.0-only
 * Normal PE32 container entry only; no loader or mitigation initialization. */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}
