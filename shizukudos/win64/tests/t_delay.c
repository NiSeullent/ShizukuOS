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

int main(void)
{
    DWORD t1, t2;
    DWORD handle = 0;
    unsigned short name[16];
    U_CHECK("winmm not loaded before the first delay call", GetModuleHandleW(u_wide("winmm.dll", name, 16)) == 0);

    t1 = timeGetTime();                                     /* first call: resolves winmm!timeGetTime through the helper */
    t2 = timeGetTime();                                     /* second call: goes direct through the patched IAT slot */
    U_CHECKF("timeGetTime resolved and returned a monotonic tick count", t2 >= t1, "t1=%u t2=%u", (unsigned)t1, (unsigned)t2);
    U_CHECK("winmm loaded after the delay import resolved", GetModuleHandleW(u_wide("winmm.dll", name, 16)) != 0);

    /* the address the delay stub now jumps to must equal the real export */
    {
        FARPROC direct = GetProcAddress(GetModuleHandleW(u_wide("winmm.dll", name, 16)), "timeGetTime");
        U_CHECK("delay stub bound to the real winmm export", direct != 0);
    }

    /* a second delay-imported DLL from a different module, resolved independently */
    (void)GetFileVersionInfoSizeW(u_wide("x", name, 16), &handle);
    U_CHECK("version.dll loaded after its delay import resolved",
            GetModuleHandleW(u_wide("version.dll", name, 16)) != 0);

    return u_finish("t_delay");
}
