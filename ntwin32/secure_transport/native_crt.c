/* SPDX-License-Identifier: GPL-2.0-only
 * C-only startup for the Win98 target. All C objects have zero/constant global
 * initialization. We do not link GCC's NT static-TLS startup, constructor tables,
 * pseudo-relocation startup or C++ thread destructors. The PE gate rejects these
 * directories, and every native import is checked against original Win98 media.
 * The already loaded native MSVCRT DLL supplies ordinary C runtime functions.
 */
#include <windows.h>
#include <stdlib.h>

/* Public legacy MSVCRT ABI, exported by the original Win98 OEM runtime. */
struct ntwst_startup_info { int newmode; };
int __cdecl __getmainargs(int *, char ***, char ***, int, struct ntwst_startup_info *);

/* GCC inserts this call at C main even when no constructors are present. */
void __main(void) {}

#if defined(NTWST_DLL_STARTUP)
BOOL WINAPI DllMainCRTStartup(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
#else
extern int main(int argc, char **argv);
void mainCRTStartup(void)
{
    int argc = 0;
    char **argv = NULL, **environment = NULL;
    struct ntwst_startup_info startup = { 0 };
    if (__getmainargs(&argc, &argv, &environment, 0, &startup) != 0)
        ExitProcess(2);
    /* Native exit flushes streams before its ExitProcess; no private CRT state. */
    exit(main(argc, argv));
}
#endif
