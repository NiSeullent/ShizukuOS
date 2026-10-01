/* SPDX-License-Identifier: GPL-2.0-only
 * C-only startup for the Win98 target. All C objects have zero/constant global
 * initialization. We do not link GCC's NT static-TLS startup, constructor tables,
 * pseudo-relocation startup or C++ thread destructors. The PE gate rejects these
 * directories, and every native import is checked against original Win98 media.
 * The already loaded native MSVCRT DLL supplies ordinary C runtime functions.
 */
#include <windows.h>
#include <stdlib.h>

/* Imported i386 MSVCRT symbol. Pre-XP versions return void; XP and later
 * return int. Never inspect EAX as an error code: validate the output pointers.
 * See the upstream MinGW ABI correction dated 2024-11-27:
 * https://sourceforge.net/p/mingw-w64/mailman/message/58846398/ */
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
    int argc = -1;
    char **argv = NULL, **environment = NULL;
    struct ntwst_startup_info startup = { 0 };
    (void)__getmainargs(&argc, &argv, &environment, 0, &startup);
    if (argc < 1 || argc > 32767 || !argv || !environment || !argv[0]
            || argv[argc] != NULL)
        ExitProcess(2);
    /* Native exit flushes streams before its ExitProcess; no private CRT state. */
    exit(main(argc, argv));
}
#endif
