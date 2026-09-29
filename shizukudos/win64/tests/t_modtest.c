/* SPDX-License-Identifier: GPL-2.0-only
 * Imports modtest.dll: proves the loader resolves an extra system DLL and runs its DllMain. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"
extern int WINAPI ModtestAdd(int, int);
extern int WINAPI ModtestAttached(void);
int main(void)
{
    int bad = 0;
    if (ModtestAdd(40, 2) != 42) { printf("FAIL: ModtestAdd\n"); ++bad; } else printf("PASS: ModtestAdd\n");
    if (!ModtestAttached()) { printf("FAIL: DllMain(DLL_PROCESS_ATTACH) not run\n"); ++bad; } else printf("PASS: DllMain attach\n");
    return bad;
}
