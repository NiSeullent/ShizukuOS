/* SPDX-License-Identifier: GPL-2.0-only
 * Console probe for the WIN64 subsystem bridge (kernel64/subsys64.c): a Win64 program whose standard handles are
 * relayed to a 32-bit Windows 98 client over the inter-domain channel.
 *
 *   default      writes 30 lines of 100 bytes to stdout (more than one CONSOLE_OUTPUT window: exercises the
 *                flow control), reports the command-line length, writes one stderr line, then echoes every stdin
 *                chunk back with an "echo:" prefix until stdin reports end of file, and exits 0.
 *   hang         loops until it is killed (KILL_PROCESS test).
 *
 * Run by the plain Kernel64 self-test (no bridge) it sees stdin at end of file immediately and still exits 0. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

int main(int argc, char **argv)
{
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE), out = GetStdHandle(STD_OUTPUT_HANDLE), err = GetStdHandle(STD_ERROR_HANDLE);
    char buf[256], line[104];
    DWORD n, i, total = 0;
    LPWSTR cmd = GetCommandLineW();
    if (argc > 1 && !strcmp(argv[1], "hang")) {
        printf("t_w64con: hanging until killed\n");
        for (;;)
            Sleep(10);
    }
    for (i = 0; i < 30; ++i) {
        DWORD k;
        int len = snprintf(line, sizeof line, "line %02u ", (unsigned)i);
        for (k = (DWORD)len; k < 99; ++k)
            line[k] = (char)('a' + (i + k) % 26);
        line[99] = '\n';
        if (!WriteFile(out, line, 100, &n, 0) || n != 100)
            return 2;
    }
    printf("t_w64con: cmdline=%u chars argc=%d\n", (unsigned)lstrlenW(cmd), argc);
    WriteFile(err, "t_w64con: stderr marker\n", 24, &n, 0);
    while (ReadFile(in, buf, sizeof buf - 1, &n, 0) && n) {
        buf[n] = 0;
        printf("echo:%s", buf);
        total += n;
    }
    printf("t_w64con: stdin closed after %u bytes\n", (unsigned)total);
    return 0;
}
