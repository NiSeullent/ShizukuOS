/* SPDX-License-Identifier: GPL-2.0-only
 * Win98 -> Shizuku64 connection fixture: prints a fixed banner, reads ONE line from the console stdin that the
 * Win98 side feeds through NtwWriteConsole64, echoes it, and exits with a code derived from the input so a
 * dropped/altered stdin or stdout path is observable: exit 40 + len (len = bytes before the line end, max 20);
 * exit 2 when stdin is at end with no data; exit 3 when stdin read fails. Console only; no GUI window. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

int main(void)
{
    char buf[64];
    DWORD got = 0, i;
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);

    printf("W98W64-ECHO-READY\n");
    if (!ReadFile(in, buf, sizeof buf - 1, &got, 0)) {
        printf("W98W64-ECHO-READFAIL %u\n", (unsigned)GetLastError());
        return 3;
    }
    if (!got) {
        printf("W98W64-ECHO-EOF\n");
        return 2;
    }
    for (i = 0; i < got && buf[i] != '\r' && buf[i] != '\n'; ++i) {}
    buf[i] = 0;
    printf("W98W64-ECHO-GOT[%s]\n", buf);
    return (int)(40u + (i > 20u ? 20u : i));
}
