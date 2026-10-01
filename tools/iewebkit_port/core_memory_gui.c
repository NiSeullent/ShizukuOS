/* GUI entry for the unchanged Win9x memory probe on the GOP desktop.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 * No console allocation, API emulation, or alternate memory implementation.
 */
#define main memory_probe_main
#include "core_memory_native.c"
#undef main

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command, int show)
{
    char nonce[81];
    char* arguments[5] = { "MEM9XG.EXE", "C:\\GOPLAB\\MEM9X.LOG", nonce,
                          "C:\\GOPLAB\\MEMPROV.TXT", NULL };
    size_t length = strlen(command);
    (void)instance;
    (void)previous;
    (void)show;
    if (!length || length >= sizeof(nonce))
        return 10;
    memcpy(nonce, command, length + 1);
    return memory_probe_main(4, arguments);
}
