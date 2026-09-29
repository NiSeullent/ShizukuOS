/* SPDX-License-Identifier: GPL-2.0-only */
#include "shutdown.h"
#include <stdio.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
int main(void) {
    uint32_t level = 0, flags = 9, error = 0;
    C(ntw_shutdown_get(&level, &flags, &error) == 1 && level == 0x280u && flags == 0);
    C(ntw_shutdown_set(0x500u, 0, &error) == 0 && error == 87);
    C(ntw_shutdown_get(&level, &flags, &error) == 1 && level == 0x280u);
    C(ntw_shutdown_set(0x180u, 2, &error) == 0 && error == 87);
    C(ntw_shutdown_set(0x180u, 1, &error) == 1);
    C(ntw_shutdown_get(&level, &flags, &error) == 1 && level == 0x180u && flags == 1);
    C(ntw_shutdown_get(0, &flags, &error) == 0 && error == 87);
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"shutdown\":true}\n");
    return 0;
}
