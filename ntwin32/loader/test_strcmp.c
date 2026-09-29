/* SPDX-License-Identifier: GPL-2.0-only */
#include "strcmp.h"
#include <stdio.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
int main(void) {
    C(ntw_lstrcmpi_a(0, 0) == 0);
    C(ntw_lstrcmpi_a(0, (const uint8_t *)"a") < 0);
    C(ntw_lstrcmpi_a((const uint8_t *)"a", 0) > 0);
    C(ntw_lstrcmpi_a((const uint8_t *)"ABC", (const uint8_t *)"abc") == 0);
    C(ntw_lstrcmpi_a((const uint8_t *)"a", (const uint8_t *)"b") < 0);
    C(ntw_lstrcmpi_a((const uint8_t *)"b", (const uint8_t *)"a") > 0);
    C(ntw_lstrcmpi_a((const uint8_t *)"ab", (const uint8_t *)"abc") < 0);
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"strcmp\":true}\n");
    return 0;
}
