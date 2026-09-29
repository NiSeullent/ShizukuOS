/* SPDX-License-Identifier: GPL-2.0-only */
#include "initonce.h"
#include <stdio.h>
static int failures, calls;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static uint32_t init_ok(uint32_t once, uint32_t param, uint32_t *context) {
    (void)once;
    calls++;
    *context = param;
    return 1;
}
static uint32_t init_fail(uint32_t once, uint32_t param, uint32_t *context) {
    (void)once; (void)param; (void)context;
    calls++;
    return 0;
}
int main(void) {
    uint32_t once = 0, context = 0, error = 0;
    C(ntw_init_execute(0, init_ok, 4, &context, &error) == 0 && error == 87);
    C(ntw_init_execute(&once, init_fail, 4, &context, &error) == 0 && calls == 1 && once == 0);
    C(ntw_init_execute(&once, init_ok, 8, &context, &error) == 1 && context == 8 && calls == 2);
    context = 0;
    C(ntw_init_execute(&once, init_ok, 9, &context, &error) == 1 && context == 8 && calls == 2);
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"initonce\":true}\n");
    return 0;
}
