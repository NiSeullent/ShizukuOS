/* SPDX-License-Identifier: GPL-2.0-only */
#include "job.h"
#include <stdio.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
int main(void) {
    uint32_t result = 7, error = 9, seen;
    seen = ntw_job_is_process(0xffffffffu, 0, &result, &error, 1);
    C(seen == 1 && error == 0 && result == 0);
    result = 7;
    error = 9;
    seen = ntw_job_is_process(1, 0, &result, &error, 0);
    C(seen == 0 && error == 6 && result == 7);
    error = 9;
    seen = ntw_job_is_process(0xffffffffu, 0, 0, &error, 1);
    C(seen == 0 && error == 87);
    result = 7;
    error = 9;
    seen = ntw_job_is_process(0xffffffffu, 0x1111u, &result, &error, 1);
    C(seen == 0 && error == 6 && result == 7);
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"job\":true}\n");
    return 0;
}
