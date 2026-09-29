/* SPDX-License-Identifier: GPL-2.0-only */
#include "fls.h"
#include <stdio.h>
static int failures;
static void *freed;
static void NTW_FLS_CALL note(void *value) { freed = value; }
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
int main(void) {
    uint32_t slot, other, n;
    C(ntw_fls_get(0) == 0 && ntw_fls_last_error() == 87);
    C(ntw_fls_set(1, (void *)1) == 0 && ntw_fls_last_error() == 87);
    C(ntw_fls_free(0) == 0);
    slot = ntw_fls_alloc(0);
    C(slot >= 1 && slot < NTW_FLS_LIMIT);
    C(ntw_fls_get(slot) == 0 && ntw_fls_last_error() == 0);
    C(ntw_fls_set(slot, (void *)0x20) == 1 && ntw_fls_get(slot) == (void *)0x20);
    other = ntw_fls_alloc(note);
    C(other != slot && ntw_fls_set(other, (void *)0x30) == 1);
    C(ntw_fls_free(other) == 1 && freed == (void *)0x30);
    C(ntw_fls_get(other) == 0 && ntw_fls_last_error() == 87);
    C(ntw_fls_get(slot) == (void *)0x20);
    for (n = 0; n < NTW_FLS_LIMIT + 2; ++n) ntw_fls_alloc(0);
    C(ntw_fls_alloc(0) == NTW_FLS_OUT_OF_INDEXES && ntw_fls_last_error() == 259);
    if (failures) return 1;
    printf("{\"passed\":true,\"fls_limit\":128}\n");
    return 0;
}
