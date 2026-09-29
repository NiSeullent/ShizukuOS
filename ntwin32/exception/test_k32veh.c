/* SPDX-License-Identifier: GPL-2.0-only */
#include "k32veh.h"
#include <stdio.h>
#include <string.h>
static int checks, failures;
static void expect(int cond, const char *text, int line) {
    ++checks;
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static int order[8], used;
static int32_t NTW_VEH_CALL handler_a(void *info) {
    struct pointers { void *record; void *context; } *points = info;
    int *record = points->record;
    int *context = points->context;
    C(record && context && record[0] == 17 && context[0] == 19);
    order[used++] = 1;
    return 0;
}
static int32_t NTW_VEH_CALL handler_b(void *info) {
    (void)info;
    order[used++] = 2;
    return 0;
}
static int32_t NTW_VEH_CALL handler_stop(void *info) {
    (void)info;
    order[used++] = 3;
    return -1;
}
static int32_t NTW_VEH_CALL handler_other(void *info) {
    (void)info;
    order[used++] = 4;
    return 1;
}
int main(void) {
    void *first = (void *)1, *second = (void *)1, *third = (void *)1, *missing = 0;
    int record[2] = {17, 19};
    int32_t disposition = 77;
    ntw_k32_test_reset();
    C(ntw_k32_add(1, NULL, &first) == NTWE_INVALID && first == (void *)1);
    C(ntw_k32_add(0, handler_a, NULL) == NTWE_INVALID);
    C(ntw_k32_remove(NULL) == NTWE_INVALID);
    C(ntw_k32_add(0, handler_a, &first) == NTWE_OK && first);
    C(ntw_k32_add(1, handler_b, &second) == NTWE_OK && second && second != first);
    C(ntw_k32_add(2, handler_other, &third) == NTWE_OK);
    used = 0;
    C(ntw_k32_dispatch(record, record + 1, &disposition) == NTWE_OK && disposition == 0);
    C(used == 3 && order[0] == 4 && order[1] == 2 && order[2] == 1);
    C(ntw_k32_remove(second) == NTWE_OK);
    C(ntw_k32_remove(second) == NTWE_NOT_FOUND);
    used = 0;
    disposition = 77;
    C(ntw_k32_dispatch(record, record + 1, &disposition) == NTWE_OK && used == 2 && order[0] == 4 && order[1] == 1);
    C(ntw_k32_remove(third) == NTWE_OK);
    C(ntw_k32_add(1, handler_stop, &missing) == NTWE_OK);
    used = 0;
    C(ntw_k32_dispatch(record, record + 1, &disposition) == NTWE_OK && disposition == -1 && used == 1 && order[0] == 3);
    C(ntw_k32_dispatch(NULL, record, &disposition) == NTWE_INVALID);
    C(ntw_k32_remove(first) == NTWE_OK);
    C(ntw_k32_remove(missing) == NTWE_OK);
    if (failures) {
        fprintf(stderr, "{\"passed\":false,\"checks\":%d,\"failures\":%d}\n", checks, failures);
        return 1;
    }
    printf("{\"passed\":true,\"checks\":%d,\"order\":[4,2,1],\"stop_return\":-1}\n", checks);
    return 0;
}
