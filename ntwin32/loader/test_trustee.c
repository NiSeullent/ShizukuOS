/* SPDX-License-Identifier: GPL-2.0-only */
#include "trustee.h"
#include <stdio.h>
#include <stdlib.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static void *take(unsigned bytes) { return malloc(bytes); }
int main(void) {
    uint32_t words[5];
    uint32_t error = 9;
    uint8_t sid[12] = {1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0};
    uint32_t i;
    for (i = 0; i < 5; ++i) words[i] = 7;
    C(ntw_trustee_with_sid(0, sid, 1, &error) == 0 && error == 87 && words[0] == 7);
    error = 9;
    C(ntw_trustee_with_sid(words, sid, 0, &error) == 0 && error == 87 && words[4] == 7);
    error = 9;
    C(ntw_trustee_with_sid(words, sid, 1, &error) == 1 && error == 0);
    C(words[0] == 0 && words[1] == 0 && words[2] == 0 && words[3] == 0);
    C(words[4] == (uint32_t)(unsigned long)sid);
    {
        void *acl = (void *)1;
        C(ntw_acl_set_entries(1, 0, &acl, take) == 87 && acl == 0);
        C(ntw_acl_set_entries(0, 0, 0, take) == 87);
        C(ntw_acl_set_entries(0, 0, &acl, take) == 0 && acl);
        C(((uint8_t *)acl)[0] == 2 && ((uint8_t *)acl)[2] == 8);
        free(acl);
    }
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"trustee\":true}\n");
    return 0;
}
