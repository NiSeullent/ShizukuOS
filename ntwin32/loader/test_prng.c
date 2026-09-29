/* SPDX-License-Identifier: GPL-2.0-only */
#include "prng.h"
#include <stdio.h>
#include <string.h>
static int failures;
static int deny(void *user, uint8_t *buffer, uint32_t bytes) {
    (void)user; (void)buffer; (void)bytes; return -1;
}
static int patterned(void *user, uint8_t *buffer, uint32_t bytes) {
    uint32_t i, *calls = user;
    for (i = 0; i < bytes; ++i) buffer[i] = (uint8_t)(0xa0 + *calls);
    (*calls)++;
    if (bytes > 16) return 16;
    return (int)bytes;
}
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
int main(void) {
    uint8_t buf[40];
    uint32_t error = 0, calls = 0;
    memset(buf, 0x5a, sizeof buf);
    C(ntw_process_prng(0, 4, patterned, &calls, &error) == 0 && error == 87 && buf[0] == 0x5a);
    C(ntw_process_prng(buf, 0, deny, 0, &error) == 1 && error == 0);
    C(ntw_process_prng(buf, 4, deny, 0, &error) == 0 && error == 8 && buf[0] == 0x5a);
    C(ntw_process_prng(buf, 20, patterned, &calls, &error) == 1 && error == 0);
    C(buf[0] == 0xa0 && buf[15] == 0xa0 && buf[16] == 0xa1 && calls == 2);
    if (failures) return 1;
    printf("{\"passed\":true,\"chunks\":2}\n");
    return 0;
}
