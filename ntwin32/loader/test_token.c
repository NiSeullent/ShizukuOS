/* SPDX-License-Identifier: GPL-2.0-only */
#include "token.h"
#include "winfile.h"
#include <stdio.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
int main(void) {
    uint32_t handle = 1, error = 0, needed = 0, bits = 0;
    uint8_t buf[64];
    int32_t previous = -1;
    uint16_t name[8];
    C(ntw_token_open(0, &handle, &error) == 0 && error == 5);
    C(ntw_token_open(0x8, 0, &error) == 0);
    C(ntw_token_open(0x8, &handle, &error) == 1 && error == 0);
    C(ntw_token_info(handle, 99, buf, sizeof buf, &needed, &error) == 0 && error == 87);
    C(ntw_token_info(handle, 1, buf, 4, &needed, &error) == 0 && error == 122 && needed == 8 + 8 + 16);
    C(ntw_token_info(handle, 1, buf, sizeof buf, &needed, &error) == 1);
    C(*(uint32_t *)buf == (uint32_t)(unsigned long)(buf + 8) && buf[8] == 1 && buf[9] == 4);
    C(ntw_token_info(handle, 20, buf, 4, &needed, &error) == 1 && *(uint32_t *)buf == 0);
    C(ntw_token_info(1, 1, buf, sizeof buf, &needed, &error) == 0 && error == 6);
    C(ntw_token_close(handle, &error) == 1);
    C(ntw_sem_create(-1, 1, 0, &handle, &error) == 0 && error == 87);
    C(ntw_sem_create(2, 1, 0, &handle, &error) == 0 && error == 87);
    C(ntw_sem_create(1, 2, 0, &handle, &error) == 1 && error == 0);
    C(ntw_sem_wait(handle, &bits) == 1 && bits == 0);
    C(ntw_sem_wait(handle, &bits) == 1 && bits == 258);
    C(ntw_sem_release(handle, 0, &previous, &error) == 0 && error == 87);
    C(ntw_sem_release(handle, 3, &previous, &error) == 0 && error == 298);
    C(ntw_sem_release(handle, 2, &previous, &error) == 1 && previous == 0);
    name[0] = 's'; name[1] = 'e'; name[2] = 'm'; name[3] = 0;
    C(ntw_sem_create(0, 1, name, &handle, &error) == 1);
    C(ntw_sem_create(0, 1, name, &bits, &error) == 1 && error == 183 && bits == handle);
    C(ntw_sem_flags(handle, 1, 2, 2, 0) == 1);
    C(ntw_sem_close(handle, &error) == 0 && error == 6);
    C(ntw_sem_flags(handle, 1, 2, 0, 0) == 1);
    C(ntw_sem_close(handle, &error) == 1);
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"token\":true,\"semaphore\":true}\n");
    return 0;
}
