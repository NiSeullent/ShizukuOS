/* SPDX-License-Identifier: GPL-2.0-only
 * T_EXE: MZ executable (Open Watcom, small model, 16-bit) exercising the C
 * runtime over DOS services: argv/environment, buffered file I/O, heap, 32-bit
 * math on 16-bit code, and an exit code the batch file checks.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp(const void *a, const void *b)
{
    return *(const int *)a - *(const int *)b;
}

int main(int argc, char **argv)
{
    FILE *f;
    char buf[64];
    int values[16], i, failures = 0;
    unsigned long acc = 1;
    char *heap[8];

    if (argc != 3 || strcmp(argv[1], "ARG1") || strcmp(argv[2], "ARG2"))
        failures |= 1;
    if (!getenv("PATH") && !getenv("COMSPEC"))
        failures |= 2;
    f = fopen("T_EXE.OUT", "wb");
    if (!f)
        return 90;
    for (i = 0; i < 400; ++i)
        fprintf(f, "line %03d SHZ-EXE\r\n", i);
    fclose(f);
    f = fopen("T_EXE.OUT", "rb");
    if (!f)
        return 91;
    for (i = 0; i < 400; ++i) {
        char want[32];
        if (!fgets(buf, sizeof buf, f)) { failures |= 4; break; }
        sprintf(want, "line %03d SHZ-EXE\r\n", i);
        if (strcmp(buf, want)) { failures |= 8; break; }
    }
    if (fgets(buf, sizeof buf, f))
        failures |= 16;
    fclose(f);
    for (i = 0; i < 8; ++i) {
        heap[i] = malloc(2000);
        if (!heap[i]) { failures |= 32; break; }
        memset(heap[i], i + 1, 2000);
    }
    for (i = 0; i < 8; ++i)
        if (heap[i]) {
            if (heap[i][1999] != i + 1) failures |= 64;
            free(heap[i]);
        }
    for (i = 0; i < 16; ++i)
        values[i] = (i * 7919) % 101;
    qsort(values, 16, sizeof values[0], cmp);
    for (i = 1; i < 16; ++i)
        if (values[i - 1] > values[i]) failures |= 128;
    for (i = 1; i <= 12; ++i)
        acc *= (unsigned long)i;
    if (acc != 479001600UL)
        failures |= 256;
    f = fopen("RESULT.TXT", "ab");
    if (!f)
        return 92;
    fprintf(f, failures ? "T_EXE FAIL mask=%d\r\n" : "T_EXE PASS argc=%d\r\n", failures ? failures : argc);
    fclose(f);
    return failures ? 1 : 42;
}
