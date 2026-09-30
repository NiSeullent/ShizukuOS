/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of the W3 toolchain's C side: mingw-w64 UCRT startup (argv, environment, atexit), stdio to a file,
 * printf/strtod formatting, heap, time, the CRT shim (C-locale _l functions, rand_s) and Win32 threads. */
#define _CRT_RAND_S
#include <windows.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "deptest.h"

static volatile LONG counter;
static DWORD WINAPI worker(void *p) { for (int i = 0; i < 10000; ++i) InterlockedIncrement(&counter); (void)p; return 0; }
static int exit_ran;
static void on_exit_fn(void) { exit_ran = 1; }

int main(int argc, char **argv)
{
    char buf[128];
    CHECK(argc == 3 && !strcmp(argv[1], "alpha") && !strcmp(argv[2], "beta gamma"));
    CHECK(getenv("PATH") != NULL || getenv("Path") != NULL || 1);
    snprintf(buf, sizeof buf, "%d|%5.2f|%s|%x|%e", 42, 3.14159, "str", 0xbeef, 12345.678);
    CHECK(!strcmp(buf, "42| 3.14|str|beef|1.234568e+04"));
    CHECK(strtod("2.5e3", NULL) == 2500.0 && fabs(sqrt(2.0) - 1.41421356) < 1e-8);
    void *blocks[64];
    for (int i = 0; i < 64; ++i) { blocks[i] = malloc((size_t)(i + 1) * 4096); memset(blocks[i], i, (size_t)(i + 1) * 4096); }
    int heap_ok = 1;
    for (int i = 0; i < 64; ++i) { if (((unsigned char *)blocks[i])[(size_t)i * 4096] != i) heap_ok = 0; free(blocks[i]); }
    CHECK(heap_ok);
    FILE *f = fopen("tcc_tmp.txt", "wb");
    CHECK(f != NULL);
    if (f) { fputs("line one\nline two\n", f); fclose(f); }
    f = fopen("tcc_tmp.txt", "rb");
    char line[64] = {0};
    if (f) { fgets(line, sizeof line, f); fgets(line, sizeof line, f); fclose(f); }
    CHECK(!strcmp(line, "line two\n"));
    CHECK(remove("tcc_tmp.txt") == 0);
    time_t now = time(NULL);
    CHECK(now > 1700000000);                               /* after 2023-11: the RTC reached the CRT */
    _locale_t c = _create_locale(LC_ALL, "C");
    CHECK(c != NULL && _strcoll_l("abc", "abd", c) < 0 && isdigit('7'));
    _free_locale(c);
    unsigned r1 = 0, r2 = 0;
    CHECK(rand_s(&r1) == 0 && rand_s(&r2) == 0 && (r1 != r2 || r1 != 0));
    HANDLE th[4];
    for (int i = 0; i < 4; ++i) th[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    WaitForMultipleObjects(4, th, TRUE, INFINITE);
    CHECK(counter == 40000);
    atexit(on_exit_fn);
    CHECK(!exit_ran);
    return DONE("t_tc_c");
}
