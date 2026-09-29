/* SPDX-License-Identifier: GPL-2.0-only */
#include "fileio.h"
#include <stdio.h>
#include <string.h>
static int failures;
static char captured[64];
static uint32_t captured_n;
static int fake_transfer(void *user, int fd, void *buffer, uint32_t bytes, int writing) {
    (void)user;
    if (!writing) {
        if (fd != 0) return -1;
        if (bytes < 4) return -1;
        memcpy(buffer, "ab", 2);
        return 2;
    }
    if (fd != 1 && fd != 2) return -1;
    if (captured_n + bytes > sizeof captured) return -1;
    memcpy(captured + captured_n, buffer, bytes);
    captured[captured_n + bytes] = 0;
    captured_n += bytes;
    captured[captured_n++] = (char)('0' + fd);
    return (int)bytes;
}
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
int main(void) {
    uint32_t written = 99, error = 0, kind;
    char in[8];
    ntw_file_set_transfer(fake_transfer, 0);
    C(ntw_file_get_std(NTW_STD_OUTPUT) == 2);
    C(ntw_file_write(2, "hi", 2, &written, 0, &error) == 1 && written == 2 && error == 0);
    C(captured_n >= 3 && captured[0] == 'h' && captured[2] == '1');
    written = 99;
    C(ntw_file_write(2, "x", 1, &written, (void *)1, &error) == 0 && written == 0 && error == 87);
    written = 99;
    C(ntw_file_write(2, "x", 1, 0, 0, &error) == 0 && error == 87);
    written = 99;
    C(ntw_file_write(2, 0, 1, &written, 0, &error) == 0 && written == 0 && error == 87);
    C(ntw_file_write(1, "no", 2, &written, 0, &error) == 0 && error == 5);
    C(ntw_file_write(99, "no", 2, &written, 0, &error) == 0 && error == 6);
    C(ntw_file_write(2, "z", 0, &written, 0, &error) == 1 && written == 0);
    C(ntw_file_set_std(NTW_STD_OUTPUT, 0) == 0);
    C(ntw_file_set_std(NTW_STD_OUTPUT, 50) == 1);
    C(ntw_file_write(2, "old", 3, &written, 0, &error) == 0 && error == 6);
    C(ntw_file_write(50, "ok", 2, &written, 0, &error) == 1 && written == 2);
    C(ntw_file_read(50, in, 4, &written, 0, &error) == 0 && error == 5);
    C(ntw_file_set_std(NTW_STD_OUTPUT, 2) == 1);
    C(ntw_file_read(1, in, 4, &written, 0, &error) == 1 && written == 2 && in[0] == 'a');
    kind = ntw_file_type(1, &error);
    C(kind == NTW_FILE_TYPE_CHAR && error == 0);
    C(ntw_file_type(77, &error) == NTW_FILE_TYPE_UNKNOWN && error == 6);
    if (failures) return 1;
    printf("{\"passed\":true,\"captured\":\"%s\"}\n", captured);
    return 0;
}
