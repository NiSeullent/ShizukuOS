/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "iocp.h"
#include <stdio.h>
#include <time.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static void pause_once(void) {
    struct timespec step = {0, 1000000};
    nanosleep(&step, 0);
}
static int valid_file(uint32_t file) { return file == 0x4100u; }
int main(void) {
    uint32_t port = 0, again = 0, error = 0, bytes = 0, key = 0, overlapped = 0;
    ntw_iocp_set_pause(pause_once);
    C(ntw_iocp_create(0xffffffffu, 1, 0, 0, valid_file, &port, &error) == 0 && error == 87);
    C(ntw_iocp_create(0xffffffffu, 0, 0, 0, valid_file, &port, &error) == 1 && port != 0);
    C(ntw_iocp_create(0xffffffffu, 0, 0, 0, valid_file, &port, &error) == 1 && port != 0);
    C(ntw_iocp_create(0x1111u, port, 3, 1, valid_file, &again, &error) == 0 && error == 6 && again == 0);
    C(ntw_iocp_post(0, 1, 2, 3, &error) == 0 && error == 6);
    C(ntw_iocp_get(port, &bytes, &key, &overlapped, 0, &error) == 0 && error == 258);
    C(ntw_iocp_post(port, 7, 0x11u, 0x22u, &error) == 1);
    bytes = key = overlapped = 0;
    C(ntw_iocp_get(port, &bytes, &key, &overlapped, 0, &error) == 1);
    C(bytes == 7 && key == 0x11u && overlapped == 0x22u && error == 0);
    C(ntw_iocp_get(port, &bytes, &key, &overlapped, 2, &error) == 0 && error == 258);
    C(ntw_iocp_create(0x4100u, port, 9, 1, valid_file, &again, &error) == 1 && again == port);
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"iocp\":true}\n");
    return 0;
}
