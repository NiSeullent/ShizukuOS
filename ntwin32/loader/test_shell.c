/* SPDX-License-Identifier: GPL-2.0-only */
#include "shell.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static void wide(const char *ascii, uint16_t *out) {
    while (*ascii) *out++ = (uint16_t)(unsigned char)*ascii++;
    *out = 0;
}
static int host_exists(void *user, const char *path) {
    (void)user;
    return access(path, F_OK) == 0 ? 1 : 0;
}
static int host_mkdir(void *user, const char *path) {
    (void)user;
    if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
    return -errno;
}
static int denied_mkdir(void *user, const char *path) {
    (void)user;
    (void)path;
    return -13;
}
int main(void) {
    uint16_t cmd[64], words[64], path[260];
    uint32_t offsets[8], error = 0, hr = 0;
    int argc = 0;
    static const uint8_t roam[] = {0xDB,0x85,0xB6,0x3E,0xF9,0x65,0xF6,0x4C,0xA0,0x3A,0xE3,0xEF,0x65,0x72,0x9F,0x3D};
    static const uint8_t unknown[16] = {0};
    const char *root = "/tmp/ntw-shell-root";
    wide("one \"two three\" four", cmd);
    C(ntw_shell_argv(0, words, 64, offsets, 8, &argc, &error) == 0 && error == 87);
    C(ntw_shell_argv(cmd, words, 64, offsets, 8, &argc, &error) == 1 && argc == 3 && error == 0);
    C(words[offsets[0]] == 'o' && words[offsets[1]] == 't' && words[offsets[1] + 3] == ' ');
    C(words[offsets[2]] == 'f');
    if (system("rm -rf /tmp/ntw-shell-root && mkdir /tmp/ntw-shell-root") != 0) failures++;
    C(ntw_shell_folder(0x1c, root, host_exists, host_mkdir, 0, path, 260, &hr) == 1 && hr == 0);
    C(access("/tmp/ntw-shell-root/AppData/Local", F_OK) == 0);
    C(path[0] == 'C' && path[1] == ':' && path[2] == '\\' && path[3] == 'A');
    C(ntw_shell_folder(0x1a, root, host_exists, host_mkdir, 0, path, 260, &hr) == 1 && hr == 0);
    C(access("/tmp/ntw-shell-root/AppData/Roaming", F_OK) == 0);
    C(ntw_shell_folder(0x99, root, host_exists, host_mkdir, 0, path, 260, &hr) == 0 && hr == 0x80070057u);
    C(ntw_shell_known(unknown, 0x8000u, root, host_exists, host_mkdir, 0, path, 260, &hr) == 0 && hr == 0x80070057u);
    C(ntw_shell_known(roam, 0, root, host_exists, host_mkdir, 0, path, 260, &hr) == 1 && hr == 0);
    {
        C(ntw_shell_folder(0x23, "/tmp/ntw-shell-denied", host_exists, denied_mkdir, 0, path, 260, &hr) == 0 &&
          hr == 0x80070005u);
        C(access("/tmp/ntw-shell-denied", F_OK) != 0);
    }
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"shell\":true}\n");
    return 0;
}
