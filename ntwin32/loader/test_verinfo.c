/* SPDX-License-Identifier: GPL-2.0-only */
#include "verinfo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static uint8_t *load(const char *path, uint32_t *size) {
    FILE *file = fopen(path, "rb");
    long length;
    uint8_t *data;
    if (!file) return 0;
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return 0; }
    length = ftell(file);
    if (length < 64 || length > 16 * 1024 * 1024) { fclose(file); return 0; }
    rewind(file);
    data = malloc((size_t)length);
    if (!data || fread(data, 1, (size_t)length, file) != (size_t)length) { free(data); fclose(file); return 0; }
    fclose(file);
    *size = (uint32_t)length;
    return data;
}
int main(void) {
    static const uint16_t root[] = {'\\', 0};
    static const uint16_t missing[] = {'\\', 'N', 'o', 'S', 'u', 'c', 'h', 0};
    static const uint8_t bare[] = {'M', 'Z', 0};
    const char *paths[] = {"/tmp/ntw-run/chrome.exe", "/tmp/ntw-run/chrome_elf.dll", 0};
    uint32_t error = 0, offset = 0, size = 0, i, info_bytes = 0;
    const void *info = 0;
    C(ntw_ver_find(bare, sizeof bare, &offset, &size, &error) == 0 && error == 1812);
    for (i = 0; paths[i]; ++i) {
        uint32_t file_size = 0;
        uint8_t *image = load(paths[i], &file_size);
        const uint8_t *block;
        if (!image) { fprintf(stderr, "missing %s\n", paths[i]); failures++; continue; }
        error = 0;
        C(ntw_ver_find(image, file_size, &offset, &size, &error) == 1);
        C(size >= 52 && error == 0);
        block = image + offset;
        C(ntw_ver_query(block, size, root, &info, &info_bytes, &error) == 1 && info_bytes == 52);
        C(info && ((const uint8_t *)info)[0] == 0xbd && ((const uint8_t *)info)[1] == 0x04 &&
          ((const uint8_t *)info)[2] == 0xef && ((const uint8_t *)info)[3] == 0xfe);
        C(ntw_ver_query(block, size, missing, &info, &info_bytes, &error) == 0 && error == 1812);
        free(image);
    }
    if (failures) return 1;
    printf("{\"passed\":true,\"verinfo\":true}\n");
    return 0;
}
