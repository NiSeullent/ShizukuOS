/* SPDX-License-Identifier: GPL-2.0-only
 * Host placement of the official chrome.exe image and the TLS fixture.
 * Does not execute Chrome's i386 callbacks and does not rewrite subsystem 10.0.
 */
#include "start.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static void *allocate(void *user, size_t bytes) { (void)user; return malloc(bytes); }
static void release(void *user, void *memory, size_t bytes) { (void)user; (void)bytes; free(memory); }
static uint8_t *read_file(const char *path, uint32_t *out_len) {
    FILE *file = fopen(path, "rb");
    long length;
    uint8_t *data;
    if (!file) return 0;
    fseek(file, 0, SEEK_END);
    length = ftell(file);
    fseek(file, 0, SEEK_SET);
    data = malloc((size_t)length);
    if (!data || fread(data, 1, (size_t)length, file) != (size_t)length) { free(data); fclose(file); return 0; }
    fclose(file);
    *out_len = (uint32_t)length;
    return data;
}
static void check_image(const char *path, uint32_t expect_align, uint32_t expect_callbacks) {
    uint32_t length = 0, i, saved_major_offset;
    uint8_t *file = read_file(path, &length);
    uint8_t *image = calloc(1, 8 * 1024 * 1024);
    uint8_t *storage = calloc(1, ntwtls_process_size() + ntwtls_thread_size());
    ntw_placed placed;
    ntwtls_services services = {0, allocate, release};
    void *slot = 0;
    int status;
    C(file && image && storage);
    memset(&placed, 0, sizeof placed);
    status = ntw_place_pe32(file, length, image, 8 * 1024 * 1024, 0, &placed);
    C(status == NTW_MAP_OK);
    C(placed.subsystem_major == 10 && placed.subsystem_minor == 0);
    C(placed.relocations_applied == 0);
    C(placed.tls.present && placed.tls.alignment == expect_align);
    C(placed.tls.callback_count == expect_callbacks);
    /* File bytes stay bit-identical, including subsystem 10.0. */
    {
        uint8_t *again = read_file(path, &length);
        C(again && memcmp(again, file, length) == 0);
        free(again);
    }
    status = ntw_loader_start(image, &placed, (ntwtls_process *)storage,
                              (ntwtls_thread *)(storage + ntwtls_process_size()),
                              &services, 0, &slot);
    C(status == NTWTLS_OK && slot);
    C(((uintptr_t)slot & (expect_align - 1)) == 0);
    for (i = 0; i < placed.tls.raw_bytes && i < 16; ++i)
        C(((uint8_t *)slot)[i] == placed.tls.raw[i]);
    (void)saved_major_offset;
    printf("{\"path\":\"%s\",\"status\":%d,\"subsystem\":[%u,%u],\"raw\":%u,\"align\":%u,\"callbacks\":%u,\"index\":%u}\n",
           path, status, placed.subsystem_major, placed.subsystem_minor, placed.tls.raw_bytes,
           placed.tls.alignment, placed.tls.callback_count, *placed.tls.index_slot);
    free(file); free(image); free(storage);
}
int main(void) {
    check_image("benchmarks/media/chromium-1705698/chrome.exe", 32, 6);
    check_image("benchmarks/media/chromium-1705698/chrome_elf.dll", 8, 6);
    return failures ? 1 : 0;
}
