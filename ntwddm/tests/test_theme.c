/* SPDX-License-Identifier: GPL-2.0-only
 * Host contract and pixel evidence for the in-process visual style painter.
 */
#include "sample_window.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NTTH_THEME_DIR
#define NTTH_THEME_DIR "theme"
#endif
#ifndef NTTH_EVIDENCE_DIR
#define NTTH_EVIDENCE_DIR "build/evidence"
#endif

#define CHECK(expression) do { \
    ++checks; \
    if (!(expression)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
        exit(1); \
    } \
} while (0)

static unsigned long checks;

static void *allocate(void *user, size_t bytes)
{
    (void)user;
    return calloc(1, bytes);
}

static void deallocate(void *user, void *memory, size_t bytes)
{
    (void)user;
    (void)bytes;
    free(memory);
}

static ntth_session *open_session(void)
{
    ntth_create_desc desc;
    ntth_session *session = NULL;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.allocate = allocate;
    desc.deallocate = deallocate;
    CHECK(ntth_session_open(&desc, &session) == NTTH_OK);
    return session;
}

static char *read_all(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    long size;
    char *data;
    CHECK(file != NULL);
    CHECK(fseek(file, 0, SEEK_END) == 0);
    size = ftell(file);
    CHECK(size > 0);
    CHECK(fseek(file, 0, SEEK_SET) == 0);
    data = (char *)malloc((size_t)size);
    CHECK(data != NULL);
    CHECK(fread(data, 1, (size_t)size, file) == (size_t)size);
    CHECK(fclose(file) == 0);
    *length = (size_t)size;
    return data;
}

static void expect_file(const char *path, const char *builtin, size_t length)
{
    size_t got = 0;
    char *data = read_all(path, &got);
    CHECK(got == length);
    CHECK(memcmp(data, builtin, length) == 0);
    free(data);
}

static void save(const char *name, const uint8_t *pixels, uint32_t width,
                 uint32_t height, uint32_t pitch, uint32_t scale)
{
    char path[512];
    CHECK(snprintf(path, sizeof(path), "%s/%s", NTTH_EVIDENCE_DIR, name) > 0);
    CHECK(evidence_write_xrgb(path, pixels, width, height, pitch, scale) == 0);
}

static void paint_loaded(ntth_session *session, const char *style, size_t length,
                         const char *caption, uint32_t client, uint8_t *pixels,
                         int with_text)
{
    CHECK(ntth_session_load(session, style, length) == NTTH_OK);
    CHECK(ntth_theme_active(session) == 1);
    CHECK(sample_window_paint(session, pixels, SAMPLE_WINDOW_W * 4u, caption,
                             client, with_text) == NTTH_OK);
}

int main(void)
{
    ntth_session *session;
    ntth_theme button = 0;
    ntth_theme window = 0;
    ntth_draw_opts opts;
    ntwg_rect rect;
    uint8_t *classic;
    uint8_t *modern;
    uint8_t glyph[8 * 4 * 10];
    uint8_t chip[40 * 4 * 28];
    uint8_t compare[(12u + SAMPLE_WINDOW_W + 16u + SAMPLE_WINDOW_W + 12u) *
                    (12u + SAMPLE_WINDOW_H + 12u) * 4u];
    const uint32_t compare_w = 12u + SAMPLE_WINDOW_W + 16u + SAMPLE_WINDOW_W + 12u;
    const uint32_t compare_h = 12u + SAMPLE_WINDOW_H + 12u;
    const uint32_t pitch = SAMPLE_WINDOW_W * 4u;
    char bad[] = "name Broken\n";

    expect_file(NTTH_THEME_DIR "/classic.ntth", ntth_builtin_classic_text,
                ntth_builtin_classic_length);
    expect_file(NTTH_THEME_DIR "/modern.ntth", ntth_builtin_modern_text,
                ntth_builtin_modern_length);

    classic = (uint8_t *)calloc(1, SAMPLE_WINDOW_H * pitch);
    modern = (uint8_t *)calloc(1, SAMPLE_WINDOW_H * pitch);
    CHECK(classic != NULL && modern != NULL);
    session = open_session();
    CHECK(ntth_theme_active(session) == 0);
    CHECK(ntth_session_load(session, "", 0) == NTTH_E_INVALID);
    CHECK(ntth_session_load(session, bad, sizeof(bad) - 1u) == NTTH_E_PARSE);
    CHECK(ntth_theme_active(session) == 0);

    paint_loaded(session, ntth_builtin_classic_text, ntth_builtin_classic_length,
                 "CLASSIC", 0xFFC0C0C0u, classic, 0);
    save("classic-background.ppm", classic, SAMPLE_WINDOW_W, SAMPLE_WINDOW_H, pitch, 4);
    CHECK(sample_window_paint(session, classic, pitch, "CLASSIC", 0xFFC0C0C0u, 1) == NTTH_OK);
    save("classic-window.ppm", classic, SAMPLE_WINDOW_W, SAMPLE_WINDOW_H, pitch, 4);
    CHECK(evidence_read_xrgb(classic, pitch, 0, 0) == 0xFF000040u);
    CHECK(evidence_read_xrgb(classic, pitch, 60, 10) == 0xFF000080u);
    CHECK(evidence_read_xrgb(classic, pitch, 9, 7) == 0xFFFFFFFFu);
    CHECK(evidence_read_xrgb(classic, pitch, 16, 48) == 0xFF808080u);
    CHECK(evidence_read_xrgb(classic, pitch, 24, 56) == 0xFFC0C0C0u);
    CHECK(evidence_read_xrgb(classic, pitch, 100, 48) == 0xFF000000u);
    CHECK(evidence_read_xrgb(classic, pitch, 110, 56) == 0xFFA0A0A0u);
    CHECK(evidence_read_xrgb(classic, pitch, 47, 57) == 0xFF000000u);

    paint_loaded(session, ntth_builtin_modern_text, ntth_builtin_modern_length,
                 "MODERN", 0xFFF0F0F0u, modern, 0);
    save("modern-background.ppm", modern, SAMPLE_WINDOW_W, SAMPLE_WINDOW_H, pitch, 4);
    CHECK(sample_window_paint(session, modern, pitch, "MODERN", 0xFFF0F0F0u, 1) == NTTH_OK);
    save("modern-window.ppm", modern, SAMPLE_WINDOW_W, SAMPLE_WINDOW_H, pitch, 4);
    CHECK(evidence_read_xrgb(modern, pitch, 0, 0) == 0xFF004578u);
    CHECK(evidence_read_xrgb(modern, pitch, 1, 8) == 0xFF0078D7u);
    CHECK(evidence_read_xrgb(modern, pitch, SAMPLE_WINDOW_W - 2u, 8) == 0xFF005A9Eu);
    CHECK(evidence_read_xrgb(modern, pitch, 16, 48) == 0xFF0078D7u);
    CHECK(evidence_read_xrgb(modern, pitch, 24, 56) == 0xFFF0F0F0u);
    CHECK(evidence_read_xrgb(classic, pitch, 60, 10) != evidence_read_xrgb(modern, pitch, 60, 10));

    evidence_fill_xrgb(compare, compare_w, compare_h, compare_w * 4u, 0xFF202020u);
    evidence_blit(compare, compare_w * 4u, 12, 12, classic, SAMPLE_WINDOW_W,
                  SAMPLE_WINDOW_H, pitch);
    evidence_blit(compare, compare_w * 4u, 12u + SAMPLE_WINDOW_W + 16u, 12, modern,
                  SAMPLE_WINDOW_W, SAMPLE_WINDOW_H, pitch);
    save("classic-modern-compare.ppm", compare, compare_w, compare_h, compare_w * 4u, 4);

    evidence_fill_xrgb(chip, 40, 28, 160, 0xFF202020u);
    CHECK(ntth_open_data(session, "BUTTON", &button) == NTTH_OK);
    rect.x = 2; rect.y = 2; rect.width = 36; rect.height = 24;
    CHECK(ntth_draw_background(session, button, NTTH_BP_PUSHBUTTON, NTTH_PBS_HOT,
                              chip, 40, 28, 160, &rect, NULL) == NTTH_OK);
    save("fixture-modern-hot-button.ppm", chip, 40, 28, 160, 8);

    memset(&opts, 0, sizeof(opts));
    opts.struct_size = sizeof(opts);
    opts.flags = NTTH_DRAW_OMIT_BORDER;
    evidence_fill_xrgb(chip, 40, 28, 160, 0xFF111111u);
    CHECK(ntth_draw_background(session, button, NTTH_BP_PUSHBUTTON, NTTH_PBS_NORMAL,
                              chip, 40, 28, 160, &rect, &opts) == NTTH_OK);
    CHECK(evidence_read_xrgb(chip, 160, 2, 2) == 0xFF111111u);
    CHECK(evidence_read_xrgb(chip, 160, 8, 8) == 0xFFF0F0F0u);
    opts.flags = NTTH_DRAW_CLIP;
    opts.clip.x = 10; opts.clip.y = 10; opts.clip.width = 4; opts.clip.height = 4;
    evidence_fill_xrgb(chip, 40, 28, 160, 0xFF111111u);
    CHECK(ntth_draw_background(session, button, NTTH_BP_PUSHBUTTON, NTTH_PBS_NORMAL,
                              chip, 40, 28, 160, &rect, &opts) == NTTH_OK);
    CHECK(evidence_read_xrgb(chip, 160, 10, 10) == 0xFFF0F0F0u);
    CHECK(evidence_read_xrgb(chip, 160, 8, 8) == 0xFF111111u);

    memset(glyph, 0x11, sizeof(glyph));
    rect.x = 2; rect.y = 2; rect.width = 8; rect.height = 8;
    CHECK(ntth_draw_text(session, button, NTTH_BP_PUSHBUTTON, NTTH_PBS_NORMAL,
                        "A", 1, glyph, 8, 10, 32, &rect, NULL) == NTTH_OK);
    CHECK(evidence_read_xrgb(glyph, 32, 2, 2) == 0x11111111u);
    CHECK(evidence_read_xrgb(glyph, 32, 3, 2) == 0xFF000000u);
    CHECK(ntth_draw_text(session, button, 1, 1, "!", 1, glyph, 8, 10, 32, &rect, NULL) ==
          NTTH_E_UNSUPPORTED);
    CHECK(evidence_read_xrgb(glyph, 32, 2, 2) == 0x11111111u);

    CHECK(ntth_draw_background(session, 0, 1, 1, glyph, 8, 10, 32, &rect, NULL) == NTTH_E_HANDLE);
    CHECK(ntth_open_data(session, "SCROLLBAR", &window) == NTTH_E_NO_THEME);
    CHECK(ntth_close_data(session, button) == NTTH_OK);
    CHECK(ntth_draw_background(session, button, 1, 1, glyph, 8, 10, 32, &rect, NULL) ==
          NTTH_E_HANDLE);
    CHECK(ntth_session_load(session, bad, sizeof(bad) - 1u) == NTTH_E_PARSE);
    CHECK(ntth_theme_active(session) == 1);
    CHECK(ntth_open_data(session, "BUTTON", &button) == NTTH_OK);
    {
        uint8_t one[4] = {0, 0, 0, 0};
        ntwg_rect tiny;
        char image[] =
            "name Img\n"
            "class BUTTON\n"
            "part 1 state 1 bgtype imagefile bordersize 1 bordercolor 000000 "
            "filltype solid fillcolor FFFFFF textcolor 000000\n";
        ntth_theme stale = button;
        CHECK(ntth_session_close(session) == NTTH_E_BUSY);
        CHECK(ntth_session_load(session, image, sizeof(image) - 1u) == NTTH_OK);
        tiny.x = 0; tiny.y = 0; tiny.width = 1; tiny.height = 1;
        CHECK(ntth_draw_background(session, stale, 1, 1, one, 1, 1, 4, &tiny, NULL) ==
              NTTH_E_HANDLE);
        CHECK(ntth_close_data(session, stale) == NTTH_OK);
        CHECK(one[0] == 0 && one[1] == 0 && one[2] == 0 && one[3] == 0);
        CHECK(ntth_open_data(session, "BUTTON", &button) == NTTH_OK);
        one[0] = 0x22;
        CHECK(ntth_draw_background(session, button, 1, 1, one, 1, 1, 4, &tiny, NULL) ==
              NTTH_E_UNSUPPORTED);
        CHECK(one[0] == 0x22);
        CHECK(ntth_close_data(session, button) == NTTH_OK);
    }
    CHECK(ntth_session_close(session) == NTTH_OK);
    free(classic);
    free(modern);
    printf("PASS theme checks %lu\n", checks);
    return 0;
}
