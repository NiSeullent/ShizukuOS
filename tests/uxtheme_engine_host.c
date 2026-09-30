/* SPDX-License-Identifier: GPL-2.0-only
 * Behavioral tests exercise the real portable painter, not a mocked copy.
 */
#include "uxtheme_engine_core.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static unsigned allocations, frees, fail_at, checks;
#define CHECK(c) do { ++checks; assert(c); } while (0)
static void *alloc(void *u, size_t n) {
    (void)u; ++allocations;
    return allocations == fail_at ? NULL : calloc(1, n);
}
static void release(void *u, void *p, size_t n) {
    (void)u; (void)n; ++frees; free(p);
}
static uint32_t pixel(const unsigned char *p, unsigned pitch, unsigned x, unsigned y) {
    const unsigned char *a = p + y * pitch + x * 4;
    return ((uint32_t)a[2] << 16) | ((uint32_t)a[1] << 8) | a[0];
}
int main(void)
{
    ntth_create_desc desc = { sizeof(desc), alloc, release, NULL };
    m98_theme_engine *e = NULL;
    m98_theme_handle h, replacement, caption, many[M98_THEME_CAPACITY];
    ntth_part_properties p, untouched;
    unsigned char target[12 * 52];
    ntwg_rect bounds = {2, 2, 8, 8};
    ntth_draw_opts clip = {sizeof(clip), NTTH_DRAW_CLIP, {4, 4, 2, 2}};
    unsigned i;
    fail_at = 1;
    CHECK(m98_theme_engine_create(&desc, &e) == NTTH_E_NOMEM && !e);
    fail_at = 3;
    CHECK(m98_theme_engine_create(&desc, &e) == NTTH_E_NOMEM && !e && frees == 1);
    fail_at = 0;
    CHECK(m98_theme_engine_create(&desc, &e) == NTTH_OK);
    CHECK(!m98_theme_engine_active(e) && !m98_theme_engine_app_themed(e));
    h = 99;
    CHECK(m98_theme_engine_open(e, "BUTTON", &h) == NTTH_E_NO_THEME && h == 0);
    CHECK(m98_theme_engine_style(e, 99) == NTTH_E_INVALID && !m98_theme_engine_active(e));
    CHECK(m98_theme_engine_style(e, M98_THEME_MODERN) == NTTH_OK);
    CHECK(m98_theme_engine_active(e) && m98_theme_engine_app_themed(e));
    CHECK(m98_theme_engine_open(e, "SCROLLBAR", &h) == NTTH_E_NO_THEME && !h);
    CHECK(m98_theme_engine_open(e, "BUTTON", &h) == NTTH_OK && h);
    CHECK(m98_theme_engine_query(e, h, 1, 1, &p) == NTTH_OK);
    CHECK(p.bordercolor == 0x0078d7 && p.fillcolor == 0xf0f0f0 && p.bordersize == 1);
    CHECK(m98_theme_engine_query(e, h, 1, 2, &p) == NTTH_OK && p.fillcolor == 0xe5f1fb);
    CHECK(m98_theme_engine_query(e, h, 1, 3, &p) == NTTH_OK && p.fillcolor == 0xcce4f7);
    CHECK(m98_theme_engine_query(e, h, 1, 4, &p) == NTTH_OK && p.textcolor == 0xa0a0a0);
    memset(&p, 0x5a, sizeof(p)); untouched = p;
    CHECK(m98_theme_engine_query(e, h, 1, 5, &p) == NTTH_E_UNSUPPORTED);
    CHECK(memcmp(&p, &untouched, sizeof(p)) == 0);
    memset(target, 0x5a, sizeof(target));
    CHECK(m98_theme_engine_draw(e, h, 1, 1, target, 12, 12, 52, &bounds, NULL) == NTTH_OK);
    CHECK(pixel(target, 52, 2, 2) == 0x0078d7 && pixel(target, 52, 3, 3) == 0xf0f0f0);
    CHECK(pixel(target, 52, 1, 1) == 0x5a5a5a && target[51] == 0x5a);
    memset(target, 0x5a, sizeof(target));
    CHECK(m98_theme_engine_draw(e, h, 1, 2, target, 12, 12, 52, &bounds, &clip) == NTTH_OK);
    CHECK(pixel(target, 52, 4, 4) == 0xe5f1fb && pixel(target, 52, 3, 4) == 0x5a5a5a);
    CHECK(m98_theme_engine_draw(e, h, 99, 1, target, 12, 12, 52, &bounds, NULL) == NTTH_E_UNSUPPORTED);
    CHECK(m98_theme_engine_open(e, "WINDOW", &caption) == NTTH_OK);
    CHECK(m98_theme_engine_query(e, caption, 1, 1, &p) == NTTH_OK && p.filltype == NTTH_FT_HORZGRADIENT);
    CHECK(m98_theme_engine_draw(e, caption, 1, 1, target, 12, 12, 52, &bounds, NULL) == NTTH_OK);
    CHECK(pixel(target, 52, 3, 4) == 0x0078d7 && pixel(target, 52, 8, 4) == 0x005a9e);
    CHECK(m98_theme_engine_destroy(e) == NTTH_E_BUSY);
    CHECK(m98_theme_engine_style(e, M98_THEME_CLASSIC) == NTTH_OK);
    CHECK(m98_theme_engine_query(e, h, 1, 1, &p) == NTTH_E_HANDLE);
    CHECK(m98_theme_engine_close(e, h) == NTTH_OK);
    CHECK(m98_theme_engine_close(e, h) == NTTH_E_HANDLE);
    CHECK(m98_theme_engine_close(e, caption) == NTTH_OK);
    CHECK(m98_theme_engine_open(e, "BUTTON", &replacement) == NTTH_OK && replacement != h);
    CHECK(m98_theme_engine_query(e, replacement, 1, 1, &p) == NTTH_OK && p.fillcolor == 0xc0c0c0);
    CHECK(m98_theme_engine_query(e, h, 1, 1, &p) == NTTH_E_HANDLE);
    CHECK(m98_theme_engine_style(e, M98_THEME_OFF) == NTTH_OK);
    CHECK(!m98_theme_engine_active(e));
    CHECK(m98_theme_engine_query(e, replacement, 1, 1, &p) == NTTH_E_NO_THEME);
    CHECK(m98_theme_engine_style(e, M98_THEME_MODERN) == NTTH_OK);
    CHECK(m98_theme_engine_query(e, replacement, 1, 1, &p) == NTTH_E_HANDLE);
    CHECK(m98_theme_engine_close(e, replacement) == NTTH_OK);
    m98_theme_engine_set_flags(e, 0);
    CHECK(m98_theme_engine_active(e) && !m98_theme_engine_app_themed(e));
    CHECK(m98_theme_engine_open(e, "BUTTON", &h) == NTTH_E_NO_THEME);
    m98_theme_engine_set_flags(e, M98_THEME_ALLOW_NONCLIENT);
    CHECK(m98_theme_engine_open(e, "BUTTON", &h) == NTTH_E_NO_THEME);
    CHECK(m98_theme_engine_open(e, "WINDOW", &caption) == NTTH_OK);
    CHECK(m98_theme_engine_close(e, caption) == NTTH_OK);
    m98_theme_engine_set_flags(e, M98_THEME_ALLOW_WEBCONTENT);
    CHECK(!m98_theme_engine_app_themed(e));
    m98_theme_engine_set_flags(e, 0xffffffffu);
    CHECK(m98_theme_engine_get_flags(e) == 7);
    for (i = 0; i < M98_THEME_CAPACITY; ++i)
        CHECK(m98_theme_engine_open(e, "BUTTON", &many[i]) == NTTH_OK);
    CHECK(m98_theme_engine_open(e, "BUTTON", &h) == NTTH_E_EXHAUSTED && h == 0);
    for (i = 0; i < M98_THEME_CAPACITY; ++i) CHECK(m98_theme_engine_close(e, many[i]) == NTTH_OK);
    CHECK(m98_theme_engine_destroy(e) == NTTH_OK);
    CHECK(allocations == frees + 2); /* two deliberately failed allocations */
    CHECK(m98_theme_engine_create(&desc, &e) == NTTH_OK);
    CHECK(m98_theme_engine_style(e, M98_THEME_MODERN) == NTTH_OK);
    CHECK(m98_theme_engine_open(e, "BUTTON", &h) == NTTH_OK);
    m98_theme_engine_dispose(e);
    CHECK(allocations == frees + 2);
    printf("PASS: %u theme lifecycle, pixel, state, query and allocation checks\n", checks);
    return 0;
}
