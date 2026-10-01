/* SPDX-License-Identifier: GPL-2.0-only
 * Real engine/painter regressions: wrong palette, style dispatch, stale handles,
 * clips, row padding, gradients or allocator cleanup must fail literal oracles.
 */
#include "uxtheme_engine_core.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, allocation_calls, fail_at, live_blocks;
static size_t live_bytes;
typedef struct allocation_header { max_align_t align; size_t size; } allocation_header;
#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "FAIL line %u: %s\n", (unsigned)__LINE__, #c); exit(1); \
} } while (0)

static void *allocate(void *user, size_t size)
{
    allocation_header *header;
    (void)user;
    ++allocation_calls;
    if (fail_at && allocation_calls == fail_at) return NULL;
    CHECK(size <= SIZE_MAX - sizeof(*header));
    header = calloc(1, sizeof(*header) + size);
    if (!header) return NULL;
    header->size = size; ++live_blocks; live_bytes += size;
    return header + 1;
}

static void deallocate(void *user, void *memory, size_t size)
{
    allocation_header *header = (allocation_header *)memory - 1;
    (void)user;
    CHECK(memory && live_blocks && header->size == size && live_bytes >= size);
    --live_blocks; live_bytes -= size; free(header);
}

static m98_theme_engine *create_engine(void)
{
    ntth_create_desc desc = { sizeof(desc), allocate, deallocate, NULL };
    m98_theme_engine *engine = NULL;
    CHECK(m98_theme_engine_create(&desc, &engine) == NTTH_OK && engine);
    return engine;
}

static void selection_and_lifetimes(void)
{
    /* Literal3 makes RED a missing-feature runtime failure, not a compile error. */
    m98_theme_engine *engine = create_engine();
    m98_theme_handle old = 0, current = 0;
    ntth_part_properties properties, saved;
    unsigned i;
    static const uint32_t cycle[] = { 1, 3, 2, 0, 3, 1 };
    CHECK(m98_theme_engine_style(engine, 3) == NTTH_OK);
    CHECK(m98_theme_engine_get_style(engine) == 3);
    for (i = 0; i < 120; ++i) {
        uint32_t selected = cycle[i % 6];
        uint32_t previous = m98_theme_engine_get_style(engine);
        CHECK(m98_theme_engine_style(engine, selected) == NTTH_OK);
        CHECK(m98_theme_engine_get_style(engine) == selected);
        if (old) {
            ntth_status wanted = !selected ? NTTH_E_NO_THEME :
                (selected == previous ? NTTH_OK : NTTH_E_HANDLE);
            CHECK(m98_theme_engine_query(engine, old, 1, 1, &properties) == wanted);
            CHECK(m98_theme_engine_close(engine, old) == NTTH_OK);
            CHECK(m98_theme_engine_close(engine, old) == NTTH_E_HANDLE);
            old = 0;
        }
        if (!selected) {
            current = 99;
            CHECK(m98_theme_engine_open(engine, "BUTTON", &current) == NTTH_E_NO_THEME && !current);
            continue;
        }
        CHECK(m98_theme_engine_open(engine, "BUTTON", &current) == NTTH_OK && current);
        CHECK(m98_theme_engine_query(engine, current, 1, 1, &properties) == NTTH_OK);
        CHECK(properties.fillcolor == (selected == 1 ? 0xc0c0c0u :
                                       selected == 2 ? 0xf0f0f0u : 0xedf5f9u));
        saved = properties;
        CHECK(m98_theme_engine_style(engine, selected) == NTTH_OK);
        CHECK(m98_theme_engine_query(engine, current, 1, 1, &properties) == NTTH_OK);
        CHECK(memcmp(&saved, &properties, sizeof(saved)) == 0);
        CHECK(m98_theme_engine_style(engine, 4) == NTTH_E_INVALID);
        CHECK(m98_theme_engine_style(engine, UINT32_MAX) == NTTH_E_INVALID);
        CHECK(m98_theme_engine_get_style(engine) == selected);
        CHECK(m98_theme_engine_query(engine, current, 1, 1, &properties) == NTTH_OK);
        CHECK(memcmp(&saved, &properties, sizeof(saved)) == 0);
        old = current;
    }
    if (old) CHECK(m98_theme_engine_close(engine, old) == NTTH_OK);
    CHECK(m98_theme_engine_destroy(engine) == NTTH_OK);
    CHECK(!live_blocks && !live_bytes);
}

enum { WIDTH = 12, HEIGHT = 12, PITCH = 52, GUARD = 32, FRAME_BYTES = HEIGHT * PITCH };
typedef struct frame { uint8_t bytes[GUARD + FRAME_BYTES + GUARD]; } frame;
static void reset(frame *target) { memset(target->bytes, 0xa7, sizeof(target->bytes)); }
static uint8_t *pixels(frame *target) { return target->bytes + GUARD; }
static void guards(const frame *target)
{
    unsigned i, y;
    for (i = 0; i < GUARD; ++i) {
        CHECK(target->bytes[i] == 0xa7);
        CHECK(target->bytes[GUARD + FRAME_BYTES + i] == 0xa7);
    }
    for (y = 0; y < HEIGHT; ++y)
        for (i = WIDTH * 4; i < PITCH; ++i)
            CHECK(target->bytes[GUARD + y * PITCH + i] == 0xa7);
}
static void pixel(const frame *target, unsigned x, unsigned y, uint32_t color, int painted)
{
    const uint8_t *p = target->bytes + GUARD + y * PITCH + x * 4;
    if (painted) {
        CHECK(p[0] == (uint8_t)color && p[1] == (uint8_t)(color >> 8) &&
              p[2] == (uint8_t)(color >> 16) && p[3] == 255);
    } else CHECK(p[0] == 0xa7 && p[1] == 0xa7 && p[2] == 0xa7 && p[3] == 0xa7);
}
static int in_rect(unsigned x, unsigned y, unsigned left, unsigned top, unsigned width, unsigned height)
{ return x >= left && x - left < width && y >= top && y - top < height; }

static void literal_palette_and_pixels(void)
{
    /* Palette literals come from the approved design, not engine queries. */
    static const uint32_t border[] = { 0x3d7890, 0x40a5c5, 0x0e6680, 0xa6b6c3 };
    static const uint32_t fill[] = { 0xedf5f9, 0xdceff7, 0xbedfea, 0xe8eef2 };
    static const uint32_t text[] = { 0x12283b, 0x12283b, 0x12283b, 0x526575 };
    /* Six independently hand-calculated interior columns, with floor rounding. */
    static const uint32_t gradient[] = { 0x102a43, 0x113a54, 0x124a66,
                                        0x135b78, 0x146b8a, 0x167c9c };
    const ntwg_rect rectangle = { 2, 2, 8, 8 };
    const ntth_draw_opts clip = { sizeof(clip), NTTH_DRAW_CLIP, { 4, 4, 2, 2 } };
    m98_theme_engine *engine = create_engine();
    m98_theme_handle button = 0, window = 0, missing = 91;
    ntth_part_properties properties, unchanged;
    frame target, saved;
    unsigned state, x, y;
    CHECK(m98_theme_engine_style(engine, 3) == NTTH_OK);
    CHECK(m98_theme_engine_open(engine, "BUTTON", &button) == NTTH_OK);
    CHECK(m98_theme_engine_open(engine, "WINDOW", &window) == NTTH_OK);
    CHECK(m98_theme_engine_open(engine, "SCROLLBAR", &missing) == NTTH_E_NO_THEME && !missing);
    for (state = 1; state <= 4; ++state) {
        CHECK(m98_theme_engine_query(engine, button, 1, (int32_t)state, &properties) == NTTH_OK);
        CHECK(properties.bordercolor == border[state - 1] && properties.fillcolor == fill[state - 1] &&
              properties.textcolor == text[state - 1] && properties.bordersize == 1 &&
              properties.bgtype == NTTH_BG_BORDERFILL && properties.filltype == NTTH_FT_SOLID);
        reset(&target);
        CHECK(m98_theme_engine_draw(engine, button, 1, (int32_t)state,
              pixels(&target), WIDTH, HEIGHT, PITCH, &rectangle, NULL) == NTTH_OK);
        for (y = 0; y < HEIGHT; ++y) for (x = 0; x < WIDTH; ++x) {
            int painted = in_rect(x, y, 2, 2, 8, 8);
            int interior = in_rect(x, y, 3, 3, 6, 6);
            pixel(&target, x, y, interior ? fill[state - 1] : border[state - 1], painted);
        }
        guards(&target);
    }
    reset(&target);
    CHECK(m98_theme_engine_draw(engine, button, 1, 2, pixels(&target),
          WIDTH, HEIGHT, PITCH, &rectangle, &clip) == NTTH_OK);
    for (y = 0; y < HEIGHT; ++y) for (x = 0; x < WIDTH; ++x)
        pixel(&target, x, y, 0xdceff7, in_rect(x, y, 4, 4, 2, 2));
    guards(&target);
    reset(&target); saved = target;
    CHECK(m98_theme_engine_draw(engine, button, 1, 1, pixels(&target), WIDTH,
          HEIGHT, WIDTH * 4 - 1, &rectangle, NULL) == NTTH_E_BOUNDS);
    CHECK(memcmp(&target, &saved, sizeof(target)) == 0);
    CHECK(m98_theme_engine_draw(engine, button, 1, 5, pixels(&target), WIDTH,
          HEIGHT, PITCH, &rectangle, NULL) == NTTH_E_UNSUPPORTED);
    CHECK(memcmp(&target, &saved, sizeof(target)) == 0);
    memset(&properties, 0x6c, sizeof(properties)); unchanged = properties;
    CHECK(m98_theme_engine_query(engine, window, 99, 1, &properties) == NTTH_E_UNSUPPORTED);
    CHECK(memcmp(&properties, &unchanged, sizeof(properties)) == 0);
    CHECK(m98_theme_engine_query(engine, window, 1, 1, &properties) == NTTH_OK);
    CHECK(properties.filltype == NTTH_FT_HORZGRADIENT && properties.textcolor == 0xffffff &&
          properties.gradient1 == 0x102a43 && properties.gradient2 == 0x167c9c);
    reset(&target);
    CHECK(m98_theme_engine_draw(engine, window, 1, 1, pixels(&target), WIDTH,
          HEIGHT, PITCH, &rectangle, NULL) == NTTH_OK);
    for (y = 0; y < HEIGHT; ++y) for (x = 0; x < WIDTH; ++x) {
        int inside = in_rect(x, y, 2, 2, 8, 8);
        int interior = in_rect(x, y, 3, 3, 6, 6);
        pixel(&target, x, y, interior ? gradient[x - 3] : 0x102a43, inside);
    }
    guards(&target);
    for (state = 7; state <= 9; ++state) {
        CHECK(m98_theme_engine_query(engine, window, (int32_t)state, 1, &properties) == NTTH_OK);
        CHECK(properties.fillcolor == 0xf5f9fc && properties.bordercolor == 0x3d7890);
        reset(&target);
        CHECK(m98_theme_engine_draw(engine, window, (int32_t)state, 1, pixels(&target),
              WIDTH, HEIGHT, PITCH, &rectangle, NULL) == NTTH_OK);
        pixel(&target, 2, 2, 0x3d7890, 1); pixel(&target, 3, 3, 0xf5f9fc, 1);
        guards(&target);
    }
    CHECK(m98_theme_engine_query(engine, window, 1, 2, &properties) == NTTH_OK);
    CHECK(properties.fillcolor == 0xe8eef2 && properties.textcolor == 0x526575);
    CHECK(m98_theme_engine_close(engine, button) == NTTH_OK);
    CHECK(m98_theme_engine_close(engine, window) == NTTH_OK);
    CHECK(m98_theme_engine_destroy(engine) == NTTH_OK);
    CHECK(!live_blocks && !live_bytes);
}

static void allocator_cleanup(void)
{
    ntth_create_desc desc = { sizeof(desc), allocate, deallocate, NULL };
    m98_theme_engine *engine = NULL;
    m98_theme_handle handle = 0;
    unsigned failure;
    for (failure = 1; failure <= 2; ++failure) {
        allocation_calls = 0; fail_at = failure; engine = (void *)(uintptr_t)1;
        CHECK(m98_theme_engine_create(&desc, &engine) == NTTH_E_NOMEM && !engine);
        CHECK(!live_blocks && !live_bytes);
    }
    fail_at = 0; allocation_calls = 0; engine = create_engine();
    CHECK(m98_theme_engine_style(engine, 3) == NTTH_OK);
    CHECK(m98_theme_engine_open(engine, "BUTTON", &handle) == NTTH_OK);
    CHECK(m98_theme_engine_destroy(engine) == NTTH_E_BUSY);
    m98_theme_engine_dispose(engine);
    CHECK(!live_blocks && !live_bytes);
}

int main(void)
{
    selection_and_lifetimes();
    literal_palette_and_pixels();
    allocator_cleanup();
    printf("PASS: %u ShizukuOS style, literal pixels, clipping, lifecycle and allocator checks\n", checks);
    return 0;
}
