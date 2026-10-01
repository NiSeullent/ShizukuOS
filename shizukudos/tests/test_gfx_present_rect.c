/* SPDX-License-Identifier: GPL-2.0-only
 * Link the actual gfx_fb_present implementation. A recording backend observes
 * clipped rectangles; the independent oracle counts covered screen pixels.
 * No kernel allocator, hardware probe or framebuffer mapping executes here.
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel64/gfx.h"

static unsigned checks, calls;
static int recorded[4];
#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); \
} } while (0)

static void record_present(int x, int y, int w, int h)
{
    ++calls;
    recorded[0] = x; recorded[1] = y; recorded[2] = w; recorded[3] = h;
}
static const gfx_backend_t recording_backend = {"host recording", 0, NULL, record_present};

static void check_rectangle(int x, int y, int w, int h, int ready)
{
    unsigned px, py, area = 0;
    int left = 13, top = 9, right = 0, bottom = 0;
    const uint64_t initial_presents = 19, initial_pixels = 211;
    memset(&g_fb, 0, sizeof g_fb);
    g_fb.ready = ready;
    g_fb.width = 13; g_fb.height = 9;
    g_fb.backend = &recording_backend;
    g_fb.stat_presents = initial_presents;
    g_fb.stat_present_pixels = initial_pixels;
    calls = 0;
    memset(recorded, 0xa5, sizeof recorded);
    if (ready && w > 0 && h > 0)
        for (py = 0; py < 9; ++py)
            for (px = 0; px < 13; ++px)
                if ((int64_t)px >= x && (int64_t)px < (int64_t)x + w &&
                    (int64_t)py >= y && (int64_t)py < (int64_t)y + h) {
                    ++area;
                    if ((int)px < left) left = (int)px;
                    if ((int)py < top) top = (int)py;
                    if ((int)px + 1 > right) right = (int)px + 1;
                    if ((int)py + 1 > bottom) bottom = (int)py + 1;
                }
    gfx_fb_present(x, y, w, h);
    CHECK(calls == (area ? 1u : 0u));
    CHECK(g_fb.stat_presents == initial_presents + (area ? 1u : 0u));
    CHECK(g_fb.stat_present_pixels == initial_pixels + area);
    if (area) {
        CHECK(recorded[0] == left && recorded[1] == top);
        CHECK(recorded[2] == right - left && recorded[3] == bottom - top);
    }
}

static void check_invalid_dimensions(uint32_t width, uint32_t height)
{
    memset(&g_fb, 0, sizeof g_fb);
    g_fb.ready = 1;
    g_fb.width = width; g_fb.height = height;
    g_fb.backend = &recording_backend;
    calls = 0;
    gfx_fb_present(0, 0, 1, 1);
    CHECK(calls == 0);
    CHECK(g_fb.stat_presents == 0 && g_fb.stat_present_pixels == 0);
}

int main(void)
{
    static const int edge[] = {INT_MIN, INT_MIN + 1, -100, -13, -9, -1,
                              0, 1, 8, 9, 12, 13, 100, INT_MAX - 1, INT_MAX};
    unsigned x, y, w, h;
    check_rectangle(0, 0, 13, 9, 1);
    check_rectangle(-2, -3, 20, 20, 1);
    check_rectangle(0, 0, 13, 9, 0);
    /* Positive offscreen origin plus width used to overflow and reach a backend. */
    check_rectangle(INT_MAX, 0, 1, 1, 1);
    check_rectangle(0, INT_MAX, 1, 1, 1);
    check_rectangle(INT_MIN, 0, INT_MIN, 1, 1);
    check_invalid_dimensions(0, 9);
    check_invalid_dimensions(13, 0);
    check_invalid_dimensions((uint32_t)INT_MAX + 1, 9);
    check_invalid_dimensions(13, (uint32_t)INT_MAX + 1);
    for (x = 0; x < sizeof edge / sizeof edge[0]; ++x)
        for (y = 0; y < sizeof edge / sizeof edge[0]; ++y)
            for (w = 0; w < sizeof edge / sizeof edge[0]; ++w)
                for (h = 0; h < sizeof edge / sizeof edge[0]; ++h)
                    check_rectangle(edge[x], edge[y], edge[w], edge[h], 1);
    printf("PASS: %u production framebuffer clipping and statistics checks\n", checks);
    return 0;
}
