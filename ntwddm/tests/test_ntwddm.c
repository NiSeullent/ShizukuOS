/* SPDX-License-Identifier: GPL-2.0-only
 * Host contract tests, independently authored. Not a Win98 driver test.
 */
#include "ntwddm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression) do { \
    ++checks; \
    if (!(expression)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
        exit(1); \
    } \
} while (0)

static unsigned long checks;
static unsigned long overlap_cases;

typedef struct allocation {
    void *pointer;
    size_t bytes;
} allocation;

typedef struct allocator_state {
    allocation records[NTWG_MAX_SURFACES + 4];
    size_t live;
    size_t calls;
    size_t fail_after;
    size_t max_bytes;
} allocator_state;

static void *allocate(void *user, size_t bytes)
{
    allocator_state *state = (allocator_state *)user;
    size_t i;
    uint8_t *p;
    ++state->calls;
    if (state->calls > state->fail_after || bytes > state->max_bytes) return NULL;
    CHECK(bytes <= SIZE_MAX - 16);
    p = (uint8_t *)malloc(bytes + 16);
    CHECK(p != NULL);
    memset(p, 0xdd, bytes + 16);
    for (i = 0; i < sizeof(state->records) / sizeof(state->records[0]); ++i)
        if (state->records[i].pointer == NULL) break;
    CHECK(i < sizeof(state->records) / sizeof(state->records[0]));
    state->records[i].pointer = p;
    state->records[i].bytes = bytes;
    ++state->live;
    return p;
}

static void deallocate(void *user, void *memory, size_t bytes)
{
    allocator_state *state = (allocator_state *)user;
    size_t i, j;
    for (i = 0; i < sizeof(state->records) / sizeof(state->records[0]); ++i)
        if (state->records[i].pointer == memory) break;
    CHECK(i < sizeof(state->records) / sizeof(state->records[0]));
    CHECK(state->records[i].bytes == bytes);
    for (j = 0; j < 16; ++j) CHECK(((uint8_t *)memory)[bytes + j] == 0xdd);
    state->records[i].pointer = NULL;
    --state->live;
    free(memory);
}

static ntwg_context *create(allocator_state *state)
{
    ntwg_context *ctx = NULL;
    ntwg_create_desc desc = { sizeof(desc), NTWG_ABI_VERSION,
                             allocate, deallocate, state };
    memset(state, 0, sizeof(*state));
    state->fail_after = SIZE_MAX;
    state->max_bytes = 1024 * 1024;
    CHECK(ntwg_create(&desc, &ctx) == NTWG_OK);
    CHECK(ctx != NULL);
    return ctx;
}

static ntwg_surface surface(ntwg_context *ctx, uint32_t width, uint32_t height,
                            uint32_t pitch, uint32_t format)
{
    ntwg_surface result = 0;
    ntwg_surface_desc desc = { sizeof(desc), NTWG_ABI_VERSION,
                              width, height, pitch, format };
    CHECK(ntwg_surface_create(ctx, &desc, &result) == NTWG_OK);
    CHECK(result != 0);
    return result;
}

static ntwg_framebuffer_desc framebuffer(void *pixels, size_t bytes,
                                         uint32_t width, uint32_t height,
                                         uint32_t pitch, uint32_t format)
{
    ntwg_framebuffer_desc desc = { sizeof(desc), NTWG_ABI_VERSION,
        pixels, bytes, width, height, pitch, format, NULL, NULL };
    return desc;
}

/* Independent oracle: component bytes are placed using a format layout table. */
static void reference_pixel(uint8_t *target, uint32_t format, uint32_t color)
{
    static const uint8_t shifts[4][4] = {
        { 0, 8, 16, 24 }, { 0, 8, 16, 24 },
        { 0, 8, 16, 24 }, { 16, 8, 0, 24 }
    };
    uint32_t n = format == NTWG_PIXEL_BGR888 ? 3u : 4u;
    uint32_t i;
    for (i = 0; i < n; ++i) {
        if (i == 3 && format != NTWG_PIXEL_ARGB8888) target[i] = 255;
        else target[i] = (uint8_t)(color >> shifts[format - 1][i]);
    }
}

static void check_fence(ntwg_context *ctx, const ntwg_fence *fence)
{
    uint32_t completed = 7;
    CHECK(fence->sequence != 0);
    CHECK(ntwg_fence_query(ctx, fence, &completed) == NTWG_OK);
    CHECK(completed == 1);
}

static void invalid_arguments(void)
{
    allocator_state state;
    ntwg_context *ctx = create(&state), *invalid = ctx;
    ntwg_create_desc create_desc = { sizeof(create_desc), NTWG_ABI_VERSION,
                                    allocate, deallocate, &state };
    ntwg_surface_desc sd = { sizeof(sd), NTWG_ABI_VERSION, 3, 2, 12,
                            NTWG_PIXEL_XRGB8888 };
    uint8_t bytes[32] = { 0 };
    ntwg_framebuffer_desc fd = framebuffer(bytes, sizeof(bytes), 3, 2, 12,
                                           NTWG_PIXEL_XRGB8888);
    ntwg_surface s = 99;
    ntwg_mapping mapping;
    ntwg_fence fence = { 5, 6, 7 };
    ntwg_rect rect = { 0, 0, 1, 1 };
    uint32_t completed = 7;
    CHECK(ntwg_capabilities() == UINT64_C(63));
    CHECK(ntwg_require_capabilities(ntwg_capabilities()) == NTWG_OK);
    CHECK(ntwg_require_capabilities(0) == NTWG_OK);
    CHECK(ntwg_require_capabilities(NTWG_CAP_WDDM_MINIPORT) == NTWG_E_UNSUPPORTED);
    CHECK(ntwg_require_capabilities(NTWG_CAP_D3D) == NTWG_E_UNSUPPORTED);
    CHECK(ntwg_require_capabilities(NTWG_CAP_GPU_ACCELERATION) == NTWG_E_UNSUPPORTED);
    CHECK(ntwg_require_capabilities(UINT64_C(1) << 63) == NTWG_E_UNSUPPORTED);
    CHECK(ntwg_create(NULL, &invalid) == NTWG_E_INVALID && invalid == NULL);
    CHECK(ntwg_create(&create_desc, NULL) == NTWG_E_INVALID);
    create_desc.struct_size = 0;
    CHECK(ntwg_create(&create_desc, &invalid) == NTWG_E_INVALID);
    create_desc.struct_size = sizeof(create_desc);
    create_desc.abi_version++;
    CHECK(ntwg_create(&create_desc, &invalid) == NTWG_E_VERSION);
    create_desc.abi_version = NTWG_ABI_VERSION;
    create_desc.allocate = NULL;
    CHECK(ntwg_create(&create_desc, &invalid) == NTWG_E_INVALID);
    create_desc.allocate = allocate;
    create_desc.deallocate = NULL;
    CHECK(ntwg_create(&create_desc, &invalid) == NTWG_E_INVALID);
    create_desc.deallocate = deallocate;
    state.fail_after = state.calls;
    CHECK(ntwg_create(&create_desc, &invalid) == NTWG_E_NOMEM && invalid == NULL);
    CHECK(ntwg_surface_create(ctx, &sd, &s) == NTWG_E_NOMEM && s == 0);
    state.fail_after = SIZE_MAX;
    CHECK(ntwg_destroy(NULL) == NTWG_E_INVALID);
    CHECK(ntwg_bind_framebuffer(NULL, &fd) == NTWG_E_INVALID);
    CHECK(ntwg_bind_framebuffer(ctx, NULL) == NTWG_E_INVALID);
    CHECK(ntwg_unbind_framebuffer(NULL) == NTWG_E_INVALID);
    CHECK(ntwg_unbind_framebuffer(ctx) == NTWG_E_UNBOUND);
    CHECK(ntwg_surface_create(NULL, &sd, &s) == NTWG_E_INVALID);
    CHECK(ntwg_surface_create(ctx, NULL, &s) == NTWG_E_INVALID);
    CHECK(ntwg_surface_create(ctx, &sd, NULL) == NTWG_E_INVALID);
    sd.struct_size = 1;
    CHECK(ntwg_surface_create(ctx, &sd, &s) == NTWG_E_INVALID);
    sd.struct_size = sizeof(sd);
    sd.abi_version++;
    CHECK(ntwg_surface_create(ctx, &sd, &s) == NTWG_E_VERSION);
    sd.abi_version = NTWG_ABI_VERSION;
    sd.format = 99;
    CHECK(ntwg_surface_create(ctx, &sd, &s) == NTWG_E_UNSUPPORTED);
    sd.format = NTWG_PIXEL_XRGB8888;
    sd.width = 0;
    CHECK(ntwg_surface_create(ctx, &sd, &s) == NTWG_E_INVALID);
    sd.width = UINT32_MAX;
    CHECK(ntwg_surface_create(ctx, &sd, &s) == NTWG_E_BOUNDS);
    sd.width = 3;
    sd.pitch_bytes = 11;
    CHECK(ntwg_surface_create(ctx, &sd, &s) == NTWG_E_BOUNDS);
    sd.pitch_bytes = 12;
    sd.height = 0;
    CHECK(ntwg_surface_create(ctx, &sd, &s) == NTWG_E_INVALID);
    sd.height = UINT32_MAX;
    sd.pitch_bytes = UINT32_MAX;
    CHECK(ntwg_surface_create(ctx, &sd, &s) ==
          (SIZE_MAX == UINT32_MAX ? NTWG_E_BOUNDS : NTWG_E_NOMEM));
    CHECK(ntwg_surface_retain(ctx, 0) == NTWG_E_HANDLE);
    CHECK(ntwg_surface_release(ctx, UINT64_MAX) == NTWG_E_HANDLE);
    CHECK(ntwg_surface_map(ctx, UINT64_MAX, &mapping) == NTWG_E_HANDLE);
    CHECK(mapping.pixels == NULL && mapping.byte_length == 0);
    CHECK(ntwg_surface_map(ctx, 0, NULL) == NTWG_E_INVALID);
    CHECK(ntwg_surface_unmap(ctx, UINT64_C(1)) == NTWG_E_HANDLE);
    CHECK(ntwg_fill(ctx, 0, &rect, 0, &fence) == NTWG_E_HANDLE);
    CHECK(fence.owner == 0 && fence.epoch == 0 && fence.sequence == 0);
    CHECK(ntwg_blit(ctx, 0, &rect, 0, 0, 0, &fence) == NTWG_E_HANDLE);
    CHECK(ntwg_present(ctx, 0, &rect, 0, 0, &fence) == NTWG_E_HANDLE);
    CHECK(ntwg_fence_query(ctx, &fence, &completed) == NTWG_E_HANDLE && completed == 0);
    CHECK(ntwg_fence_query(ctx, NULL, &completed) == NTWG_E_INVALID);
    CHECK(ntwg_fence_query(NULL, &fence, &completed) == NTWG_E_INVALID);
    CHECK(ntwg_fence_query(ctx, &fence, NULL) == NTWG_E_INVALID);
    CHECK(ntwg_destroy(ctx) == NTWG_OK && state.live == 0);
}

static void lifetime_and_limits(void)
{
    allocator_state state;
    ntwg_context *ctx = create(&state);
    ntwg_surface s = surface(ctx, 3, 2, 16, NTWG_PIXEL_ARGB8888), replacement;
    ntwg_surface handles[NTWG_MAX_SURFACES];
    ntwg_surface_desc sd = { sizeof(sd), NTWG_ABI_VERSION, 1, 1, 0,
                            NTWG_PIXEL_XRGB8888 };
    ntwg_mapping map, second;
    ntwg_rect r = { 0, 0, 3, 2 };
    ntwg_fence fence;
    uint8_t fb[32];
    ntwg_framebuffer_desc fd = framebuffer(fb, sizeof(fb), 3, 2, 16,
                                           NTWG_PIXEL_ARGB8888);
    size_t i;
    CHECK(ntwg_bind_framebuffer(ctx, &fd) == NTWG_OK);
    CHECK(ntwg_surface_map(ctx, s, &map) == NTWG_OK);
    CHECK(map.width == 3 && map.height == 2 && map.pitch_bytes == 16);
    CHECK(map.format == NTWG_PIXEL_ARGB8888 && map.byte_length == 32);
    for (i = 0; i < map.byte_length; ++i) CHECK(((uint8_t *)map.pixels)[i] == 0);
    CHECK(ntwg_surface_map(ctx, s, &second) == NTWG_E_BUSY && second.pixels == NULL);
    CHECK(ntwg_fill(ctx, s, &r, 0, &fence) == NTWG_E_BUSY);
    CHECK(ntwg_blit(ctx, s, &r, s, 0, 0, &fence) == NTWG_E_BUSY);
    CHECK(ntwg_present(ctx, s, &r, 0, 0, &fence) == NTWG_E_BUSY);
    CHECK(ntwg_surface_retain(ctx, s) == NTWG_OK);
    CHECK(ntwg_surface_release(ctx, s) == NTWG_OK);
    CHECK(ntwg_surface_release(ctx, s) == NTWG_E_BUSY);
    CHECK(ntwg_destroy(ctx) == NTWG_E_BUSY && state.live == 2);
    fd.pixels = map.pixels;
    CHECK(ntwg_bind_framebuffer(ctx, &fd) == NTWG_E_INVALID);
    fd.pixels = ctx;
    CHECK(ntwg_bind_framebuffer(ctx, &fd) == NTWG_E_INVALID);
    CHECK(ntwg_surface_unmap(ctx, s) == NTWG_OK);
    CHECK(ntwg_surface_unmap(ctx, s) == NTWG_E_INVALID);
    CHECK(ntwg_fill(ctx, s, &r, UINT32_C(0x12345678), &fence) == NTWG_OK);
    CHECK(ntwg_surface_release(ctx, s) == NTWG_OK && state.live == 1);
    check_fence(ctx, &fence); /* Completed CPU work survives surface release. */
    CHECK(ntwg_surface_release(ctx, s) == NTWG_E_HANDLE);
    replacement = surface(ctx, 1, 1, 0, NTWG_PIXEL_XRGB8888);
    CHECK(s != replacement);
    CHECK(ntwg_surface_retain(ctx, s) == NTWG_E_HANDLE);
    CHECK(ntwg_surface_release(ctx, replacement) == NTWG_OK);
    for (i = 0; i < NTWG_MAX_SURFACES; ++i)
        handles[i] = surface(ctx, 1, 1, 0, NTWG_PIXEL_XRGB8888);
    CHECK(ntwg_surface_create(ctx, &sd, &replacement) == NTWG_E_EXHAUSTED);
    CHECK(replacement == 0);
    CHECK(ntwg_surface_release(ctx, handles[17]) == NTWG_OK);
    replacement = surface(ctx, 1, 1, 0, NTWG_PIXEL_XRGB8888);
    CHECK(replacement != handles[17]);
    CHECK(ntwg_surface_release(ctx, handles[17]) == NTWG_E_HANDLE);
    CHECK(ntwg_destroy(ctx) == NTWG_OK && state.live == 0);
}

static void framebuffer_validation(void)
{
    allocator_state state, other_state;
    ntwg_context *ctx = create(&state), *other = create(&other_state);
    ntwg_surface s = surface(ctx, 3, 2, 0, NTWG_PIXEL_XRGB8888);
    uint8_t pixels[64], expected[64];
    ntwg_framebuffer_desc good = framebuffer(pixels + 5, 32, 3, 2, 16,
                                             NTWG_PIXEL_XRGB8888), bad;
    ntwg_rect r = { 0, 0, 3, 2 }, invalid;
    ntwg_fence before, after, fake;
    uint32_t completed;
    memset(pixels, 0xb3, sizeof(pixels));
    memcpy(expected, pixels, sizeof(pixels));
    CHECK(ntwg_fill(ctx, s, &r, UINT32_C(0x99887766), &before) == NTWG_OK);
    CHECK(ntwg_present(ctx, s, &r, 0, 0, &after) == NTWG_E_UNBOUND);
    CHECK(after.sequence == 0);
    CHECK(ntwg_bind_framebuffer(ctx, &good) == NTWG_OK);
    CHECK(ntwg_fence_query(ctx, &before, &completed) == NTWG_E_HANDLE);
    CHECK(ntwg_fill(ctx, s, &r, UINT32_C(0x99887766), &before) == NTWG_OK);
#define BAD_BIND(member, value, expected_status) do { \
    bad = good; bad.member = (value); \
    CHECK(ntwg_bind_framebuffer(ctx, &bad) == (expected_status)); \
    check_fence(ctx, &before); \
    CHECK(memcmp(pixels, expected, sizeof(pixels)) == 0); \
} while (0)
    BAD_BIND(struct_size, 0, NTWG_E_INVALID);
    BAD_BIND(abi_version, 9, NTWG_E_VERSION);
    BAD_BIND(format, 999, NTWG_E_UNSUPPORTED);
    BAD_BIND(width, 0, NTWG_E_INVALID);
    BAD_BIND(height, 0, NTWG_E_INVALID);
    BAD_BIND(width, UINT32_MAX, NTWG_E_BOUNDS);
    BAD_BIND(pitch_bytes, 11, NTWG_E_BOUNDS);
    BAD_BIND(pitch_bytes, 0, NTWG_E_BOUNDS);
    BAD_BIND(byte_length, 31, NTWG_E_BOUNDS);
    BAD_BIND(byte_length, SIZE_MAX, NTWG_E_BOUNDS);
    BAD_BIND(pixels, NULL, NTWG_E_BOUNDS);
    BAD_BIND(pixels, (void *)(uintptr_t)(UINTPTR_MAX - 8), NTWG_E_BOUNDS);
#undef BAD_BIND
    bad = good;
    bad.height = UINT32_MAX;
    bad.pitch_bytes = UINT32_MAX;
    CHECK(ntwg_bind_framebuffer(ctx, &bad) == NTWG_E_BOUNDS);
    invalid = r;
    invalid.x = UINT32_MAX;
    CHECK(ntwg_fill(ctx, s, &invalid, 0, &after) == NTWG_E_BOUNDS);
    CHECK(ntwg_blit(ctx, s, &invalid, s, 0, 0, &after) == NTWG_E_BOUNDS);
    CHECK(ntwg_present(ctx, s, &invalid, 0, 0, &after) == NTWG_E_BOUNDS);
    CHECK(ntwg_present(ctx, s, &r, UINT32_MAX, 0, &after) == NTWG_E_BOUNDS);
    CHECK(ntwg_present(ctx, s, &r, 0, UINT32_MAX, &after) == NTWG_E_BOUNDS);
    CHECK(ntwg_blit(ctx, s, &r, s, 1, 0, &after) == NTWG_E_BOUNDS);
    invalid = r;
    invalid.width = 0;
    CHECK(ntwg_fill(ctx, s, &invalid, 0, &after) == NTWG_E_INVALID);
    CHECK(ntwg_present(ctx, s, NULL, 0, 0, &after) == NTWG_E_INVALID);
    CHECK(ntwg_fill(ctx, s, NULL, 0, &after) == NTWG_E_INVALID);
    CHECK(ntwg_blit(ctx, s, NULL, s, 0, 0, &after) == NTWG_E_INVALID);
    CHECK(memcmp(pixels, expected, sizeof(pixels)) == 0);
    CHECK(ntwg_present(ctx, s, &r, 0, 0, &after) == NTWG_OK);
    check_fence(ctx, &after);
    CHECK(after.sequence == before.sequence + 1);
    CHECK(ntwg_fence_query(other, &after, &completed) == NTWG_E_HANDLE && completed == 0);
    fake = after;
    fake.sequence = UINT64_MAX;
    CHECK(ntwg_fence_query(ctx, &fake, &completed) == NTWG_E_HANDLE);
    CHECK(ntwg_bind_framebuffer(ctx, &good) == NTWG_OK);
    CHECK(ntwg_fence_query(ctx, &after, &completed) == NTWG_E_HANDLE);
    CHECK(ntwg_present(ctx, s, &r, 0, 0, &after) == NTWG_OK);
    CHECK(ntwg_unbind_framebuffer(ctx) == NTWG_OK);
    CHECK(ntwg_fence_query(ctx, &after, &completed) == NTWG_E_HANDLE);
    CHECK(ntwg_present(ctx, s, &r, 0, 0, &after) == NTWG_E_UNBOUND);
    CHECK(after.sequence == 0);
    CHECK(ntwg_destroy(ctx) == NTWG_OK && state.live == 0);
    CHECK(ntwg_destroy(other) == NTWG_OK && other_state.live == 0);
}

static void format_conversions(void)
{
    static const uint32_t colors[6] = {
        UINT32_C(0x00112233), UINT32_C(0x44556677), UINT32_C(0x8899aabb),
        UINT32_C(0xccddeeff), UINT32_C(0xff123456), UINT32_C(0x783421fe)
    };
    allocator_state state;
    ntwg_context *ctx = create(&state);
    uint32_t sf, df, x, y;
    for (sf = NTWG_PIXEL_XRGB8888; sf <= NTWG_PIXEL_XBGR8888; ++sf) {
        uint32_t sbpp = sf == NTWG_PIXEL_BGR888 ? 3u : 4u;
        ntwg_surface src = surface(ctx, 3, 2, 3 * sbpp + 5, sf);
        ntwg_mapping map;
        ntwg_rect sr = { 1, 0, 2, 2 };
        CHECK(ntwg_surface_map(ctx, src, &map) == NTWG_OK);
        memset(map.pixels, 0xcc, map.byte_length);
        for (y = 0; y < 2; ++y)
            for (x = 0; x < 3; ++x)
                reference_pixel((uint8_t *)map.pixels + y * map.pitch_bytes + x * sbpp,
                                 sf, colors[y * 3 + x]);
        CHECK(ntwg_surface_unmap(ctx, src) == NTWG_OK);
        for (df = NTWG_PIXEL_XRGB8888; df <= NTWG_PIXEL_XBGR8888; ++df) {
            uint32_t dbpp = df == NTWG_PIXEL_BGR888 ? 3u : 4u;
            uint32_t pitch = 4 * dbpp + 5;
            ntwg_surface dst = surface(ctx, 4, 4, pitch, df);
            uint8_t expected[128], pixels[128];
            ntwg_framebuffer_desc fd = framebuffer(pixels + 7, 4 * pitch, 4, 4, pitch, df);
            ntwg_fence fence;
            ntwg_rect fill_rect = { 3, 3, 1, 1 };
            memset(pixels, 0xa5, sizeof(pixels));
            memset(expected, 0xa5, sizeof(expected));
            CHECK(ntwg_surface_map(ctx, dst, &map) == NTWG_OK);
            memset(map.pixels, 0xa5, map.byte_length);
            CHECK(ntwg_surface_unmap(ctx, dst) == NTWG_OK);
            for (y = 0; y < 2; ++y)
                for (x = 0; x < 2; ++x) {
                    uint32_t color = colors[y * 3 + x + 1];
                    if (sf != NTWG_PIXEL_ARGB8888) color |= UINT32_C(0xff000000);
                    reference_pixel(expected + 7 + (y + 1) * pitch + x * dbpp, df, color);
                }
            CHECK(ntwg_blit(ctx, src, &sr, dst, 0, 1, &fence) == NTWG_OK);
            check_fence(ctx, &fence);
            CHECK(ntwg_surface_map(ctx, dst, &map) == NTWG_OK);
            CHECK(memcmp(map.pixels, expected + 7, map.byte_length) == 0);
            CHECK(ntwg_surface_unmap(ctx, dst) == NTWG_OK);
            CHECK(ntwg_bind_framebuffer(ctx, &fd) == NTWG_OK);
            CHECK(ntwg_present(ctx, src, &sr, 0, 1, &fence) == NTWG_OK);
            check_fence(ctx, &fence);
            CHECK(memcmp(pixels, expected, sizeof(pixels)) == 0);
            CHECK(ntwg_fill(ctx, dst, &fill_rect, UINT32_C(0x7e123456), &fence) == NTWG_OK);
            reference_pixel(expected + 7 + 3 * pitch + 3 * dbpp, df, UINT32_C(0x7e123456));
            CHECK(ntwg_surface_map(ctx, dst, &map) == NTWG_OK);
            CHECK(memcmp(map.pixels, expected + 7, map.byte_length) == 0);
            CHECK(ntwg_surface_unmap(ctx, dst) == NTWG_OK);
            CHECK(ntwg_surface_release(ctx, dst) == NTWG_OK);
            CHECK(ntwg_unbind_framebuffer(ctx) == NTWG_OK);
        }
        CHECK(ntwg_surface_release(ctx, src) == NTWG_OK);
    }
    CHECK(ntwg_destroy(ctx) == NTWG_OK && state.live == 0);
}

static void exhaustive_self_blits(void)
{
    allocator_state state;
    ntwg_context *ctx = create(&state);
    uint32_t format;
    for (format = NTWG_PIXEL_XRGB8888; format <= NTWG_PIXEL_XBGR8888; ++format) {
        const uint32_t width = 7, height = 6;
        uint32_t bpp = format == NTWG_PIXEL_BGR888 ? 3u : 4u;
        uint32_t pitch = width * bpp + 3;
        uint8_t initial[192], expected[192];
        ntwg_surface s = surface(ctx, width, height, pitch, format);
        ntwg_mapping map;
        uint32_t w, h, sx, sy, dx, dy, x, y;
        memset(initial, 0x6c, sizeof(initial));
        for (y = 0; y < height; ++y)
            for (x = 0; x < width; ++x)
                reference_pixel(initial + y * pitch + x * bpp, format,
                                 UINT32_C(0x32100000) + y * 256 + x);
        for (w = 1; w <= width; ++w)
        for (h = 1; h <= height; ++h)
        for (sx = 0; sx <= width - w; ++sx)
        for (sy = 0; sy <= height - h; ++sy)
        for (dx = 0; dx <= width - w; ++dx)
        for (dy = 0; dy <= height - h; ++dy) {
            ntwg_rect rect = { sx, sy, w, h };
            memcpy(expected, initial, sizeof(expected));
            for (y = 0; y < h; ++y)
                memcpy(expected + (dy + y) * pitch + dx * bpp,
                        initial + (sy + y) * pitch + sx * bpp, w * bpp);
            CHECK(ntwg_surface_map(ctx, s, &map) == NTWG_OK);
            memcpy(map.pixels, initial, map.byte_length);
            CHECK(ntwg_surface_unmap(ctx, s) == NTWG_OK);
            CHECK(ntwg_blit(ctx, s, &rect, s, dx, dy, NULL) == NTWG_OK);
            CHECK(ntwg_surface_map(ctx, s, &map) == NTWG_OK);
            CHECK(memcmp(map.pixels, expected, map.byte_length) == 0);
            CHECK(ntwg_surface_unmap(ctx, s) == NTWG_OK);
            ++overlap_cases;
        }
        CHECK(ntwg_surface_release(ctx, s) == NTWG_OK);
    }
    CHECK(ntwg_destroy(ctx) == NTWG_OK && state.live == 0);
}

typedef struct flush_state {
    ntwg_context *ctx;
    ntwg_fence *out_fence;
    const uint8_t *pixels;
    int fail;
    unsigned calls;
} flush_state;

static int flush(void *user)
{
    flush_state *state = (flush_state *)user;
    /* The writes precede the platform completion hook; no fence is issued yet. */
    CHECK(state->pixels[0] == 0x33 && state->pixels[1] == 0x22);
    CHECK(state->pixels[2] == 0x11 && state->pixels[3] == 0xff);
    CHECK(state->out_fence->sequence == 0);
    ++state->calls;
    return state->fail;
}

static void completion_failure(void)
{
    allocator_state state;
    ntwg_context *ctx = create(&state);
    ntwg_surface s = surface(ctx, 1, 1, 0, NTWG_PIXEL_XRGB8888);
    uint8_t pixels[4] = { 0 };
    ntwg_framebuffer_desc fd = framebuffer(pixels, sizeof(pixels), 1, 1, 4,
                                           NTWG_PIXEL_XRGB8888);
    ntwg_fence failed, success, previous;
    ntwg_rect rect = { 0, 0, 1, 1 };
    flush_state fs = { ctx, &failed, pixels, 1, 0 };
    uint32_t completed;
    fd.flush = flush;
    fd.flush_user = &fs;
    CHECK(ntwg_bind_framebuffer(ctx, &fd) == NTWG_OK);
    CHECK(ntwg_fill(ctx, s, &rect, UINT32_C(0xaa112233), &previous) == NTWG_OK);
    CHECK(ntwg_present(ctx, s, &rect, 0, 0, &failed) == NTWG_E_FLUSH);
    CHECK(fs.calls == 1 && failed.sequence == 0);
    CHECK(ntwg_fence_query(ctx, &failed, &completed) == NTWG_E_HANDLE && completed == 0);
    check_fence(ctx, &previous);
    fs.fail = 0;
    fs.out_fence = &success;
    CHECK(ntwg_present(ctx, s, &rect, 0, 0, &success) == NTWG_OK);
    CHECK(fs.calls == 2 && success.sequence == previous.sequence + 1);
    check_fence(ctx, &success);
    CHECK(ntwg_destroy(ctx) == NTWG_OK && state.live == 0);
}

int main(void)
{
    invalid_arguments();
    lifetime_and_limits();
    framebuffer_validation();
    format_conversions();
    exhaustive_self_blits();
    completion_failure();
    printf("NTWDDMWrapper9x: %lu checks passed; %lu exhaustive self-blit cases; host only.\n",
            checks, overlap_cases);
    return 0;
}
