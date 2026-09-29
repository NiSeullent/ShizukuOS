/* SPDX-License-Identifier: GPL-2.0-only
 * Host proof that a themed primary is presented through the software
 * device/context path and through the app-owned DIB adapter.
 */
#include "sample_window.h"
#include "ntwd_present.h"
#include "../win98/adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

typedef struct heap {
    uint32_t calls;
    int fail;
} heap;

static void *allocate(void *user, size_t bytes)
{
    heap *state = (heap *)user;
    state->calls++;
    if (state->fail) return NULL;
    return calloc(1, bytes);
}

static void deallocate(void *user, void *memory, size_t bytes)
{
    (void)user;
    (void)bytes;
    free(memory);
}

typedef struct dib_user {
    heap heap;
    int paints;
} dib_user;

static int dib_create(void *user, uint32_t width, uint32_t height, ntwg98_dib *dib)
{
    (void)user;
    dib->pitch = width * 4u;
    dib->bytes = (size_t)dib->pitch * height;
    dib->pixels = calloc(1, dib->bytes);
    dib->handle = dib->pixels;
    return dib->pixels != NULL;
}

static int dib_release(void *user, ntwg98_dib *dib)
{
    (void)user;
    free(dib->pixels);
    dib->pixels = NULL;
    dib->handle = NULL;
    return 1;
}

static int dib_sync(void *user)
{
    (void)user;
    return 1;
}

static int dib_paint(void *user, const ntwg98_dib *dib, uint32_t width, uint32_t height)
{
    dib_user *state = (dib_user *)user;
    (void)dib;
    (void)width;
    (void)height;
    state->paints++;
    return 1;
}

static void save(const char *name, const uint8_t *pixels, uint32_t width,
                 uint32_t height, uint32_t pitch, uint32_t scale)
{
    char path[512];
    CHECK(snprintf(path, sizeof(path), "%s/%s", NTTH_EVIDENCE_DIR, name) > 0);
    CHECK(evidence_write_xrgb(path, pixels, width, height, pitch, scale) == 0);
}

static void bind_desc(ntwd_device_desc *desc, heap *state, uint8_t *fb,
                      uint32_t width, uint32_t height)
{
    memset(desc, 0, sizeof(*desc));
    desc->struct_size = sizeof(*desc);
    desc->abi_version = NTWD_ABI_VERSION;
    desc->allocate = allocate;
    desc->deallocate = deallocate;
    desc->allocator_user = state;
    desc->framebuffer.struct_size = sizeof(desc->framebuffer);
    desc->framebuffer.abi_version = NTWG_ABI_VERSION;
    desc->framebuffer.pixels = fb;
    desc->framebuffer.byte_length = (size_t)width * 4u * height;
    desc->framebuffer.width = width;
    desc->framebuffer.height = height;
    desc->framebuffer.pitch_bytes = width * 4u;
    desc->framebuffer.format = NTWG_PIXEL_XRGB8888;
}

int main(void)
{
    const uint32_t fb_w = 200;
    const uint32_t fb_h = 140;
    uint8_t *framebuffer;
    uint8_t saved;
    heap state;
    ntwd_device_desc desc;
    ntwd_device *device = NULL;
    ntwd_context *first = NULL;
    ntwd_context *second = NULL;
    ntwg_context *core = NULL;
    ntwg_surface primary = 0;
    ntwg_mapping mapping;
    ntwg_rect source;
    ntwg_fence fence;
    uint32_t completed = 0;
    ntth_session *session;
    ntth_create_desc theme_desc;
    ntwg98_view view;
    ntwg98_ops ops;
    dib_user dib;

    memset(&state, 0, sizeof(state));
    framebuffer = (uint8_t *)malloc((size_t)fb_w * 4u * fb_h);
    CHECK(framebuffer != NULL);
    evidence_fill_xrgb(framebuffer, fb_w, fb_h, fb_w * 4u, 0xFFFF00FFu);
    saved = framebuffer[0];

    desc.struct_size = sizeof(desc);
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.abi_version = NTWD_ABI_VERSION;
    desc.create_flags = NTWD_CREATE_GPU;
    desc.allocate = allocate;
    desc.deallocate = deallocate;
    desc.allocator_user = &state;
    CHECK(ntwd_device_create(&desc, &device) == NTWG_E_UNSUPPORTED);
    CHECK(device == NULL);
    CHECK(state.calls == 0);

    bind_desc(&desc, &state, framebuffer, fb_w, fb_h);
    CHECK(ntwd_device_create(&desc, &device) == NTWG_OK);
    CHECK(ntwd_context_create(device, NTWD_NODE_GPU, &first) == NTWG_E_UNSUPPORTED);
    CHECK(first == NULL);
    CHECK(ntwd_context_create(device, NTWD_NODE_SOFTWARE, &first) == NTWG_OK);
    CHECK(ntwd_context_create(device, NTWD_NODE_SOFTWARE, &second) == NTWG_OK);
    CHECK(ntwd_primary_surface(device, &primary) == NTWG_OK);
    CHECK(ntwd_software_context(device, &core) == NTWG_OK);
    CHECK(ntwg_surface_map(core, primary, &mapping) == NTWG_OK);
    memset(&theme_desc, 0, sizeof(theme_desc));
    theme_desc.struct_size = sizeof(theme_desc);
    theme_desc.allocate = allocate;
    theme_desc.deallocate = deallocate;
    theme_desc.allocator_user = &state;
    CHECK(ntth_session_open(&theme_desc, &session) == NTTH_OK);
    CHECK(ntth_session_load(session, ntth_builtin_classic_text,
                           ntth_builtin_classic_length) == NTTH_OK);
    CHECK(sample_window_paint(session, (uint8_t *)mapping.pixels, mapping.pitch_bytes,
                             "CLASSIC", 0xFFC0C0C0u, 1) == NTTH_OK);
    CHECK(ntwg_surface_unmap(core, primary) == NTWG_OK);
    source.x = 0;
    source.y = 0;
    source.width = SAMPLE_WINDOW_W;
    source.height = SAMPLE_WINDOW_H;
    memset(&fence, 0, sizeof(fence));
    CHECK(ntwd_present(NULL, &source, 10, 8, &fence) == NTWG_E_INVALID);
    source.width = fb_w + 1u;
    CHECK(ntwd_present(first, &source, 0, 0, &fence) == NTWG_E_BOUNDS);
    CHECK(framebuffer[0] == saved);
    source.width = SAMPLE_WINDOW_W;
    CHECK(ntwd_present(first, &source, 10, 8, &fence) == NTWG_OK);
    CHECK(ntwg_fence_query(core, &fence, &completed) == NTWG_OK);
    CHECK(completed == 1);
    CHECK(evidence_read_xrgb(framebuffer, fb_w * 4u, 0, 0) == 0xFFFF00FFu);
    CHECK(evidence_read_xrgb(framebuffer, fb_w * 4u, 10, 8) == 0xFF000040u);
    CHECK(evidence_read_xrgb(framebuffer, fb_w * 4u, 70, 18) == 0xFF000080u);
    CHECK(evidence_read_xrgb(framebuffer, fb_w * 4u, 57, 65) == 0xFF000000u);
    save("present-framebuffer.ppm", framebuffer, fb_w, fb_h, fb_w * 4u, 4);
    CHECK(ntwd_present(second, &source, 10, 8, &fence) == NTWG_OK);
    CHECK(ntwd_device_destroy(device) == NTWG_E_BUSY);
    CHECK(ntwd_context_destroy(second) == NTWG_OK);
    CHECK(ntwd_present(first, &source, 10, 8, NULL) == NTWG_OK);
    CHECK(ntwd_context_destroy(first) == NTWG_OK);
    CHECK(ntwg_surface_map(core, primary, &mapping) == NTWG_OK);
    CHECK(ntwd_device_destroy(device) == NTWG_E_BUSY);
    CHECK(ntwg_surface_unmap(core, primary) == NTWG_OK);
    CHECK(ntwd_device_destroy(device) == NTWG_OK);
    CHECK(ntth_session_close(session) == NTTH_OK);

    memset(&view, 0, sizeof(view));
    memset(&ops, 0, sizeof(ops));
    memset(&dib, 0, sizeof(dib));
    ops.allocate = allocate;
    ops.deallocate = deallocate;
    ops.create = dib_create;
    ops.sync = dib_sync;
    ops.paint = dib_paint;
    ops.release = dib_release;
    CHECK(ntwg98_open(&view, &ops, &dib, SAMPLE_WINDOW_W, SAMPLE_WINDOW_H) == NTWG_OK);
    CHECK(ntth_session_open(&theme_desc, &session) == NTTH_OK);
    CHECK(ntth_session_load(session, ntth_builtin_modern_text,
                           ntth_builtin_modern_length) == NTTH_OK);
    CHECK(ntwg_surface_map(view.core, view.surface, &mapping) == NTWG_OK);
    CHECK(sample_window_paint(session, (uint8_t *)mapping.pixels, mapping.pitch_bytes,
                             "MODERN", 0xFFF0F0F0u, 1) == NTTH_OK);
    CHECK(ntwg_surface_unmap(view.core, view.surface) == NTWG_OK);
    source.width = SAMPLE_WINDOW_W;
    source.height = SAMPLE_WINDOW_H;
    CHECK(ntwg98_present(&view, &source, 0, 0, &fence) == NTWG_OK);
    CHECK(ntwg98_paint(&view) == NTWG_OK);
    CHECK(dib.paints == 1);
    CHECK(evidence_read_xrgb((uint8_t *)view.dib.pixels, view.dib.pitch, 1, 8) ==
          0xFF0078D7u);
    CHECK(evidence_read_xrgb((uint8_t *)view.dib.pixels, view.dib.pitch,
                            SAMPLE_WINDOW_W - 2u, 8) == 0xFF005A9Eu);
    save("gdi-dib-modern.ppm", (uint8_t *)view.dib.pixels, SAMPLE_WINDOW_W,
         SAMPLE_WINDOW_H, view.dib.pitch, 4);
    CHECK(ntth_session_close(session) == NTTH_OK);
    CHECK(ntwg98_close(&view) == NTWG_OK);
    free(framebuffer);
    printf("PASS present checks %lu\n", checks);
    return 0;
}
