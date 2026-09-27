/* SPDX-License-Identifier: GPL-2.0-only
 * Original pixel oracle: coordinate formula, independent of renderer loops. */
#include "adapter.h"

static uint32_t color_at(uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    if (x < width / 2u) return y < height / 2u ? UINT32_C(0xffff0000) : UINT32_C(0xff00ff00);
    return y < height / 2u ? UINT32_C(0xff0000ff) : UINT32_C(0xffffffff);
}

int ntwg98_selftest(ntwg98_view *v, uint32_t *checks)
{
    ntwg_rect rect;
    ntwg_fence fence, stale;
    ntwg_framebuffer_desc fb;
    uint32_t x, y, complete;
    unsigned part;
    uint8_t *bits;
    if (!checks) return NTWG_E_INVALID;
    *checks = 0;
    if (!v || !v->core || v->width < 16 || v->height < 16) return NTWG_E_INVALID;
#define VERIFY(condition) do { ++*checks; if (!(condition)) return NTWG98_E_PLATFORM; } while (0)
    VERIFY(v->ops->sync(v->user));
    bits = v->dib.pixels;
    for (y = 0; y < v->height; ++y)
        for (x = 0; x < v->dib.pitch; ++x) bits[(size_t)y * v->dib.pitch + x] = 0x5a;
    for (part = 0; part < 4; ++part) {
        rect.x = (part & 1u) ? v->width / 2u : 0;
        rect.y = (part & 2u) ? v->height / 2u : 0;
        rect.width = (part & 1u) ? v->width - rect.x : v->width / 2u;
        rect.height = (part & 2u) ? v->height - rect.y : v->height / 2u;
        VERIFY(ntwg_fill(v->core, v->surface, &rect,
                        color_at(rect.x, rect.y, v->width, v->height), NULL) == NTWG_OK);
    }
    rect.x = 0; rect.y = 0; rect.width = v->width - 1; rect.height = v->height - 1;
    VERIFY(ntwg_blit(v->core, v->surface, &rect, v->surface, 1, 1, NULL) == NTWG_OK);
    rect.x = 2; rect.y = 3; rect.width = 7; rect.height = 5;
    VERIFY(ntwg98_present(v, &rect, 4, 6, &fence) == NTWG_OK);
    VERIFY(ntwg_fence_query(v->core, &fence, &complete) == NTWG_OK && complete == 1);
    for (y = 0; y < v->height; ++y) for (x = 0; x < v->width; ++x) {
        const uint8_t *p = bits + (size_t)y * v->dib.pitch + (size_t)x * 4;
        uint32_t expected = (x >= 4 && x < 11 && y >= 6 && y < 11) ?
            color_at(x - 3, y - 4, v->width, v->height) : UINT32_C(0x5a5a5a5a);
        VERIFY(p[0] == (uint8_t)expected && p[1] == (uint8_t)(expected >> 8) &&
               p[2] == (uint8_t)(expected >> 16) && p[3] == (uint8_t)(expected >> 24));
    }
    stale = fence;
    VERIFY(ntwg_unbind_framebuffer(v->core) == NTWG_OK);
    VERIFY(ntwg_fence_query(v->core, &stale, &complete) == NTWG_E_HANDLE);
    fb.struct_size = sizeof(fb); fb.abi_version = NTWG_ABI_VERSION;
    fb.pixels = bits; fb.byte_length = v->dib.bytes; fb.width = v->width; fb.height = v->height;
    fb.pitch_bytes = v->dib.pitch; fb.format = NTWG_PIXEL_XRGB8888;
    fb.flush = NULL; fb.flush_user = NULL;
    VERIFY(ntwg_bind_framebuffer(v->core, &fb) == NTWG_OK);
    rect.x = 0; rect.y = 0; rect.width = v->width; rect.height = v->height;
    VERIFY(ntwg98_present(v, &rect, 0, 0, &fence) == NTWG_OK);
    for (y = 0; y < v->height; ++y) {
        for (x = 0; x < v->width; ++x) {
            const uint8_t *p = bits + (size_t)y * v->dib.pitch + (size_t)x * 4;
            uint32_t expected = color_at(x && y ? x - 1 : x, x && y ? y - 1 : y, v->width, v->height);
            VERIFY(p[0] == (uint8_t)expected && p[1] == (uint8_t)(expected >> 8) &&
                   p[2] == (uint8_t)(expected >> 16) && p[3] == 255);
        }
        for (x = v->width * 4u; x < v->dib.pitch; ++x)
            VERIFY(bits[(size_t)y * v->dib.pitch + x] == 0x5a);
    }
    VERIFY(ntwg_fence_query(v->core, &fence, &complete) == NTWG_OK && complete == 1);
    VERIFY(ntwg_require_capabilities(NTWG_CAP_WDDM_MINIPORT | NTWG_CAP_D3D) == NTWG_E_UNSUPPORTED);
#undef VERIFY
    return NTWG_OK;
}
