/* SPDX-License-Identifier: GPL-2.0-only
 * Original bridge from the validated GOP snapshot to NTWDDMWrapper9x.
 * All memory is supplied by the loader before ExitBootServices.
 */
#include "display.h"
#include "ntwddm.h"

typedef struct { uint8_t *base; size_t size, used; } SD_ARENA;

static void *arena_allocate(void *user, size_t bytes)
{
    SD_ARENA *a = (SD_ARENA *)user;
    size_t aligned;
    if (a->used > SIZE_MAX - 15) return 0;
    aligned = (a->used + 15) & ~(size_t)15;
    if (aligned > a->size || bytes > a->size - aligned) return 0;
    a->used = aligned + bytes;
    return a->base + aligned;
}

static void arena_deallocate(void *user, void *memory, size_t bytes)
{
    /* A single bounded bring-up transaction; loader owns the entire arena. */
    (void)user; (void)memory; (void)bytes;
}

int sd_ntwddm_demo(const SD_FRAMEBUFFER *f, void *memory, size_t bytes)
{
    SD_ARENA arena = {(uint8_t *)memory, bytes, 0};
    ntwg_create_desc create = {sizeof(create), NTWG_ABI_VERSION,
                              arena_allocate, arena_deallocate, &arena};
    ntwg_framebuffer_desc target = {0};
    ntwg_surface_desc description = {sizeof(description), NTWG_ABI_VERSION,
                                    64, 64, 0, NTWG_PIXEL_XRGB8888};
    ntwg_rect tile = {0, 0, 64, 64};
    ntwg_context *context = 0;
    ntwg_surface surface = 0;
    ntwg_fence fence;
    uint32_t complete = 0;
    int result = 0;
    if (!f || !memory || ((uintptr_t)memory & 15) || f->pixel_format > 1 ||
        f->pitch_pixels > UINT32_MAX / 4 || f->width < 256 || f->height < 96)
        return 0;
    target.struct_size = sizeof(target);
    target.abi_version = NTWG_ABI_VERSION;
    target.pixels = (volatile void *)(uintptr_t)f->base;
    target.byte_length = f->size;
    target.width = f->width;
    target.height = f->height;
    target.pitch_bytes = f->pitch_pixels * 4;
    target.format = f->pixel_format ? NTWG_PIXEL_XRGB8888 : NTWG_PIXEL_XBGR8888;
    if (ntwg_create(&create, &context) != NTWG_OK) return 0;
    if (ntwg_bind_framebuffer(context, &target) != NTWG_OK) goto done;
    if (ntwg_surface_create(context, &description, &surface) != NTWG_OK) goto done;
    if (ntwg_fill(context, surface, &tile, UINT32_C(0xffffb020), 0) != NTWG_OK) goto done;
    if (ntwg_present(context, surface, &tile, 192, 32, &fence) != NTWG_OK) goto done;
    if (ntwg_fence_query(context, &fence, &complete) != NTWG_OK || !complete) goto done;
    result = 1;
done:
    if (surface) ntwg_surface_release(context, surface);
    ntwg_destroy(context);
    return result;
}
