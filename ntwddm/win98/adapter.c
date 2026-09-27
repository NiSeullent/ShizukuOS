/* SPDX-License-Identifier: GPL-2.0-only
 * Original app-owned DIB bridge; not a Windows display driver. */
#include "adapter.h"

int ntwg98_close(ntwg98_view *v)
{
    int status;
    if (!v) return NTWG_E_INVALID;
    if (!v->ops) return NTWG_OK;
    if (v->dib.handle && !v->ops->sync(v->user)) return NTWG98_E_PLATFORM;
    if (v->core) {
        status = ntwg_destroy(v->core);
        if (status != NTWG_OK) return status;
        v->core = NULL;
        v->surface = 0;
    }
    v->image_ready = 0;
    if (v->dib.handle && !v->ops->release(v->user, &v->dib)) return NTWG98_E_PLATFORM;
    v->dib.handle = NULL; v->dib.pixels = NULL;
    v->dib.bytes = 0; v->dib.pitch = 0;
    v->ops = NULL; v->user = NULL; v->width = 0; v->height = 0;
    return NTWG_OK;
}

int ntwg98_open(ntwg98_view *v, const ntwg98_ops *ops, void *user,
                uint32_t width, uint32_t height)
{
    ntwg_create_desc create;
    ntwg_framebuffer_desc fb;
    ntwg_surface_desc surface;
    int status, cleanup;
    if (!v || !ops || !ops->allocate || !ops->deallocate || !ops->create ||
        !ops->sync || !ops->paint || !ops->release || !width || !height)
        return NTWG_E_INVALID;
    if (v->ops || v->core || v->dib.handle) return NTWG_E_BUSY;
    if (width > INT32_MAX / 4u || height > INT32_MAX ||
        (size_t)height > SIZE_MAX / ((size_t)width * 4u)) return NTWG_E_BOUNDS;
    v->ops = ops; v->user = user; v->width = width; v->height = height;
    v->surface = 0; v->image_ready = 0;
    create.struct_size = sizeof(create); create.abi_version = NTWG_ABI_VERSION;
    create.allocate = ops->allocate; create.deallocate = ops->deallocate;
    create.allocator_user = user;
    status = ntwg_create(&create, &v->core);
    if (status != NTWG_OK) goto fail;
    if (!ops->create(user, width, height, &v->dib)) { status = NTWG98_E_PLATFORM; goto fail; }
    if (!v->dib.handle) { status = NTWG98_E_PLATFORM; goto fail; }
    fb.struct_size = sizeof(fb); fb.abi_version = NTWG_ABI_VERSION;
    fb.pixels = v->dib.pixels; fb.byte_length = v->dib.bytes;
    fb.width = width; fb.height = height; fb.pitch_bytes = v->dib.pitch;
    fb.format = NTWG_PIXEL_XRGB8888; fb.flush = NULL; fb.flush_user = NULL;
    status = ntwg_bind_framebuffer(v->core, &fb);
    if (status != NTWG_OK) goto fail;
    if (!ops->sync(user)) { status = NTWG98_E_PLATFORM; goto fail; }
    {
        volatile uint8_t *pixels = v->dib.pixels;
        size_t i, bytes = (size_t)v->dib.pitch * height;
        /* A first partial present must not expose uninitialized DIB bytes. */
        for (i = 0; i < bytes; ++i) pixels[i] = 0;
    }
    surface.struct_size = sizeof(surface); surface.abi_version = NTWG_ABI_VERSION;
    surface.width = width; surface.height = height; surface.pitch_bytes = 0;
    surface.format = NTWG_PIXEL_XRGB8888;
    status = ntwg_surface_create(v->core, &surface, &v->surface);
    if (status == NTWG_OK) return status;
fail:
    cleanup = ntwg98_close(v);
    return cleanup == NTWG_OK ? status : cleanup;
}

int ntwg98_present(ntwg98_view *v, const ntwg_rect *rect, uint32_t x, uint32_t y,
                   ntwg_fence *fence)
{
    int status;
    if (fence) { fence->owner = 0; fence->epoch = 0; fence->sequence = 0; }
    if (!v || !v->ops || !v->core || !v->dib.handle) return NTWG_E_INVALID;
    /* GDI must finish using the DIB before the CPU writes its bits. */
    if (!v->ops->sync(v->user)) return NTWG98_E_PLATFORM;
    status = ntwg_present(v->core, v->surface, rect, x, y, fence);
    if (status == NTWG_OK) v->image_ready = 1;
    return status;
}

int ntwg98_paint(ntwg98_view *v)
{
    if (!v || !v->ops || !v->core || !v->image_ready) return NTWG_E_INVALID;
    return v->ops->paint(v->user, &v->dib, v->width, v->height) ? NTWG_OK : NTWG98_E_PLATFORM;
}
