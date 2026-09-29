/* SPDX-License-Identifier: GPL-2.0-only
 * Independently authored for Windows 98 Shizuku's Second Edition.
 */
#include "ntwddm.h"

typedef struct ntwg_storage {
    uint8_t *pixels;
    size_t byte_length;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t format;
    uint32_t generation;
    uint32_t references;
    uint32_t mapped;
} ntwg_storage;

struct ntwg_context {
    ntwg_allocate_fn allocate;
    ntwg_deallocate_fn deallocate;
    void *allocator_user;
    volatile uint8_t *framebuffer;
    size_t framebuffer_length;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t format;
    ntwg_flush_fn flush;
    void *flush_user;
    uint64_t epoch;
    uint64_t completed;
    ntwg_storage surfaces[NTWG_MAX_SURFACES];
};

static void zero_memory(void *memory, size_t bytes)
{
    uint8_t *p = (uint8_t *)memory;
    size_t i;
    for (i = 0; i < bytes; ++i) p[i] = 0;
}

static uint32_t pixel_bytes(uint32_t format)
{
    switch (format) {
    case NTWG_PIXEL_XRGB8888:
    case NTWG_PIXEL_ARGB8888:
    case NTWG_PIXEL_XBGR8888: return 4;
    case NTWG_PIXEL_BGR888: return 3;
    default: return 0;
    }
}

static ntwg_status layout(uint32_t width, uint32_t height, uint32_t pitch,
                         uint32_t format, size_t *bytes)
{
    uint32_t bpp = pixel_bytes(format);
    if (bpp == 0) return NTWG_E_UNSUPPORTED;
    if (width == 0 || height == 0) return NTWG_E_INVALID;
    if (width > UINT32_MAX / bpp || pitch < width * bpp)
        return NTWG_E_BOUNDS;
    if ((size_t)height > SIZE_MAX / (size_t)pitch) return NTWG_E_BOUNDS;
    *bytes = (size_t)height * (size_t)pitch;
    return NTWG_OK;
}

static int address_valid(const volatile void *p, size_t bytes)
{
    uintptr_t start = (uintptr_t)p;
    return p != NULL && bytes != 0 && bytes <= UINTPTR_MAX - start;
}

/* Called only after checking that both address ranges do not wrap. */
static int overlaps(const volatile void *a, size_t a_bytes,
                     const volatile void *b, size_t b_bytes)
{
    uintptr_t a_start = (uintptr_t)a;
    uintptr_t b_start = (uintptr_t)b;
    return a_start < b_start + b_bytes && b_start < a_start + a_bytes;
}

static ntwg_storage *lookup(ntwg_context *ctx, ntwg_surface handle)
{
    uint32_t slot = (uint32_t)handle;
    uint32_t generation = (uint32_t)(handle >> 32);
    ntwg_storage *surface;
    if (ctx == NULL || slot == 0 || slot > NTWG_MAX_SURFACES || generation == 0)
        return NULL;
    surface = &ctx->surfaces[slot - 1];
    if (surface->pixels == NULL || surface->generation != generation)
        return NULL;
    return surface;
}

static ntwg_status rectangle(uint32_t width, uint32_t height,
                            const ntwg_rect *rect)
{
    if (rect == NULL || rect->width == 0 || rect->height == 0)
        return NTWG_E_INVALID;
    if (rect->x > width || rect->y > height ||
        rect->width > width - rect->x || rect->height > height - rect->y)
        return NTWG_E_BOUNDS;
    return NTWG_OK;
}

static ntwg_status destination(uint32_t width, uint32_t height,
                              uint32_t x, uint32_t y,
                              const ntwg_rect *rect)
{
    if (x > width || y > height || rect->width > width - x ||
        rect->height > height - y) return NTWG_E_BOUNDS;
    return NTWG_OK;
}

static uint32_t read_pixel(const volatile uint8_t *p, uint32_t format)
{
    uint32_t alpha = format == NTWG_PIXEL_ARGB8888 ? p[3] : UINT32_C(255);
    if (format == NTWG_PIXEL_XBGR8888)
        return (alpha << 24) | ((uint32_t)p[0] << 16) |
               ((uint32_t)p[1] << 8) | (uint32_t)p[2];
    return (alpha << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static void write_pixel(volatile uint8_t *p, uint32_t format, uint32_t color)
{
    if (format == NTWG_PIXEL_XBGR8888) {
        p[0] = (uint8_t)(color >> 16);
        p[1] = (uint8_t)(color >> 8);
        p[2] = (uint8_t)color;
    } else {
        p[0] = (uint8_t)color;
        p[1] = (uint8_t)(color >> 8);
        p[2] = (uint8_t)(color >> 16);
    }
    if (format != NTWG_PIXEL_BGR888)
        p[3] = format == NTWG_PIXEL_ARGB8888 ? (uint8_t)(color >> 24) : 255;
}

static void clear_fence(ntwg_fence *fence)
{
    if (fence != NULL) {
        fence->owner = 0;
        fence->epoch = 0;
        fence->sequence = 0;
    }
}

static void complete(ntwg_context *ctx, ntwg_fence *fence)
{
    ++ctx->completed;
    if (fence != NULL) {
        fence->owner = (uintptr_t)ctx;
        fence->epoch = ctx->epoch;
        fence->sequence = ctx->completed;
    }
}

uint64_t ntwg_capabilities(void)
{
    return NTWG_CAP_SOFTWARE_FILL | NTWG_CAP_SOFTWARE_BLIT |
           NTWG_CAP_LINEAR_PRESENT | NTWG_CAP_FORMAT_CONVERSION |
           NTWG_CAP_SYNC_FENCES | NTWG_CAP_SURFACE_MAPPING;
}

ntwg_status ntwg_require_capabilities(uint64_t requested)
{
    return (requested & ~ntwg_capabilities()) == 0 ? NTWG_OK : NTWG_E_UNSUPPORTED;
}

ntwg_status ntwg_create(const ntwg_create_desc *desc, ntwg_context **out)
{
    ntwg_context *ctx;
    uint32_t i;
    if (out == NULL) return NTWG_E_INVALID;
    *out = NULL;
    if (desc == NULL || desc->struct_size < sizeof(*desc)) return NTWG_E_INVALID;
    if (desc->abi_version != NTWG_ABI_VERSION) return NTWG_E_VERSION;
    if (desc->allocate == NULL || desc->deallocate == NULL) return NTWG_E_INVALID;
    ctx = (ntwg_context *)desc->allocate(desc->allocator_user, sizeof(*ctx));
    if (ctx == NULL) return NTWG_E_NOMEM;
    zero_memory(ctx, sizeof(*ctx));
    ctx->allocate = desc->allocate;
    ctx->deallocate = desc->deallocate;
    ctx->allocator_user = desc->allocator_user;
    ctx->epoch = 1;
    for (i = 0; i < NTWG_MAX_SURFACES; ++i) ctx->surfaces[i].generation = 1;
    *out = ctx;
    return NTWG_OK;
}

ntwg_status ntwg_destroy(ntwg_context *ctx)
{
    uint32_t i;
    if (ctx == NULL) return NTWG_E_INVALID;
    for (i = 0; i < NTWG_MAX_SURFACES; ++i)
        if (ctx->surfaces[i].mapped != 0) return NTWG_E_BUSY;
    for (i = 0; i < NTWG_MAX_SURFACES; ++i)
        if (ctx->surfaces[i].pixels != NULL)
            ctx->deallocate(ctx->allocator_user, ctx->surfaces[i].pixels,
                            ctx->surfaces[i].byte_length);
    ctx->deallocate(ctx->allocator_user, ctx, sizeof(*ctx));
    return NTWG_OK;
}

ntwg_status ntwg_bind_framebuffer(ntwg_context *ctx,
                               const ntwg_framebuffer_desc *desc)
{
    size_t bytes;
    uint32_t i;
    ntwg_status status;
    if (ctx == NULL || desc == NULL || desc->struct_size < sizeof(*desc))
        return NTWG_E_INVALID;
    if (desc->abi_version != NTWG_ABI_VERSION) return NTWG_E_VERSION;
    status = layout(desc->width, desc->height, desc->pitch_bytes,
                    desc->format, &bytes);
    if (status != NTWG_OK) return status;
    if (desc->byte_length < bytes ||
        !address_valid(desc->pixels, desc->byte_length)) return NTWG_E_BOUNDS;
    if (overlaps(desc->pixels, desc->byte_length, ctx, sizeof(*ctx)))
        return NTWG_E_INVALID;
    for (i = 0; i < NTWG_MAX_SURFACES; ++i)
        if (ctx->surfaces[i].pixels != NULL &&
            overlaps(desc->pixels, desc->byte_length, ctx->surfaces[i].pixels,
                     ctx->surfaces[i].byte_length)) return NTWG_E_INVALID;
    if (ctx->epoch == UINT64_MAX) return NTWG_E_EXHAUSTED;
    ctx->framebuffer = (volatile uint8_t *)desc->pixels;
    ctx->framebuffer_length = desc->byte_length;
    ctx->width = desc->width;
    ctx->height = desc->height;
    ctx->pitch = desc->pitch_bytes;
    ctx->format = desc->format;
    ctx->flush = desc->flush;
    ctx->flush_user = desc->flush_user;
    ++ctx->epoch;
    ctx->completed = 0;
    return NTWG_OK;
}

ntwg_status ntwg_unbind_framebuffer(ntwg_context *ctx)
{
    if (ctx == NULL) return NTWG_E_INVALID;
    if (ctx->framebuffer == NULL) return NTWG_E_UNBOUND;
    if (ctx->epoch == UINT64_MAX) return NTWG_E_EXHAUSTED;
    ctx->framebuffer = NULL;
    ctx->framebuffer_length = 0;
    ctx->flush = NULL;
    ctx->flush_user = NULL;
    ++ctx->epoch;
    ctx->completed = 0;
    return NTWG_OK;
}

ntwg_status ntwg_surface_create(ntwg_context *ctx, const ntwg_surface_desc *desc,
                             ntwg_surface *out)
{
    size_t bytes;
    uint32_t pitch, bpp, slot;
    uint8_t *pixels;
    ntwg_storage *surface;
    ntwg_status status;
    if (out == NULL) return NTWG_E_INVALID;
    *out = 0;
    if (ctx == NULL || desc == NULL || desc->struct_size < sizeof(*desc))
        return NTWG_E_INVALID;
    if (desc->abi_version != NTWG_ABI_VERSION) return NTWG_E_VERSION;
    bpp = pixel_bytes(desc->format);
    if (bpp == 0) return NTWG_E_UNSUPPORTED;
    if (desc->width > UINT32_MAX / bpp) return NTWG_E_BOUNDS;
    pitch = desc->pitch_bytes == 0 ? desc->width * bpp : desc->pitch_bytes;
    status = layout(desc->width, desc->height, pitch, desc->format, &bytes);
    if (status != NTWG_OK) return status;
    for (slot = 0; slot < NTWG_MAX_SURFACES; ++slot)
        if (ctx->surfaces[slot].pixels == NULL &&
            ctx->surfaces[slot].generation != 0) break;
    if (slot == NTWG_MAX_SURFACES) return NTWG_E_EXHAUSTED;
    pixels = (uint8_t *)ctx->allocate(ctx->allocator_user, bytes);
    if (pixels == NULL) return NTWG_E_NOMEM;
    if (!address_valid(pixels, bytes) ||
        (ctx->framebuffer != NULL && overlaps(pixels, bytes, ctx->framebuffer,
                                               ctx->framebuffer_length))) {
        ctx->deallocate(ctx->allocator_user, pixels, bytes);
        return NTWG_E_INVALID;
    }
    zero_memory(pixels, bytes);
    surface = &ctx->surfaces[slot];
    surface->pixels = pixels;
    surface->byte_length = bytes;
    surface->width = desc->width;
    surface->height = desc->height;
    surface->pitch = pitch;
    surface->format = desc->format;
    surface->references = 1;
    surface->mapped = 0;
    *out = ((uint64_t)surface->generation << 32) | (uint64_t)(slot + 1);
    return NTWG_OK;
}

ntwg_status ntwg_surface_retain(ntwg_context *ctx, ntwg_surface handle)
{
    ntwg_storage *surface = lookup(ctx, handle);
    if (surface == NULL) return NTWG_E_HANDLE;
    if (surface->references == UINT32_MAX) return NTWG_E_EXHAUSTED;
    ++surface->references;
    return NTWG_OK;
}

ntwg_status ntwg_surface_release(ntwg_context *ctx, ntwg_surface handle)
{
    ntwg_storage *surface = lookup(ctx, handle);
    if (surface == NULL) return NTWG_E_HANDLE;
    if (surface->references == 1 && surface->mapped != 0) return NTWG_E_BUSY;
    --surface->references;
    if (surface->references == 0) {
        ctx->deallocate(ctx->allocator_user, surface->pixels, surface->byte_length);
        surface->pixels = NULL;
        surface->byte_length = 0;
        /* Generation zero permanently retires the slot rather than wrapping. */
        if (surface->generation == UINT32_MAX) surface->generation = 0;
        else ++surface->generation;
    }
    return NTWG_OK;
}

ntwg_status ntwg_surface_map(ntwg_context *ctx, ntwg_surface handle, ntwg_mapping *out)
{
    ntwg_storage *surface;
    if (out == NULL) return NTWG_E_INVALID;
    zero_memory(out, sizeof(*out));
    surface = lookup(ctx, handle);
    if (surface == NULL) return NTWG_E_HANDLE;
    if (surface->mapped != 0) return NTWG_E_BUSY;
    surface->mapped = 1;
    out->pixels = surface->pixels;
    out->byte_length = surface->byte_length;
    out->width = surface->width;
    out->height = surface->height;
    out->pitch_bytes = surface->pitch;
    out->format = surface->format;
    return NTWG_OK;
}

ntwg_status ntwg_surface_unmap(ntwg_context *ctx, ntwg_surface handle)
{
    ntwg_storage *surface = lookup(ctx, handle);
    if (surface == NULL) return NTWG_E_HANDLE;
    if (surface->mapped == 0) return NTWG_E_INVALID;
    surface->mapped = 0;
    return NTWG_OK;
}

ntwg_status ntwg_fill(ntwg_context *ctx, ntwg_surface target,
                    const ntwg_rect *rect, uint32_t color, ntwg_fence *out_fence)
{
    ntwg_storage *surface;
    ntwg_status status;
    uint32_t x, y, bpp;
    clear_fence(out_fence);
    surface = lookup(ctx, target);
    if (surface == NULL) return NTWG_E_HANDLE;
    if (surface->mapped != 0) return NTWG_E_BUSY;
    status = rectangle(surface->width, surface->height, rect);
    if (status != NTWG_OK) return status;
    if (ctx->completed == UINT64_MAX) return NTWG_E_EXHAUSTED;
    bpp = pixel_bytes(surface->format);
    for (y = 0; y < rect->height; ++y) {
        uint8_t *row = surface->pixels + (size_t)(rect->y + y) * surface->pitch;
        for (x = 0; x < rect->width; ++x)
            write_pixel(row + (size_t)(rect->x + x) * bpp, surface->format, color);
    }
    complete(ctx, out_fence);
    return NTWG_OK;
}

ntwg_status ntwg_blit(ntwg_context *ctx, ntwg_surface source,
                    const ntwg_rect *source_rect, ntwg_surface target,
                    uint32_t target_x, uint32_t target_y, ntwg_fence *out_fence)
{
    ntwg_storage *src, *dst;
    ntwg_status status;
    uint32_t x, y, src_bpp, dst_bpp;
    int backwards_y, backwards_x;
    clear_fence(out_fence);
    src = lookup(ctx, source);
    dst = lookup(ctx, target);
    if (src == NULL || dst == NULL) return NTWG_E_HANDLE;
    if (src->mapped != 0 || dst->mapped != 0) return NTWG_E_BUSY;
    status = rectangle(src->width, src->height, source_rect);
    if (status != NTWG_OK) return status;
    status = destination(dst->width, dst->height, target_x, target_y, source_rect);
    if (status != NTWG_OK) return status;
    if (ctx->completed == UINT64_MAX) return NTWG_E_EXHAUSTED;
    src_bpp = pixel_bytes(src->format);
    dst_bpp = pixel_bytes(dst->format);
    backwards_y = src == dst && target_y > source_rect->y;
    backwards_x = src == dst && target_x > source_rect->x;
    for (y = 0; y < source_rect->height; ++y) {
        uint32_t row = backwards_y ? source_rect->height - 1 - y : y;
        const uint8_t *s = src->pixels + (size_t)(source_rect->y + row) * src->pitch;
        uint8_t *d = dst->pixels + (size_t)(target_y + row) * dst->pitch;
        for (x = 0; x < source_rect->width; ++x) {
            uint32_t column = backwards_x ? source_rect->width - 1 - x : x;
            uint32_t color = read_pixel(s + (size_t)(source_rect->x + column) * src_bpp,
                                        src->format);
            write_pixel(d + (size_t)(target_x + column) * dst_bpp, dst->format, color);
        }
    }
    complete(ctx, out_fence);
    return NTWG_OK;
}

ntwg_status ntwg_present(ntwg_context *ctx, ntwg_surface source,
                       const ntwg_rect *source_rect, uint32_t target_x,
                       uint32_t target_y, ntwg_fence *out_fence)
{
    ntwg_storage *src;
    ntwg_status status;
    uint32_t x, y, src_bpp, dst_bpp;
    clear_fence(out_fence);
    src = lookup(ctx, source);
    if (src == NULL) return NTWG_E_HANDLE;
    if (ctx->framebuffer == NULL) return NTWG_E_UNBOUND;
    if (src->mapped != 0) return NTWG_E_BUSY;
    status = rectangle(src->width, src->height, source_rect);
    if (status != NTWG_OK) return status;
    status = destination(ctx->width, ctx->height, target_x, target_y, source_rect);
    if (status != NTWG_OK) return status;
    if (ctx->completed == UINT64_MAX) return NTWG_E_EXHAUSTED;
    src_bpp = pixel_bytes(src->format);
    dst_bpp = pixel_bytes(ctx->format);
    for (y = 0; y < source_rect->height; ++y) {
        const uint8_t *s = src->pixels + (size_t)(source_rect->y + y) * src->pitch;
        volatile uint8_t *d = ctx->framebuffer + (size_t)(target_y + y) * ctx->pitch;
        for (x = 0; x < source_rect->width; ++x) {
            uint32_t color = read_pixel(s + (size_t)(source_rect->x + x) * src_bpp,
                                        src->format);
            write_pixel(d + (size_t)(target_x + x) * dst_bpp, ctx->format, color);
        }
    }
    if (ctx->flush != NULL && ctx->flush(ctx->flush_user) != 0)
        return NTWG_E_FLUSH;
    complete(ctx, out_fence);
    return NTWG_OK;
}

ntwg_status ntwg_fence_query(const ntwg_context *ctx, const ntwg_fence *fence,
                           uint32_t *completed)
{
    if (completed == NULL) return NTWG_E_INVALID;
    *completed = 0;
    if (ctx == NULL || fence == NULL) return NTWG_E_INVALID;
    if (fence->owner != (uintptr_t)ctx || fence->epoch != ctx->epoch ||
        fence->sequence == 0 || fence->sequence > ctx->completed)
        return NTWG_E_HANDLE;
    *completed = 1;
    return NTWG_OK;
}
