/* SPDX-License-Identifier: GPL-2.0-only
 * Original NTWDDMWrapper9x software display core; see ../PROVENANCE.md.
 */
#ifndef NTWDDM_H
#define NTWDDM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NTWG_ABI_VERSION UINT32_C(0x00010000)
#define NTWG_MAX_SURFACES 64u

typedef enum ntwg_status {
    NTWG_OK = 0,
    NTWG_E_INVALID = -1,
    NTWG_E_VERSION = -2,
    NTWG_E_UNSUPPORTED = -3,
    NTWG_E_NOMEM = -4,
    NTWG_E_BOUNDS = -5,
    NTWG_E_HANDLE = -6,
    NTWG_E_BUSY = -7,
    NTWG_E_EXHAUSTED = -8,
    NTWG_E_UNBOUND = -9,
    NTWG_E_FLUSH = -10
} ntwg_status;

/* Memory byte order is explicit and independent of the CPU's endianness. */
typedef enum ntwg_pixel_format {
    NTWG_PIXEL_XRGB8888 = 1, /* B, G, R, X; stores set X to 255. */
    NTWG_PIXEL_ARGB8888 = 2, /* B, G, R, A; alpha is copied, never blended. */
    NTWG_PIXEL_BGR888 = 3,   /* B, G, R; reads supply alpha 255. */
    NTWG_PIXEL_XBGR8888 = 4  /* R, G, B, X; UEFI GOP RGB-reserved format. */
} ntwg_pixel_format;

#define NTWG_CAP_SOFTWARE_FILL     (UINT64_C(1) << 0)
#define NTWG_CAP_SOFTWARE_BLIT     (UINT64_C(1) << 1)
#define NTWG_CAP_LINEAR_PRESENT    (UINT64_C(1) << 2)
#define NTWG_CAP_FORMAT_CONVERSION (UINT64_C(1) << 3)
#define NTWG_CAP_SYNC_FENCES       (UINT64_C(1) << 4)
#define NTWG_CAP_SURFACE_MAPPING   (UINT64_C(1) << 5)
/* Reserved capability requests: these are deliberately NOT advertised. */
#define NTWG_CAP_WDDM_MINIPORT      (UINT64_C(1) << 32)
#define NTWG_CAP_D3D               (UINT64_C(1) << 33)
#define NTWG_CAP_GPU_ACCELERATION  (UINT64_C(1) << 34)

typedef struct ntwg_context ntwg_context;
typedef uint64_t ntwg_surface;

/* Return suitably aligned, disjoint writable memory, or NULL. Calls and
 * callbacks must be serialized; callbacks must not reenter this context. */
typedef void *(*ntwg_allocate_fn)(void *user, size_t bytes);
typedef void (*ntwg_deallocate_fn)(void *user, void *memory, size_t bytes);

typedef struct ntwg_create_desc {
    uint32_t struct_size;
    uint32_t abi_version;
    ntwg_allocate_fn allocate;
    ntwg_deallocate_fn deallocate;
    void *allocator_user;
} ntwg_create_desc;

/* A flush callback completes platform-specific posted CPU writes. Return 0
 * only when complete. NULL promises CPU-memory semantics only. No vblank,
 * scanout completion, GPU execution, or cache-policy change is implied. */
typedef int (*ntwg_flush_fn)(void *user);

typedef struct ntwg_framebuffer_desc {
    uint32_t struct_size;
    uint32_t abi_version;
    volatile void *pixels;
    size_t byte_length;
    uint32_t width;
    uint32_t height;
    uint32_t pitch_bytes;
    uint32_t format;
    ntwg_flush_fn flush;
    void *flush_user;
} ntwg_framebuffer_desc;

typedef struct ntwg_surface_desc {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t width;
    uint32_t height;
    uint32_t pitch_bytes; /* Zero selects tightly packed rows. */
    uint32_t format;
} ntwg_surface_desc;

typedef struct ntwg_mapping {
    void *pixels;
    size_t byte_length;
    uint32_t width;
    uint32_t height;
    uint32_t pitch_bytes;
    uint32_t format;
} ntwg_mapping;

typedef struct ntwg_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} ntwg_rect;

/* A fence belongs to one live context and binding epoch. Do not persist
 * handles or fences across context destruction or transfer across contexts. */
typedef struct ntwg_fence {
    uintptr_t owner;
    uint64_t epoch;
    uint64_t sequence;
} ntwg_fence;

uint64_t ntwg_capabilities(void);
ntwg_status ntwg_require_capabilities(uint64_t requested);
ntwg_status ntwg_create(const ntwg_create_desc *desc, ntwg_context **out);
/* Fails BUSY without side effects if any surface remains mapped. */
ntwg_status ntwg_destroy(ntwg_context *ctx);

/* Binding is transactional; failed binds preserve the old binding/fences.
 * Successful bind/unbind invalidates every previously issued fence. */
ntwg_status ntwg_bind_framebuffer(ntwg_context *ctx,
                              const ntwg_framebuffer_desc *desc);
ntwg_status ntwg_unbind_framebuffer(ntwg_context *ctx);

ntwg_status ntwg_surface_create(ntwg_context *ctx, const ntwg_surface_desc *desc,
                            ntwg_surface *out);
ntwg_status ntwg_surface_retain(ntwg_context *ctx, ntwg_surface surface);
ntwg_status ntwg_surface_release(ntwg_context *ctx, ntwg_surface surface);
/* Maps are exclusive. Rendering a mapped surface returns BUSY. The final
 * release cannot succeed until unmap; a returned pointer dies on unmap. */
ntwg_status ntwg_surface_map(ntwg_context *ctx, ntwg_surface surface,
                           ntwg_mapping *out);
ntwg_status ntwg_surface_unmap(ntwg_context *ctx, ntwg_surface surface);

/* Rectangles must be nonempty and wholly in bounds. Color is 0xAARRGGBB.
 * out_fence may be NULL; otherwise it is zeroed before validation and only
 * issued after successful work. There is no asynchronous queue. */
ntwg_status ntwg_fill(ntwg_context *ctx, ntwg_surface target,
                    const ntwg_rect *rect, uint32_t color,
                    ntwg_fence *out_fence);
ntwg_status ntwg_blit(ntwg_context *ctx, ntwg_surface source,
                    const ntwg_rect *source_rect, ntwg_surface target,
                    uint32_t target_x, uint32_t target_y,
                    ntwg_fence *out_fence);
ntwg_status ntwg_present(ntwg_context *ctx, ntwg_surface source,
                       const ntwg_rect *source_rect,
                       uint32_t target_x, uint32_t target_y,
                       ntwg_fence *out_fence);
ntwg_status ntwg_fence_query(const ntwg_context *ctx, const ntwg_fence *fence,
                           uint32_t *completed);

#ifdef __cplusplus
}
#endif
#endif
