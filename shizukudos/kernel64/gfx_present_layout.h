/* SPDX-License-Identifier: GPL-2.0-only
 * Checked geometry for the private, top-down 32-bpp NtGdiPresent ABI.
 * An empty clipped rectangle reads no user memory. Nonempty presentations
 * must describe a real surface and a caller-range source, never a kernel
 * pointer. This helper is also compiled by the independent host tests.
 */
#ifndef SHZ_GFX_PRESENT_LAYOUT_H
#define SHZ_GFX_PRESENT_LAYOUT_H
#include "../win64/include/shzgfx.h"

enum {
    SHZ_PRESENT_OK = 0, SHZ_PRESENT_EMPTY, SHZ_PRESENT_BAD_LAYOUT,
    SHZ_PRESENT_BAD_ADDRESS
};
typedef struct {
    shz_rect_t rect;
    uint64_t source_offset, row_bytes, packed_bytes;
} shz_present_layout_t;

static int shz_present_layout(const shz_present_t *p, int32_t width,
                              int32_t height, uint64_t limit,
                              uint64_t user_min, uint64_t user_top,
                              shz_present_layout_t *out)
{
    int64_t right, bottom, left, top;
    uint64_t row_bytes, extent, end;
    if (width < 0 || height < 0 || p->surf_w != width ||
        p->surf_h != height || p->w < 0 || p->h < 0)
        return SHZ_PRESENT_BAD_LAYOUT;
    /* Widen before addition: untrusted INT_MAX coordinates cannot wrap. */
    right = (int64_t)p->x + p->w; bottom = (int64_t)p->y + p->h;
    left = p->x; top = p->y;
    if (left < 0) left = 0;
    if (top < 0) top = 0;
    if (right > width) right = width;
    if (bottom > height) bottom = height;
    if (left >= right || top >= bottom) return SHZ_PRESENT_EMPTY;
    row_bytes = (uint64_t)(uint32_t)width * 4u;
    if (row_bytes > p->stride || row_bytes * (uint32_t)height > limit)
        return SHZ_PRESENT_BAD_LAYOUT;
    out->rect.left = (int32_t)left; out->rect.top = (int32_t)top;
    out->rect.right = (int32_t)right; out->rect.bottom = (int32_t)bottom;
    out->row_bytes = (uint64_t)(right - left) * 4u;
    out->packed_bytes = out->row_bytes * (uint64_t)(bottom - top);
    out->source_offset = (uint64_t)top * p->stride + (uint64_t)left * 4u;
    /* Only rows in the clipped rectangle are accessed. A very large stride
     * remains legal if those rows are actually mapped in the caller. With
     * positive int32 dimensions and uint32 stride these products fit u64. */
    end = (uint64_t)(bottom - 1) * p->stride + (uint64_t)right * 4u;
    extent = end - out->source_offset;
    if (user_min >= user_top || p->bits < user_min || p->bits >= user_top ||
        out->source_offset > user_top - p->bits ||
        extent > user_top - p->bits - out->source_offset)
        return SHZ_PRESENT_BAD_ADDRESS;
    return SHZ_PRESENT_OK;
}
#endif
