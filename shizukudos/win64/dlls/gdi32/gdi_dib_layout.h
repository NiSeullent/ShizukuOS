/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded arithmetic for the existing 32-bpp DIB raster backend.
 * Mapping API requires a 64KiB base; DIB pixels require only DWORD alignment.
 * Reviewed Wine11 win32u/dib.c NtGdiCreateDIBSection and ReactOS9dc3ca
 * win32ss/gdi/ntgdi/dibobj.c DIB_CreateDIBSection; no source is copied.
 */
#ifndef SHZ_GDI_DIB_LAYOUT_H
#define SHZ_GDI_DIB_LAYOUT_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    int32_t width, height;
    int topdown;
    uint32_t map_offset, delta;
    uint64_t pixel_bytes, view_bytes;
} shz_dib_layout_t;

static inline int shz_dib_layout(int32_t width, int32_t height, int section, uint32_t offset, shz_dib_layout_t *out)
{
    uint64_t rows, bytes;
    if (!out || width <= 0 || !height || height == INT32_MIN || (section && (offset & 3u))) return 0;
    rows = (uint64_t)(height < 0 ? -(int64_t)height : height);
    bytes = (uint64_t)width * rows * 4u;
    if (bytes > (256u << 20)) return 0;                       /* existing bitmap storage limit */
    out->width = width; out->height = (int32_t)rows; out->topdown = height < 0;
    out->pixel_bytes = bytes;
    out->map_offset = section ? offset & ~0xffffu : 0;
    out->delta = section ? offset & 0xffffu : 0;
    out->view_bytes = bytes + out->delta;
    return 1;
}
#endif
