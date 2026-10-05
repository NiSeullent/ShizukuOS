/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS shell wallpaper provider: bounded BMP (BI_RGB 24/32 bpp) file decode + GDI paint for the theme
 * [wallpaper] section (mode=image, style fill|fit|stretch|tile|center). Original ShizukuOS code.
 * Reuses theme.c for file reads (ShzThemeReadFileBounded) and capability publication. Status: source proposal,
 * no guest execution evidence. Unsupported (never faked): blur, non-BMP formats, indexed/RLE/compressed BMP.
 * Portable part (no OS headers) is host-testable; native part needs SHZ_THEME_NATIVE. */
#ifndef SHZ_WALLPAPER_H
#define SHZ_WALLPAPER_H
#include <stddef.h>
#include <stdint.h>
#include "theme.h"

#define SHZ_WP_MAX_W 1024u
#define SHZ_WP_MAX_H 768u
#define SHZ_WP_MAX_FILE (3u * 1024u * 1024u)
#define SHZ_WP_HDR_MAX (14u + 124u)            /* file header + up to BITMAPV5HEADER */

enum { SHZ_WPE_OK = 0, SHZ_WPE_NULL, SHZ_WPE_SHORT, SHZ_WPE_MAGIC, SHZ_WPE_HEADER, SHZ_WPE_FORMAT, SHZ_WPE_SIZE,
       SHZ_WPE_TRUNC, SHZ_WPE_IO, SHZ_WPE_NOT_IMAGE_MODE, SHZ_WPE_NO_PATH };

typedef struct SHZ_BMP_INFO {
    uint32_t width, height;     /* pixels */
    uint32_t bpp;               /* 24 or 32 */
    uint32_t stride;            /* source row bytes (4-aligned) */
    uint32_t data_off;          /* file offset of pixels */
    int      bottom_up;
} SHZ_BMP_INFO;

/* Validate header against the real file size. Rejects anything but BI_RGB 24/32 bpp, 1 plane, sane bounds. */
int ShzBmpParseHeader(const uint8_t *hdr, size_t hlen, uint64_t file_size, SHZ_BMP_INFO *out);
/* Convert source row (stride bytes at least width*bpp/8) to 0x00BBGGRR-in-memory B,G,R,0 32bpp. */
void ShzBmpConvertRow(const SHZ_BMP_INFO *bi, const uint8_t *src, uint8_t *dst32);

typedef struct SHZ_WP_RECT { int32_t x, y, w, h; } SHZ_WP_RECT;
/* Compute source/destination rectangles. fill=cover (center crop), fit=contain (centered), stretch, center
 * (1:1 clipped). Tile is handled by the painter. Returns 0 on bad arguments. */
int ShzWallpaperLayout(int style, int32_t sw, int32_t sh, int32_t dw, int32_t dh, SHZ_WP_RECT *src, SHZ_WP_RECT *dst);

#ifdef SHZ_THEME_NATIVE
#include <windows.h>
typedef struct SHZ_WP_STATUS {
    int      err;               /* SHZ_WPE_* of last Prepare */
    uint32_t win32;
    uint32_t generation;        /* theme generation the image belongs to (0 = none) */
    int      image_ready;       /* 1 only when pixels for exactly that generation are loaded */
    uint32_t width, height;
} SHZ_WP_STATUS;
/* Call AFTER a theme was published and BEFORE any relayout/invalidate of the desktop, in the same call that
 * consumes the new generation. Always drops the previous image first (no stale picture); for mode!=image it
 * returns SHZ_WPE_NOT_IMAGE_MODE with image_ready=0 (caller paints solid/gradient from the theme colours).
 * Publishes capability through ShzThemeSetWallpaperReady(generation) only on real decode success. */
int  ShzWallpaperPrepare(const SHZ_THEME *t, int theme_id, uint32_t generation, SHZ_WP_STATUS *st);
/* Paint into area. Returns 1 if the image was drawn, 0 if the caller must paint its fallback (no partial draw). */
int  ShzWallpaperPaint(HDC dc, const RECT *area);
const SHZ_WP_STATUS *ShzWallpaperStatus(void);
void ShzWallpaperRelease(void);
#endif
#endif
