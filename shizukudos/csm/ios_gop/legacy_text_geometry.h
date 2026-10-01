/* SPDX-License-Identifier: LGPL-3.0-only
 * Bounded logical BIOS mode-03 geometry over an existing linear framebuffer.
 * This header has no firmware, port-I/O, allocation, or mode-setting calls.
 * Its integer types match SeaBIOS u32/u16 without importing platform headers.
 */
#ifndef SHZ_LEGACY_TEXT_GEOMETRY_H
#define SHZ_LEGACY_TEXT_GEOMETRY_H

#define SHZ_LEGACY_TEXT_WIDTH 640U
#define SHZ_LEGACY_TEXT_HEIGHT 400U
#define SHZ_LEGACY_TEXT_COLUMNS 80U
#define SHZ_LEGACY_TEXT_ROWS 25U
#define SHZ_LEGACY_TEXT_CWIDTH 8U
#define SHZ_LEGACY_TEXT_CHEIGHT 16U
#define SHZ_LEGACY_TEXT_PAGE_BYTES 4096U
#define SHZ_LEGACY_TEXT_CB_TAG 0x53485a47U

struct shz_legacy_text_geometry {
    unsigned int viewport_width;
    unsigned int viewport_height;
    unsigned int physical_pitch;
    unsigned short columns;
    unsigned short rows;
    unsigned short character_width;
    unsigned short character_height;
    unsigned short page_bytes;
};

/* Call only after validating the firmware's framebuffer aperture and format.
 * Rejection leaves the caller's output untouched. The viewport never changes
 * the physical pitch, framebuffer address, or native VBE geometry.
 */
static inline int
shz_make_legacy_text_geometry(unsigned int width, unsigned int height,
                              unsigned int pitch, unsigned int depth,
                              struct shz_legacy_text_geometry *out)
{
    unsigned int bytes_per_pixel;
    if (!out || width < SHZ_LEGACY_TEXT_WIDTH || height < SHZ_LEGACY_TEXT_HEIGHT
        || width > 65535U || height > 65535U)
        return 0;
    if (depth != 15U && depth != 16U && depth != 24U && depth != 32U)
        return 0;
    bytes_per_pixel = (depth + 7U) / 8U;
    /* SeaVGABIOS gfx_op uses signed 32-bit scanline arithmetic. */
    if (pitch < width * bytes_per_pixel || pitch % bytes_per_pixel
        || pitch > 0x7fffffffU / height)
        return 0;

    out->viewport_width = SHZ_LEGACY_TEXT_WIDTH;
    out->viewport_height = SHZ_LEGACY_TEXT_HEIGHT;
    out->physical_pitch = pitch;
    out->columns = SHZ_LEGACY_TEXT_COLUMNS;
    out->rows = SHZ_LEGACY_TEXT_ROWS;
    out->character_width = SHZ_LEGACY_TEXT_CWIDTH;
    out->character_height = SHZ_LEGACY_TEXT_CHEIGHT;
    out->page_bytes = SHZ_LEGACY_TEXT_PAGE_BYTES;
    return 1;
}

/* Implemented by the optional SeaVGABIOS integration patch. */
struct vgamode_s;
int shz_cbvga_is_legacy_text_mode(struct vgamode_s *mode);

#endif
