/* SPDX-License-Identifier: GPL-2.0-only */
#include "evidence.h"

#include <stdio.h>
#include <string.h>

int evidence_write_xrgb(const char *path, const uint8_t *pixels,
                        uint32_t width, uint32_t height, uint32_t pitch,
                        uint32_t scale)
{
    FILE *out;
    uint32_t y, x, sy, sx;
    uint32_t out_w, out_h;
    if (path == NULL || pixels == NULL || width == 0 || height == 0 || scale == 0)
        return -1;
    if (width > UINT32_MAX / scale || height > UINT32_MAX / scale) return -1;
    out_w = width * scale;
    out_h = height * scale;
    out = fopen(path, "wb");
    if (out == NULL) return -1;
    if (fprintf(out, "P6\n%u %u\n255\n", out_w, out_h) < 0) {
        fclose(out);
        return -1;
    }
    for (y = 0; y < height; ++y) {
        const uint8_t *row = pixels + (size_t)y * pitch;
        for (sy = 0; sy < scale; ++sy) {
            for (x = 0; x < width; ++x) {
                const uint8_t *p = row + (size_t)x * 4u;
                unsigned char rgb[3];
                rgb[0] = p[2];
                rgb[1] = p[1];
                rgb[2] = p[0];
                for (sx = 0; sx < scale; ++sx) {
                    if (fwrite(rgb, 1, 3, out) != 3) {
                        fclose(out);
                        return -1;
                    }
                }
            }
        }
    }
    if (fclose(out) != 0) return -1;
    printf("EVIDENCE %s\n", path);
    return 0;
}

void evidence_fill_xrgb(uint8_t *pixels, uint32_t width, uint32_t height,
                        uint32_t pitch, uint32_t color)
{
    uint32_t y, x;
    for (y = 0; y < height; ++y) {
        uint8_t *row = pixels + (size_t)y * pitch;
        for (x = 0; x < width; ++x) {
            uint8_t *p = row + (size_t)x * 4u;
            p[0] = (uint8_t)color;
            p[1] = (uint8_t)(color >> 8);
            p[2] = (uint8_t)(color >> 16);
            p[3] = (uint8_t)(color >> 24);
        }
    }
}

void evidence_blit(uint8_t *dest, uint32_t dest_pitch, uint32_t dest_x,
                   uint32_t dest_y, const uint8_t *src, uint32_t src_w,
                   uint32_t src_h, uint32_t src_pitch)
{
    uint32_t y, x;
    for (y = 0; y < src_h; ++y) {
        const uint8_t *s = src + (size_t)y * src_pitch;
        uint8_t *d = dest + (size_t)(dest_y + y) * dest_pitch + (size_t)dest_x * 4u;
        for (x = 0; x < src_w; ++x) memcpy(d + (size_t)x * 4u, s + (size_t)x * 4u, 4);
    }
}

uint32_t evidence_read_xrgb(const uint8_t *pixels, uint32_t pitch,
                           uint32_t x, uint32_t y)
{
    const uint8_t *p = pixels + (size_t)y * pitch + (size_t)x * 4u;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
