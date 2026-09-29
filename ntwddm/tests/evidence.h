/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWDM_EVIDENCE_H
#define NTWDM_EVIDENCE_H
#include <stdint.h>
#include <stddef.h>
int evidence_write_xrgb(const char *path, const uint8_t *pixels,
                        uint32_t width, uint32_t height, uint32_t pitch,
                        uint32_t scale);
void evidence_fill_xrgb(uint8_t *pixels, uint32_t width, uint32_t height,
                        uint32_t pitch, uint32_t color);
void evidence_blit(uint8_t *dest, uint32_t dest_pitch, uint32_t dest_x,
                   uint32_t dest_y, const uint8_t *src, uint32_t src_w,
                   uint32_t src_h, uint32_t src_pitch);
uint32_t evidence_read_xrgb(const uint8_t *pixels, uint32_t pitch,
                           uint32_t x, uint32_t y);
#endif
