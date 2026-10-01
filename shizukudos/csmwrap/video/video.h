/* SPDX-License-Identifier: GPL-2.0-only
 * 80x25 VGA text cell buffer painted onto a UEFI GOP framebuffer.
 *
 * Direct writes to VGA text memory at physical 0xB8000 are NOT supported.
 * There is no MMIO window and this buffer is not shadowed at B8000. Screen
 * changes go through INT 10h (see bios/int10.h). The implementation keeps
 * an ordinary 80x25 cell array (2 bytes per cell) and draws it when asked.
 *
 * csmwrap_abi.h is owned by the core agent. This module does not include it.
 * Callers copy the GOP fields they already have into csm_video_fb.
 */
#ifndef CSMWRAP_VIDEO_H
#define CSMWRAP_VIDEO_H
#include <stdint.h>

#define CSM_VIDEO_COLS 80
#define CSM_VIDEO_ROWS 25

/* Local GOP snapshot. This is not csmwrap_abi.h (the core owns that header).
 * The fields match the handoff the collector already fills:
 *   base          mapped pixels for fb_addr (physical address stays in the ABI)
 *   width/height  fb_width / fb_height
 *   pitch_bytes   fb_pitch, bytes per scanline (PixelsPerScanLine * 4)
 *   pixel_format  fb_format: 0 RGB, 1 BGR (UEFI GOP values 0 and 1)
 * Logical colors are 0x00RRGGBB and packed like uefi/boot.c sd_pixel().
 */
typedef struct csm_video_fb {
    volatile uint32_t *base;
    uint32_t width;
    uint32_t height;
    uint32_t pitch_bytes;
    uint32_t pixel_format;
} csm_video_fb;

/* Mode 3, blank page, cursor home. Safe to call more than once. */
void csm_video_reset(void);

/* AL of INT 10h AH=00h. Accepts 02h/03h and 82h/83h (bit 7 keeps the page).
 * Returns 0 when accepted, -1 when the mode is left unchanged. */
int csm_video_set_mode(uint8_t al);

void csm_video_set_cursor(uint8_t row, uint8_t col);
void csm_video_get_cursor(uint8_t *row, uint8_t *col, uint16_t *shape);

/* down = 0 is INT 10h AH=06h (scroll up); down = 1 is AH=07h.
 * lines = 0 clears the window. Coordinates outside the 80x25 page are a no-op. */
void csm_video_scroll(int down, uint8_t lines, uint8_t attr,
                      uint8_t top, uint8_t left, uint8_t bottom, uint8_t right);

uint16_t csm_video_read_cell_at_cursor(void);
/* AH=09h: writes count copies starting at the cursor, wrapping within the
 * page, without moving the cursor. Stops at the end of the page. */
void csm_video_write_char_attr(uint8_t ch, uint8_t attr, uint16_t count);
/* AH=0Eh. Text mode keeps the attribute already in the cell. */
void csm_video_teletype(uint8_t ch);

uint8_t csm_video_mode(void);
uint8_t csm_video_columns(void);
uint8_t csm_video_page(void);

/* 0 when row/col is outside the page. */
uint16_t csm_video_cell(unsigned row, unsigned col);

/* Returns 0 and keeps the description, or -1 and drops any previous binding. */
int csm_video_bind(const csm_video_fb *fb);
/* Paints the cell buffer. No-op when no framebuffer is bound. */
void csm_video_render(void);
#endif
