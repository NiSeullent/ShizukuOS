/* SPDX-License-Identifier: GPL-2.0-only
 * Direct writes to physical 0xB8000 are NOT supported. Do not add an MMIO
 * alias here. INT 10h updates this cell buffer; csm_video_render copies the
 * cells onto the GOP framebuffer the caller bound.
 */
#include "video/video.h"
#include "video/cp437.h"
#include <stddef.h>

#define CELL_BLANK(attr) ((uint16_t)(0x20u | ((uint16_t)(attr) << 8)))

static uint16_t cells[CSM_VIDEO_ROWS][CSM_VIDEO_COLS];
static uint8_t cur_row, cur_col, mode;
static int ready;

static csm_video_fb fb;
static int fb_bound;

/* Same 16-color VGA palette as supervisor/src/video.c, stored 0x00RRGGBB. */
static const uint32_t palette[16] = {
    0x000000, 0x0000aa, 0x00aa00, 0x00aaaa,
    0xaa0000, 0xaa00aa, 0xaa5500, 0xaaaaaa,
    0x555555, 0x5555ff, 0x55ff55, 0x55ffff,
    0xff5555, 0xff55ff, 0xffff55, 0xffffff
};

static void clear_page(uint8_t attr)
{
    unsigned r, c;
    uint16_t blank = CELL_BLANK(attr);
    for (r = 0; r < CSM_VIDEO_ROWS; ++r)
        for (c = 0; c < CSM_VIDEO_COLS; ++c)
            cells[r][c] = blank;
    cur_row = 0;
    cur_col = 0;
}

void csm_video_reset(void)
{
    mode = 3;
    clear_page(0x07);
    ready = 1;
}

static void ensure(void)
{
    if (!ready)
        csm_video_reset();
}

int csm_video_set_mode(uint8_t al)
{
    uint8_t next = (uint8_t)(al & 0x7f);
    ensure();
    if (next != 2 && next != 3)
        return -1;
    mode = next;
    if (!(al & 0x80))
        clear_page(0x07);
    return 0;
}

void csm_video_set_cursor(uint8_t row, uint8_t col)
{
    ensure();
    cur_row = row < CSM_VIDEO_ROWS ? row : (uint8_t)(CSM_VIDEO_ROWS - 1);
    cur_col = col < CSM_VIDEO_COLS ? col : (uint8_t)(CSM_VIDEO_COLS - 1);
}

void csm_video_get_cursor(uint8_t *row, uint8_t *col, uint16_t *shape)
{
    ensure();
    if (row)
        *row = cur_row;
    if (col)
        *col = cur_col;
    /* AH=01h is not implemented. AH=03h still reports a VGA underline. */
    if (shape)
        *shape = 0x0607;
}

void csm_video_scroll(int down, uint8_t lines, uint8_t attr,
                      uint8_t top, uint8_t left, uint8_t bottom, uint8_t right)
{
    unsigned span, count;
    int r;
    unsigned c;
    uint16_t blank;
    ensure();
    if (top > bottom || left > right || bottom >= CSM_VIDEO_ROWS || right >= CSM_VIDEO_COLS)
        return;
    span = (unsigned)(bottom - top) + 1u;
    count = lines == 0 || lines > span ? span : lines;
    blank = CELL_BLANK(attr);
    if (!down) {
        for (r = top; r <= (int)bottom; ++r) {
            unsigned src = (unsigned)r + count;
            for (c = left; c <= right; ++c)
                cells[r][c] = src <= bottom ? cells[src][c] : blank;
        }
    } else {
        for (r = (int)bottom; r >= (int)top; --r) {
            for (c = left; c <= right; ++c)
                cells[r][c] = (unsigned)r >= (unsigned)top + count
                    ? cells[r - (int)count][c] : blank;
        }
    }
}

uint16_t csm_video_read_cell_at_cursor(void)
{
    ensure();
    return cells[cur_row][cur_col];
}

void csm_video_write_char_attr(uint8_t ch, uint8_t attr, uint16_t count)
{
    unsigned r, c;
    ensure();
    r = cur_row;
    c = cur_col;
    while (count > 0) {
        cells[r][c] = (uint16_t)(((uint16_t)attr << 8) | ch);
        --count;
        if (++c >= CSM_VIDEO_COLS) {
            c = 0;
            if (++r >= CSM_VIDEO_ROWS)
                break;
        }
    }
}

void csm_video_teletype(uint8_t ch)
{
    ensure();
    switch (ch) {
    case 7:
        return;
    case 8:
        if (cur_col)
            --cur_col;
        break;
    case 10:
        ++cur_row;
        break;
    case 13:
        cur_col = 0;
        break;
    default:
        cells[cur_row][cur_col] =
            (uint16_t)((cells[cur_row][cur_col] & 0xff00u) | ch);
        if (++cur_col >= CSM_VIDEO_COLS) {
            cur_col = 0;
            ++cur_row;
        }
        break;
    }
    if (cur_row >= CSM_VIDEO_ROWS) {
        uint8_t fill = (uint8_t)(cells[CSM_VIDEO_ROWS - 1][0] >> 8);
        csm_video_scroll(0, 1, fill, 0, 0, CSM_VIDEO_ROWS - 1, CSM_VIDEO_COLS - 1);
        cur_row = CSM_VIDEO_ROWS - 1;
    }
}

uint8_t csm_video_mode(void)
{
    ensure();
    return mode;
}

uint8_t csm_video_columns(void)
{
    return CSM_VIDEO_COLS;
}

uint8_t csm_video_page(void)
{
    return 0;
}

uint16_t csm_video_cell(unsigned row, unsigned col)
{
    ensure();
    if (row >= CSM_VIDEO_ROWS || col >= CSM_VIDEO_COLS)
        return 0;
    return cells[row][col];
}

int csm_video_bind(const csm_video_fb *in)
{
    fb_bound = 0;
    if (!in || !in->base || !in->width || !in->height)
        return -1;
    if (((uintptr_t)in->base & 3u) || in->pixel_format > 1)
        return -1;
    if (in->width > (UINT32_MAX / 4u) || in->pitch_bytes < in->width * 4u ||
        (in->pitch_bytes & 3u))
        return -1;
    if ((size_t)(in->pitch_bytes / 4u) > SIZE_MAX / in->height)
        return -1;
    fb = *in;
    fb_bound = 1;
    return 0;
}

static uint32_t pack_rgb(uint32_t rgb)
{
    rgb &= 0x00ffffffu;
    if (fb.pixel_format == 1)
        return rgb;
    return ((rgb & 255u) << 16) | (rgb & 0xff00u) | ((rgb >> 16) & 255u);
}

static void put_pixel(uint32_t x, uint32_t y, uint32_t rgb)
{
    if (x >= fb.width || y >= fb.height)
        return;
    fb.base[(size_t)y * (fb.pitch_bytes / 4u) + x] = pack_rgb(rgb);
}

static void put_glyph(uint32_t x, uint32_t y, uint8_t ch, uint32_t fg, uint32_t bg)
{
    unsigned row, col;
    for (row = 0; row < 16; ++row) {
        uint8_t bits = csm_cp437_row(ch, row);
        for (col = 0; col < 8; ++col)
            put_pixel(x + col, y + row, ((bits >> col) & 1) ? fg : bg);
    }
}

void csm_video_render(void)
{
    unsigned r, c;
    uint32_t origin_x = 0, origin_y = 0;
    const uint32_t glyph_w = CSM_VIDEO_COLS * 8u;
    const uint32_t glyph_h = CSM_VIDEO_ROWS * 16u;
    ensure();
    if (!fb_bound)
        return;
    if (fb.width >= glyph_w)
        origin_x = (fb.width - glyph_w) / 2u;
    if (fb.height >= glyph_h)
        origin_y = (fb.height - glyph_h) / 2u;
    for (r = 0; r < CSM_VIDEO_ROWS; ++r) {
        for (c = 0; c < CSM_VIDEO_COLS; ++c) {
            uint16_t cell = cells[r][c];
            uint32_t fg = palette[(cell >> 8) & 0x0f];
            uint32_t bg = palette[(cell >> 12) & 7];
            put_glyph(origin_x + c * 8u, origin_y + r * 16u,
                      (uint8_t)cell, fg, bg);
        }
    }
    /* Underline cursor, the same two scanlines the supervisor draws. */
    if (cur_row < CSM_VIDEO_ROWS && cur_col < CSM_VIDEO_COLS) {
        unsigned col;
        uint32_t x = origin_x + cur_col * 8u;
        uint32_t y = origin_y + cur_row * 16u + 14u;
        for (col = 0; col < 8; ++col) {
            put_pixel(x + col, y, palette[7]);
            put_pixel(x + col, y + 1, palette[7]);
        }
    }
}
