/* SPDX-License-Identifier: GPL-2.0-only */
#include "video.h"
#include "cpu.h"
#include "devices.h"
#include "font8x8_basic.h"
#include "guest.h"

#define TEXT_BASE 0xb8000ull
#define COLS 80
#define ROWS 25
#define BDA 0x400

static uint8_t cur_row, cur_col;
static uint16_t cursor_shape = 0x0607;
static uint32_t last_hash;
static const uint32_t palette[16] = {
    0x000000, 0x0000aa, 0x00aa00, 0x00aaaa, 0xaa0000, 0xaa00aa, 0xaa5500, 0xaaaaaa,
    0x555555, 0x5555ff, 0x55ff55, 0x55ffff, 0xff5555, 0xff55ff, 0xffff55, 0xffffff,
};

static uint16_t *cell(unsigned row, unsigned col)
{
    return (uint16_t *)gpa_ptr(TEXT_BASE + (row * COLS + col) * 2, 2);
}

static void store_cursor(void)
{
    uint8_t *bda = gpa_ptr(BDA, 0x100);
    if (bda) {
        bda[0x50] = cur_col;
        bda[0x51] = cur_row;
        bda[0x60] = (uint8_t)cursor_shape;          /* end line */
        bda[0x61] = (uint8_t)(cursor_shape >> 8);   /* start line */
    }
}

void video_clear(uint8_t attr)
{
    unsigned i;
    uint16_t *p = cell(0, 0);
    for (i = 0; i < COLS * ROWS; ++i)
        p[i] = (uint16_t)(0x20 | (attr << 8));
    cur_row = cur_col = 0;
    store_cursor();
}

void video_init(void)
{
    uint8_t *bda = gpa_ptr(BDA, 0x100);
    video_clear(0x07);
    if (bda) {
        bda[0x49] = 3;                              /* video mode */
        *(uint16_t *)(bda + 0x4a) = COLS;
        *(uint16_t *)(bda + 0x4c) = 0x1000;         /* page size */
        *(uint16_t *)(bda + 0x4e) = 0;
        *(uint16_t *)(bda + 0x63) = 0x3d4;          /* CRTC base */
        bda[0x84] = ROWS - 1;
        *(uint16_t *)(bda + 0x85) = 16;
        bda[0x65] = 0x29;
        bda[0x66] = 0x30;
    }
    store_cursor();
}

static void scroll_up(unsigned top, unsigned left, unsigned bottom, unsigned right, unsigned lines, uint8_t attr)
{
    unsigned r, c;
    if (top > bottom || left > right || bottom >= ROWS || right >= COLS)
        return;
    if (lines == 0 || lines > bottom - top + 1)
        lines = bottom - top + 1;
    for (r = top; r <= bottom; ++r)
        for (c = left; c <= right; ++c)
            *cell(r, c) = (r + lines <= bottom) ? *cell(r + lines, c) : (uint16_t)(0x20 | (attr << 8));
}

static void scroll_down(unsigned top, unsigned left, unsigned bottom, unsigned right, unsigned lines, uint8_t attr)
{
    int r;
    unsigned c;
    if (top > bottom || left > right || bottom >= ROWS || right >= COLS)
        return;
    if (lines == 0 || lines > bottom - top + 1)
        lines = bottom - top + 1;
    for (r = (int)bottom; r >= (int)top; --r)
        for (c = left; c <= right; ++c)
            *cell((unsigned)r, c) = ((unsigned)r >= top + lines) ? *cell((unsigned)r - lines, c) : (uint16_t)(0x20 | (attr << 8));
}

static void teletype(uint8_t ch, uint8_t attr_default)
{
    switch (ch) {
    case 7: return;                                 /* bell: no speaker model */
    case 8: if (cur_col) --cur_col; break;
    case 10: ++cur_row; break;
    case 13: cur_col = 0; break;
    default: {
        uint16_t *p = cell(cur_row, cur_col);
        *p = (uint16_t)((*p & 0xff00) | ch);
        (void)attr_default;
        if (++cur_col >= COLS) {
            cur_col = 0;
            ++cur_row;
        }
    }
    }
    if (cur_row >= ROWS) {
        scroll_up(0, 0, ROWS - 1, COLS - 1, 1, (uint8_t)(*cell(ROWS - 1, 0) >> 8));
        cur_row = ROWS - 1;
    }
    store_cursor();
}

void video_int10(void)
{
    const uint8_t func = AH;
    switch (func) {
    case 0x00:
        if ((AL & 0x7f) == 3 || (AL & 0x7f) == 2) {
            if (!(AL & 0x80))
                video_clear(0x07);
        }
        break;
    case 0x01: cursor_shape = CX; store_cursor(); break;
    case 0x02: cur_row = DH < ROWS ? DH : ROWS - 1; cur_col = DL < COLS ? DL : COLS - 1; store_cursor(); break;
    case 0x03:
        set_reg16(GPR_RAX, 0);
        set_reg16(GPR_RCX, cursor_shape);
        set_reg16(GPR_RDX, (uint16_t)((cur_row << 8) | cur_col));
        break;
    case 0x05: break;                               /* only page 0 exists */
    case 0x06: scroll_up(CH, CL, DH, DL, AL, BH); break;
    case 0x07: scroll_down(CH, CL, DH, DL, AL, BH); break;
    case 0x08: set_reg16(GPR_RAX, *cell(cur_row, cur_col)); break;
    case 0x09:
    case 0x0a: {
        unsigned n = CX, r = cur_row, c = cur_col;
        while (n--) {
            uint16_t *p = cell(r, c);
            *p = func == 0x09 ? (uint16_t)((BL << 8) | AL) : (uint16_t)((*p & 0xff00) | AL);
            if (++c >= COLS) {
                c = 0;
                if (++r >= ROWS)
                    break;
            }
        }
        break;
    }
    case 0x0e: teletype(AL, 0x07); break;
    case 0x0f:
        set_reg8l(GPR_RAX, 3);
        set_reg8h(GPR_RAX, COLS);
        set_reg8h(GPR_RBX, 0);
        break;
    case 0x11: break;                               /* font services: not modelled */
    case 0x12:
        if (BL == 0x10) {                           /* EGA/VGA information */
            set_reg8h(GPR_RBX, 0);
            set_reg8l(GPR_RBX, 3);
            set_reg16(GPR_RCX, 0);
        }
        break;
    case 0x13: {
        const uint8_t mode = AL;
        unsigned n = CX, r = DH, c = DL, i;
        const uint8_t *s = gpa_ptr(((vmread(VMCS_GUEST_ES_SEL) & 0xffffull) << 4) + BP, n * ((mode & 2) ? 2 : 1));
        const uint8_t save_r = cur_row, save_c = cur_col;
        if (!s)
            break;
        cur_row = (uint8_t)r;
        cur_col = (uint8_t)c;
        for (i = 0; i < n; ++i) {
            const uint8_t ch = (mode & 2) ? s[i * 2] : s[i];
            const uint8_t at = (mode & 2) ? s[i * 2 + 1] : BL;
            *cell(cur_row, cur_col) = (uint16_t)((at << 8) | ch);
            if (++cur_col >= COLS) { cur_col = 0; if (cur_row + 1 < ROWS) ++cur_row; }
        }
        if (!(mode & 1)) {
            cur_row = save_r;
            cur_col = save_c;
        }
        store_cursor();
        break;
    }
    case 0x1a:
        if (AL == 0) {
            set_reg8l(GPR_RAX, 0x1a);
            set_reg16(GPR_RBX, 0x0008);             /* VGA with color display */
        }
        break;
    default: break;
    }
}

/* ---------------------------------------------------------------- GOP renderer */
static void put_glyph(volatile uint32_t *fb, unsigned pitch, unsigned x, unsigned y, uint8_t ch,
                      uint32_t fg, uint32_t bg, int swap)
{
    unsigned row, col;
    for (row = 0; row < 16; ++row) {
        const uint8_t bits = (uint8_t)font8x8_basic[ch & 0x7f][row >> 1];
        for (col = 0; col < 8; ++col) {
            uint32_t rgb = (bits >> col) & 1 ? fg : bg;
            if (swap)
                rgb = ((rgb & 255) << 16) | (rgb & 0xff00) | ((rgb >> 16) & 255);
            fb[(y + row) * pitch + x + col] = rgb;
        }
    }
}

void video_render(void)
{
    shz_info_t *info = G.info;
    const uint16_t *page = (const uint16_t *)gpa_ptr(TEXT_BASE, COLS * ROWS * 2);
    volatile uint32_t *fb = (volatile uint32_t *)(uintptr_t)info->fb_base;
    unsigned r, c, x0, y0;
    uint32_t hash = 2166136261u;
    if (!info->fb_base || !page || info->fb_width < COLS * 8 || info->fb_height < ROWS * 16)
        return;
    for (r = 0; r < ROWS * COLS; ++r)
        hash = (hash ^ page[r]) * 16777619u;
    hash = (hash ^ cur_row) * 16777619u;
    hash = (hash ^ cur_col) * 16777619u;
    if (hash == last_hash)
        return;
    last_hash = hash;
    x0 = (info->fb_width - COLS * 8) / 2;
    y0 = (info->fb_height - ROWS * 16) / 2;
    for (r = 0; r < ROWS; ++r)
        for (c = 0; c < COLS; ++c) {
            const uint16_t v = page[r * COLS + c];
            put_glyph(fb, info->fb_pitch_pixels, x0 + c * 8, y0 + r * 16, (uint8_t)v,
                      palette[(v >> 8) & 15], palette[(v >> 12) & 7], info->fb_format == 0);
        }
    /* cursor: underline in the current cell */
    if (cur_row < ROWS && cur_col < COLS)
        for (c = 0; c < 8; ++c) {
            uint32_t rgb = palette[7];
            if (info->fb_format == 0)
                rgb = ((rgb & 255) << 16) | (rgb & 0xff00) | ((rgb >> 16) & 255);
            fb[(y0 + cur_row * 16 + 14) * info->fb_pitch_pixels + x0 + cur_col * 8 + c] = rgb;
            fb[(y0 + cur_row * 16 + 15) * info->fb_pitch_pixels + x0 + cur_col * 8 + c] = rgb;
        }
}
