/* SPDX-License-Identifier: GPL-2.0-only */
#include "video.h"
#include "cpu.h"
#include "devices.h"
#include "../../csmwrap/video/cp437.h"
#include "guest.h"

#define TEXT_BASE 0xb8000ull
#define COLS 80
#define ROWS 25
#define BDA 0x400

static uint8_t cur_row, cur_col;
static uint16_t cursor_shape = 0x0607;
static uint32_t last_hash;
static int last_render_valid;
static struct {
    uint64_t base, size, guest_ram;
    uint32_t width, height, pitch, format;
} last_target;
static const uint32_t palette[16] = {
    0x000000, 0x0000aa, 0x00aa00, 0x00aaaa, 0xaa0000, 0xaa00aa, 0xaa5500, 0xaaaaaa,
    0x555555, 0x5555ff, 0x55ff55, 0x55ffff, 0xff5555, 0xff55ff, 0xffff55, 0xffffff,
};

static uint16_t *text_page(void)
{
    return (uint16_t *)gpa_ptr(TEXT_BASE, COLS * ROWS * 2);
}

static uint16_t *cell(unsigned row, unsigned col)
{
    uint16_t *page = text_page();
    return page && row < ROWS && col < COLS ? page + row * COLS + col : 0;
}

/* Several BIOS data words start at odd addresses (notably 0463h/0485h).
 * Store their little-endian bytes without an unaligned C uint16_t access. */
static void bda_word(uint8_t *bda, unsigned offset, uint16_t value)
{
    bda[offset] = (uint8_t)value;
    bda[offset + 1] = (uint8_t)(value >> 8);
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
    uint16_t *p = text_page();
    if (!p)
        return;
    for (i = 0; i < COLS * ROWS; ++i)
        p[i] = (uint16_t)(0x20 | (attr << 8));
    cur_row = cur_col = 0;
    store_cursor();
}

void video_init(void)
{
    uint8_t *bda = gpa_ptr(BDA, 0x100);
    cursor_shape = 0x0607;
    last_render_valid = 0;
    video_clear(0x07);
    if (bda) {
        bda[0x49] = 3;                              /* video mode */
        bda_word(bda, 0x4a, COLS);
        bda_word(bda, 0x4c, 0x1000);               /* page size */
        bda_word(bda, 0x4e, 0);
        bda_word(bda, 0x63, 0x3d4);                /* CRTC base */
        bda[0x84] = ROWS - 1;
        bda_word(bda, 0x85, 16);
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

static void teletype(uint8_t ch, uint8_t attr, int write_attr)
{
    switch (ch) {
    case 7: return;                                 /* bell: no speaker model */
    case 8: if (cur_col) --cur_col; break;
    case 10: ++cur_row; break;
    case 13: cur_col = 0; break;
    default: {
        uint16_t *p = cell(cur_row, cur_col);
        *p = (uint16_t)((write_attr ? (uint16_t)attr << 8 : *p & 0xff00) | ch);
        if (++cur_col >= COLS) {
            cur_col = 0;
            ++cur_row;
        }
    }
    }
    if (cur_row >= ROWS) {
        /* AH=13h follows BIOS string/teletype scrolling, blanking the exposed
         * row with attribute 07h. AH=0Eh retains this path's existing fill. */
        const uint8_t fill = write_attr ? 0x07 : (uint8_t)(*cell(ROWS - 1, 0) >> 8);
        scroll_up(0, 0, ROWS - 1, COLS - 1, 1, fill);
        cur_row = ROWS - 1;
    }
    store_cursor();
}

void video_int10(void)
{
    uint8_t func;
    /* No service may dereference a partial or missing 4,000-byte text page. */
    if (!G.vc || !text_page())
        return;
    func = AH;
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
    case 0x0e: teletype(AL, 0x07, 0); break;
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
        const unsigned stride = (mode & 2) ? 2 : 1;
        const unsigned bytes = n * stride, offset = BP;
        uint64_t base;
        unsigned first, rest;
        const uint8_t save_r = cur_row, save_c = cur_col;
        if (!n || r >= ROWS || c >= COLS)
            break;
        base = (vmread(VMCS_GUEST_ES_SEL) & 0xffffull) << 4;
        /* The real-mode ES:BP offset wraps at 64 KiB. Validate every source
         * span before changing the page/cursor; malformed reads are a no-op. */
        first = bytes < 0x10000u - offset ? bytes : 0x10000u - offset;
        rest = bytes - first;
        if (!gpa_ptr(base + offset, first) ||
            (rest && !gpa_ptr(base, rest < 0x10000u ? rest : 0x10000u)))
            break;
        cur_row = (uint8_t)r;
        cur_col = (uint8_t)c;
        for (i = 0; i < n; ++i) {
            const unsigned source = (offset + i * stride) & 0xffff;
            const uint8_t ch = *gpa_ptr(base + source, 1);
            const uint8_t at = (mode & 2) ? *gpa_ptr(base + ((source + 1) & 0xffff), 1) : BL;
            /* Reuse the bounded text path: controls, wrapping and scrolling
             * apply even when AL bit 0 requests restoration of the cursor. */
            teletype(ch, at, 1);
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
        const uint8_t bits = csm_cp437_row(ch, row);
        for (col = 0; col < 8; ++col) {
            uint32_t rgb = (bits >> col) & 1 ? fg : bg;
            if (swap)
                rgb = ((rgb & 255) << 16) | (rgb & 0xff00) | ((rgb >> 16) & 255);
            fb[(size_t)(y + row) * pitch + x + col] = rgb;
        }
    }
}

void video_render(void)
{
    shz_info_t *info = G.info;
    const uint16_t *page = text_page();
    volatile uint32_t *fb;
    uint64_t pixels;
    unsigned r, c, x0, y0;
    uint32_t hash = 2166136261u;
    if (!info || !info->fb_base || (info->fb_base & 3) || !page ||
        info->fb_width < COLS * 8 || info->fb_height < ROWS * 16 ||
        info->fb_pitch_pixels < info->fb_width || info->fb_format > 1) {
        last_render_valid = 0;
        return;
    }
    pixels = (uint64_t)info->fb_pitch_pixels * info->fb_height;
    if (pixels > UINT64_MAX / 4 || pixels * 4 > info->fb_size ||
        info->fb_base > UINT64_MAX - info->fb_size) {
        last_render_valid = 0;
        return;
    }
    fb = (volatile uint32_t *)(uintptr_t)info->fb_base;
    for (r = 0; r < ROWS * COLS; ++r)
        hash = (hash ^ page[r]) * 16777619u;
    hash = (hash ^ cur_row) * 16777619u;
    hash = (hash ^ cur_col) * 16777619u;
    hash = (hash ^ cursor_shape) * 16777619u;
    if (last_render_valid && hash == last_hash &&
        last_target.base == info->fb_base && last_target.size == info->fb_size &&
        last_target.guest_ram == G.ram_base && last_target.width == info->fb_width &&
        last_target.height == info->fb_height && last_target.pitch == info->fb_pitch_pixels &&
        last_target.format == info->fb_format)
        return;
    x0 = (info->fb_width - COLS * 8) / 2;
    y0 = (info->fb_height - ROWS * 16) / 2;
    for (r = 0; r < ROWS; ++r)
        for (c = 0; c < COLS; ++c) {
            const uint16_t v = page[r * COLS + c];
            put_glyph(fb, info->fb_pitch_pixels, x0 + c * 8, y0 + r * 16, (uint8_t)v,
                      palette[(v >> 8) & 15], palette[(v >> 12) & 7], info->fb_format == 0);
        }
    /* CH bit 5 disables the VGA cursor. Remaining start/end scanlines are
     * clipped to this 16-line font; reversed/outside shapes stay hidden. */
    const unsigned start = (cursor_shape >> 8) & 31;
    unsigned end = cursor_shape & 31;
    if (end > 15) end = 15;
    if (!(cursor_shape & 0x2000) && start <= end && cur_row < ROWS && cur_col < COLS)
        for (r = start; r <= end; ++r)
            for (c = 0; c < 8; ++c) {
                uint32_t rgb = palette[7];
                if (info->fb_format == 0)
                    rgb = ((rgb & 255) << 16) | (rgb & 0xff00) | ((rgb >> 16) & 255);
                fb[(size_t)(y0 + cur_row * 16 + r) * info->fb_pitch_pixels + x0 + cur_col * 8 + c] = rgb;
            }
    last_hash = hash;
    last_target.base = info->fb_base;
    last_target.size = info->fb_size;
    last_target.guest_ram = G.ram_base;
    last_target.width = info->fb_width;
    last_target.height = info->fb_height;
    last_target.pitch = info->fb_pitch_pixels;
    last_target.format = info->fb_format;
    last_render_valid = 1;
}
