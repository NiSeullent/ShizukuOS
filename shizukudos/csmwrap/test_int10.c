/* SPDX-License-Identifier: GPL-2.0-only
 * Host checks for the INT 10h cell buffer and GOP pixel path.
 * Compiled and executed by test_int10.py.
 */
#include "bios/int10.h"
#include "video/cp437.h"
#include "video/video.h"
#include <stdio.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        return 1; \
    } \
} while (0)

static void call10(csmwrap_regs *r, uint8_t ah, uint8_t al,
                   uint8_t bh, uint8_t bl, uint16_t cx, uint8_t dh, uint8_t dl)
{
    r->eax = (uint32_t)((ah << 8) | al);
    r->ebx = (uint32_t)((bh << 8) | bl);
    r->ecx = cx;
    r->edx = (uint32_t)((dh << 8) | dl);
    csmwrap_int10(r);
}

static int test_mode_teletype_cursor(void)
{
    csmwrap_regs r;
    unsigned row, col;
    csm_video_reset();
    call10(&r, 0x00, 0x03, 0, 0, 0, 0, 0);
    for (row = 0; row < CSM_VIDEO_ROWS; ++row)
        for (col = 0; col < CSM_VIDEO_COLS; ++col)
            CHECK(csm_video_cell(row, col) == 0x0720);
    call10(&r, 0x0f, 0, 0x5a, 0x11, 0, 0, 0);
    CHECK((r.eax & 0xff) == 3);
    CHECK((r.eax >> 8) == 80);
    CHECK((r.ebx >> 8) == 0);
    CHECK((r.ebx & 0xff) == 0x11);

    call10(&r, 0x0e, 'H', 0, 0x4e, 0, 0, 0);
    call10(&r, 0x0e, 'i', 0, 0x4e, 0, 0, 0);
    CHECK(csm_video_cell(0, 0) == 0x0748);
    CHECK(csm_video_cell(0, 1) == 0x0769);
    call10(&r, 0x03, 0, 0, 0, 0, 0, 0);
    CHECK(r.ecx == 0x0607);
    CHECK(r.edx == 0x0002);

    call10(&r, 0x0e, '\r', 0, 0, 0, 0, 0);
    call10(&r, 0x0e, '\n', 0, 0, 0, 0, 0);
    call10(&r, 0x03, 0, 0, 0, 0, 0, 0);
    CHECK(r.edx == 0x0100);
    call10(&r, 0x0e, 8, 0, 0, 0, 0, 0);
    call10(&r, 0x03, 0, 0, 0, 0, 0, 0);
    CHECK(r.edx == 0x0100);
    call10(&r, 0x0e, 'Z', 0, 0, 0, 0, 0);
    call10(&r, 0x0e, 8, 0, 0, 0, 0, 0);
    call10(&r, 0x03, 0, 0, 0, 0, 0, 0);
    CHECK(r.edx == 0x0100);
    CHECK(csm_video_cell(1, 0) == 0x075a);

    call10(&r, 0x02, 0, 0, 0, 0, 5, 10);
    call10(&r, 0x09, 'Q', 0, 0x1e, 1, 5, 10);
    call10(&r, 0x03, 0, 0, 0, 0, 0, 0);
    CHECK(r.edx == 0x050a);
    call10(&r, 0x08, 0, 0, 0, 0, 0, 0);
    CHECK(r.eax == 0x1e51);

    call10(&r, 0x0e, 'Z', 0, 0x21, 0, 0, 0);
    CHECK(csm_video_cell(5, 10) == 0x1e5a);
    call10(&r, 0x03, 0, 0, 0, 0, 0, 0);
    CHECK(r.edx == 0x050b);

    call10(&r, 0x00, 0x13, 0, 0, 0, 0, 0);
    call10(&r, 0x0f, 0, 0, 0, 0, 0, 0);
    CHECK((r.eax & 0xff) == 3);
    CHECK(csm_video_cell(5, 10) == 0x1e5a);
    call10(&r, 0x00, 0x82, 0, 0, 0, 0, 0);
    call10(&r, 0x0f, 0, 0, 0, 0, 0, 0);
    CHECK((r.eax & 0xff) == 2);
    CHECK(csm_video_cell(5, 10) == 0x1e5a);
    call10(&r, 0x00, 0x03, 0, 0, 0, 0, 0);
    CHECK(csm_video_cell(0, 0) == 0x0720);
    CHECK(csm_video_cell(5, 10) == 0x0720);
    return 0;
}

static int test_scroll(void)
{
    csmwrap_regs r;
    unsigned i;
    csm_video_reset();
    call10(&r, 0x00, 0x03, 0, 0, 0, 0, 0);
    call10(&r, 0x02, 0, 0, 0, 0, 0, 0);
    call10(&r, 0x09, 'A', 0, 0x12, 80, 0, 0);
    call10(&r, 0x02, 0, 0, 0, 0, 1, 0);
    call10(&r, 0x09, 'B', 0, 0x34, 80, 1, 0);
    /* AL=1, BH=0x70, window (0,0)-(24,79). */
    call10(&r, 0x06, 1, 0x70, 0, 0, 24, 79);
    CHECK(csm_video_cell(0, 0) == 0x3442);
    CHECK(csm_video_cell(0, 79) == 0x3442);
    CHECK(csm_video_cell(1, 0) == 0x0720);
    CHECK(csm_video_cell(24, 0) == 0x7020);
    CHECK(csm_video_cell(24, 79) == 0x7020);

    call10(&r, 0x02, 0, 0, 0, 0, 0, 0);
    call10(&r, 0x09, 'X', 0, 0x07, 80 * 25, 0, 0);
    CHECK(csm_video_cell(0, 0) == 0x0758);
    CHECK(csm_video_cell(24, 79) == 0x0758);
    call10(&r, 0x03, 0, 0, 0, 0, 0, 0);
    CHECK(r.edx == 0x0000);

    /* AH=07h, AL=2, BH=0x40, window rows 2..4, columns 10..20. */
    call10(&r, 0x07, 2, 0x40, 0, (uint16_t)((2u << 8) | 10u), 4, 20);
    CHECK(csm_video_cell(2, 10) == 0x4020);
    CHECK(csm_video_cell(3, 20) == 0x4020);
    CHECK(csm_video_cell(4, 10) == 0x0758);
    CHECK(csm_video_cell(2, 9) == 0x0758);
    CHECK(csm_video_cell(1, 10) == 0x0758);
    CHECK(csm_video_cell(5, 10) == 0x0758);

    /* Top below bottom: no change. */
    call10(&r, 0x06, 1, 0x07, 0, (uint16_t)((10u << 8) | 0u), 4, 20);
    CHECK(csm_video_cell(0, 0) == 0x0758);
    CHECK(csm_video_cell(4, 10) == 0x0758);

    call10(&r, 0x02, 0, 0, 0, 0, 24, 79);
    call10(&r, 0x0e, 'Z', 0, 0, 0, 0, 0);
    CHECK(csm_video_cell(23, 79) == 0x075a);
    call10(&r, 0x03, 0, 0, 0, 0, 0, 0);
    CHECK(r.edx == 0x1800);
    for (i = 0; i < 79; ++i)
        call10(&r, 0x0e, 'Q', 0, 0, 0, 0, 0);
    CHECK(csm_video_cell(24, 0) == 0x0751);
    CHECK(csm_video_cell(24, 78) == 0x0751);
    call10(&r, 0x03, 0, 0, 0, 0, 0, 0);
    CHECK(r.edx == (uint16_t)((24u << 8) | 79u));
    return 0;
}

static uint32_t px(const uint32_t *fb, uint32_t pitch, uint32_t x, uint32_t y)
{
    return fb[(size_t)y * pitch + x];
}

static int test_framebuffer(void)
{
    enum { W = 640, H = 400, PITCH = 672 };
    static uint32_t pixels[H * PITCH];
    csmwrap_regs r;
    csm_video_fb gop;
    uint32_t sentinel;

    memset(pixels, 0x11, sizeof pixels);
    sentinel = pixels[0];
    csm_video_reset();
    gop.base = pixels;
    gop.width = W;
    gop.height = H;
    gop.pitch_bytes = PITCH * 4u;
    gop.pixel_format = 1;
    CHECK(csm_video_bind(&gop) == 0);

    CHECK(csm_cp437_row('A', 0) == 0x0C);
    CHECK(csm_cp437_row('A', 1) == 0x0C);
    CHECK(csm_cp437_row(' ', 0) == 0);
    CHECK(csm_cp437_row(0xDB, 0) == 0xFF);
    CHECK(csm_cp437_row(0xDB, 15) == 0xFF);
    CHECK(csm_cp437_row(0xC4, 0) == 0);
    CHECK(csm_cp437_row(0xC4, 7) == 0xFF);
    CHECK(csm_cp437_row(0xC4, 8) == 0xFF);

    call10(&r, 0x00, 0x03, 0, 0, 0, 0, 0);
    call10(&r, 0x09, 'A', 0, 0x1e, 1, 0, 0);
    call10(&r, 0x02, 0, 0, 0, 0, 2, 2);
    csm_video_render();
    CHECK(csm_video_cell(0, 0) == 0x1e41);
    CHECK(px(pixels, PITCH, 0, 0) == 0x000000AAu);
    CHECK(px(pixels, PITCH, 2, 0) == 0x00FFFF55u);
    CHECK(px(pixels, PITCH, 2, 1) == 0x00FFFF55u);
    CHECK(px(pixels, PITCH, 8, 0) == 0x00000000u);
    CHECK(px(pixels, PITCH, 0, 0) != sentinel);

    call10(&r, 0x02, 0, 0, 0, 0, 0, 1);
    call10(&r, 0x09, 0xC4, 0, 0x2a, 1, 0, 1);
    call10(&r, 0x02, 0, 0, 0, 0, 4, 4);
    csm_video_render();
    CHECK(csm_video_cell(0, 1) == 0x2ac4);
    CHECK(px(pixels, PITCH, 8, 0) == 0x0000AA00u);
    CHECK(px(pixels, PITCH, 8, 7) == 0x0055FF55u);
    CHECK(px(pixels, PITCH, 15, 7) == 0x0055FF55u);
    CHECK(px(pixels, PITCH, 15, 6) == 0x0000AA00u);

    gop.pixel_format = 0;
    CHECK(csm_video_bind(&gop) == 0);
    csm_video_render();
    CHECK(px(pixels, PITCH, 2, 0) == 0x0055FFFFu);
    CHECK(px(pixels, PITCH, 0, 0) == 0x00AA0000u);

    gop.pixel_format = 2;
    CHECK(csm_video_bind(&gop) == -1);
    gop.pixel_format = 1;
    gop.pitch_bytes = (gop.width - 1u) * 4u;
    CHECK(csm_video_bind(&gop) == -1);
    gop.pitch_bytes = PITCH * 4u + 1u;
    CHECK(csm_video_bind(&gop) == -1);
    gop.base = 0;
    gop.pitch_bytes = PITCH * 4u;
    CHECK(csm_video_bind(&gop) == -1);

    /* No hardware text page: rendering after a failed bind leaves cells intact
     * and does not require a B8000 mapping. */
    CHECK(csm_video_cell(0, 0) == 0x1e41);
    csm_video_render();
    return 0;
}

static int test_pitch_and_origin(void)
{
    enum { W = 16, H = 16, PITCH = 32 };
    static uint32_t small[H * PITCH];
    enum { BIG_W = 656, BIG_H = 16, BIG_PITCH = 700 };
    static uint32_t wide[BIG_H * BIG_PITCH];
    csmwrap_regs r;
    csm_video_fb gop;
    uint32_t sentinel;

    memset(small, 0x5a, sizeof small);
    sentinel = small[0];
    csm_video_reset();
    call10(&r, 0x00, 0x03, 0, 0, 0, 0, 0);
    call10(&r, 0x09, 'A', 0, 0x0f, 1, 0, 0);
    call10(&r, 0x02, 0, 0, 0, 0, 1, 0);
    gop.base = small;
    gop.width = W;
    gop.height = H;
    gop.pitch_bytes = PITCH * 4u;
    gop.pixel_format = 1;
    CHECK(csm_video_bind(&gop) == 0);
    csm_video_render();
    CHECK(px(small, PITCH, 2, 0) == 0x00FFFFFFu);
    CHECK(px(small, PITCH, 2, 1) == 0x00FFFFFFu);
    CHECK(px(small, PITCH, 0, 0) == 0x00000000u);
    CHECK(small[16 + 2] == sentinel);

    memset(wide, 0x5a, sizeof wide);
    sentinel = wide[0];
    gop.base = wide;
    gop.width = BIG_W;
    gop.height = BIG_H;
    gop.pitch_bytes = BIG_PITCH * 4u;
    gop.pixel_format = 1;
    CHECK(csm_video_bind(&gop) == 0);
    call10(&r, 0x02, 0, 0, 0, 0, 0, 0);
    call10(&r, 0x09, 0xDB, 0, 0x1e, 1, 0, 0);
    call10(&r, 0x02, 0, 0, 0, 0, 3, 0);
    csm_video_render();
    CHECK(px(wide, BIG_PITCH, 7, 0) == sentinel);
    CHECK(px(wide, BIG_PITCH, 8, 0) == 0x00FFFF55u);
    CHECK(px(wide, BIG_PITCH, 15, 0) == 0x00FFFF55u);
    CHECK(px(wide, BIG_PITCH, 16, 0) == 0x00000000u);
    return 0;
}

static int test_without_framebuffer(void)
{
    csmwrap_regs r;
    csm_video_reset();
    call10(&r, 0x0e, 'M', 0, 0, 0, 0, 0);
    CHECK(csm_video_cell(0, 0) == 0x074d);
    csm_video_render();
    csmwrap_int10(0);
    CHECK(csm_video_cell(0, 0) == 0x074d);
    return 0;
}

int main(void)
{
    CHECK(test_mode_teletype_cursor() == 0);
    CHECK(test_scroll() == 0);
    CHECK(test_framebuffer() == 0);
    CHECK(test_pitch_and_origin() == 0);
    CHECK(test_without_framebuffer() == 0);
    printf("test_int10: ok\n");
    return 0;
}
