/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the production legacy text path against bounded guest RAM and pixels.
 * Only the privileged VMCS read is substituted; no VM or Windows is executed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SHZ_CPU_H
static unsigned long long es_selector;
static unsigned long long host_vmread(unsigned long long field)
{
    (void)field;
    return es_selector;
}
#define vmread host_vmread
#include "../../src/video.c"

guest_t G;
enum { RAM_BYTES = 1024 * 1024, FB_CAPACITY = 720 * 448 };
static unsigned char ram[RAM_BYTES], saved_ram[RAM_BYTES];
static unsigned int pixels[FB_CAPACITY + 2], other_pixels[FB_CAPACITY + 2];
static vcpu_t vc;
static shz_info_t info;
static unsigned checks;
#define CHECK(v) do { ++checks; if (!(v)) { \
    fprintf(stderr, "FAIL %s:%u: %s\n", __func__, __LINE__, #v); return 1; \
} } while (0)

static void call10(unsigned ah, unsigned al, unsigned bx, unsigned cx, unsigned dx, unsigned bp)
{
    vc.gpr[GPR_RAX] = (ah << 8) | al;
    vc.gpr[GPR_RBX] = bx;
    vc.gpr[GPR_RCX] = cx;
    vc.gpr[GPR_RDX] = dx;
    vc.gpr[GPR_RBP] = bp;
    video_int10();
}

static unsigned cursor_position(void)
{
    call10(3, 0, 0, 0, 0, 0);
    return (unsigned)(vc.gpr[GPR_RDX] & 0xffff);
}

static uint16_t *page(void) { return (uint16_t *)(ram + 0xb8000); }
static unsigned int pixel(unsigned x, unsigned y)
{
    return pixels[1 + y * info.fb_pitch_pixels + x];
}

static void setup(void)
{
    memset(ram, 0, sizeof ram);
    memset(&vc, 0, sizeof vc);
    memset(&info, 0, sizeof info);
    G.vc = &vc;
    G.info = &info;
    G.ram_base = (uintptr_t)ram;
    G.ram_size = sizeof ram;
    info.fb_base = (uintptr_t)(pixels + 1);
    info.fb_width = 656;
    info.fb_height = 416;
    info.fb_pitch_pixels = 672;
    info.fb_size = (uint64_t)info.fb_pitch_pixels * info.fb_height * 4;
    info.fb_format = 1;
    es_selector = 0;
    for (unsigned n = 0; n < FB_CAPACITY + 2; ++n)
        pixels[n] = other_pixels[n] = 0xdeadbeef;
    video_init();
    call10(1, 0, 0, 0x2000, 0, 0); /* hidden cursor */
}

static int test_cp437_lines_blocks_and_rgb_pitch(void)
{
    setup();
    page()[0] = 0x1eb3; /* CP437 vertical line, yellow on blue */
    page()[1] = 0x1edb; /* full block */
    page()[2] = 0x1eff; /* blank nbsp */
    video_render();
    for (unsigned row = 0; row < 16; ++row)
        for (unsigned col = 0; col < 8; ++col) {
            CHECK(pixel(8 + col, 8 + row) == (col == 3 || col == 4 ? 0xffff55u : 0xaau));
            CHECK(pixel(16 + col, 8 + row) == 0xffff55u);
            CHECK(pixel(24 + col, 8 + row) == 0xaau);
        }
    /* Padding and the centered margins belong to the caller. */
    CHECK(pixels[0] == 0xdeadbeef && pixels[FB_CAPACITY + 1] == 0xdeadbeef);
    for (unsigned row = 0; row < info.fb_height; ++row)
        for (unsigned col = info.fb_width; col < info.fb_pitch_pixels; ++col)
            CHECK(pixel(col, row) == 0xdeadbeef);
    info.fb_format = 0;
    video_render();
    CHECK(pixel(11, 8) == 0x55ffff && pixel(8, 8) == 0xaa0000);
    return 0;
}

static int test_cursor_visibility_and_shape_changes(void)
{
    setup();
    call10(1, 0, 0, 0x0e0f, 0, 0);
    video_render();
    CHECK(pixel(8, 22) == 0xaaaaaa && pixel(8, 23) == 0xaaaaaa);
    call10(1, 0, 0, 0x2000, 0, 0);
    video_render();
    CHECK(pixel(8, 22) == 0 && pixel(8, 23) == 0);
    call10(1, 0, 0, 0x0204, 0, 0);
    video_render();
    for (unsigned row = 0; row < 16; ++row)
        CHECK(pixel(8, 8 + row) == (row >= 2 && row <= 4 ? 0xaaaaaau : 0u));
    call10(1, 0, 0, 0x1000, 0, 0); /* start outside the 16 scanlines */
    video_render();
    CHECK(pixel(8, 10) == 0);
    call10(1, 0, 0, 0x0802, 0, 0); /* reversed scanline range */
    video_render();
    CHECK(pixel(8, 10) == 0);
    call10(1, 0, 0, 0x0e1f, 0, 0); /* end clipped to the font raster */
    video_render();
    CHECK(pixel(8, 22) == 0xaaaaaa && pixel(8, 23) == 0xaaaaaa);
    CHECK(pixel(8, 24) == 0);
    return 0;
}

static int test_render_cache_target_and_initialization(void)
{
    setup();
    video_render();
    CHECK(pixel(8, 8) == 0);
    /* Unchanged pages retain the cache; a distinct target must be painted. */
    pixels[1 + 8 * info.fb_pitch_pixels + 8] = 0x123456;
    video_render();
    CHECK(pixel(8, 8) == 0x123456);
    info.fb_base = (uintptr_t)(other_pixels + 1);
    video_render();
    CHECK(other_pixels[1 + 8 * info.fb_pitch_pixels + 8] == 0);
    info.fb_base = (uintptr_t)(pixels + 1);
    info.fb_pitch_pixels = 680;
    info.fb_size = (uint64_t)info.fb_pitch_pixels * info.fb_height * 4;
    video_render();
    CHECK(pixel(8, 8) == 0);
    info.fb_width = 672;
    info.fb_height = 432;
    info.fb_size = (uint64_t)info.fb_pitch_pixels * info.fb_height * 4;
    video_render();
    CHECK(pixel(16, 16) == 0);
    video_init();
    CHECK(ram[0x463] == 0xd4 && ram[0x464] == 3);
    CHECK(ram[0x485] == 16 && ram[0x486] == 0);
    call10(3, 0, 0, 0, 0, 0);
    CHECK((vc.gpr[GPR_RCX] & 0xffff) == 0x0607);
    call10(1, 0, 0, 0x2000, 0, 0);
    for (unsigned n = 0; n < FB_CAPACITY + 2; ++n) pixels[n] = 0xdeadbeef;
    video_render();
    CHECK(pixel(16, 16) == 0);
    return 0;
}

static int test_ah13_invalid_destination_is_noop(void)
{
    setup();
    ram[0x1000] = 'X';
    call10(2, 0, 0, 0, 0x0304, 0);
    memcpy(saved_ram, ram, sizeof ram);
    call10(0x13, 1, 0x1e, 1, 0xff00, 0x1000);
    CHECK(memcmp(saved_ram, ram, sizeof ram) == 0 && cursor_position() == 0x0304);
    call10(0x13, 1, 0x1e, 1, 0x00ff, 0x1000);
    CHECK(memcmp(saved_ram, ram, sizeof ram) == 0 && cursor_position() == 0x0304);
    return 0;
}

static int test_ah13_end_of_page_wraps_and_scrolls(void)
{
    setup();
    memcpy(ram + 0x1000, "XYZ", 3);
    call10(0x13, 1, 0x1e, 3, 0x184f, 0x1000);
    CHECK(page()[1919] == 0x1e58); /* X scrolled to row 23, column 79 */
    CHECK(page()[1920] == 0x1e59 && page()[1921] == 0x1e5a);
    CHECK(page()[1999] == 0x0720);
    CHECK(ram[0xb8000 + 4000] == 0 && ram[0xb8000 - 1] == 0);
    CHECK(cursor_position() == 0x1802);
    return 0;
}

static int test_ah13_preflight_guest_read_and_zero_count(void)
{
    setup();
    call10(2, 0, 0, 0, 0x0304, 0);
    memcpy(saved_ram, ram, sizeof ram);
    es_selector = 0xffff;
    ram[RAM_BYTES - 1] = 'Q'; saved_ram[RAM_BYTES - 1] = 'Q';
    call10(0x13, 1, 0x1e, 2, 0x184f, 15);
    CHECK(memcmp(saved_ram, ram, sizeof ram) == 0 && cursor_position() == 0x0304);
    call10(0x13, 1, 0x1e, 0, 0x0809, 15);
    CHECK(memcmp(saved_ram, ram, sizeof ram) == 0 && cursor_position() == 0x0304);
    return 0;
}

static int test_ah13_valid_strings_attributes_and_cursor_restore(void)
{
    setup();
    ram[0x1000] = 'A'; ram[0x1001] = 0x1e;
    ram[0x1002] = 'B'; ram[0x1003] = 0x2f;
    call10(2, 0, 0, 0, 0x0304, 0);
    call10(0x13, 2, 0, 2, 0x014f, 0x1000);
    CHECK(page()[159] == 0x1e41 && page()[160] == 0x2f42);
    CHECK(cursor_position() == 0x0304);
    call10(0x13, 3, 0, 2, 0x014f, 0x1000);
    CHECK(cursor_position() == 0x0201);
    call10(9, 'Z', 0x4e, 1, 0, 0);
    CHECK(page()[161] == 0x4e5a && cursor_position() == 0x0201);
    call10(0x0a, 'Y', 0, 1, 0, 0);
    CHECK(page()[161] == 0x4e59);
    return 0;
}

static int test_ah13_control_characters_and_segment_wrap(void)
{
    static const unsigned char string[] = {'A', 13, 'B', 10, 'C', 8, 'D', 7};
    setup();
    memcpy(ram + 0x1000, string, sizeof string);
    call10(0x13, 1, 0x1e, sizeof string, 0x174e, 0x1000);
    CHECK(page()[1918] == 0x1e41 && page()[1840] == 0x1e42);
    CHECK(page()[1921] == 0x1e44 && cursor_position() == 0x1802);
    es_selector = 0x100;
    ram[0x10fff] = 'A'; ram[0x1000] = 'B'; ram[0x11000] = 'X';
    call10(0x13, 0, 0x2f, 2, 0x0000, 0xffff);
    CHECK(page()[0] == 0x2f41 && page()[1] == 0x2f42);
    CHECK(cursor_position() == 0x1802);
    return 0;
}

static int test_incomplete_guest_text_page_is_noop(void)
{
    setup();
    G.ram_size = 0xb8000 + 3998;
    memcpy(saved_ram, ram, sizeof ram);
    video_clear(0x1e);
    CHECK(memcmp(saved_ram, ram, sizeof ram) == 0);
    call10(9, 'X', 0x1e, 1, 0, 0);
    call10(0x0e, 'X', 0, 0, 0, 0);
    ram[0x1000] = 'Q'; saved_ram[0x1000] = 'Q';
    call10(0x13, 1, 0x1e, 1, 0, 0x1000);
    CHECK(memcmp(saved_ram, ram, sizeof ram) == 0);
    return 0;
}

static int test_malformed_framebuffer_descriptor_is_noop(void)
{
    setup();
    info.fb_size = 4;
    video_render();
    for (unsigned n = 0; n < FB_CAPACITY + 2; ++n) CHECK(pixels[n] == 0xdeadbeef);
    info.fb_size = (uint64_t)info.fb_pitch_pixels * info.fb_height * 4;
    info.fb_pitch_pixels = 655;
    video_render();
    CHECK(pixels[1 + 8 * 655 + 8] == 0xdeadbeef);
    info.fb_pitch_pixels = 672;
    info.fb_format = 2; /* this legacy renderer has no arbitrary-mask adapter */
    video_render();
    CHECK(pixel(8, 8) == 0xdeadbeef);
    return 0;
}

int main(int argc, char **argv)
{
    int (*const tests[])(void) = {
        test_cp437_lines_blocks_and_rgb_pitch,
        test_cursor_visibility_and_shape_changes,
        test_render_cache_target_and_initialization,
        test_ah13_invalid_destination_is_noop,
        test_ah13_end_of_page_wraps_and_scrolls,
        test_ah13_preflight_guest_read_and_zero_count,
        test_ah13_valid_strings_attributes_and_cursor_restore,
        test_ah13_control_characters_and_segment_wrap,
        test_incomplete_guest_text_page_is_noop,
        test_malformed_framebuffer_descriptor_is_noop,
    };
    unsigned failed = 0, begin = 0, end = sizeof tests / sizeof tests[0];
    if (argc == 2) {
        unsigned selected = (unsigned)strtoul(argv[1], NULL, 10);
        if (selected >= end) return 2;
        begin = selected; end = selected + 1;
    }
    for (unsigned n = begin; n < end; ++n) failed += tests[n]();
    printf("%s %u legacy text/CP437/cursor/pitch/guest-memory checks; %u failing groups; no VM\n",
           failed ? "FAIL" : "PASS", checks, failed);
    return failed ? 1 : 0;
}
