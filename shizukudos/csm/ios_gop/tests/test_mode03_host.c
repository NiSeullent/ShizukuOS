/* SPDX-License-Identifier: LGPL-3.0-only
 * Executes the actual patched SeaVGABIOS mode functions with host accessors.
 * No interrupts, framebuffer mappings, device I/O, firmware, or guest runs.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "shz_legacy_text_geometry.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define MM_TEXT 0
#define MM_DIRECT 6
#define MM_CGA 1
#define MF_NOCLEARMEM 0x8000
#define MF_VBEFLAGS 0xfe00
#define MF_LEGACY 1
#define MF_LINEARFB 0x4000
#define BF_EMULATE_TEXT 0x10
#define BF_EXTRA_STACK 0x40
#define SR_HARDWARE 1
#define SR_DAC 4
#define SR_REGISTERS 8
#define CONFIG_VGA_COREBOOT 1
#define CONFIG_VGA_EMULATE_TEXT 1
#define CONFIG_VGA_ALLOCATE_EXTRA_STACK 1
#define CONFIG_VGA_STDVGA_PORTS 0
#define VBE_RETURN_STATUS_FAILED 1
#define SEG_CTEXT 0xb800
#define GO_MEMSET 2
#define CB_TAG_FRAMEBUFFER 0x12
#define GET_GLOBAL(value) (value)
#define GET_FARVAR(segment, value) (value)
#define SET_VGA(value, replacement) ((value) = (replacement))
#define SET_BDA(value, replacement) ((bda.value) = (replacement))
#define GET_BDA(value) (bda.value)
#define GET_BDA_EXT(value) (bda_ext.value)
#define SET_BDA_EXT(value, replacement) ((bda_ext.value) = (replacement))
#define MASK_BDA_EXT(value, off, on) \
    SET_BDA_EXT(value, (GET_BDA_EXT(value) & ~(off)) | (on))
#define SET_IVT(number, target) ((void)0)
#define SEGOFF(segment, offset) (0)
#define ALIGN(value, boundary) (((value) + (boundary) - 1) & ~((boundary) - 1))
#define dprintf(...) ((void)0)

struct vgamode_s {
    u8 memmodel;
    u16 width, height;
    u8 depth, cwidth, cheight;
    u16 sstart;
};
struct generic_svga_mode { u16 mode; struct vgamode_s info; };
struct cb_header { int unused; };
struct cb_framebuffer {
    u32 tag, size;
    u64 physical_address;
    u32 x_resolution, y_resolution, bytes_per_line;
    u8 bits_per_pixel, red_mask_pos, red_mask_size, green_mask_pos,
       green_mask_size, blue_mask_pos, blue_mask_size, reserved_mask_pos,
       reserved_mask_size;
};
struct gfx_op { int x, y, xlen, ylen, op; };
struct bregs { u8 bh, al, ah; };
static struct {
    u16 video_mode, video_cols, video_rows, cursor_type, video_pagesize;
    u16 crtc_address, char_height, video_ctl, video_switches, modeset_ctl;
    u16 cursor_pos[8], video_pagestart, video_page;
} bda;
static struct { u8 flags; u16 vbe_mode; u32 vgamode_offset; } bda_ext;
static struct cb_header table;
static struct cb_framebuffer fixture;
static struct { u32 tag, size; } marker;
static struct generic_svga_mode svga_modes[2];
static int svga_mcount = 2, HaveRunInit, have_table, have_framebuffer, have_marker;
static int CBmode;
static struct vgamode_s CBmodeinfo, CBemulinfo;
static u32 CBlinelength, VBE_framebuffer, VBE_total_memory;
static u8 ShzLegacyText03;

static unsigned get_global_seg(void) { return 0; }
static void memcpy_far(unsigned ds, void *dst, unsigned ss, const void *src, size_t n)
{ (void)ds; (void)ss; memcpy(dst, src, n); }
static void memset16_far(unsigned s, void *p, unsigned v, size_t n)
{ (void)s; (void)p; (void)v; (void)n; }
static struct cb_header *find_cb_table(void) { return have_table ? &table : NULL; }
static void *find_cb_subtable(struct cb_header *h, u32 tag)
{
    (void)h;
    if (tag == CB_TAG_FRAMEBUFFER) return have_framebuffer ? &fixture : NULL;
    if (tag == SHZ_LEGACY_TEXT_CB_TAG) return have_marker ? &marker : NULL;
    return NULL;
}
static void init_gfx_op(struct gfx_op *op, struct vgamode_s *mode)
{ (void)mode; memset(op, 0, sizeof(*op)); }
static void handle_gfx_op(struct gfx_op *op) { (void)op; }
static int stdvga_get_crtc(void) { return 0; }
static int vga_emulate_text(void) { return bda_ext.flags & BF_EMULATE_TEXT; }
static struct vgamode_s *cbvga_find_mode(int mode);
static int cbvga_set_mode(struct vgamode_s *mode, int flags);
static struct vgamode_s *vgahw_find_mode(int mode) { return cbvga_find_mode(mode); }
static int vgahw_set_mode(struct vgamode_s *mode, int flags) { return cbvga_set_mode(mode, flags); }

/* Generated in a temporary directory from the patch applied to pinned
 * source fixtures. This includes real cbvga_setup, mode switching, BDA
 * updates, and AH=0f mode reporting rather than a reimplementation. */
#include "mode03-functions.inc"

static void reset_fixture(int explicit_gop)
{
    memset(&bda, 0, sizeof(bda)); memset(&bda_ext, 0, sizeof(bda_ext));
    memset(&CBmodeinfo, 0, sizeof(CBmodeinfo)); memset(&CBemulinfo, 0, sizeof(CBemulinfo));
    HaveRunInit = ShzLegacyText03 = 0;
    CBmode = CBlinelength = VBE_framebuffer = VBE_total_memory = 0;
    have_table = have_framebuffer = 1; have_marker = explicit_gop;
    marker.tag = SHZ_LEGACY_TEXT_CB_TAG; marker.size = 24;
    fixture = (struct cb_framebuffer){.physical_address = 0x80000000U,
        .x_resolution = 1280, .y_resolution = 800, .bytes_per_line = 5120,
        .bits_per_pixel = 32, .red_mask_size = 8, .green_mask_size = 8,
        .blue_mask_size = 8, .reserved_mask_size = 8};
    svga_modes[0] = (struct generic_svga_mode){0x118, {MM_DIRECT, 1024, 768, 32, 8, 16, 0}};
    svga_modes[1] = (struct generic_svga_mode){0x160, {MM_DIRECT, 1280, 800, 32, 8, 16, 0}};
}

static void assert_mode03(void)
{
    struct bregs regs = {0};
    assert(vga_set_mode(3, MF_LEGACY | MF_NOCLEARMEM) == 0);
    assert(CBemulinfo.memmodel == MM_DIRECT);
    assert(vga_emulate_text());
    assert(bda.video_mode == 3 && bda.video_cols == 80 && bda.video_rows == 24);
    assert(bda.char_height == 16 && bda.video_pagesize == 4096);
    assert(bda.video_page == 0 && bda.video_pagestart == 0);
    assert(bda.cursor_type == 0x0607);
    handle_100f(&regs);
    assert(regs.al == (3 | 0x80) && regs.ah == 80 && regs.bh == 0);
}

static void test_geometry(void)
{
    struct shz_legacy_text_geometry g;
    assert(shz_make_legacy_text_geometry(1280, 800, 5120, 32, &g));
    assert(g.viewport_width == 640 && g.viewport_height == 400);
    assert(g.physical_pitch == 5120 && g.columns == 80 && g.rows == 25);
    assert(g.character_width == 8 && g.character_height == 16 && g.page_bytes == 4096);
    assert(shz_make_legacy_text_geometry(640, 400, 1280, 15, &g));
    assert(g.physical_pitch == 1280);
    assert(shz_make_legacy_text_geometry(640, 480, 1280, 16, &g));
    assert(shz_make_legacy_text_geometry(800, 600, 2430, 24, &g));
    assert(g.physical_pitch == 2430); /* padded rows stay padded */
}

static void test_rejected_geometry(void)
{
    const unsigned cases[][4] = {
        {639, 800, 5120, 32}, {1280, 399, 5120, 32}, {0, 0, 0, 32},
        {65536, 800, 262144, 32}, {1280, 65536, 5120, 32},
        {1280, 800, 5120, 8}, {1280, 800, 5120, 64},
        {1280, 800, 5116, 32}, {1280, 800, 5121, 32},
        {640, 65535, 65536, 32}, {640, 400, 0, 32},
    };
    struct shz_legacy_text_geometry g, before;
    memset(&g, 0xa5, sizeof(g)); before = g;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert(!shz_make_legacy_text_geometry(cases[i][0], cases[i][1], cases[i][2], cases[i][3], &g));
        assert(memcmp(&g, &before, sizeof(g)) == 0);
    }
    assert(!shz_make_legacy_text_geometry(1280, 800, 5120, 32, NULL));
}

static void test_profile_and_native_mode(void)
{
    reset_fixture(1); assert(cbvga_setup() == 0);
    struct vgamode_s native = CBmodeinfo;
    int native_mode = CBmode;
    assert(native.width == 1280 && native.height == 800 && native.depth == 32);
    assert(CBemulinfo.width == 640 && CBemulinfo.height == 400);
    assert(CBlinelength == 5120 && VBE_framebuffer == 0x80000000U);
    assert(VBE_total_memory == 4096000);
    assert_mode03();
    assert(vga_set_mode(native_mode, MF_LINEARFB | MF_NOCLEARMEM) == 0);
    assert(!vga_emulate_text() && !shz_cbvga_is_legacy_text_mode(&CBmodeinfo));
    assert(memcmp(&native, &CBmodeinfo, sizeof(native)) == 0);
    assert(cbvga_find_mode(native_mode) == &CBmodeinfo);
    assert(CBlinelength == 5120 && VBE_framebuffer == 0x80000000U);
    assert_mode03(); /* native->legacy transition restores the correct metadata */
}

static void test_baseline_and_cached_gate(void)
{
    reset_fixture(0); assert(cbvga_setup() == 0);
    assert(vga_set_mode(3, MF_LEGACY | MF_NOCLEARMEM) == 0);
    assert(bda.video_cols == 160 && bda.video_rows == 49 && bda.video_pagesize == 0);
    assert(!shz_cbvga_is_legacy_text_mode(&CBemulinfo));
    reset_fixture(1); assert(cbvga_setup() == 0);
    have_marker = have_table = 0; /* IO.SYS may reuse the low coreboot page. */
    assert_mode03();
}

static void test_setup_rejections(void)
{
    reset_fixture(1); fixture.x_resolution = 639;
    assert(cbvga_setup() == -1 && !ShzLegacyText03 && VBE_framebuffer == 0);
    reset_fixture(1); fixture.y_resolution = 399;
    assert(cbvga_setup() == -1 && !ShzLegacyText03);
    reset_fixture(1); fixture.bytes_per_line = 5116;
    assert(cbvga_setup() == -1 && !ShzLegacyText03);
    reset_fixture(1); marker.size = 8;
    assert(cbvga_setup() == -1 && !ShzLegacyText03);
    reset_fixture(1); have_framebuffer = 0;
    assert(cbvga_setup() == -1 && !ShzLegacyText03);
    reset_fixture(0); have_framebuffer = 0;
    assert(cbvga_setup() == 0 && CBmodeinfo.memmodel == MM_TEXT);
    assert(CBmodeinfo.width == 80 && CBmodeinfo.height == 25);
}

int main(void)
{
    test_geometry(); test_rejected_geometry();
    test_profile_and_native_mode(); test_baseline_and_cached_gate(); test_setup_rejections();
    puts("PASS: geometry bounds, patched mode03/BDA, native-mode preservation, baseline, cached gate, setup rejection");
    return 0;
}
