/* SPDX-License-Identifier: GPL-2.0-only
 * Host control: Supervisor -> Kernel64 GOP display grant validation (src/display_grant.c) and the explicit
 * BOOT.INI k64_display opt-in (loader/bootini.c). Host only; no guest/VM evidence. */
#include <stdio.h>
#include <string.h>
#include "../../src/display_grant.h"
#include "../../../abi/shz_abi.h"
#include "../../loader/bootini.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); ++fails; } } while (0)

static shz_info_t base_info(void)
{
    shz_info_t i;
    memset(&i, 0, sizeof i);
    i.fb_base = 0x80000000ull; i.fb_size = 16ull << 20;          /* QEMU std-vga BAR0 in OVMF */
    i.fb_width = 1280; i.fb_height = 800; i.fb_pitch_pixels = 1280; i.fb_format = 1;
    i.region_base = SHZ_REGION_BASE; i.region_size = SHZ_REGION_SIZE;
    i.guest_ram_base = 0x10000000ull; i.guest_ram_size = 64ull << 20;
    i.k64_ram_base = 0x20000000ull; i.k64_ram_size = 256ull << 20;
    i.ipc_base = 0x30000000ull; i.ipc_size = 4ull << 20;
    i.loader_flags = SHZ_LOADER_K64_DISPLAY;
    return i;
}

static int parse(const char *t, bootini_policy_t *p)
{
    char err[160];
    return bootini_parse(t, strlen(t), p, err, sizeof err);
}

int main(void)
{
    shz_fb_grant_t g;
    shz_info_t i = base_info();
    bootini_policy_t p;
    CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) == 0);
    CHECK(g.base == 0x80000000ull && g.size == 1280ull * 4 * 800 && g.map_bytes == 1280ull * 4 * 800);
    CHECK(g.pitch == 5120 && g.format == SHZ_FB_BGRX8888 && g.width == 1280 && g.height == 800);
    i.fb_format = 0; CHECK(!shz_fb_grant_check(&i, 256ull << 20, &g) && g.format == SHZ_FB_RGBX8888);
    i = base_info(); i.fb_format = 2; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) && g.base == 0);   /* bitmask */
    i = base_info(); i.fb_format = 3; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);            /* BLT only */
    i = base_info(); i.fb_base = 0; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);
    i = base_info(); i.fb_base += 0x10; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);          /* unaligned */
    i = base_info(); i.fb_pitch_pixels = 1000; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);
    i = base_info(); i.fb_size = 1280ull * 4 * 800 - 4; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);
    i = base_info(); i.fb_width = 9000; i.fb_pitch_pixels = 9000; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);
    i = base_info(); i.fb_base = (64ull << 30) - 0x1000; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);
    i = base_info(); i.fb_base = 0xfffffffffffff000ull; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);
    i = base_info(); CHECK(shz_fb_grant_check(&i, 4ull << 30, &g) != 0);                 /* shadows guest RAM */
    i = base_info(); i.fb_base = SHZ_IPC_GPA_BASE; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);
    i = base_info(); i.fb_base = 0x20100000ull; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0); /* K64 host RAM */
    i = base_info(); i.fb_base = SHZ_REGION_BASE; CHECK(shz_fb_grant_check(&i, 16ull << 20, &g) != 0);
    i = base_info(); i.loader_flags |= SHZ_LOADER_NATIVE_WIN98; CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);
    i = base_info(); i.fb_size = 1281ull * 4 * 800 + 100; i.fb_pitch_pixels = 1281;                  /* round-up leaves fb */
    CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) == 0 && g.map_bytes == ((1281ull * 4 * 800 + 0xfff) & ~0xfffull));
    i = base_info(); i.fb_size = 1280ull * 4 * 799 + 4096 + 1; i.fb_height = 800; i.fb_pitch_pixels = 1280;
    CHECK(shz_fb_grant_check(&i, 256ull << 20, &g) != 0);
    CHECK(shz_fb_grant_check(0, 1, &g) != 0 && shz_fb_grant_check(&i, 1, 0) != 0);
    /* BOOT.INI: explicit opt-in only; default and old files keep the console. */
    CHECK(parse("mode=supervisor\n", &p) == 0 && p.k64_display == 0);
    CHECK(parse("mode=supervisor\nk64_display=yes\n", &p) == 0 && p.k64_display == 1);
    CHECK(parse("mode=supervisor\nk64_display=no\n", &p) == 0 && p.k64_display == 0);
    CHECK(parse("mode=supervisor\nk64_display=maybe\n", &p) != 0);
    CHECK(parse("mode=supervisor\nk64_display=yes\nk64_display=yes\n", &p) != 0);
    CHECK(parse("mode=csm\nk64_display=yes\n", &p) != 0);
    CHECK(parse("mode=supervisor\nwin98_vga=yes\nk64_display=yes\n", &p) != 0);
    printf("%s %d failures\n", fails ? "FAIL" : "PASS", fails);
    return fails != 0;
}
