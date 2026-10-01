/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the production decoder and its private copied boot information.
 * The host linker discards kmain and all unrelated privileged kernel code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel64/main.c"

static unsigned checks;
#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); \
} } while (0)

static shz_bootinfo_t valid_bootinfo(void)
{
    shz_bootinfo_t b = {0};
    b.magic = SHZ_BOOTINFO_MAGIC;
    b.abi_major = SHZ_ABI_MAJOR;
    b.abi_minor = SHZ_ABI_MINOR;
    b.size = sizeof b;
    b.domain_id = SHZ_DOM_KERNEL64;
    b.fb_base = 0x800004;
    b.fb_width = 17;
    b.fb_height = 11;
    b.fb_pitch = 80;             /* padded rows, not width * 4 */
    b.fb_size = (uint64_t)b.fb_pitch * b.fb_height + 128;
    b.fb_format = SHZ_FB_BGRX8888;
    b.fb_bpp = 32;
    return b;
}

static void rejects_without_output_change(shz_bootinfo_t b)
{
    k64_boot_fb_t out, before;
    memset(&out, 0xa5, sizeof out);
    memcpy(&before, &out, sizeof out);
    bootinfo = b;
    CHECK(k64_boot_framebuffer(&out) == -1);
    CHECK(memcmp(&out, &before, sizeof out) == 0);
}

int main(void)
{
    shz_bootinfo_t b = valid_bootinfo();
    k64_boot_fb_t out;
    unsigned format;

    for (format = SHZ_FB_RGBX8888; format <= SHZ_FB_BGRX8888; ++format) {
        bootinfo = b;
        bootinfo.fb_format = format;
        CHECK(k64_boot_framebuffer(&out) == 0);
        CHECK(out.base == b.fb_base && out.size == b.fb_size);
        CHECK(out.width == 17 && out.height == 11 && out.pitch == 80);
        CHECK(out.bpp == 32 && out.format == format);
    }

    /* The old decoder accepted this and GOP truncated the 69-byte pitch to 68. */
    b.fb_pitch = 69;
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.fb_base++;
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.fb_base = UINT64_MAX & ~UINT64_C(3);
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.fb_size = UINT64_MAX;
    rejects_without_output_change(b);
    /* A raw non-wrapping range still must fit the actual mapping aperture.
     * Otherwise pci.c's page roundup/alias can wrap or overlap kernel code. */
    b = valid_bootinfo();
    b.fb_base = UINT64_MAX - 7;
    b.fb_width = b.fb_height = 1;
    b.fb_pitch = 4; b.fb_size = 4;
    rejects_without_output_change(b);
    b.fb_base = K64_VIRT_BASE - DIRECT_MAP;
    rejects_without_output_change(b);
    b.fb_base -= 4; b.fb_size = 8;
    rejects_without_output_change(b);
    /* Above-4-GiB firmware memory remains representable by this backend. */
    bootinfo = valid_bootinfo();
    bootinfo.fb_base = UINT64_C(0x100000004);
    CHECK(k64_boot_framebuffer(&out) == 0 && out.base == bootinfo.fb_base);
    /* The final pixel below the page-aligned aperture end is safe. */
    b.fb_size = 4;
    bootinfo = b;
    CHECK(k64_boot_framebuffer(&out) == 0 && out.base == b.fb_base);
    b = valid_bootinfo(); b.fb_base = 0;
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.fb_width = 0;
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.fb_height = 0;
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.fb_pitch = 64;
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.fb_size = 879;
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.fb_bpp = 24;
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.fb_format = SHZ_FB_NONE;
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.fb_format = UINT32_MAX;
    rejects_without_output_change(b);

    /* ABI 1.0 and tails ending before either format or bpp must fail closed. */
    b = valid_bootinfo(); b.size = __builtin_offsetof(shz_bootinfo_t, fb_base);
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.size = __builtin_offsetof(shz_bootinfo_t, fb_format);
    rejects_without_output_change(b);
    b = valid_bootinfo(); b.size = __builtin_offsetof(shz_bootinfo_t, fb_bpp) + 3;
    rejects_without_output_change(b);
    bootinfo = valid_bootinfo();
    bootinfo.size = __builtin_offsetof(shz_bootinfo_t, fb_bpp) + sizeof bootinfo.fb_bpp;
    CHECK(k64_boot_framebuffer(&out) == 0); /* cmdline is not needed to decode pixels */
    CHECK(k64_boot_framebuffer(NULL) == -1);

    printf("PASS: %u production Kernel64 boot-framebuffer contract checks\n", checks);
    return 0;
}
