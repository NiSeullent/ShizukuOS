/* SPDX-License-Identifier: GPL-2.0-only
 * Validation of the Supervisor -> Kernel64 GOP framebuffer grant. See display_grant.h. */
#include "display_grant.h"
#include "../../abi/shz_abi.h"

/* [a, a+an) and [b, b+bn) intersect; callers guarantee neither range wraps. */
static int overlaps(uint64_t a, uint64_t an, uint64_t b, uint64_t bn)
{
    return an && bn && a < b + bn && b < a + an;
}

static int wraps(uint64_t base, uint64_t size) { return base > UINT64_MAX - size; }

const char *shz_fb_grant_check(const shz_info_t *info, uint64_t dom_ram_size, shz_fb_grant_t *out)
{
    uint64_t visible, map_bytes, ipc_lo, ipc_n;
    unsigned i;
    if (!out) return "no output";
    for (i = 0; i < sizeof *out; ++i) ((volatile uint8_t *)out)[i] = 0;
    if (!info) return "no loader handoff";
    if (info->loader_flags & SHZ_LOADER_NATIVE_WIN98)
        return "installed-Win98 profile owns the display (native VGA/GOP epoch)";
    if (!info->fb_base || !info->fb_size || !info->fb_width || !info->fb_height)
        return "the loader recorded no GOP linear framebuffer";
    if (info->fb_format > 1)
        return "GOP pixel format is not 32-bit RGBX/BGRX (bitmask or BLT-only mode)";
    if (info->fb_width > SHZ_FB_GRANT_MAX_DIM || info->fb_height > SHZ_FB_GRANT_MAX_DIM)
        return "GOP mode larger than 8192x8192";
    if (info->fb_pitch_pixels < info->fb_width || info->fb_pitch_pixels > (UINT32_MAX / 4u))
        return "GOP pitch smaller than the visible width";
    if (info->fb_base & 0xfffull)
        return "framebuffer base is not 4 KiB aligned (EPT granularity)";
    visible = (uint64_t)info->fb_pitch_pixels * 4u * info->fb_height;
    if (visible > info->fb_size)
        return "pitch * height exceeds the GOP framebuffer size";
    map_bytes = (visible + 0xfffull) & ~0xfffull;
    if (wraps(info->fb_base, map_bytes) || wraps(info->fb_base, info->fb_size))
        return "framebuffer range wraps the physical address space";
    if (info->fb_base + map_bytes > ((info->fb_base + info->fb_size + 0xfffull) & ~0xfffull))
        return "4 KiB-rounded mapping would leave the GOP framebuffer";
    if (info->fb_base + map_bytes > SHZ_FB_GRANT_GPA_LIMIT)
        return "framebuffer ends above 64 GiB (Kernel64 graphics arena)";
    /* Identity grant: the guest-physical window must not shadow the domain's RAM or its IPC windows. */
    if (overlaps(info->fb_base, map_bytes, 0, dom_ram_size))
        return "framebuffer overlaps the Kernel64 domain's guest RAM";
    ipc_lo = SHZ_IPC_GPA_BASE;
    ipc_n = (uint64_t)SHZ_MAX_CHANNELS * SHZ_IPC_REGION_SIZE;
    if (overlaps(info->fb_base, map_bytes, ipc_lo, ipc_n) || overlaps(info->fb_base, map_bytes, SHZ_BOOTINFO_GPA, 0x1000))
        return "framebuffer overlaps the IPC/bootinfo guest windows";
    /* Host side: the firmware framebuffer can never alias memory the loader handed to the Supervisor or a domain. */
    {
        const uint64_t spans[][2] = {
            {info->region_base, info->region_size}, {info->guest_ram_base, info->guest_ram_size},
            {info->k32_ram_base, info->k32_ram_size}, {info->k64_ram_base, info->k64_ram_size},
            {info->ipc_base, info->ipc_size}, {info->disk_base, info->disk_size},
            {SHZ_REGION_BASE, SHZ_REGION_SIZE},
        };
        for (i = 0; i < sizeof spans / sizeof spans[0]; ++i) {
            if (spans[i][1] && wraps(spans[i][0], spans[i][1])) return "loader memory span wraps";
            if (overlaps(info->fb_base, map_bytes, spans[i][0], spans[i][1]))
                return "framebuffer aliases Supervisor/domain/disk memory";
        }
    }
    out->base = info->fb_base;
    out->size = visible;
    out->map_bytes = map_bytes;
    out->width = info->fb_width;
    out->height = info->fb_height;
    out->pitch = info->fb_pitch_pixels * 4u;
    out->format = info->fb_format == 0 ? SHZ_FB_RGBX8888 : SHZ_FB_BGRX8888;   /* GOP PixelRed.../PixelBlue... */
    return 0;
}
