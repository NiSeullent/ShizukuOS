/* SPDX-License-Identifier: GPL-2.0-only
 * Supervisor -> Kernel64 display grant (explicit BOOT.INI `k64_display=yes`, loader flag SHZ_LOADER_K64_DISPLAY).
 *
 * The UEFI loader hands the firmware GOP framebuffer to the Supervisor (shz_info_t.fb_*). With the explicit opt-in the
 * Supervisor validates that mode, identity-maps exactly the visible rows into the Kernel64 domain's EPT (R/W, no execute,
 * WC memory type), writes the descriptor into the domain's shz_bootinfo_t ABI 1.1 framebuffer tail with
 * SHZ_BIF_FB_SUPERVISOR_GRANT, and stops drawing its DOS text console there (video_delegate_display). Without the
 * opt-in, or when this check refuses, nothing is written: Kernel64 keeps returning STATUS_NO_SUCH_DEVICE.
 * Pure (no I/O, no globals): shared by kdom.c and the host control native_win98/tests/display_grant_host.c.
 */
#ifndef SHZ_DISPLAY_GRANT_H
#define SHZ_DISPLAY_GRANT_H
#include <stdint.h>
#include "../include/shz_info.h"

/* Kernel64 maps boot framebuffers below its private graphics page arena (kernel64/gfx_address.h
 * K64_GFX_ARENA_OFFSET = 64 GiB) and refuses anything above; the grant enforces the same bound. */
#define SHZ_FB_GRANT_GPA_LIMIT (64ull << 30)
#define SHZ_FB_GRANT_MAX_DIM 8192u

typedef struct {
    uint64_t base;          /* host-physical == guest-physical (identity grant) */
    uint64_t size;          /* visible bytes: pitch * height */
    uint64_t map_bytes;     /* size rounded up to 4 KiB: the EPT mapping */
    uint32_t width, height;
    uint32_t pitch;         /* bytes per scan line */
    uint32_t format;        /* enum shz_fb_format (SHZ_FB_RGBX8888 / SHZ_FB_BGRX8888) */
} shz_fb_grant_t;

/* Returns 0 and fills *out when the loader's GOP mode can be granted to a Kernel64 domain whose RAM is
 * guest-physical [0, dom_ram_size); otherwise returns a static reason and leaves *out zeroed. */
const char *shz_fb_grant_check(const shz_info_t *info, uint64_t dom_ram_size, shz_fb_grant_t *out);
#endif
