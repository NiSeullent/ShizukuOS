/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 <-> user-mode ABI of the Win32 GUI subsystem (kernel64/gfx_*.c, win64/dlls/user32, win64/dlls/gdi32).
 *
 * This header is included by BOTH the freestanding kernel and the mingw-w64 user-mode DLLs, so it uses only fixed-width
 * integer types. Syscall numbers live in kernel64/ntsys.h (SYSCALL_LIST_GRAPHICS); the user-mode stubs are generated
 * from that list into ntdll as NtUser and NtGdi exports. Every structure here is passed by pointer to a system call.
 *
 * The GUI stack needs a display device (QEMU `-vga std`, Bochs VBE). The Supervisor profile has none, so on it every
 * call fails with STATUS_NO_SUCH_DEVICE and user-mode programs report that they cannot show a window.
 */
#ifndef SHZ_GFX_ABI_H
#define SHZ_GFX_ABI_H
#include <stdint.h>

/* ---- display ---- */
typedef struct {
    uint32_t size;                      /* sizeof(shz_display_info_t), filled in by the caller */
    uint32_t flags;                     /* bit 0: the framebuffer is live */
    uint32_t width, height, bpp, pitch; /* pitch in bytes; pixels are 0x00RRGGBB dwords */
    uint32_t bga_version;               /* Bochs VBE dispi ID register (0xB0C0..0xB0C5) */
    uint32_t desktop_rgb;               /* solid desktop colour drawn where no window covers the screen (0x00RRGGBB) */
    uint64_t lfb_pa;                    /* guest-physical address of the linear framebuffer (BAR 0) */
} shz_display_info_t;
#define SHZ_DISP_QUERY 0                /* initialise the display on first use, return the info */
#define SHZ_DISP_TESTPATTERN 1          /* draw the kernel test pattern (see gfx_fb.c) and present it */
#define SHZ_DESKTOP_RGB 0x00008080u

#ifdef _WIN32
/* User-mode side: the ntdll stubs generated from SYSCALL_LIST_GRAPHICS. Status is an NTSTATUS (negative = failure). */
#define SHZ_NT __stdcall
int32_t SHZ_NT NtUserQueryDisplay(void *info_out, uint64_t op);
#endif

#endif
