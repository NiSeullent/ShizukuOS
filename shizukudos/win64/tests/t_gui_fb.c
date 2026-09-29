/* SPDX-License-Identifier: GPL-2.0-only
 * GUI step 1: the kernel display driver. Queries the display (which brings up the Bochs VBE framebuffer on first use),
 * checks the reported geometry, asks the kernel to draw its test pattern and holds it on screen so the host-side runner
 * (tests/run_k64_gui.py) can screendump QEMU and verify the pixels against a pattern computed on the host.
 * Without a display device (the plain standalone runner has none) it reports SKIP and exits 0. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"
#include "shzgfx.h"

int main(void)
{
    shz_display_info_t info;
    int32_t st;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    st = NtUserQueryDisplay(&info, SHZ_DISP_QUERY);
    if (st == (int32_t)0xC000000E) {
        printf("SKIP: no display device (%08x)\n", (unsigned)st);
        return 0;
    }
    if (st < 0) { printf("FAIL: NtUserQueryDisplay -> %08x\n", (unsigned)st); return 1; }
    printf("display %ux%ux%u pitch %u bga %x lfb %llx\n", info.width, info.height, info.bpp, info.pitch, info.bga_version,
           (unsigned long long)info.lfb_pa);
    if (info.width != 1024 || info.height != 768 || info.bpp != 32 || info.pitch != 4096 || !(info.flags & 1) ||
        info.desktop_rgb != SHZ_DESKTOP_RGB) {
        printf("FAIL: unexpected display geometry\n");
        return 1;
    }
    printf("PASS: display info\n");
    st = NtUserQueryDisplay(&info, SHZ_DISP_TESTPATTERN);
    if (st < 0) { printf("FAIL: test pattern -> %08x\n", (unsigned)st); return 1; }
    printf("GUI-READY: fb\n");
    Sleep(2500);                                    /* the host screendumps during this window */
    printf("PASS: test pattern presented\n");
    return 0;
}
