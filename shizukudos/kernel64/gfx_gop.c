/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 display backend: the UEFI GOP linear framebuffer that the boot manager's direct Kernel64 boot handed over
 * (k64_boot_framebuffer(), shz_bootinfo_t ABI 1.1). Third entry of the backend table in gfx_fb.c.
 *
 *  - When it is used: only after a UEFI direct boot, and then whenever the paravirtual virtio-gpu is absent. The
 *    firmware left that framebuffer scanning out, so it IS the active display: its mode is kept as it is (the Bochs VBE
 *    backend declines such boots instead of reprogramming the adapter underneath it). Under the Multiboot stub there is
 *    no boot framebuffer and this backend never probes successfully.
 *  - Mode: the firmware's (width, height, pitch in bytes, BGRX or RGBX, 32 bpp only: k64_boot_framebuffer() refuses the
 *    rest). The GUI adopts the width and height; the back buffer is reallocated to that size before anything is drawn.
 *  - Presenting: the damaged rectangle of the back buffer is copied row by row into the framebuffer, honouring the pitch;
 *    BGRX rows are copied unchanged, RGBX rows swap red and blue (gfx_pixfmt.h). The framebuffer is mapped uncached with
 *    mmio_map() (no write-combining exists here), as the Bochs VBE backend's is.
 *  - Device binding: if the framebuffer lies in a memory BAR of a PCI display function (QEMU -vga std, a real GPU in
 *    firmware mode) that function is recorded as driven by "gfx_fb (UEFI GOP)" (pci_claim); a firmware framebuffer in
 *    reserved RAM (QEMU ramfb) has no PCI owner. No mode set, no cursor plane, no acceleration: the device itself is never
 *    programmed, only the memory the firmware already set up is written.
 */
#include "gfx.h"
#include "pci.h"
#include "gfx_pixfmt.h"

#ifdef SHZ_STANDALONE
static struct {
    volatile uint32_t *fb;
    uint32_t pitch_px;
    int rgbx;
} gop;

/* The PCI display function (class 03) with a memory BAR containing `pa`. BARs are sized with memory decoding switched off
 * so the live framebuffer never moves while a BAR briefly reads back all ones. */
static int gop_owner(uint64_t pa, pci_dev_t *out)
{
    pci_dev_t devs[64];
    unsigned n = pci_enumerate(devs, 64), i, b;
    for (i = 0; i < n; ++i) {
        const uint32_t cmd = pci_cfg_read32(&devs[i], 4);
        int found = 0;
        if (devs[i].class_code != 0x03) continue;
        pci_cfg_write32(&devs[i], 4, cmd & 0xffff & ~2u);               /* memory space off (status bits are write-1-clear: 0) */
        for (b = 0; b < 6 && !found; ++b) {
            const uint32_t raw = pci_cfg_read32(&devs[i], 0x10 + b * 4);
            uint64_t size = 0, base;
            int io = 0;
            if (!raw) continue;
            base = pci_bar(&devs[i], b, &size, &io);
            if (!io && size && pa >= base && pa - base < size) found = 1;
            if (!(raw & 1) && ((raw >> 1) & 3) == 2) ++b;                /* a 64-bit BAR takes two slots */
        }
        pci_cfg_write32(&devs[i], 4, cmd & 0xffff);
        if (found) { *out = devs[i]; return 0; }
    }
    return -1;
}

static int gop_probe(gfx_fb_t *fb)
{
    k64_boot_fb_t b;
    pci_dev_t dev;
    int owned;
    if (k64_boot_framebuffer(&b)) return -1;
    if (b.width > 8192 || b.height > 8192) {
        kprintf("K64 gfx: UEFI GOP mode %ux%u is larger than this GUI handles\n", b.width, b.height);
        return -1;
    }
    gop.fb = mmio_map(b.base, (uint64_t)b.pitch * b.height);
    if (!gop.fb) {
        kprintf("K64 gfx: cannot map the UEFI GOP framebuffer at %llx\n", b.base);
        return -1;
    }
    if (b.width != fb->width || b.height != fb->height) {             /* adopt the firmware's mode */
        const uint64_t n = (uint64_t)b.width * b.height;
        uint32_t *back = gfx_pages_alloc(n * 4);
        uint64_t i;
        if (!back) {
            kprintf("K64 gfx: no memory for a %ux%u back buffer\n", b.width, b.height);
            return -1;
        }
        for (i = 0; i < n; ++i) back[i] = SHZ_DESKTOP_RGB;
        gfx_pages_free(fb->back, (uint64_t)fb->pitch * fb->height);
        fb->back = back;
        fb->width = b.width;
        fb->height = b.height;
        fb->pitch = b.width * 4;
    }
    gop.pitch_px = b.pitch / 4;
    gop.rgbx = b.format == SHZ_FB_RGBX8888;
    fb->lfb_pa = b.base;
    fb->lfb = 0;                                                      /* the Bochs VBE copy loop must never see this mapping */
    fb->bga_version = 0;
    owned = gop_owner(b.base, &dev) == 0;
    kprintf("K64 gfx: UEFI GOP framebuffer %ux%u, pitch %u, %s, at %llx (%llu KiB)\n", b.width, b.height, b.pitch,
            gop.rgbx ? "RGBX" : "BGRX", b.base, ((uint64_t)b.pitch * b.height) >> 10);
    if (owned) {
        kprintf("K64 gfx: UEFI GOP framebuffer lies in a BAR of PCI display %x:%x.%x %04x:%04x\n", dev.bus, dev.dev, dev.fn,
                dev.vendor, dev.device);
        pci_claim(&dev, "gfx_fb (UEFI GOP)");
    } else {
        kprintf("K64 gfx: UEFI GOP framebuffer lies in no PCI display BAR (a firmware RAM framebuffer)\n");
    }
    return 0;
}

static void gop_present(int x, int y, int w, int h)
{
    int row;
    for (row = y; row < y + h; ++row) {
        const uint32_t *src = g_fb.back + (uint64_t)row * g_fb.width + (uint32_t)x;
        volatile uint32_t *dst = gop.fb + (uint64_t)row * gop.pitch_px + (uint32_t)x;
        if (gop.rgbx) {
            gfx_row_convert(dst, src, w, 1);
        } else {
            uint64_t n = (uint64_t)w;
            __asm__ volatile("rep movsl" : "+D"(dst), "+S"(src), "+c"(n) :: "memory");
        }
    }
}

const gfx_backend_t gfx_backend_gop = { "UEFI GOP", SHZ_GPU_BACKEND_GOP, gop_probe, gop_present };
#endif
