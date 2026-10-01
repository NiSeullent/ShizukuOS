/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 display: mode, back buffer and backend selection. Backends: the paravirtual virtio-gpu (gfx_virtio.c, QEMU
 * `-device virtio-vga`) when present, else Bochs VBE ("BGA", PCI 1234:1111) as provided by QEMU `-machine pc -vga std`,
 * else the UEFI GOP framebuffer a UEFI direct boot handed over (gfx_gop.c). After a UEFI direct boot the firmware's
 * framebuffer is the active display, so the BGA backend declines and the GOP backend keeps the firmware's mode.
 *
 * Scope and honesty notes
 *  - ONLY the SHZ_STANDALONE profile (QEMU TCG/KVM booted by the standalone stub) has a display device. Under the
 *    Supervisor the I/O bitmap traps ports 0xCF8/0xCFC/0x1CE/0x1CF and no display is passed through, so there
 *    gfx_fb_init() returns STATUS_NO_SUCH_DEVICE without touching any port and the whole GUI stack stays inert.
 *  - Initialisation is lazy: the first GUI system call probes the PCI bus, programs the mode and allocates the back
 *    buffer. (kmain is not touched; a machine without the device simply never pays for any of this.)
 *  - Mode: 1024x768, 32 bits per pixel. A pixel is a little-endian dword 0x00RRGGBB (blue in the lowest byte), which is
 *    what the BGA scans out at 32 bpp and what virtio-gpu calls B8G8R8X8_UNORM.
 *  - Every drawing operation goes to a normal RAM back buffer and only changed rectangles are made visible by
 *    gfx_fb_present(): the BGA backend copies them into its uncached linear framebuffer (mmio_map has no write-combining);
 *    the virtio-gpu backend uses the back buffer itself as the guest backing of the host-side scanout resource and sends
 *    TRANSFER_TO_HOST_2D + RESOURCE_FLUSH for the rectangle.
 *  - The single font is the public-domain 8x8 IBM VGA lineage font (supervisor/src/font8x8_basic.h, ASCII 0..127),
 *    each row doubled to form an 8x16 cell. Nothing else exists: no other sizes, no bold/italic, no non-ASCII.
 */
#include "gfx.h"
#include "../dead_screen/native.h"
#include "pci.h"
#include "../supervisor/src/font8x8_basic.h"

gfx_fb_t g_fb;

#define BGA_PORT_INDEX 0x1ce
#define BGA_PORT_DATA 0x1cf
#define BGA_INDEX_ID 0
#define BGA_INDEX_XRES 1
#define BGA_INDEX_YRES 2
#define BGA_INDEX_BPP 3
#define BGA_INDEX_ENABLE 4
#define BGA_INDEX_VIRT_WIDTH 6
#define BGA_INDEX_VIRT_HEIGHT 7
#define BGA_INDEX_X_OFFSET 8
#define BGA_INDEX_Y_OFFSET 9
#define BGA_ENABLED 0x01
#define BGA_LFB_ENABLED 0x40
#define GFX_WIDTH 1024u
#define GFX_HEIGHT 768u

/* ---------------------------------------------------------------- page arena for large pixel buffers */
/* Kernel address range for pixel buffers: DIRECT_MAP + 64 GiB. Guest RAM is at most 256 MiB and PCI BARs sit below
 * 4 GiB (64-bit BARs at 32 GiB and up), so the range is unused; it lies inside PML4 slot 256, whose PDPT is shared by
 * every process, so mappings made here are visible under every address space without touching other page tables. */
#define ARENA_BASE (DIRECT_MAP + (64ull << 30))
#define ARENA_PAGES (256u * 1024u)                    /* 1 GiB of address space */
static uint32_t arena_bits[ARENA_PAGES / 32];
static uint32_t arena_hint;
static kmutex_t arena_lock;

static int arena_test(uint32_t i) { return (arena_bits[i >> 5] >> (i & 31)) & 1; }
static void arena_set(uint32_t i) { arena_bits[i >> 5] |= 1u << (i & 31); }
static void arena_clr(uint32_t i) { arena_bits[i >> 5] &= ~(1u << (i & 31)); }

void *gfx_pages_alloc(uint64_t bytes)
{
    const uint32_t n = (uint32_t)((bytes + PAGE_SIZE - 1) / PAGE_SIZE);
    uint32_t start = 0, run = 0, i, k;
    int found = 0;
    if (!n || n > ARENA_PAGES) return 0;
    mutex_lock(&arena_lock);
    for (k = 0; k < ARENA_PAGES && !found; ++k) {
        i = (arena_hint + k) % ARENA_PAGES;
        if (i == 0) run = 0;                            /* a run never wraps around the end of the arena */
        if (arena_test(i)) { run = 0; continue; }
        if (!run) start = i;
        if (++run == n) found = 1;
    }
    if (found) {
        for (k = 0; k < n; ++k) {
            const uint64_t pa = pmm_alloc();
            if (!pa || vm_map(kernel_pml4(), ARENA_BASE + (uint64_t)(start + k) * PAGE_SIZE, pa, PT_W | PT_NX)) {
                if (pa) pmm_free(pa);
                while (k--) {                           /* roll back */
                    uint64_t old;
                    if (!vm_unmap(kernel_pml4(), ARENA_BASE + (uint64_t)(start + k) * PAGE_SIZE, &old)) pmm_free(old);
                }
                mutex_unlock(&arena_lock);
                return 0;
            }
        }
        for (k = 0; k < n; ++k) arena_set(start + k);
        arena_hint = (start + n) % ARENA_PAGES;
    }
    mutex_unlock(&arena_lock);
    return found ? (void *)(ARENA_BASE + (uint64_t)start * PAGE_SIZE) : 0;
}

void gfx_pages_free(void *p, uint64_t bytes)
{
    const uint32_t n = (uint32_t)((bytes + PAGE_SIZE - 1) / PAGE_SIZE);
    uint32_t start, k;
    if (!p) return;
    KASSERT((uint64_t)p >= ARENA_BASE && (uint64_t)p < ARENA_BASE + (uint64_t)ARENA_PAGES * PAGE_SIZE);
    start = (uint32_t)(((uint64_t)p - ARENA_BASE) / PAGE_SIZE);
    mutex_lock(&arena_lock);
    for (k = 0; k < n; ++k) {
        uint64_t pa;
        KASSERT(arena_test(start + k));
        if (!vm_unmap(kernel_pml4(), ARENA_BASE + (uint64_t)(start + k) * PAGE_SIZE, &pa)) pmm_free(pa);
        arena_clr(start + k);
    }
    mutex_unlock(&arena_lock);
}

uint64_t gfx_pages_in_use(void)
{
    uint64_t n = 0;
    uint32_t i;
    for (i = 0; i < ARENA_PAGES / 32; ++i) {
        uint32_t v = arena_bits[i];
        while (v) { v &= v - 1; ++n; }
    }
    return n;
}

/* ---------------------------------------------------------------- Bochs VBE backend */
#ifdef SHZ_STANDALONE
static void bga_write(uint16_t idx, uint16_t v) { k_outw(BGA_PORT_INDEX, idx); k_outw(BGA_PORT_DATA, v); }
static uint16_t bga_read(uint16_t idx) { k_outw(BGA_PORT_INDEX, idx); return k_inw(BGA_PORT_DATA); }

static int bga_probe(gfx_fb_t *fb)
{
    pci_dev_t dev;
    uint64_t bar_size = 0, bar;
    int is_io = 0;
    uint32_t w, h;
    k64_boot_fb_t boot;
    if (pci_find(0x1234, 0x1111, &dev) || dev.class_code != 0x03) return -1;
    if (!k64_boot_framebuffer(&boot)) {                 /* the firmware's framebuffer is on screen: leave the adapter alone */
        kprintf("K64 gfx: Bochs VBE present, but the UEFI boot framebuffer is the active display: GOP backend\n");
        return -1;
    }
    bar = pci_bar(&dev, 0, &bar_size, &is_io);
    if (!bar || is_io || bar_size < (uint64_t)fb->pitch * fb->height) {
        kprintf("K64 gfx: BGA BAR0 unusable (base %llx size %llx io %d)\n", bar, bar_size, is_io);
        return -1;
    }
    pci_enable(&dev, 1, 1, 0);
    bga_write(BGA_INDEX_ID, 0xb0c5);
    fb->bga_version = bga_read(BGA_INDEX_ID);
    if (fb->bga_version < 0xb0c2) {                     /* 0xB0C2 is the first revision with a 32 bpp linear framebuffer */
        kprintf("K64 gfx: BGA revision %x too old\n", fb->bga_version);
        return -1;
    }
    bga_write(BGA_INDEX_ENABLE, 0);
    bga_write(BGA_INDEX_XRES, (uint16_t)fb->width);
    bga_write(BGA_INDEX_YRES, (uint16_t)fb->height);
    bga_write(BGA_INDEX_BPP, 32);
    bga_write(BGA_INDEX_ENABLE, BGA_ENABLED | BGA_LFB_ENABLED);
    w = bga_read(BGA_INDEX_XRES);
    h = bga_read(BGA_INDEX_YRES);
    if (w != fb->width || h != fb->height || bga_read(BGA_INDEX_BPP) != 32 || !(bga_read(BGA_INDEX_ENABLE) & BGA_LFB_ENABLED)) {
        kprintf("K64 gfx: BGA refused %ux%ux32 (got %ux%u bpp %u)\n", fb->width, fb->height, w, h, bga_read(BGA_INDEX_BPP));
        return -1;
    }
    fb->lfb_pa = bar;
    fb->lfb = mmio_map(bar, (uint64_t)fb->pitch * h);
    if (!fb->lfb) {
        kprintf("K64 gfx: cannot map the BGA framebuffer\n");
        return -1;
    }
    kprintf("K64 gfx: BGA %x %ux%ux32 LFB %llx (%llu KiB)\n", fb->bga_version, w, h, bar, bar_size >> 10);
    pci_claim(&dev, "gfx_fb (Bochs VBE)");
    ds_native_bind(fb->lfb, fb->width, fb->height, fb->pitch, (size_t)fb->pitch * h, 0);
    return 0;
}

static void bga_present(int x, int y, int w, int h)
{
    int row;
    for (row = y; row < y + h; ++row) {
        const uint32_t *src = g_fb.back + (uint64_t)row * g_fb.width + x;
        volatile uint32_t *dst = g_fb.lfb + (uint64_t)row * g_fb.width + x;
        uint64_t n = (uint64_t)w;
        __asm__ volatile("rep movsl" : "+D"(dst), "+S"(src), "+c"(n) :: "memory");
    }
}

static const gfx_backend_t gfx_backend_bga = { "Bochs VBE", SHZ_GPU_BACKEND_BGA, bga_probe, bga_present };

/* THE backend hook: display drivers in the order they are tried. The paravirtual virtio-gpu (gfx_virtio.c) comes first;
 * it only exists when QEMU runs with -device virtio-vga / virtio-gpu-pci, and then there is no BGA (the VGA-compatible
 * part of virtio-vga has a different PCI id). Then the Bochs VBE linear framebuffer, except after a UEFI direct boot (it
 * declines), and last the UEFI GOP framebuffer (gfx_gop.c), which exists only after a UEFI direct boot: any firmware
 * display with a linear 32 bpp framebuffer (a PCI adapter in firmware mode, QEMU ramfb, ...). */
static const gfx_backend_t *const gfx_backends[] = { &gfx_backend_virtio, &gfx_backend_bga, &gfx_backend_gop };

static kmutex_t init_lock;
static int init_state;                                  /* 0 not tried, 1 ready, -1 failed */
static int32_t init_status = STATUS_NO_SUCH_DEVICE;
#endif

int gfx_fb_init(void)
{
#ifdef SHZ_STANDALONE
    unsigned i;
    uint64_t bytes;
    mutex_lock(&init_lock);
    if (init_state) {
        mutex_unlock(&init_lock);
        return init_state > 0 ? 0 : init_status;
    }
    init_state = -1;
    init_status = STATUS_NO_SUCH_DEVICE;
    g_fb.width = GFX_WIDTH;
    g_fb.height = GFX_HEIGHT;
    g_fb.bpp = 32;
    g_fb.pitch = GFX_WIDTH * 4;
    bytes = (uint64_t)g_fb.pitch * g_fb.height;
    g_fb.back = gfx_pages_alloc(bytes);
    if (!g_fb.back) {
        kprintf("K64 gfx: cannot allocate the back buffer\n");
        init_status = STATUS_NO_MEMORY;
        goto out;
    }
    for (i = 0; i < g_fb.width * g_fb.height; ++i) g_fb.back[i] = SHZ_DESKTOP_RGB;
    for (i = 0; i < sizeof gfx_backends / sizeof gfx_backends[0] && !g_fb.backend; ++i)
        if (gfx_backends[i]->probe(&g_fb) == 0) g_fb.backend = gfx_backends[i];
    if (!g_fb.backend) {
        kprintf("K64 gfx: no display device (virtio-gpu 1af4:1050, Bochs VBE 1234:1111 or a UEFI GOP framebuffer); "
                "GUI subsystem inactive\n");
        gfx_pages_free(g_fb.back, bytes);
        g_fb.back = 0;
        goto out;
    }
    g_fb.ready = 1;
    init_state = 1;
    kprintf("K64 gfx: display backend %s, %ux%ux32, back buffer %llu KiB\n", g_fb.backend->name, g_fb.width, g_fb.height,
            ((uint64_t)g_fb.pitch * g_fb.height) >> 10);                /* a backend may have adopted another mode (GOP) */
    gfx_fb_present(0, 0, (int)g_fb.width, (int)g_fb.height);
out:
    mutex_unlock(&init_lock);
    return init_state > 0 ? 0 : init_status;
#else
    return STATUS_NO_SUCH_DEVICE;                       /* Supervisor profile: no display device is passed through */
#endif
}

void gfx_fb_present(int x, int y, int w, int h)
{
    int64_t left = x, top = y, right = left + w, bottom = top + h;
    if (!g_fb.ready || w <= 0 || h <= 0 || g_fb.width > INT32_MAX || g_fb.height > INT32_MAX) return;
    /* Form and intersect endpoints in 64 bits before narrowing. Signed int
     * wrapping here could send an offscreen rectangle to a framebuffer backend. */
    if (left < 0) left = 0;
    if (top < 0) top = 0;
    if (right > g_fb.width) right = g_fb.width;
    if (bottom > g_fb.height) bottom = g_fb.height;
    if (left >= right || top >= bottom) return;
    x = (int)left;
    y = (int)top;
    w = (int)(right - left);
    h = (int)(bottom - top);
    ++g_fb.stat_presents;
    g_fb.stat_present_pixels += (uint64_t)w * (uint64_t)h;
    g_fb.backend->present(x, y, w, h);
}

/* Kernel-drawn test pattern: what the host-side check expects, computed independently there.
 *   top half (y < H/2): eight vertical bars, bar index = x*8/W, colours white, yellow, cyan, green, magenta, red, blue,
 *                       grey 808080;
 *   bottom half:        horizontal grey ramp, level = x*255/(W-1) on all three channels;
 *   4x4 corner markers over both: top-left red, top-right green, bottom-left blue, bottom-right yellow. */
void gfx_fb_test_pattern(void)
{
    static const uint32_t bars[8] = { 0xffffff, 0xffff00, 0x00ffff, 0x00ff00, 0xff00ff, 0xff0000, 0x0000ff, 0x808080 };
    const uint32_t W = g_fb.width, H = g_fb.height;
    uint32_t x, y, k;
    if (!g_fb.ready) return;
    for (y = 0; y < H; ++y)
        for (x = 0; x < W; ++x) {
            uint32_t c;
            if (y < H / 2) c = bars[x * 8 / W];
            else { const uint32_t g = x * 255 / (W - 1); c = (g << 16) | (g << 8) | g; }
            g_fb.back[y * W + x] = c;
        }
    for (y = 0; y < 4; ++y)
        for (k = 0; k < 4; ++k) {
            g_fb.back[y * W + k] = 0xff0000;
            g_fb.back[y * W + (W - 4 + k)] = 0x00ff00;
            g_fb.back[(H - 4 + y) * W + k] = 0x0000ff;
            g_fb.back[(H - 4 + y) * W + (W - 4 + k)] = 0xffff00;
        }
    gfx_fb_present(0, 0, (int)W, (int)H);
}

void gfx_text(uint32_t *buf, int stride, int bufw, int bufh, int x, int y, const uint16_t *s, unsigned n, uint32_t rgb,
              int cx0, int cy0, int cx1, int cy1)
{
    unsigned i;
    if (cx0 < 0) cx0 = 0;
    if (cy0 < 0) cy0 = 0;
    if (cx1 > bufw) cx1 = bufw;
    if (cy1 > bufh) cy1 = bufh;
    for (i = 0; i < n; ++i, x += GFX_FONT_W) {
        const unsigned ch = s[i] < 0x80 ? s[i] : '?';
        int row, col;
        if (x + GFX_FONT_W <= cx0 || x >= cx1) continue;
        for (row = 0; row < GFX_FONT_H; ++row) {
            const int py = y + row;
            const uint8_t bits = font8x8_basic[ch][row >> 1];
            if (py < cy0 || py >= cy1) continue;
            for (col = 0; col < GFX_FONT_W; ++col) {
                const int px = x + col;
                if (px >= cx0 && px < cx1 && ((bits >> col) & 1))
                    buf[(uint64_t)py * (uint64_t)stride + (uint64_t)px] = rgb;
            }
        }
    }
}

int32_t gfx_syscall_display(process_t *cur, uint64_t out, uint64_t op)
{
    shz_display_info_t info;
    int32_t st = gfx_fb_init();
    if (st) return st;
    if (op == SHZ_DISP_TESTPATTERN) gfx_fb_test_pattern();
    else if (op != SHZ_DISP_QUERY) return STATUS_INVALID_PARAMETER;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    info.flags = 1u | (g_fb.backend && g_fb.backend->id == SHZ_GPU_BACKEND_VIRTIO ? SHZ_DISP_FLAG_PARAVIRT : 0u);
    info.width = g_fb.width;
    info.height = g_fb.height;
    info.bpp = g_fb.bpp;
    info.pitch = g_fb.pitch;
    info.bga_version = g_fb.bga_version;
    info.desktop_rgb = SHZ_DESKTOP_RGB;
    info.lfb_pa = g_fb.lfb_pa;
    return copy_to_user(cur, out, &info, sizeof info) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}
