/* SPDX-License-Identifier: GPL-2.0-only -- Kernel64 USB HID pointer thread over the original xHCI core (drivers/xhci_*). */
#include "laptop_input_native.h"

#ifdef SHZ_STANDALONE
#include "pci.h"
#include "gfx.h"
#include "../../drivers/xhci_usb/hid_interrupt.h"
#include "../../drivers/shz_laptop/ps2_touchpad.h"

#define LIN_MAX_CONTROLLERS 4
#define LIN_POLL_MS 2
#define LIN_RETRY_MS 2000
#define LIN_MAX_PAGES 32u

struct lin_dma { void *cpu; uint64_t pa; unsigned pages; uint64_t base_pa; unsigned base_pages; };
static struct {
    volatile uint32_t *regs; uint32_t bytes;
    struct lin_dma dma[2];
} g_hw;
static struct xhci_device g_xhci;
static struct xhciu_configuration_descriptor g_probe;
static struct xhciu_hid g_hid;
static struct shz_pointer_adapter g_adapter;
static struct k64_lin_status g_status;
static uint64_t g_generation;
static volatile uint64_t g_live_generation;     /* generation allowed to publish; 0 = none */

/* ---------------------------------------------------------------- xhci_ops: MMIO, coherent contiguous DMA, clock */
static int op_read32(void *c, uint32_t off, uint32_t *v)
{
    (void)c;
    if ((off & 3u) || off > g_hw.bytes - 4u) return 0;
    *v = g_hw.regs[off / 4u];
    return 1;
}
static int op_write32(void *c, uint32_t off, uint32_t v)
{
    (void)c;
    if ((off & 3u) || off > g_hw.bytes - 4u) return 0;
    g_hw.regs[off / 4u] = v;
    return 1;
}
static int op_write8(void *c, uint32_t off, uint8_t v)
{
    (void)c;
    if (off >= g_hw.bytes) return 0;
    ((volatile uint8_t *)g_hw.regs)[off] = v;
    return 1;
}
/* The device block must not cross a 64 KiB boundary (control buffer rule); over-allocate and pick the first fitting page. */
static int op_allocate(void *c, size_t bytes, size_t align, uint64_t limit, struct xhci_dma *out)
{
    unsigned want, extra, total, skip, slot = bytes == XHCI_DMA_BYTES ? 0u : 1u;
    uint64_t pa, start;
    (void)c;
    if (align != 4096u || (bytes != XHCI_DMA_BYTES && bytes != XHCI_DEVICE_DMA_BYTES) || g_hw.dma[slot].cpu) return 0;
    want = (unsigned)(bytes / 4096u);
    extra = bytes == XHCI_DMA_BYTES ? 0u : 16u;
    total = want + extra;
    if (total > LIN_MAX_PAGES) return 0;
    pa = pmm_alloc_contig(total);
    if (!pa) return 0;
    start = pa;
    for (skip = 0; skip <= extra; ++skip, start += 4096u)
        if (bytes == XHCI_DMA_BYTES || (start & 0xffffu) + bytes <= 0x10000u) break;
    if (skip > extra || start > limit || bytes - 1u > limit - start) { pmm_free_contig(pa, total); return 0; }
    g_hw.dma[slot].cpu = (void *)p2v(start);
    g_hw.dma[slot].pa = start;
    g_hw.dma[slot].base_pa = pa;
    g_hw.dma[slot].base_pages = total;
    out->cpu = g_hw.dma[slot].cpu;
    out->bus = start;
    out->bytes = bytes;
    return 1;
}
static void op_release(void *c, struct xhci_dma *d)
{
    unsigned i;
    (void)c;
    for (i = 0; i < 2u; ++i)
        if (g_hw.dma[i].cpu && g_hw.dma[i].cpu == d->cpu) {
            pmm_free_contig(g_hw.dma[i].base_pa, g_hw.dma[i].base_pages);
            memset(&g_hw.dma[i], 0, sizeof g_hw.dma[i]);
            return;
        }
}
static int op_sync(void *c, const struct xhci_dma *d, size_t off, size_t n, int to_device)
{
    (void)c; (void)d; (void)off; (void)n; (void)to_device;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);                  /* x86 DMA is cache coherent; order CPU accesses vs MMIO */
    return 1;
}
static uint64_t op_now_us(void *c) { (void)c; return shz_time_ns() / 1000u; }
static void op_relax(void *c) { (void)c; __asm__ volatile("pause"); }

/* ---------------------------------------------------------------- pointer sink: adapter -> gin */
static int sink_validate(void *c, uint64_t owner, uint64_t generation)
{
    (void)c;
    return owner == K64_LIN_OWNER && generation == g_live_generation && generation ? SHZ_DRIVER_OK : SHZ_REVOKED;
}
static int sink_emit(void *c, int32_t x, int32_t y, uint8_t buttons)
{
    (void)c;
    return gin_pointer_inject(x, y, buttons) == 0 ? SHZ_DRIVER_OK : SHZ_IO;
}
static int hid_report(void *c, uint64_t generation, const struct shz_hid_layout *layout, const uint8_t *r, size_t n)
{
    int e;
    (void)c;
    if (generation != g_generation) return -1;
    e = shz_pointer_adapter_report(&g_adapter, layout, r, n);
    if (e == SHZ_DRIVER_OK) return 0;
    return (e == SHZ_REVOKED || e == SHZ_STALE) ? -1 : 1;      /* anything else refuses this report only */
}
/* X/Y logical range heuristic: relative mice have small ranges (1:1); absolute pads/tablets spread over the framebuffer. */
static uint32_t axis_units(const struct shz_hid_layout *l, uint16_t usage, uint32_t pixels)
{
    unsigned i;
    for (i = 0; i < l->count; ++i) {
        const struct shz_hid_field *f = &l->fields[i];
        if (f->page == 1u && f->usage == usage && f->maximum > f->minimum) {
            const uint32_t range = (uint32_t)(f->maximum - f->minimum);
            if (range < 256u || !pixels) return 1u;
            return range / pixels ? range / pixels : 1u;
        }
    }
    return 1u;
}

/* ---------------------------------------------------------------- PS/2 Synaptics absolute route (i8042 aux, via gfx_input.c) */
#define LIN_PS2_TIMEOUT_US 100000u
#define LIN_PS2_TOUCH_Z 25u
static struct shz_ps2_device g_ps2;
static struct shz_pointer_adapter g_ps2_adapter;
static volatile uint64_t g_ps2_live;             /* generation allowed to publish; 0 = none */
static uint64_t g_ps2_generation;
static volatile int g_ps2_route;                 /* 1 only while Synaptics absolute mode owns the aux stream */
static int ps2_validate(void *c, uint64_t owner, uint64_t generation)
{
    (void)c;
    return owner == K64_LIN_OWNER && generation == g_ps2_live && generation ? SHZ_DRIVER_OK : SHZ_REVOKED;
}
static int ps2_emit(void *c, int32_t x, int32_t y, uint8_t buttons)
{
    (void)c;
    return gin_pointer_inject_locked(x, y, buttons) == 0 ? SHZ_DRIVER_OK : SHZ_IO;   /* gfx_lock is already held by gin_main */
}
int k64_laptop_ps2_open(const struct k64_lin_ps2_transport *t)
{
    struct shz_ps2_ops ops;
    struct shz_pointer_sink ps = { 0, ps2_validate, ps2_emit };
    int r;
    if (!t || !t->write_aux || !t->read_aux || !t->drain || g_ps2_route) return SHZ_INVALID;
    if (g_ps2.state == SHZ_PS2_POISONED) return SHZ_QUARANTINED;
    ops.context = t->context; ops.validate = ps2_validate; ops.write_aux = t->write_aux; ops.read_aux = t->read_aux; ops.drain = t->drain;
    g_ps2_live = ++g_ps2_generation;
    r = shz_ps2_open(&g_ps2, &ops, K64_LIN_OWNER, g_ps2_generation, LIN_PS2_TIMEOUT_US, LIN_PS2_TOUCH_Z);
    if (r) { g_ps2_live = 0; g_status.ps2_state = 3; g_status.ps2_touchpad = "failed: aux transport error during probe; device left in unknown mode, needs FF reset"; return r; }
    if (g_ps2.kind != SHZ_PS2_SYNAPTICS) {
        g_ps2_live = 0;                                           /* standard mouse: the gin relative decoder keeps the stream */
        g_status.ps2_state = 2;
        g_status.ps2_touchpad = "standard PS/2 relative mouse: absolute route not taken";
        return 1;
    }
    memset(&g_ps2_adapter, 0, sizeof g_ps2_adapter);
    /* Touchpad-style relative motion from absolute deltas: a fixed 4 pad units per pointer pixel (a ~6000 unit pad spans ~1500
     * px); per-device calibration from the reported units/mm is not claimed. */
    {
        const uint32_t ux = 4u, uy = 4u;
        if (shz_pointer_adapter_bind(&g_ps2_adapter, &ps, K64_LIN_OWNER, g_ps2_generation, ux, uy) != SHZ_DRIVER_OK) {
            g_ps2_live = 0; g_status.ps2_state = 3; g_status.ps2_touchpad = "failed: pointer adapter bind refused";
            return SHZ_IO;
        }
    }
    g_ps2_route = 1;
    g_status.ps2_state = 1;
    g_status.ps2_touchpad = "Synaptics absolute mode active (aux bytes routed to ps2_touchpad -> pointer adapter -> gin)";
    return 0;
}
int k64_laptop_ps2_feed(uint8_t byte)
{
    int r;
    if (!g_ps2_route) return 0;
    r = shz_ps2_feed_adapter(&g_ps2, &g_ps2_adapter, byte);
    if (r == SHZ_DRIVER_OK) ++g_status.ps2_reports;
    else if (r == SHZ_REVOKED || r == SHZ_STALE) g_ps2_route = 0;  /* stop consuming; bytes fall back to the standard decoder, which will discard them by sync */
    else if (r != SHZ_NO_EVENT) ++g_status.ps2_refused;            /* resync / unsupported frame: this frame only */
    return 1;                                                      /* the byte belonged to the absolute stream either way */
}
void k64_laptop_ps2_revoke(void)
{
    g_ps2_live = 0;
    g_ps2_route = 0;
    shz_pointer_adapter_close(&g_ps2_adapter);
    g_status.ps2_state = 3;
    g_status.ps2_touchpad = "revoked: the device may still be in absolute mode until an FF reset";
}

static int open_device(const pci_dev_t *pd)
{
    struct xhci_ops ops = { 0, op_read32, op_write32, op_allocate, op_release, op_sync, op_now_us, op_relax, op_write8 };
    struct xhci_config cfg;
    struct xhciu_configuration_request rq = { sizeof rq, XHCIU_ABI_VERSION, 0, 0, 0 };
    struct xhciu_hid_sink sink = { 0, hid_report };
    struct xhciu_result pr;
    uint64_t bar, size;
    int is_io, r;
    bar = pci_bar(pd, 0, &size, &is_io);
    if (!bar || is_io || size < 0x400u || size > 0x100000u) return XHCI_UNSUPPORTED;
    pci_enable(pd, 0, 1, 1);
    if (!g_hw.regs) { g_hw.regs = mmio_map(bar, size); g_hw.bytes = (uint32_t)size; }
    if (!g_hw.regs) return XHCI_NO_MEMORY;
    cfg.pci_class = ((uint32_t)pd->class_code << 16) | ((uint32_t)pd->subclass << 8) | pd->prog_if;
    cfg.pci_command = pci_cfg_read32(pd, 4) & 0xffffu;
    cfg.mmio_bytes = g_hw.bytes;
    cfg.timeout_us = 1000000u;
    cfg.exclusive = 1;
    memset(&g_xhci, 0, sizeof g_xhci);
    if ((r = xhci_open_one_slot(&g_xhci, &ops, &cfg)) != 0) return r;
    pr = xhciu_probe_configuration(&g_xhci, &rq, &g_probe);       /* existing EP0 probe; closes its disposable session */
    if (pr.status) return pr.status == XHCI_QUARANTINED ? pr.status : (pr.transport_error ? pr.transport_error : pr.status);
    memset(&g_xhci, 0, sizeof g_xhci);
    if ((r = xhci_open_one_slot(&g_xhci, &ops, &cfg)) != 0) return r;
    g_generation = g_generation + 1u;
    g_live_generation = 0;
    if ((r = xhciu_hid_open(&g_hid, &g_xhci, &g_probe, g_generation, &sink)) != 0) return r;
    {
        struct shz_pointer_sink ps = { 0, sink_validate, sink_emit };
        const uint32_t ux = axis_units(&g_hid.layout, 0x30, g_fb.width), uy = axis_units(&g_hid.layout, 0x31, g_fb.height);
        memset(&g_adapter, 0, sizeof g_adapter);
        g_live_generation = g_generation;
        if (shz_pointer_adapter_bind(&g_adapter, &ps, K64_LIN_OWNER, g_generation, ux, uy) != SHZ_DRIVER_OK) {
            g_live_generation = 0;
            xhciu_hid_close(&g_hid, g_generation);
            return XHCIU_HID_SINK;
        }
    }
    pci_claim(pd, "xhci-hid-pointer");
    ++g_status.opens;
    return 0;
}
static void lin_main(void *arg)
{
    pci_dev_t devs[48];
    int last_error = 0x7fffffff;
    (void)arg;
    for (;;) {
        unsigned n, i, controllers = 0, streaming = 0;
        g_status.state = K64_LIN_SCANNING;
        n = pci_enumerate(devs, 48);
        for (i = 0; i < n && !streaming && controllers < LIN_MAX_CONTROLLERS; ++i) {
            const pci_dev_t *pd = &devs[i];
            int r;
            if (pd->class_code != 0x0c || pd->subclass != 0x03 || pd->prog_if != 0x30 || pci_claimed_by(pd)) continue;
            ++controllers;
            g_status.have_controller = 1; g_status.bus = pd->bus; g_status.dev = pd->dev; g_status.fn = pd->fn;
            r = open_device(pd);
            if (r) {
                g_status.last_error = r;
                g_status.state = K64_LIN_NO_DEVICE;
                if (r != last_error) kprintf("K64 laptop-input: xHCI %02x:%02x.%x no USB HID pointer (error %d)\n", pd->bus, pd->dev, pd->fn, r);
                last_error = r;
                continue;
            }
            kprintf("K64 laptop-input: xHCI %02x:%02x.%x USB HID pointer streaming (interface %u, endpoint DCI %u)\n",
                    pd->bus, pd->dev, pd->fn, g_hid.iface, g_hid.dci);
            last_error = 0x7fffffff;
            streaming = 1;
            g_status.state = K64_LIN_STREAMING;
            for (;;) {
                uint32_t got = 0;
                r = xhciu_hid_poll(&g_hid, 32u, &got);
                g_status.reports = g_hid.reports; g_status.refused = g_hid.refused; g_status.polls = g_hid.polls;
                if (r) break;
                if (!got) thread_sleep_ms(LIN_POLL_MS);
            }
            g_live_generation = 0;                                    /* revoke before tearing the device down */
            shz_pointer_adapter_close(&g_adapter);
            g_status.last_error = r;
            kprintf("K64 laptop-input: USB HID pointer stopped (error %d)\n", r);
            if (xhciu_hid_close(&g_hid, g_generation) == XHCI_QUARANTINED) {
                g_status.state = K64_LIN_FAILED;                      /* DMA lifetime continues: never reuse the controller */
                return;
            }
            streaming = 0;
        }
        if (!controllers) g_status.state = K64_LIN_NO_CONTROLLER;
        thread_sleep_ms(LIN_RETRY_MS);
    }
}

void k64_laptop_input_init(void)
{
    g_status.ps2_touchpad = "not probed: absolute route is implemented (k64_laptop_ps2_open/feed) but gin_init does not yet call "
                            "gin_ps2_touchpad_probe (core integrator call site); Synaptics pads work as standard relative mice";
    g_status.i2c_touchpad = "refused: no I2C controller/GPIO/IRQ grant or hidi2c transport owner exists in Kernel64";
    g_status.state = K64_LIN_IDLE;
    if (!thread_create("laptopin", lin_main, 0)) kprintf("K64 laptop-input: cannot start the input thread\n");
}
void k64_laptop_input_status(struct k64_lin_status *out) { if (out) *out = g_status; }

#else  /* Supervisor profile: no PCI devices are passed through */
void k64_laptop_input_init(void) {}
void k64_laptop_input_status(struct k64_lin_status *out) { if (out) memset(out, 0, sizeof *out); }
int k64_laptop_ps2_open(const struct k64_lin_ps2_transport *t) { (void)t; return -1; }
int k64_laptop_ps2_feed(uint8_t byte) { (void)byte; return 0; }
void k64_laptop_ps2_revoke(void) {}
#endif
