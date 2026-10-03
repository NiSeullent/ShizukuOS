/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 boot driver-binding report over the REAL PCI enumeration (pci.c) and the REAL ownership record that kernel
 * backends write with pci_claim() once they drive a function (gfx_*, ahci_blk, nvme, sdhci, net_rtl8139, hosted ntdrv).
 *
 * This file never starts, resets or programs a device: it reads type-0/1 header fields (revision, header type,
 * subsystem IDs) with pci_cfg_read32(), never sizes a BAR, and only classifies. A catalogue match without a
 * pci_claim() owner is reported as "backend not attached", so unsupported hardware stays unsupported.
 *
 * GOP basic display: the handoff is the UEFI direct boot's shz_bootinfo_t fb_* tail read through
 * k64_boot_framebuffer(); it is re-checked with shz_gop_mode_check() (pitch*height <= size, 32 bpp RGBX/BGRX,
 * below K64_GFX_ARENA_OFFSET, <= 8192x8192). Under the Supervisor profile the Supervisor's console owns the GOP
 * framebuffer and does not delegate it into the Kernel64 domain's bootinfo, so gfx_fb_init() truthfully returns
 * STATUS_NO_SUCH_DEVICE there; this report says so instead of claiming a display.
 */
#include "k64.h"
#include "pci.h"
#include "gfx.h"
#include "gfx_address.h"
#include "ntdrv_catalog.h"

#ifdef SHZ_STANDALONE
static void copy_owner(char *dst, unsigned cap, const char *src)
{
    unsigned i = 0;
    while (src && src[i] && i + 1 < cap) { dst[i] = src[i]; ++i; }
    dst[i] = 0;
}
#endif

void ntdrv_gop_status(shz_gop_status_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof *out);
    out->check = SHZ_GOP_ABSENT;
    if (g_fb.ready && g_fb.backend) out->active_backend = g_fb.backend->name;
    k64_boot_fb_t b;
    if (k64_boot_framebuffer(&b)) {
#ifndef SHZ_STANDALONE
        out->state = SHZ_GOPDISP_SUPERVISED;            /* no explicit Supervisor grant in this domain's boot info */
#else
        out->state = SHZ_GOPDISP_NO_HANDOFF;
#endif
        return;
    }
    out->mode.base = b.base; out->mode.size = b.size;
    out->mode.width = b.width; out->mode.height = b.height;
    out->mode.pitch = b.pitch; out->mode.bpp = b.bpp; out->mode.format = b.format;
    out->check = shz_gop_mode_check(&out->mode, K64_GFX_ARENA_OFFSET);
    if (out->check != SHZ_GOP_OK) out->state = SHZ_GOPDISP_REJECTED;
    else if (!out->active_backend) out->state = SHZ_GOPDISP_AVAILABLE;
    else out->state = g_fb.backend == &gfx_backend_gop ? SHZ_GOPDISP_ACTIVE : SHZ_GOPDISP_SUPERSEDED;
}

unsigned ntdrv_binding_snapshot(shz_drvbind_t *out, unsigned max, unsigned *total)
{
    unsigned written = 0;
#ifdef SHZ_STANDALONE                                   /* under the Supervisor the config ports trap: nothing to list */
    pci_dev_t all[SHZ_DRVBIND_MAX];
    shz_gop_status_t gop;
    const unsigned n = pci_enumerate(all, SHZ_DRVBIND_MAX);
    unsigned i;
    int fb_valid;
    ntdrv_gop_status(&gop);
    fb_valid = gop.check == SHZ_GOP_OK;
    if (total) *total = n;
    for (i = 0; i < n && out && written < max; ++i) {
        shz_drvbind_t *e = &out[written];
        const uint32_t rev = pci_cfg_read32(&all[i], 0x08), hdr = pci_cfg_read32(&all[i], 0x0c) >> 16 & 0x7f;
        const char *owner = pci_claimed_by(&all[i]);
        memset(e, 0, sizeof *e);
        e->bus = all[i].bus; e->dev = all[i].dev; e->fn = all[i].fn;
        e->ident.vendor = all[i].vendor; e->ident.device = all[i].device;
        e->ident.class_code = all[i].class_code; e->ident.subclass = all[i].subclass;
        e->ident.prog_if = all[i].prog_if; e->ident.revision = (uint8_t)rev;
        if (hdr == 0) {                                 /* type-0 header: subsystem vendor/device at 0x2c */
            const uint32_t ss = pci_cfg_read32(&all[i], 0x2c);
            e->ident.subsys_vendor = (uint16_t)ss;
            e->ident.subsys_device = (uint16_t)(ss >> 16);
            e->ident.has_subsys = 1;
        }
        copy_owner(e->owner, sizeof e->owner, owner);
        if (shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &e->ident, owner, fb_valid, &e->result))
            continue;                                   /* not counted: invalid identity cannot be classified */
        ++written;
    }
#else
    (void)out; (void)max;
    if (total) *total = 0;
#endif
    return written;
}

static const char *gop_state_name(enum shz_gop_display s)
{
    switch (s) {
    case SHZ_GOPDISP_NO_HANDOFF: return "no validated UEFI GOP handoff (Multiboot/legacy boot or no GOP)";
    case SHZ_GOPDISP_REJECTED: return "handoff rejected";
    case SHZ_GOPDISP_AVAILABLE: return "validated, display stack not initialised yet (gfx_fb_init is lazy)";
    case SHZ_GOPDISP_ACTIVE: return "active display backend";
    case SHZ_GOPDISP_SUPERSEDED: return "validated, superseded by another display backend";
    case SHZ_GOPDISP_SUPERVISED: return "Supervisor profile: GOP not granted (BOOT.INI k64_display=yes absent or "
                                        "Supervisor refused); gfx_fb_init returns STATUS_NO_SUCH_DEVICE";
    }
    return "invalid";
}

void ntdrv_binding_report(void)
{
    static shz_drvbind_t rows[SHZ_DRVBIND_MAX];          /* boot-time report only; not reentrant */
    shz_gop_status_t gop;
    unsigned total = 0, n, i, bound = 0, unbound = 0, gop_pci = 0;
    ntdrv_gop_status(&gop);
    n = ntdrv_binding_snapshot(rows, SHZ_DRVBIND_MAX, &total);
#ifndef SHZ_STANDALONE
    kprintf("K64 drvbind: Supervisor profile: no PCI function is passed through to Kernel64; nothing enumerated\n");
#endif
    for (i = 0; i < n; ++i) {
        const shz_drvbind_t *e = &rows[i];
        const shz_drvcat_entry_t *best = e->result.best >= 0 ? &shz_k64_catalog[e->result.best] : 0;
        const shz_drvcat_entry_t *own = e->result.bound >= 0 ? &shz_k64_catalog[e->result.bound] : 0;
        if (e->result.state >= SHZ_BIND_BOUND) ++bound; else ++unbound;
        if (own && (own->flags & SHZ_DRVCAT_BASIC_DISPLAY)) gop_pci = 1;
        shz_pci_ids_t ids;
        if (shz_pci_ids_build(&e->ident, &ids) || !ids.n_hw) ids.hw[0][0] = 0;
        kprintf("K64 drvbind: %x:%x.%x %s -> %s%s%s [%s] %s%s\n", e->bus, e->dev, e->fn, ids.hw[0],
                own ? own->service : best ? best->service : "-",
                best && !own ? " via " : "", best && !own ? e->result.matched_id : "",
                shz_drvcat_binding_name(e->result.state), e->owner[0] ? "owner=" : "", e->owner);
    }
    if (total > n) kprintf("K64 drvbind: %u more PCI function(s) not classified\n", total - n);
    kprintf("K64 drvbind: %u function(s) enumerated, %u bound to an attached backend, %u without one\n", total, bound,
            unbound);
    if (gop.check == SHZ_GOP_OK || gop.state == SHZ_GOPDISP_REJECTED)
        kprintf("K64 drvbind: shzgop basic display: %s; %ux%u pitch %u %s at %llx size %llx (%s)%s\n",
                gop_state_name(gop.state), gop.mode.width, gop.mode.height, gop.mode.pitch,
                gop.mode.format == SHZ_GOP_FMT_BGRX8888 ? "BGRX" : "RGBX", gop.mode.base, gop.mode.size,
                shz_gop_check_name(gop.check),
                gop.state == SHZ_GOPDISP_ACTIVE ? (gop_pci ? "; PCI display BAR owner" : "; ROOT\\SHZGOP (no PCI owner)") : "");
    else
        kprintf("K64 drvbind: shzgop basic display: %s\n", gop_state_name(gop.state));
    if (gop.state == SHZ_GOPDISP_SUPERSEDED && gop.active_backend)
        kprintf("K64 drvbind: shzgop basic display superseded by %s\n", gop.active_backend);
}
