/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 PCI configuration space access and MMIO mapping (see pci.h). */
#include "pci.h"

static uint32_t cfg_addr(const pci_dev_t *d, unsigned off)
{
    return 0x80000000u | ((uint32_t)d->bus << 16) | ((uint32_t)d->dev << 11) | ((uint32_t)d->fn << 8) | (off & 0xfc);
}
uint32_t pci_cfg_read32(const pci_dev_t *d, unsigned off)
{
    k_outl(0xcf8, cfg_addr(d, off));
    return k_inl(0xcfc);
}
void pci_cfg_write32(const pci_dev_t *d, unsigned off, uint32_t v)
{
    k_outl(0xcf8, cfg_addr(d, off));
    k_outl(0xcfc, v);
}

unsigned pci_enumerate(pci_dev_t *out, unsigned max)
{
    unsigned n = 0, dev, fn;
    for (dev = 0; dev < 32; ++dev) {
        for (fn = 0; fn < 8; ++fn) {
            pci_dev_t d = { .bus = 0, .dev = (uint8_t)dev, .fn = (uint8_t)fn };
            const uint32_t id = pci_cfg_read32(&d, 0);
            uint32_t cls, hdr;
            if ((id & 0xffff) == 0xffff) {
                if (fn == 0) break;                         /* no function 0: no device in this slot */
                continue;
            }
            cls = pci_cfg_read32(&d, 8);
            hdr = pci_cfg_read32(&d, 0x0c);
            d.vendor = (uint16_t)id;
            d.device = (uint16_t)(id >> 16);
            d.class_code = (uint8_t)(cls >> 24);
            d.subclass = (uint8_t)(cls >> 16);
            d.prog_if = (uint8_t)(cls >> 8);
            d.irq_line = (uint8_t)pci_cfg_read32(&d, 0x3c);
            if (n < max) out[n++] = d;
            if (fn == 0 && !((hdr >> 16) & 0x80)) break;    /* single-function device */
        }
    }
    return n;
}

int pci_find(uint16_t vendor, uint16_t device, pci_dev_t *out)
{
    pci_dev_t all[32];
    const unsigned n = pci_enumerate(all, 32);
    unsigned i;
    for (i = 0; i < n; ++i)
        if (all[i].vendor == vendor && all[i].device == device) {
            *out = all[i];
            return 0;
        }
    return -1;
}

uint64_t pci_bar(const pci_dev_t *d, unsigned idx, uint64_t *size, int *is_io)
{
    const unsigned off = 0x10 + idx * 4;
    const uint32_t orig = pci_cfg_read32(d, off);
    uint32_t probe, hi_orig = 0, hi_probe = 0;
    uint64_t base, mask;
    const int io = orig & 1, mem64 = !io && ((orig >> 1) & 3) == 2;
    if (is_io) *is_io = io;
    pci_cfg_write32(d, off, 0xffffffffu);
    probe = pci_cfg_read32(d, off);
    pci_cfg_write32(d, off, orig);
    if (!probe || probe == 0xffffffffu) {
        if (size) *size = 0;
        return 0;
    }
    if (mem64) {
        hi_orig = pci_cfg_read32(d, off + 4);
        pci_cfg_write32(d, off + 4, 0xffffffffu);
        hi_probe = pci_cfg_read32(d, off + 4);
        pci_cfg_write32(d, off + 4, hi_orig);
    }
    if (io) {
        base = orig & ~3u;
        mask = probe & ~3u;
        if (size) *size = (~mask + 1) & 0xffff;
    } else {
        base = (orig & ~0xfu) | ((uint64_t)hi_orig << 32);
        mask = (probe & ~0xfu) | ((uint64_t)hi_probe << 32);
        if (!mem64) mask |= 0xffffffff00000000ull;
        if (size) *size = ~mask + 1;
    }
    return base;
}

void pci_enable(const pci_dev_t *d, int io, int mem, int bus_master)
{
    uint32_t cmd = pci_cfg_read32(d, 4);
    cmd &= 0xffffu;
    if (io) cmd |= 1;
    if (mem) cmd |= 2;
    if (bus_master) cmd |= 4;
    pci_cfg_write32(d, 4, cmd);
}

void *mmio_map(uint64_t pa, uint64_t size)
{
    const uint64_t first = pa & ~0xfffull, last = (pa + size + 0xfff) & ~0xfffull, off = pa - first;
    uint64_t a;
    for (a = first; a < last; a += PAGE_SIZE)
        if (vm_map(kernel_pml4(), DIRECT_MAP + a, a, PT_W | PT_NX | PT_PCD | PT_PWT))
            return 0;
    return (void *)(DIRECT_MAP + first + off);
}

static struct { uint8_t bus, dev, fn; const char *driver; } g_claims[32];
static unsigned g_nclaims;

void pci_claim(const pci_dev_t *d, const char *driver)
{
    unsigned i;
    for (i = 0; i < g_nclaims; ++i)
        if (g_claims[i].bus == d->bus && g_claims[i].dev == d->dev && g_claims[i].fn == d->fn) {
            g_claims[i].driver = driver;
            return;
        }
    if (g_nclaims < 32) {
        g_claims[g_nclaims].bus = d->bus;
        g_claims[g_nclaims].dev = d->dev;
        g_claims[g_nclaims].fn = d->fn;
        g_claims[g_nclaims++].driver = driver;
    }
}

const char *pci_claimed_by(const pci_dev_t *d)
{
    unsigned i;
    for (i = 0; i < g_nclaims; ++i)
        if (g_claims[i].bus == d->bus && g_claims[i].dev == d->dev && g_claims[i].fn == d->fn)
            return g_claims[i].driver;
    return 0;
}

void pci_log_devices(void)
{
    pci_dev_t all[32];
    const unsigned n = pci_enumerate(all, 32);
    unsigned i;
    for (i = 0; i < n; ++i)
        kprintf("K64 pci: %x:%x.%x %x:%x class %x%x%x irq %u\n", all[i].bus, all[i].dev, all[i].fn, all[i].vendor,
                all[i].device, all[i].class_code, all[i].subclass, all[i].prog_if, all[i].irq_line);
}
