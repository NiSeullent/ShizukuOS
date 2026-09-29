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

/* ---------------------------------------------------------------- capabilities, MSI-X, shared INTx (see pci.h) */
unsigned pci_find_cap(const pci_dev_t *d, unsigned id)
{
    unsigned off, guard;
    if (!(pci_cfg_read32(d, 4) >> 16 & 0x10)) return 0;             /* status.CAP_LIST */
    off = pci_cfg_read32(d, 0x34) & 0xfc;
    for (guard = 0; off >= 0x40 && guard < 48; ++guard) {
        const uint32_t h = pci_cfg_read32(d, off);
        if ((h & 0xff) == id) return off;
        off = (h >> 8) & 0xfc;
    }
    return 0;
}

#define LAPIC_ID 0x20
#define LAPIC_TPR 0x80
#define LAPIC_EOI 0xb0
#define LAPIC_SVR 0xf0
#define MSI_VEC_FIRST 0x40
#define MSI_VEC_LAST 0xef
#define SPURIOUS_VEC 0xff

static volatile uint32_t *lapic;
static uint32_t lapic_id;
static struct { pci_irq_fn fn; void *ctx; } msi_route[256];
static uint64_t irq_counts[256];
static unsigned next_vec = MSI_VEC_FIRST;

uint64_t pci_irq_count(unsigned vector) { return vector < 256 ? irq_counts[vector] : 0; }

static void spurious(struct regs *r) { (void)r; }

static void msi_trampoline(struct regs *r)
{
    const unsigned v = (unsigned)r->vector & 0xff;
    ++irq_counts[v];
    if (msi_route[v].fn) msi_route[v].fn(msi_route[v].ctx);
    lapic[LAPIC_EOI / 4] = 0;
}

static int lapic_init(void)
{
    uint64_t base;
    if (lapic) return 0;
    base = rdmsr(0x1b);                                             /* IA32_APIC_BASE */
    if (!(base & (1ull << 11)) || (base & (1ull << 10))) {          /* globally disabled, or x2APIC mode */
        kprintf("K64 pci: local APIC unusable for MSI (APIC_BASE %llx)\n", base);
        return -1;
    }
    lapic = mmio_map(base & 0xffffff000ull, PAGE_SIZE);
    if (!lapic) return -1;
    irq_register(SPURIOUS_VEC, spurious);
    lapic[LAPIC_TPR / 4] = 0;
    lapic[LAPIC_SVR / 4] = 0x100 | SPURIOUS_VEC;                    /* software enable; LVTs keep their BIOS values */
    lapic_id = lapic[LAPIC_ID / 4] >> 24;
    kprintf("K64 pci: local APIC %llx id %u enabled for MSI-X\n", base & 0xffffff000ull, lapic_id);
    return 0;
}

int pci_msix_init(const pci_dev_t *d, pci_msix_t *m)
{
    uint32_t ctl, tbl, pba;
    uint64_t bar, size, off;
    int is_io;
    unsigned bir;
    memset(m, 0, sizeof *m);
    m->dev = *d;
    m->cap = pci_find_cap(d, 0x11);
    if (!m->cap) return -1;
    ctl = pci_cfg_read32(d, m->cap) >> 16;
    m->entries = (ctl & 0x7ff) + 1;
    tbl = pci_cfg_read32(d, m->cap + 4);
    pba = pci_cfg_read32(d, m->cap + 8);
    bir = tbl & 7;
    bar = pci_bar(d, bir, &size, &is_io);
    off = tbl & ~7u;
    if (!bar || is_io || off + 16ull * m->entries > size) { m->cap = 0; return -1; }
    m->table = mmio_map(bar + off, 16ull * m->entries);
    bar = pci_bar(d, pba & 7, &size, &is_io);
    if (bar && !is_io) m->pba = mmio_map(bar + (pba & ~7u), 8ull * ((m->entries + 63) / 64));
    if (!m->table) { m->cap = 0; return -1; }
    pci_cfg_write32(d, m->cap, (pci_cfg_read32(d, m->cap) & 0xffffu) | ((uint32_t)(ctl | 0x4000u) & ~0x8000u) << 16);
    for (bir = 0; bir < m->entries; ++bir) m->table[bir * 4 + 3] = 1;   /* every entry masked */
    return 0;
}

int pci_msix_bind(pci_msix_t *m, unsigned entry, pci_irq_fn fn, void *ctx)
{
    unsigned v;
    uint64_t f;
    if (!m->cap || entry >= m->entries || !fn || lapic_init()) return -1;
    f = irq_save();
    v = m->vector[entry < 32 ? entry : 0];
    if (!v || entry >= 32) {
        if (next_vec > MSI_VEC_LAST) { irq_restore(f); return -1; }
        v = next_vec++;
    }
    msi_route[v].fn = fn;
    msi_route[v].ctx = ctx;
    irq_register(v, msi_trampoline);
    if (entry < 32) m->vector[entry] = (uint8_t)v;
    m->table[entry * 4 + 3] = 1;
    m->table[entry * 4 + 0] = 0xfee00000u | (lapic_id << 12);      /* physical destination, no redirection hint */
    m->table[entry * 4 + 1] = 0;
    m->table[entry * 4 + 2] = v;                                    /* fixed delivery, edge */
    m->table[entry * 4 + 3] = 0;
    irq_restore(f);
    return (int)v;
}

void pci_msix_mask(pci_msix_t *m, unsigned entry, int masked)
{
    if (m->cap && entry < m->entries) m->table[entry * 4 + 3] = masked ? 1 : 0;
}

void pci_intx_disable(const pci_dev_t *d, int disabled)
{
    uint32_t cmd = pci_cfg_read32(d, 4) & 0xffffu;
    cmd = disabled ? cmd | 0x400u : cmd & ~0x400u;
    pci_cfg_write32(d, 4, cmd);
}

void pci_msix_enable(pci_msix_t *m, int on)
{
    uint32_t ctl;
    if (!m->cap) return;
    ctl = pci_cfg_read32(&m->dev, m->cap) >> 16;
    ctl = on ? (ctl | 0x8000u) & ~0x4000u : ctl & ~0x8000u;          /* bit 15 enable, bit 14 function mask */
    pci_cfg_write32(&m->dev, m->cap, (pci_cfg_read32(&m->dev, m->cap) & 0xffffu) | ctl << 16);
    pci_intx_disable(&m->dev, on);
}

#ifdef SHZ_STANDALONE
#define INTX_PER_LINE 4
static struct { pci_irq_fn fn; void *ctx; } intx_chain[16][INTX_PER_LINE];
static uint8_t intx_registered[16];

static void intx_trampoline(struct regs *r)
{
    const unsigned line = (unsigned)r->vector - standalone_irq_vector(0);
    unsigned i;
    if (line >= 16) return;
    ++irq_counts[r->vector & 0xff];
    for (i = 0; i < INTX_PER_LINE; ++i)
        if (intx_chain[line][i].fn) intx_chain[line][i].fn(intx_chain[line][i].ctx);
}

int pci_intx_ready(void) { return standalone_irq_vector(0) != 0; }

int pci_intx_attach(const pci_dev_t *d, pci_irq_fn fn, void *ctx)
{
    const unsigned line = d->irq_line;
    unsigned i;
    uint64_t f;
    if (!fn || line == 0 || line >= 16 || line == 2 || !pci_intx_ready()) return -1;
    f = irq_save();
    for (i = 0; i < INTX_PER_LINE && intx_chain[line][i].fn; ++i) ;
    if (i == INTX_PER_LINE) { irq_restore(f); return -1; }
    intx_chain[line][i].fn = fn;
    intx_chain[line][i].ctx = ctx;
    if (!intx_registered[line]) {
        irq_register(standalone_irq_vector(line), intx_trampoline);
        intx_registered[line] = 1;
    }
    irq_restore(f);
    pci_intx_disable(d, 0);
    standalone_irq_unmask(line);
    return (int)line;
}

void pci_intx_detach(const pci_dev_t *d, pci_irq_fn fn, void *ctx)
{
    const unsigned line = d->irq_line;
    unsigned i;
    uint64_t f;
    if (line >= 16) return;
    f = irq_save();
    for (i = 0; i < INTX_PER_LINE; ++i)
        if (intx_chain[line][i].fn == fn && intx_chain[line][i].ctx == ctx) { intx_chain[line][i].fn = 0; intx_chain[line][i].ctx = 0; }
    irq_restore(f);
}
#else
int pci_intx_ready(void) { return 0; }
int pci_intx_attach(const pci_dev_t *d, pci_irq_fn fn, void *ctx) { (void)d; (void)fn; (void)ctx; return -1; }
void pci_intx_detach(const pci_dev_t *d, pci_irq_fn fn, void *ctx) { (void)d; (void)fn; (void)ctx; }
#endif
