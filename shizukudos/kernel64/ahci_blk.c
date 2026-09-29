/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 AHCI driver: the original AHCI core (drivers/ahci_native/ahci.c, linked unmodified into the
 * SHZ_STANDALONE kernel only) registered as block device "ahci0" in the generic registry (blk.h).
 * STANDALONE PROFILE ONLY: under the Supervisor no disk is passed through and port I/O is trapped, so
 * ahci_blk_init() reports "no device" there. QEMU fixture: -device ahci + ide-hd (ICH9 8086:2922, class 010601).
 *
 * ahci_native's contract: callbacks return nonzero on success; one 512-byte sector per command; the core polls
 * PxCI/PxTFD with now_us() as its deadline clock (the TSC here, so it also works with interrupts masked) and never
 * touches memory outside the one 4 KiB DMA block it was given.
 */
#include "blk.h"
#include "pci.h"
#ifdef SHZ_STANDALONE
#include "../../drivers/ahci_native/ahci.h"

static struct ahci_device disk;
static volatile uint32_t *abar;
static uint32_t abar_bytes;
static uint64_t dma_pa;
static int ready;
static kmutex_t blk_lock;
static blk_dev_t dev;

static int mmio_read(void *ctx, uint32_t off, uint32_t *v)
{
    (void)ctx;
    if ((off & 3) || off > abar_bytes - 4 || !v) return 0;
    *v = abar[off / 4];
    return 1;
}
static int mmio_write(void *ctx, uint32_t off, uint32_t v)
{
    (void)ctx;
    if ((off & 3) || off > abar_bytes - 4) return 0;
    abar[off / 4] = v;
    return 1;
}
static int dma_allocate(void *ctx, size_t bytes, size_t align, uint64_t max_bus, struct ahci_dma *b)
{
    (void)ctx;
    if (!b || dma_pa || bytes > PAGE_SIZE || !align || (align & (align - 1)) || align > PAGE_SIZE) return 0;
    dma_pa = pmm_alloc();                           /* zeroed, 4 KiB aligned, physical == bus (no IOMMU under QEMU pc) */
    if (!dma_pa) return 0;
    if (dma_pa + bytes - 1 > max_bus) { pmm_free(dma_pa); dma_pa = 0; return 0; }
    b->cpu = (void *)p2v(dma_pa);
    b->bus = dma_pa;
    b->bytes = bytes;
    return 1;
}
static void dma_release(void *ctx, struct ahci_dma *b)
{
    (void)ctx;
    if (b && dma_pa && b->bus == dma_pa) { pmm_free(dma_pa); dma_pa = 0; }
}
static int dma_sync(void *ctx, const struct ahci_dma *b, size_t off, size_t bytes, int to_device)
{
    (void)ctx; (void)to_device;
    if (!b || !dma_pa || off > PAGE_SIZE || bytes > PAGE_SIZE - off) return 0;
    __asm__ volatile("mfence" ::: "memory");        /* coherent DMA under QEMU: ordering only */
    return 1;
}
static uint64_t tsc_now_us(void *ctx)
{
    uint32_t lo, hi;
    (void)ctx;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    /* Nominal 1 GHz TSC (bootinfo tsc_hz under QEMU TCG). A faster TSC only shortens the generous timeouts. */
    return (((uint64_t)hi << 32) | lo) / 1000u;
}
static void relax(void *ctx) { (void)ctx; __asm__ volatile("pause" ::: "memory"); }

static int ahci_read(blk_dev_t *d, uint64_t lba, unsigned count, void *buf)
{
    uint8_t *b = buf;
    int rc = AHCI_OK;
    (void)d;
    if (!ready) return -1;
    mutex_lock(&blk_lock);                          /* one command at a time: the core is not reentrant */
    while (count--) {
        rc = ahci_read_sector(&disk, lba, b, 512);
        if (rc != AHCI_OK) {
            kprintf("K64 ahci: read lba %llu failed (%d) is=%x tfd=%x serr=%x\n", lba, rc, disk.last_is, disk.last_tfd, disk.last_serr);
            if (disk.state != AHCI_READY) ready = 0;    /* the core closed the port after an error */
            break;
        }
        ++lba;
        b += 512;
    }
    mutex_unlock(&blk_lock);
    return rc == AHCI_OK ? 0 : -1;
}

int ahci_blk_init(void)
{
    pci_dev_t all[32], *d = 0;
    const unsigned n = pci_enumerate(all, 32);
    unsigned i;
    uint64_t bar, size;
    int is_io, rc;
    struct ahci_ops ops = { 0, mmio_read, mmio_write, dma_allocate, dma_release, dma_sync, tsc_now_us, relax };
    struct ahci_config cfg = { 0x010601, 0, 0, AHCI_AUTO_PORT, 5000000, 1 };
    mutex_init(&blk_lock);
    for (i = 0; i < n; ++i)
        if (all[i].class_code == 1 && all[i].subclass == 6 && all[i].prog_if == 1) { d = &all[i]; break; }
    if (!d) { kprintf("K64 ahci: no AHCI controller (class 010601) on PCI bus 0\n"); return -1; }
    bar = pci_bar(d, 5, &size, &is_io);
    if (!bar || is_io || size < 0x180 || size > (1u << 20)) { kprintf("K64 ahci: BAR5 unusable (%llx, %llu)\n", bar, size); return -1; }
    pci_enable(d, 0, 1, 1);
    abar = mmio_map(bar, size);
    if (!abar) { kprintf("K64 ahci: cannot map ABAR\n"); return -1; }
    abar_bytes = (uint32_t)size;
    cfg.abar_bytes = abar_bytes;
    cfg.pci_command = pci_cfg_read32(d, 4) & 0xffff;
    rc = ahci_open(&disk, &ops, &cfg);
    if (rc != AHCI_OK) {
        kprintf("K64 ahci: ahci_open failed (%d) is=%x tfd=%x serr=%x\n", rc, disk.last_is, disk.last_tfd, disk.last_serr);
        return -1;
    }
    ready = 1;
    kprintf("K64 ahci: %x:%x.%x %x:%x abar %llx port %u: \"%s\" %llu sectors (%llu MiB)\n", d->bus, d->dev, d->fn,
            d->vendor, d->device, bar, disk.port, disk.identity.model, disk.identity.sectors, disk.identity.sectors / 2048);
    memset(&dev, 0, sizeof dev);
    memcpy(dev.name, "ahci0", 6);
    dev.sector_size = 512;
    dev.sectors = disk.identity.sectors;
    dev.flags = BLK_F_READONLY;                     /* ahci_native is a read-only core: no write command */
    dev.read = ahci_read;
    dev.priv = &disk;
    return blk_register(&dev);
}
#else
int ahci_blk_init(void) { return -1; }              /* Supervisor profile: no passed-through disk */
#endif
