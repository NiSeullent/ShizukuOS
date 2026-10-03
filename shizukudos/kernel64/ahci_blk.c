/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 AHCI driver: the original AHCI core (drivers/ahci_native/ahci.c, linked as is into the
 * SHZ_STANDALONE kernel only) registered as block device "ahci0" in the generic registry (blk.h).
 * STANDALONE PROFILE ONLY: under the Supervisor no disk is passed through and port I/O is trapped, so
 * ahci_blk_init() reports "no device" there. QEMU fixture: -device ahci + ide-hd (ICH9 8086:2922, class 010601).
 *
 * ahci_native's contract: callbacks return nonzero on success; up to four 512-byte sectors per command; the core polls
 * PxCI/PxTFD with now_us() as its deadline clock (the TSC here, so it also works with interrupts masked) and never
 * touches memory outside the one 4 KiB DMA block it was given. The disk is opened with allow_write=1: blk_write()
 * issues bounded WRITE DMA EXT and blk_flush() FLUSH CACHE EXT when IDENTIFY advertises it (QEMU's disks do);
 * without that command blk_flush() has nothing to issue and returns success (the legacy FLUSH CACHE is not used).
 */
#include "blk.h"
#include "pci.h"
#ifdef SHZ_STANDALONE
#include "../../drivers/ahci_native/ahci.h"
#include "../../drivers/ahci_native/ahci_clock.h"

static struct ahci_device disk;
static volatile uint32_t *abar;
static uint32_t abar_bytes;
static uint64_t dma_pa;
static uint64_t tsc_per_ms;
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
    return ahci_ticks_to_us(((uint64_t)hi << 32) | lo, tsc_per_ms);
}
static void relax(void *ctx) { (void)ctx; __asm__ volatile("pause" ::: "memory"); }

static int ahci_read(blk_dev_t *d, uint64_t lba, unsigned count, void *buf)
{
    uint8_t *b = buf;
    int rc = AHCI_OK;
    (void)d;
    if (!ready) return -1;
    mutex_lock(&blk_lock);                          /* one command at a time: the core is not reentrant */
    while (count) {
        const unsigned n = count < AHCI_MAX_SECTORS ? count : AHCI_MAX_SECTORS;
        rc = ahci_read_sectors(&disk, lba, n, b, (size_t)n * AHCI_SECTOR_BYTES);
        if (rc != AHCI_OK) {
            kprintf("K64 ahci: read lba %llu count %u failed (%d) is=%x tfd=%x serr=%x deadline_reason=%u elapsed_us=%llu polls=%u limit_us=%u\n",
                    lba, n, rc, disk.last_is, disk.last_tfd, disk.last_serr, disk.last_wait_reason,
                    disk.last_wait_elapsed_us, disk.last_wait_polls, disk.timeout_us);
            if (disk.state != AHCI_READY) ready = 0;    /* the core closed the port after an error */
            break;
        }
        lba += n;
        b += (size_t)n * AHCI_SECTOR_BYTES;
        count -= n;
    }
    mutex_unlock(&blk_lock);
    return rc == AHCI_OK ? 0 : -1;
}

static int ahci_write(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf)
{
    const uint8_t *b = buf;
    int rc = AHCI_OK;
    (void)d;
    if (!ready) return -1;
    mutex_lock(&blk_lock);
    while (count) {
        const unsigned n = count < AHCI_MAX_SECTORS ? count : AHCI_MAX_SECTORS;
        rc = ahci_write_sectors(&disk, lba, n, b, (size_t)n * AHCI_SECTOR_BYTES);
        if (rc != AHCI_OK) {
            kprintf("K64 ahci: write lba %llu count %u failed (%d) is=%x tfd=%x serr=%x deadline_reason=%u elapsed_us=%llu polls=%u limit_us=%u\n",
                    lba, n, rc, disk.last_is, disk.last_tfd, disk.last_serr, disk.last_wait_reason,
                    disk.last_wait_elapsed_us, disk.last_wait_polls, disk.timeout_us);
            if (disk.state != AHCI_READY) ready = 0;
            break;
        }
        lba += n;
        b += (size_t)n * AHCI_SECTOR_BYTES;
        count -= n;
    }
    mutex_unlock(&blk_lock);
    return rc == AHCI_OK ? 0 : -1;
}

static uint32_t flushes;
static int ahci_flush_dev(blk_dev_t *d)
{
    int rc;
    (void)d;
    if (!ready) return -1;
    if (!(disk.identity.features & AHCI_FEATURE_FLUSH_EXT)) return 0;
    mutex_lock(&blk_lock);
    rc = ahci_flush(&disk);
    if (rc != AHCI_OK) {
        kprintf("K64 ahci: FLUSH CACHE EXT failed (%d) is=%x tfd=%x serr=%x deadline_reason=%u elapsed_us=%llu polls=%u limit_us=%u\n",
                rc, disk.last_is, disk.last_tfd, disk.last_serr, disk.last_wait_reason,
                disk.last_wait_elapsed_us, disk.last_wait_polls, disk.timeout_us);
        if (disk.state != AHCI_READY) ready = 0;
    } else {
        ++flushes;
    }
    mutex_unlock(&blk_lock);
    return rc == AHCI_OK ? 0 : -1;
}
uint32_t ahci_blk_flushes(void) { return flushes; }

int ahci_blk_init(void)
{
    pci_dev_t all[32], *d = 0;
    const unsigned n = pci_enumerate(all, 32);
    unsigned i;
    uint64_t bar, size;
    int is_io, rc;
    struct ahci_ops ops = { 0, mmio_read, mmio_write, dma_allocate, dma_release, dma_sync, tsc_now_us, relax };
    struct ahci_config cfg = { 0x010601, 0, 0, AHCI_AUTO_PORT, 5000000, 1, 1 };
    mutex_init(&blk_lock);
    tsc_per_ms = blk_tsc_per_ms();                 /* existing PIT measurement also works with interrupts off */
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
    kprintf("K64 ahci: %x:%x.%x %x:%x abar %llx port %u: \"%s\" %llu sectors (%llu MiB), flush-ext %u, write cache %u\n",
            d->bus, d->dev, d->fn, d->vendor, d->device, bar, disk.port, disk.identity.model, disk.identity.sectors,
            disk.identity.sectors / 2048, (disk.identity.features & AHCI_FEATURE_FLUSH_EXT) != 0,
            (disk.identity.features & AHCI_FEATURE_WRITE_CACHE) != 0);
    memset(&dev, 0, sizeof dev);
    memcpy(dev.name, "ahci0", 6);
    dev.sector_size = 512;
    dev.sectors = disk.identity.sectors;
    dev.read = ahci_read;
    dev.write = ahci_write;
    dev.flush = ahci_flush_dev;
    dev.priv = &disk;
    dev.storage.version=SHZ_STORAGE_VERSION;dev.storage.size=sizeof dev.storage;
    dev.storage.transport=SHZ_STORAGE_SATA;dev.storage.bus=d->bus;
    dev.storage.device=d->dev;dev.storage.function=d->fn;
    dev.storage.unit=disk.port;dev.storage.multiplier=0xffff;
    dev.storage.sectors=dev.sectors;dev.storage.block_size=dev.sector_size;
    memcpy(dev.model,disk.identity.model,sizeof dev.model);
    memcpy(dev.serial,disk.identity.serial,sizeof dev.serial);
    dev.flags=(disk.identity.features&AHCI_FEATURE_FLUSH_EXT)?BLK_F_FLUSH:0;
    dev.driver = "ahci";                            /* storage-track metadata (blk.h extensions) */
    dev.irq_mode = "poll";
    dev.queue_depth = 1;
    dev.max_sectors = AHCI_MAX_SECTORS;
    pci_claim(d, "ahci_blk (AHCI SATA)");
    return blk_register(&dev);
}
#else
int ahci_blk_init(void) { return -1; }              /* Supervisor profile: no passed-through disk */
uint32_t ahci_blk_flushes(void) { return 0; }
#endif
