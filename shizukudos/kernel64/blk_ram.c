/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 RAM block devices for the installer (interim target until the AHCI/NVMe drivers of the storage track are
 * merged; same blk_dev_t shape, see blk_compat.h).
 *
 * Source of the RAM: a QEMU "ivshmem-plain" PCI device (vendor 1AF4, device 1110), whose BAR2 is plain memory. When
 * the VM gives it a host file (`-object memory-backend-file,share=on,mem-path=disk.img -device ivshmem-plain,memdev=`)
 * every sector written here lands in that file, so the host can inspect exactly what SHZSETUP wrote: the test harness
 * (tests/run_install.py) verifies the installed disk image this way and then boots it. It is a byte-addressable RAM
 * disk; flush is a full memory barrier. Standalone profile only (PCI port I/O is not available under the Supervisor).
 */
#include "blk_compat.h"
#include "pci.h"

#define IVSHMEM_VENDOR 0x1af4
#define IVSHMEM_DEVICE 0x1110
#define MAX_RAM_DEVS 4

typedef struct {
    blk_dev_t dev;
    uint8_t *base;
    char serial[24];
} ram_dev_t;

static ram_dev_t ram_devs[MAX_RAM_DEVS];
static unsigned ram_count;
static int ram_probed;

#ifndef K64_HAVE_BLK_REGISTRY
/* ---- minimal registry with the blk.h API (replaced by blk.c when the storage branch is merged) ---- */
static blk_dev_t *reg_head, *reg_tail;

int blk_register(blk_dev_t *d)
{
    blk_dev_t *x;
    for (x = reg_head; x; x = x->next)
        if (!strcmp(x->name, d->name)) return -1;
    d->next = 0;
    if (reg_tail) reg_tail->next = d; else reg_head = d;
    reg_tail = d;
    return 0;
}
blk_dev_t *blk_first(void) { return reg_head; }
static int in_range(const blk_dev_t *d, uint64_t lba, unsigned count) { return count && lba < d->sectors && count <= d->sectors - lba; }
int blk_read(blk_dev_t *d, uint64_t lba, unsigned count, void *buf)
{
    if (!in_range(d, lba, count)) return -1;
    d->reads += count;
    return d->read(d, lba, count, buf);
}
int blk_write(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf)
{
    if (!d->write || (d->flags & BLK_F_READONLY) || !in_range(d, lba, count)) return -1;
    d->writes += count;
    return d->write(d, lba, count, buf);
}
int blk_flush(blk_dev_t *d) { return d->flush ? d->flush(d) : 0; }
#endif

#ifdef SHZ_STANDALONE
static int ram_read(blk_dev_t *d, uint64_t lba, unsigned count, void *buf)
{
    const ram_dev_t *r = d->priv;
    memcpy(buf, r->base + lba * 512u, (size_t)count * 512u);
    return 0;
}

static int ram_write(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf)
{
    const ram_dev_t *r = d->priv;
    memcpy(r->base + lba * 512u, buf, (size_t)count * 512u);
    return 0;
}

static int ram_flush(blk_dev_t *d)
{
    (void)d;
    __asm__ volatile("mfence" ::: "memory");
    return 0;
}

static void hex2(char *o, unsigned v) { o[0] = "0123456789abcdef"[(v >> 4) & 15]; o[1] = "0123456789abcdef"[v & 15]; }
#endif

int blk_ram_init(void)
{
#ifdef SHZ_STANDALONE
    pci_dev_t all[32];
    unsigned n, i;
    if (ram_probed) return (int)ram_count;
    ram_probed = 1;
    n = pci_enumerate(all, 32);
    for (i = 0; i < n && ram_count < MAX_RAM_DEVS; ++i) {
        ram_dev_t *r = &ram_devs[ram_count];
        uint64_t size = 0, pa;
        int is_io = 0;
        if (all[i].vendor != IVSHMEM_VENDOR || all[i].device != IVSHMEM_DEVICE) continue;
        pa = pci_bar(&all[i], 2, &size, &is_io);
        if (!pa || is_io || size < (1u << 20)) {
            kprintf("K64 blk_ram: ivshmem %x:%x.%x has no usable BAR2 (base %llx size %llx)\n", all[i].bus, all[i].dev,
                    all[i].fn, (unsigned long long)pa, (unsigned long long)size);
            continue;
        }
        pci_enable(&all[i], 0, 1, 0);
        r->base = mmio_map(pa, size);
        if (!r->base) {
            kprintf("K64 blk_ram: cannot map %llx (%llu MiB)\n", (unsigned long long)pa, (unsigned long long)(size >> 20));
            continue;
        }
        memset(&r->dev, 0, sizeof r->dev);
        memcpy(r->dev.name, "ram0", 5);
        r->dev.name[3] = (char)('0' + ram_count);
        r->dev.sector_size = 512;
        r->dev.sectors = size / 512;
        r->dev.read = ram_read;
        r->dev.write = ram_write;
        r->dev.flush = ram_flush;
        r->dev.priv = r;
        memcpy(r->serial, "IVSHMEM-00:00.0", 16);
        hex2(r->serial + 8, all[i].bus);
        hex2(r->serial + 11, all[i].dev);
        r->serial[14] = (char)('0' + all[i].fn);
        if (blk_register(&r->dev)) continue;
        kprintf("K64 blk_ram: %s = ivshmem %x:%x.%x BAR2 %llx, %llu MiB, serial %s\n", r->dev.name, all[i].bus,
                all[i].dev, all[i].fn, (unsigned long long)pa, (unsigned long long)(size >> 20), r->serial);
        ++ram_count;
    }
#else
    ram_probed = 1;
#endif
    return (int)ram_count;
}

int blk_ram_serial(const blk_dev_t *d, char *out, unsigned cap)
{
    unsigned i, n;
    for (i = 0; i < ram_count; ++i) {
        if (d != &ram_devs[i].dev) continue;
        n = (unsigned)strlen(ram_devs[i].serial);
        if (n >= cap) n = cap - 1;
        memcpy(out, ram_devs[i].serial, n);
        out[n] = 0;
        return 0;
    }
    return -1;
}
