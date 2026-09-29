/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 block-device registry and partition devices (see blk.h). Drivers register whole devices; MBR/EBR and GPT
 * partitions found by blk_part.c become devices of their own that bounds-check and forward to the parent.
 */
#include "blk.h"
#include "pci.h"

static blk_dev_t *head, *tail;
static unsigned count;
static blk_dev_t parts[BLK_MAX_DEVICES];        /* partition devices (whole devices live in their drivers) */
static unsigned nparts;

int blk_register(blk_dev_t *d)
{
    uint64_t f;
    if (!d || !d->name[0] || !d->sector_size || !d->sectors || !d->read || blk_find(d->name)) return -1;
    f = irq_save();
    d->next = 0;
    d->reg_index = count;
    if (tail) tail->next = d; else head = d;
    tail = d;
    ++count;
    irq_restore(f);
    if (!(d->flags & BLK_F_PARTITION)) d->scan_result = -1;
    kprintf("K64 blk: %s: %llu sectors of %u bytes%s%s\n", d->name, d->sectors, d->sector_size,
            d->flags & BLK_F_PARTITION ? " (partition)" : "", d->write ? "" : " read-only");
    return 0;
}

blk_dev_t *blk_find(const char *name)
{
    blk_dev_t *d;
    for (d = head; d; d = d->next)
        if (!strcmp(d->name, name)) return d;
    return 0;
}

blk_dev_t *blk_first(void) { return head; }
unsigned blk_count(void) { return count; }

blk_dev_t *blk_get(unsigned index)
{
    blk_dev_t *d;
    for (d = head; d && index; d = d->next) --index;
    return d;
}

blk_dev_t *blk_whole(blk_dev_t *d)
{
    while (d && d->parent) d = d->parent;
    return d;
}

static int in_range(const blk_dev_t *d, uint64_t lba, unsigned n) { return d && n && lba < d->sectors && n <= d->sectors - lba; }

int blk_read(blk_dev_t *d, uint64_t lba, unsigned count_, void *buf)
{
    int rc;
    if (!in_range(d, lba, count_) || !buf) return -1;
    rc = d->read(d, lba, count_, buf);
    if (!rc) { d->reads += count_; ++d->read_ops; } else ++d->errors;
    return rc;
}

int blk_write(blk_dev_t *d, uint64_t lba, unsigned count_, const void *buf)
{
    int rc;
    if (!d || !d->write || (d->flags & BLK_F_READONLY) || !in_range(d, lba, count_) || !buf) return -1;
    rc = d->write(d, lba, count_, buf);
    if (!rc) { d->writes += count_; ++d->write_ops; } else ++d->errors;
    return rc;
}

int blk_flush(blk_dev_t *d)
{
    int rc;
    if (!d) return -1;
    rc = d->flush ? d->flush(d) : 0;
    if (!rc) ++d->flushes; else ++d->errors;
    return rc;
}

/* Walks a partition chain down to the whole device, translating the LBA. */
static blk_dev_t *resolve(blk_dev_t *d, uint64_t *lba)
{
    while (d->parent) { *lba += d->start_lba; d = d->parent; }
    return d;
}

int blk_discard(blk_dev_t *d, uint64_t lba, unsigned count_)
{
    blk_dev_t *w;
    int rc;
    if (!in_range(d, lba, count_) || (d->flags & BLK_F_READONLY)) return -1;
    w = resolve(d, &lba);
    if (!w->discard) return -1;
    rc = w->discard(w, lba, count_);
    if (!rc) ++d->discards; else ++d->errors;
    return rc;
}

int blk_control(blk_dev_t *d, unsigned op, uint64_t arg, uint64_t *out)
{
    blk_dev_t *w = blk_whole(d);
    if (!w) return -1;
    return w->control ? w->control(w, op, arg, out) : -2;
}

int blk_read_async(blk_dev_t *d, uint64_t lba, unsigned count_, void *buf, blk_done_fn done, void *ctx)
{
    blk_dev_t *w;
    uint64_t abs = lba;
    if (!in_range(d, lba, count_) || !buf || !done) return -1;
    w = resolve(d, &abs);
    if (w->read_async && w->read_async(w, abs, count_, buf, done, ctx) == 0) {
        d->reads += count_; ++d->read_ops;
        return 0;
    }
    done(ctx, blk_read(d, lba, count_, buf));
    return 0;
}

int blk_write_async(blk_dev_t *d, uint64_t lba, unsigned count_, const void *buf, blk_done_fn done, void *ctx)
{
    blk_dev_t *w;
    uint64_t abs = lba;
    if (!d || !d->write || (d->flags & BLK_F_READONLY) || !in_range(d, lba, count_) || !buf || !done) return -1;
    w = resolve(d, &abs);
    if (w->write_async && w->write_async(w, abs, count_, buf, done, ctx) == 0) {
        d->writes += count_; ++d->write_ops;
        return 0;
    }
    done(ctx, blk_write(d, lba, count_, buf));
    return 0;
}

uint64_t blk_kva_to_pa(const void *kva)
{
    const uint64_t va = (uint64_t)kva;
    const uint64_t *t = (const uint64_t *)p2v(kernel_pml4());
    int level;
    if (va < DIRECT_MAP) return 0;                      /* user half: per-process, not ours to translate */
    for (level = 3; level >= 0; --level) {
        const uint64_t e = t[(va >> (12 + 9 * level)) & 511];
        if (!(e & PT_P)) return 0;
        if (level == 0) return (e & 0x000ffffffffff000ull) | (va & 0xfff);
        if (level <= 2 && (e & (1ull << 7))) {         /* 2 MiB (PD) or 1 GiB (PDPT) page */
            const uint64_t mask = (1ull << (12 + 9 * level)) - 1;
            return (e & 0x000ffffffffff000ull & ~mask) | (va & mask);
        }
        t = (const uint64_t *)p2v(e & 0x000ffffffffff000ull);
    }
    return 0;
}

static inline uint64_t rdtsc64(void) { uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); return ((uint64_t)hi << 32) | lo; }

uint64_t blk_tsc_per_ms(void)
{
    static uint64_t per_ms;
    if (per_ms) return per_ms;
    per_ms = 1000000u;                                  /* nominal 1 GHz */
#ifdef SHZ_STANDALONE
    {   /* PIT channel 2, mode 0, 11932 counts = 10 ms: OUT2 (port 0x61 bit 5) rises at terminal count */
        const uint8_t saved = k_inb(0x61);
        const uint64_t f = irq_save();
        uint64_t t0, t1, guard = 0;
        k_outb(0x61, (uint8_t)((saved & ~0x02) | 0x01));   /* gate on, speaker off */
        k_outb(0x43, 0xb0);
        k_outb(0x42, 11932 & 0xff);
        k_outb(0x42, 11932 >> 8);
        t0 = rdtsc64();
        while (!(k_inb(0x61) & 0x20) && ++guard < 50000000u) ;
        t1 = rdtsc64();
        k_outb(0x61, saved);
        irq_restore(f);
        if (guard < 50000000u && (t1 - t0) / 10 >= 100000u && (t1 - t0) / 10 <= 20000000u) per_ms = (t1 - t0) / 10;
        kprintf("K64 blk: TSC %llu kHz%s\n", per_ms, per_ms == 1000000u ? " (nominal: PIT calibration unusable)" : " (PIT channel 2)");
    }
#endif
    return per_ms;
}

/* ---------------------------------------------------------------- partitions */
static int part_read(blk_dev_t *d, uint64_t lba, unsigned n, void *buf) { return blk_read(d->parent, d->start_lba + lba, n, buf); }
static int part_write(blk_dev_t *d, uint64_t lba, unsigned n, const void *buf) { return blk_write(d->parent, d->start_lba + lba, n, buf); }
static int part_flush(blk_dev_t *d) { return blk_flush(d->parent); }

static blk_dev_t *add_partition(blk_dev_t *whole, const blk_part_t *bp)
{
    blk_dev_t *p;
    unsigned n;
    const unsigned index = bp->index;
    if (nparts >= BLK_MAX_DEVICES || !bp->sectors || bp->start >= whole->sectors || bp->sectors > whole->sectors - bp->start) return 0;
    p = &parts[nparts];
    memset(p, 0, sizeof *p);
    for (n = 0; whole->name[n] && n < BLK_NAME_MAX - 4; ++n) p->name[n] = whole->name[n];
    p->name[n++] = 'p';
    if (index >= 10) p->name[n++] = (char)('0' + index / 10 % 10);
    p->name[n++] = (char)('0' + index % 10);
    p->name[n] = 0;
    p->sector_size = whole->sector_size;
    p->sectors = bp->sectors;
    p->start_lba = bp->start;
    p->parent = whole;
    p->flags = BLK_F_PARTITION | (whole->flags & (BLK_F_READONLY | BLK_F_REMOVABLE | BLK_F_FLUSH | BLK_F_DISCARD));
    p->mbr_type = bp->scheme == PART_SCHEME_GPT ? 0xee : bp->mbr_type;
    memcpy(p->type_guid, bp->type_guid, 16);
    memcpy(p->part_name, bp->name, sizeof p->part_name);
    p->part_scheme = bp->scheme;
    p->index = index;
    p->read = part_read;
    p->write = whole->write ? part_write : 0;
    p->flush = part_flush;
    p->driver = whole->driver;
    p->irq_mode = whole->irq_mode;
    p->queue_depth = whole->queue_depth;
    p->max_sectors = whole->max_sectors;
    memcpy(p->model, whole->model, sizeof p->model);
    memcpy(p->serial, whole->serial, sizeof p->serial);
    if (blk_register(p)) return 0;
    ++nparts;
    return p;
}

static int scan_read(void *ctx, uint64_t lba, uint32_t n, void *buf) { return blk_read((blk_dev_t *)ctx, lba, n, buf); }

int blk_scan_partitions(blk_dev_t *whole)
{
    uint8_t *s;
    blk_part_t *tab;
    uint32_t notes = 0;
    int n, i, found = 0;
    if (!whole || (whole->flags & BLK_F_PARTITION) || whole->sector_size < 512 || whole->sector_size > 4096) return 0;
    s = kmalloc(2 * whole->sector_size);
    tab = kmalloc(sizeof *tab * 16);
    if (!s || !tab) { kfree(s); kfree(tab); return -1; }
    if (blk_read(whole, 0, 1, s)) { kfree(s); kfree(tab); return -1; }
    /* A FAT/NTFS volume boot record also ends in 55AA: a jump opcode plus a plausible BPB means "superfloppy". */
    if (s[510] == 0x55 && s[511] == 0xaa && (s[0] == 0xeb || s[0] == 0xe9) &&
        (unsigned)(s[11] | (s[12] << 8)) == whole->sector_size && s[13] && !(s[13] & (s[13] - 1))) {
        whole->scan_result = 0;
        kfree(s); kfree(tab);
        return 0;
    }
    n = blk_part_scan(scan_read, whole, whole->sector_size, whole->sectors, s, tab, 16, &notes);
    whole->scan_notes = notes;
    whole->scan_result = n;
    kprintf("K64 blk: %s: partition scan %d (notes %x)\n", whole->name, n, notes);
    for (i = 0; i < n; ++i)
        if (add_partition(whole, &tab[i])) ++found;
    kfree(s);
    kfree(tab);
    if (n < 0) return (notes & PSCAN_READ_ERROR) ? -1 : 0;
    return found;
}
