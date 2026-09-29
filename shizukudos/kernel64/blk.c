/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 block-device registry and partition scanner (see blk.h). Drivers register whole devices; MBR and GPT
 * partitions become devices of their own that bounds-check and forward to the parent.
 */
#include "blk.h"

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
    if (tail) tail->next = d; else head = d;
    tail = d;
    ++count;
    irq_restore(f);
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

int blk_read(blk_dev_t *d, uint64_t lba, unsigned count_, void *buf)
{
    int rc;
    if (!d || !count_ || lba >= d->sectors || count_ > d->sectors - lba) return -1;
    rc = d->read(d, lba, count_, buf);
    if (!rc) d->reads += count_;
    return rc;
}

int blk_write(blk_dev_t *d, uint64_t lba, unsigned count_, const void *buf)
{
    int rc;
    if (!d || !d->write || (d->flags & BLK_F_READONLY) || !count_ || lba >= d->sectors || count_ > d->sectors - lba) return -1;
    rc = d->write(d, lba, count_, buf);
    if (!rc) d->writes += count_;
    return rc;
}

int blk_flush(blk_dev_t *d) { return d ? (d->flush ? d->flush(d) : 0) : -1; }

/* ---------------------------------------------------------------- partitions */
static int part_read(blk_dev_t *d, uint64_t lba, unsigned n, void *buf) { return blk_read(d->parent, d->start_lba + lba, n, buf); }
static int part_write(blk_dev_t *d, uint64_t lba, unsigned n, const void *buf) { return blk_write(d->parent, d->start_lba + lba, n, buf); }
static int part_flush(blk_dev_t *d) { return blk_flush(d->parent); }

static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

static blk_dev_t *add_partition(blk_dev_t *whole, unsigned index, uint64_t start, uint64_t sectors, uint8_t mbr_type, const uint8_t *guid)
{
    blk_dev_t *p;
    unsigned k, n;
    if (nparts >= BLK_MAX_DEVICES || !sectors || start >= whole->sectors || sectors > whole->sectors - start) return 0;
    p = &parts[nparts];
    memset(p, 0, sizeof *p);
    for (n = 0; whole->name[n] && n < BLK_NAME_MAX - 4; ++n) p->name[n] = whole->name[n];
    p->name[n++] = 'p';
    if (index >= 10) p->name[n++] = (char)('0' + index / 10);
    p->name[n++] = (char)('0' + index % 10);
    p->name[n] = 0;
    p->sector_size = whole->sector_size;
    p->sectors = sectors;
    p->start_lba = start;
    p->parent = whole;
    p->flags = BLK_F_PARTITION | (whole->flags & BLK_F_READONLY);
    p->mbr_type = mbr_type;
    if (guid) for (k = 0; k < 16; ++k) p->type_guid[k] = guid[k];
    p->index = index;
    p->read = part_read;
    p->write = whole->write ? part_write : 0;
    p->flush = part_flush;
    if (blk_register(p)) return 0;
    ++nparts;
    return p;
}

int blk_scan_partitions(blk_dev_t *whole)
{
    uint8_t *s;
    unsigned i, found = 0;
    int rc;
    if (!whole || whole->sector_size != 512) return 0;
    s = kmalloc(512);
    if (!s) return -1;
    if (blk_read(whole, 0, 1, s)) { kfree(s); return -1; }
    if (s[510] != 0x55 || s[511] != 0xaa) { kfree(s); return 0; }
    /* A FAT/NTFS volume boot record also ends in 55AA: a jump opcode plus a plausible BPB means "superfloppy". */
    if ((s[0] == 0xeb || s[0] == 0xe9) && (s[11] | (s[12] << 8)) == 512 && s[13] && !(s[13] & (s[13] - 1))) { kfree(s); return 0; }
    for (i = 0; i < 4; ++i) {
        const uint8_t *e = s + 446 + 16 * i;
        if (e[4] == 0xee) {                              /* protective MBR: GPT header at LBA 1 */
            uint8_t *h = kmalloc(512);
            uint64_t entries_lba, nent, esize, k, lba;
            if (!h) { kfree(s); return -1; }
            if (blk_read(whole, 1, 1, h) || memcmp(h, "EFI PART", 8)) { kfree(h); break; }
            entries_lba = rd64(h + 72); nent = rd32(h + 80); esize = rd32(h + 84);
            if (esize < 128 || esize > 512 || nent > 128) { kfree(h); break; }
            for (k = 0; k < nent; ++k) {
                const uint8_t *e2;
                uint64_t first, last;
                unsigned z, nonzero = 0;
                lba = entries_lba + (k * esize) / 512;
                if (blk_read(whole, lba, 1, h)) break;
                e2 = h + (k * esize) % 512;
                for (z = 0; z < 16; ++z) nonzero |= e2[z];
                if (!nonzero) continue;
                first = rd64(e2 + 32); last = rd64(e2 + 40);
                if (last < first) continue;
                if (add_partition(whole, (unsigned)k + 1, first, last - first + 1, 0xee, e2)) ++found;
            }
            kfree(h);
            kfree(s);
            return (int)found;
        }
    }
    for (i = 0; i < 4; ++i) {
        const uint8_t *e = s + 446 + 16 * i;
        const uint64_t start = rd32(e + 8), sectors = rd32(e + 12);
        if (!e[4] || !start || !sectors) continue;
        if ((e[0] & 0x7f) != 0) continue;                /* boot indicator must be 0x00 or 0x80 */
        if (add_partition(whole, i + 1, start, sectors, e[4], 0)) ++found;
    }
    rc = (int)found;
    kfree(s);
    return rc;
}
