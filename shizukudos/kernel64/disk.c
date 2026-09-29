/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 disk bring-up: block drivers -> partition scan -> first FAT32 volume mounted read-only as D:\.
 * Called once from kmain() after the RAM file system and the initrd are up. STANDALONE PROFILE ONLY in practice:
 * under the Supervisor no disk device is passed through, the registry stays empty and C:\ remains alone.
 *
 * The FAT32 reader (fat32.c) only sees a blk_dev_t (blk.h): a partition device or a superfloppy whole device.
 * Its nodes appear in the common fs.c name space (FSB_DISK backing): directories are enumerated into fsnodes on
 * first use, file reads go through a per-file extent list. Everything is read-only (documented limit: no writes,
 * no timestamps changes, no delete/rename on D:).
 *
 * Evidence (parsed by tests/run_k64_disk.py):
 *   slot 13: (sector count << 32) | CRC-32 of sector 0 of the first whole device, computed from the DMA'd bytes
 *   slot 14: (root entries << 32) | FAT32 volume id when D: is mounted
 */
#include "fs.h"
#include "blk.h"
#include "fat32.h"

typedef struct {
    fat32_vol_t fat;
    blk_dev_t *dev;
    kmutex_t lock;                              /* fat32_vol_t has one bounce buffer: one operation at a time */
    fsvol_t vol;
    fsnode_t root;
    uint32_t nodes;
} disk_vol_t;

static disk_vol_t dvol;

uint32_t k64_crc32(const void *data, uint64_t n)
{
    const uint8_t *p = data;
    uint32_t c = 0xffffffffu;
    uint64_t i;
    int k;
    for (i = 0; i < n; ++i) {
        c ^= p[i];
        for (k = 0; k < 8; ++k) c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
    }
    return ~c;
}

/* ---------------------------------------------------------------- fat32 callbacks */
static int cb_read(void *ctx, uint64_t lba, void *buf) { return blk_read((blk_dev_t *)ctx, lba, 1, buf); }
static void *cb_alloc(void *ctx, uint64_t bytes) { (void)ctx; return kzalloc((size_t)bytes); }
static void cb_free(void *ctx, void *p, uint64_t bytes) { (void)ctx; (void)bytes; kfree(p); }
static void *cb_page(void *ctx)
{
    const uint64_t pa = pmm_alloc();
    (void)ctx;
    return pa ? (void *)p2v(pa) : 0;            /* FAT copy pages are never freed: the volume stays mounted */
}

/* ---------------------------------------------------------------- fsvol operations */
static int vol_read(fsvol_t *v, fsnode_t *n, uint64_t off, void *buf, uint64_t len, uint64_t *done)
{
    disk_vol_t *d = v->priv;
    int rc;
    *done = 0;
    mutex_lock(&d->lock);
    if (!n->chain) {
        fat32_chain_t *c = kzalloc(sizeof *c);
        if (!c) { mutex_unlock(&d->lock); return -1; }
        rc = fat32_chain_build(&d->fat, n->first_cluster, c);
        if (rc) { kprintf("K64 disk: %s: broken cluster chain (%d)\n", n->name, rc); kfree(c); mutex_unlock(&d->lock); return -1; }
        n->chain = c;
    }
    rc = fat32_read(&d->fat, (fat32_chain_t *)n->chain, (uint32_t)n->size, off, buf, len, done);
    mutex_unlock(&d->lock);
    return rc ? -1 : 0;
}

static int vol_populate(fsvol_t *v, fsnode_t *dir)
{
    disk_vol_t *d = v->priv;
    fat32_dir_t it;
    fat32_dirent_t *e = kmalloc(sizeof *e);
    int rc, n = 0;
    if (!e) return -1;
    mutex_lock(&d->lock);
    fat32_dir_open(&d->fat, dir->first_cluster, &it);
    while ((rc = fat32_dir_next(&d->fat, &it, e)) == 1) {
        char name[FS_NAME_MAX];
        fsnode_t *c;
        if (utf16_to_utf8(e->name, e->name_len, name, sizeof name) < 0) {
            kprintf("K64 disk: name too long in %s, entry skipped\n", dir->name[0] ? dir->name : "\\");
            continue;
        }
        c = fs_new_child(dir, name, (e->attr & FAT32_ATTR_DIR) != 0);
        if (!c) { rc = -1; break; }
        c->first_cluster = e->first_cluster;
        c->size = c->is_dir ? 0 : e->size;
        c->attrs = e->attr & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE);
        if (c->is_dir) c->attrs |= FILE_ATTRIBUTE_DIRECTORY;
        else if (!c->attrs) c->attrs = FILE_ATTRIBUTE_NORMAL;
        c->ftime_c = fat32_filetime(e->cdate, e->ctime, e->ctenth);
        c->ftime_m = fat32_filetime(e->mdate, e->mtime, 0);
        c->ctime = c->mtime = 0;
        ++n;
        ++d->nodes;
    }
    mutex_unlock(&d->lock);
    kfree(e);
    if (rc < 0) kprintf("K64 disk: enumeration of %s failed (%d) after %d entries\n", dir->name[0] ? dir->name : "\\", rc, n);
    return rc < 0 ? -1 : n;
}

/* ---------------------------------------------------------------- mount */
static int try_mount(blk_dev_t *dev)
{
    int rc;
    memset(&dvol.fat, 0, sizeof dvol.fat);
    dvol.fat.read = cb_read; dvol.fat.alloc = cb_alloc; dvol.fat.free = cb_free; dvol.fat.alloc_page = cb_page;
    dvol.fat.ctx = dev; dvol.fat.disk_sectors = dev->sectors;
    rc = fat32_mount(&dvol.fat);
    if (rc) return rc;
    dvol.dev = dev;
    mutex_init(&dvol.lock);
    dvol.vol.letter = 'D';
    dvol.vol.read = vol_read;
    dvol.vol.populate = vol_populate;
    dvol.vol.priv = &dvol;
    memset(&dvol.root, 0, sizeof dvol.root);
    dvol.root.is_dir = 1;
    dvol.root.readonly = 1;
    dvol.root.attrs = FILE_ATTRIBUTE_DIRECTORY;
    dvol.root.backing = FSB_DISK;
    dvol.root.vol = &dvol.vol;
    dvol.root.first_cluster = dvol.fat.root_cluster;
    if (fs_mount('D', &dvol.root)) return -1;
    kprintf("K64 disk: D: = %s, FAT32 \"%s\" id %x, %u clusters of %u bytes, %u FAT page(s), %u sector reads\n", dev->name,
            dvol.fat.label, dvol.fat.volume_id, dvol.fat.cluster_count, dvol.fat.bytes_per_cluster, dvol.fat.fat_npages,
            dvol.fat.sector_reads);
    return 0;
}

void disk_init(void)
{
    blk_dev_t *d, *whole = 0;
    uint8_t *sector;
    int mounted = -1;
    if (ahci_blk_init()) return;                /* NVMe / SDHCI drivers register here too once they exist */
    for (d = blk_first(); d; d = d->next)
        if (!(d->flags & BLK_F_PARTITION)) { whole = d; break; }
    if (!whole) return;
    sector = kmalloc(512);
    KASSERT(sector);
    if (blk_read(whole, 0, 1, sector) == 0) {
        const uint32_t crc = k64_crc32(sector, 512);
        kprintf("K64 disk: %s sector 0 crc32 %x, bytes 510..511 %x %x\n", whole->name, crc, sector[510], sector[511]);
        shz_evidence(13, (whole->sectors << 32) | crc);
    }
    kfree(sector);
    for (d = blk_first(); d; d = d->next)
        if (!(d->flags & BLK_F_PARTITION)) {
            const int n = blk_scan_partitions(d);
            kprintf("K64 disk: %s: %d partition(s)\n", d->name, n);
        }
    for (d = blk_first(); d && mounted; d = d->next)
        if (d->flags & BLK_F_PARTITION)
            mounted = try_mount(d);
    for (d = blk_first(); d && mounted; d = d->next)   /* superfloppy: the whole device holds the volume */
        if (!(d->flags & BLK_F_PARTITION))
            mounted = try_mount(d);
    if (mounted) { kprintf("K64 disk: no FAT32 volume found\n"); return; }
    fs_populate(&dvol.root);
    {
        fsnode_t *c;
        uint32_t n = 0;
        for (c = dvol.root.child; c; c = c->sibling) ++n;
        shz_evidence(14, ((uint64_t)n << 32) | dvol.fat.volume_id);
    }
}
