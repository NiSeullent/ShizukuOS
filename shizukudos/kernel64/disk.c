/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 disk bring-up: block drivers -> partition scan -> first FAT32 volume mounted as D:\ (read/write when the
 * block device can write).
 * Called once from kmain() after the RAM file system and the initrd are up. STANDALONE PROFILE ONLY in practice:
 * under the Supervisor no disk device is passed through, the registry stays empty and C:\ remains alone.
 *
 * The FAT32 reader (fat32.c) only sees a blk_dev_t (blk.h): a partition device or a superfloppy whole device.
 * Its nodes appear in the common fs.c name space (FSB_DISK backing): directories are enumerated into fsnodes on
 * first use, file reads go through a per-file extent list. Writes (fat32.c) create files and directories with long
 * names, extend/overwrite/truncate files and update the directory entry (size, first cluster, write time from the
 * RTC); every call leaves the on-disk FAT and directories consistent. NtFlushBuffersFile issues FLUSH CACHE EXT.
 * Not supported on D: (documented): delete, rename, writing a file while it backs a mapped image (kwin view).
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
static int cb_write(void *ctx, uint64_t lba, const void *buf) { return blk_write((blk_dev_t *)ctx, lba, 1, buf); }
static void *cb_alloc(void *ctx, uint64_t bytes) { (void)ctx; return kzalloc((size_t)bytes); }
static void cb_free(void *ctx, void *p, uint64_t bytes) { (void)ctx; (void)bytes; kfree(p); }
static void *cb_page(void *ctx)
{
    const uint64_t pa = pmm_alloc();
    (void)ctx;
    return pa ? (void *)p2v(pa) : 0;            /* FAT copy pages are never freed: the volume stays mounted */
}

/* "NAME~1.EXT" from an 11-byte short entry name (stored only for entries that also have a long name); bytes of the
 * OEM code page (>= 0x80, including the 0x05 escape for a leading 0xE5) become '_' as in fat32.c's 8.3 names. */
static void set_alias(fsnode_t *c, const uint8_t *sn)
{
    unsigned i, n = 0;
    for (i = 0; i < 8 && sn[i] != ' '; ++i) c->alias[n++] = sn[i] >= 0x80 || (i == 0 && sn[0] == 0x05) ? '_' : (char)sn[i];
    if (sn[8] != ' ') {
        c->alias[n++] = '.';
        for (i = 8; i < 11 && sn[i] != ' '; ++i) c->alias[n++] = sn[i] >= 0x80 ? '_' : (char)sn[i];
    }
    c->alias[n] = 0;
}

/* ---------------------------------------------------------------- fsvol operations */
/* Extent list of a file, built on first use (caller holds d->lock). */
static fat32_chain_t *node_chain(disk_vol_t *d, fsnode_t *n)
{
    if (!n->chain) {
        fat32_chain_t *c = kzalloc(sizeof *c);
        int rc;
        if (!c) return 0;
        rc = fat32_chain_build(&d->fat, n->first_cluster, c);
        if (rc) { kprintf("K64 disk: %s: broken cluster chain (%d)\n", n->name, rc); kfree(c); return 0; }
        n->chain = c;
    }
    return n->chain;
}

static int vol_read(fsvol_t *v, fsnode_t *n, uint64_t off, void *buf, uint64_t len, uint64_t *done)
{
    disk_vol_t *d = v->priv;
    fat32_chain_t *c;
    int rc;
    *done = 0;
    mutex_lock(&d->lock);
    c = node_chain(d, n);
    rc = c ? fat32_read(&d->fat, c, (uint32_t)n->size, off, buf, len, done) : -1;
    mutex_unlock(&d->lock);
    return rc ? -1 : 0;
}

static uint32_t writes_ok, creates_ok;
extern uint32_t ahci_blk_flushes(void);         /* ahci_blk.c diagnostics (kept out of the shared blk.h) */

/* Current time as a FAT date/time (the RTC is UTC; FAT stores local time, UTC is used as the local zone). */
static void now_dos(uint16_t *date, uint16_t *time)
{
    hcreg_t secs = 0;
    shz_hcall(SHZ_HC_WALLTIME, 0, 0, &secs);
    fat32_dostime(secs, date, time);
}

/* After a size/extent change: record first cluster, size and write time in the directory entry and the node. */
static int commit_entry(disk_vol_t *d, fsnode_t *n, uint32_t first, uint32_t size)
{
    uint16_t date, time;
    int rc;
    now_dos(&date, &time);
    rc = fat32_set_entry(&d->fat, n->dir_cluster, n->dir_offset, first, size, date, time);
    n->first_cluster = first;
    n->size = size;
    n->ftime_m = fat32_filetime(date, time, 0);
    n->attrs = (n->attrs & ~(uint32_t)FILE_ATTRIBUTE_NORMAL) | FILE_ATTRIBUTE_ARCHIVE;
    return rc;
}

static int vol_write(fsvol_t *v, fsnode_t *n, uint64_t off, const void *buf, uint64_t len)
{
    disk_vol_t *d = v->priv;
    fat32_chain_t *c;
    uint32_t first, size;
    int rc, rc2;
    if (n->view) return -1;                         /* the file backs a mapped image: its cached pages must not change */
    mutex_lock(&d->lock);
    c = node_chain(d, n);
    if (!c) { mutex_unlock(&d->lock); return -1; }
    first = n->first_cluster; size = (uint32_t)n->size;
    rc = fat32_write(&d->fat, c, &first, &size, off, buf, len);
    rc2 = commit_entry(d, n, first, size);          /* also after a partial failure: allocated clusters stay reachable */
    if (!rc && !rc2) ++writes_ok;
    mutex_unlock(&d->lock);
    if (rc || rc2) kprintf("K64 disk: write %s at %llu (+%llu) failed (%d/%d)\n", n->name, off, len, rc, rc2);
    return rc == FAT32_E_FULL ? -2 : (rc || rc2) ? -1 : 0;
}

static int vol_truncate(fsvol_t *v, fsnode_t *n, uint64_t new_size)
{
    disk_vol_t *d = v->priv;
    fat32_chain_t *c;
    uint32_t first, size;
    int rc, rc2;
    if (n->view) return -1;
    if (new_size > 0xffffffffull) return -2;
    mutex_lock(&d->lock);
    c = node_chain(d, n);
    if (!c) { mutex_unlock(&d->lock); return -1; }
    first = n->first_cluster; size = (uint32_t)n->size;
    rc = fat32_truncate(&d->fat, c, &first, &size, (uint32_t)new_size);
    rc2 = commit_entry(d, n, first, size);
    mutex_unlock(&d->lock);
    return rc == FAT32_E_FULL ? -2 : (rc || rc2) ? -1 : 0;
}

static fsnode_t *vol_create(fsvol_t *v, fsnode_t *dir, const char *name, int is_dir)
{
    disk_vol_t *d = v->priv;
    uint16_t wname[256], date, time;
    fat32_dirent_t *e = kmalloc(sizeof *e);
    fsnode_t *c = 0;
    int n, rc;
    if (!e) return 0;
    n = utf8_to_utf16(name, wname, 256);
    if (n <= 0) { kfree(e); return 0; }
    now_dos(&date, &time);
    mutex_lock(&d->lock);
    rc = fat32_create(&d->fat, dir->first_cluster, wname, (unsigned)n, is_dir, date, time, e);
    if (!rc) {
        c = fs_new_child(dir, name, is_dir);
        if (c) {
            c->first_cluster = e->first_cluster;
            c->size = 0;
            c->attrs = is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
            c->ftime_c = c->ftime_m = fat32_filetime(date, time, 0);
            c->dir_cluster = e->dir_cluster;
            c->dir_offset = e->dir_offset;
            if (e->has_lfn) set_alias(c, e->short_name);
            c->populated = 1;                       /* a new directory holds only "." and ".." */
            ++creates_ok;
            ++d->nodes;
        }
    } else {
        kprintf("K64 disk: create %s in %s failed (%d)\n", name, dir->name[0] ? dir->name : "\\", rc);
    }
    mutex_unlock(&d->lock);
    kfree(e);
    return c;
}

/* Flushes the device write cache and logs the disk counters (the evidence line tests/run_k64_disk.py reads). */
static int vol_flush(fsvol_t *v)
{
    disk_vol_t *d = v->priv;
    blk_dev_t *w;
    int rc;
    mutex_lock(&d->lock);
    rc = blk_flush(d->dev);
    for (w = d->dev; w->parent; w = w->parent) ;
    kprintf("K64 disk: flush %s: rc %d; %s: %llu sectors read, %llu written, %u cache flush(es); D: %u write(s), "
            "%u create(s), %u sector writes, %u free clusters\n", d->dev->name, rc, w->name, w->reads, w->writes,
            ahci_blk_flushes(), writes_ok, creates_ok, d->fat.sector_writes, d->fat.free_clusters);
    mutex_unlock(&d->lock);
    return rc;
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
        c->dir_cluster = e->dir_cluster;
        c->dir_offset = e->dir_offset;
        if (e->has_lfn) set_alias(c, e->short_name);
        c->size = c->is_dir ? 0 : e->size;
        if (e->attr & FAT32_ATTR_RO) c->readonly = 1;
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
    dvol.fat.write = dev->write && !(dev->flags & BLK_F_READONLY) ? cb_write : 0;
    dvol.fat.ctx = dev; dvol.fat.disk_sectors = dev->sectors;
    rc = fat32_mount(&dvol.fat);
    if (rc) return rc;
    dvol.dev = dev;
    mutex_init(&dvol.lock);
    dvol.vol.letter = 'D';
    dvol.vol.read = vol_read;
    dvol.vol.populate = vol_populate;
    if (dvol.fat.write) {                           /* fat32_mount clears it for volumes it will not modify */
        dvol.vol.write = vol_write;
        dvol.vol.truncate = vol_truncate;
        dvol.vol.create = vol_create;
    }
    dvol.vol.flush = vol_flush;
    dvol.vol.priv = &dvol;
    memset(&dvol.root, 0, sizeof dvol.root);
    dvol.root.is_dir = 1;
    dvol.root.readonly = !dvol.fat.write;
    dvol.root.attrs = FILE_ATTRIBUTE_DIRECTORY;
    dvol.root.backing = FSB_DISK;
    dvol.root.vol = &dvol.vol;
    dvol.root.first_cluster = dvol.fat.root_cluster;
    if (fs_mount('D', &dvol.root)) return -1;
    kprintf("K64 disk: D: = %s, FAT32 \"%s\" id %x, %u clusters of %u bytes, %u free, %u FAT page(s), %u sector reads, %s\n",
            dev->name, dvol.fat.label, dvol.fat.volume_id, dvol.fat.cluster_count, dvol.fat.bytes_per_cluster,
            dvol.fat.free_clusters, dvol.fat.fat_npages, dvol.fat.sector_reads, dvol.fat.write ? "read/write" : "read-only");
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
