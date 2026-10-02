/* SPDX-License-Identifier: GPL-2.0-only
 * Includes the actual disk bridge and links actual fat32.c. Only scheduler,
 * clock and kernel allocation boundaries are replaced for this host process.
 */
#define main fat_backend_fixture_main
#include "test_fat32_rename_failures.c"
#undef main
#include "../kernel64/fs.h"
#include "../kernel64/blk.h"
static long host_clock(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value)
{ (void)op; (void)a; (void)b; if (value) *value = 1785283200; return 0; }
#define shz_hcall host_clock
#include "../kernel64/disk.c"
#undef shz_hcall
void *kmalloc(size_t bytes) { return malloc(bytes); }
void *kzalloc(size_t bytes) { return calloc(1, bytes); }
void kfree(void *p) { free(p); }
void kprintf(const char *fmt, ...) { (void)fmt; }
void mutex_lock(kmutex_t *m) { (void)m; }
void mutex_unlock(kmutex_t *m) { (void)m; }
static unsigned host_flushes;
int blk_flush(blk_dev_t *dev) { (void)dev; ++host_flushes; return 0; }
uint32_t ahci_blk_flushes(void) { return host_flushes; }
int blk_read(blk_dev_t *dev, uint64_t lba, unsigned count, void *buf)
{
    for (unsigned i = 0; i < count; ++i) if (rd(dev->priv, lba + i, (uint8_t *)buf + i * 512u)) return -1;
    return 0;
}
int blk_write(blk_dev_t *dev, uint64_t lba, unsigned count, const void *buf)
{
    for (unsigned i = 0; i < count; ++i) if (wr(dev->priv, lba + i, (const uint8_t *)buf + i * 512u)) return -1;
    return 0;
}

int main(void)
{
    device d; disk_vol_t volume; scenario s; fsnode_t n, before, parent;
    fat32_dirent_t source; uint32_t serial, spc; uint64_t total, avail; char text[12]; int writable, rc;
    blk_dev_t block; uint64_t done; char readbyte = '?';
    label = "production disk bridge"; memset(&d, 0, sizeof d); memset(&volume, 0, sizeof volume);
    d.disk = malloc(BYTES); CHECK(d.disk != NULL, "RAM device"); s = seed(&d, 0);
    mount_volume(&d, &volume.fat); volume.vol.priv = &volume; volume.vol.write = vol_write;
    memset(&block, 0, sizeof block); strcpy(block.name, "memory-only"); volume.dev = &block;
    memset(&n, 0, sizeof n); memset(&parent, 0, sizeof parent);
    CHECK(find(&volume.fat, 0, s.source_name, &source) == 1, "source readback");
    n.backing = FSB_DISK; n.vol = &volume.vol; n.parent = &parent;
    n.first_cluster = source.first_cluster; n.size = source.size;
    n.dir_cluster = source.dir_cluster; n.dir_offset = source.dir_offset;
    n.ftime_m = 123; n.attrs = FILE_ATTRIBUTE_NORMAL; strcpy(n.name, s.source_name); before = n;
    d.armed = 1; d.fail_write = 1;
    rc = commit_entry(&volume, &n, 400, 900);
    CHECK(rc != 0 && d.hit, "actual metadata write fails");
    CHECK(memcmp(&n, &before, sizeof n) == 0, "failed production commit must not publish fsnode metadata");
    d.armed = 0; d.hit = 0; d.writes = 0; d.fail_write = 0;
    CHECK(commit_entry(&volume, &n, source.first_cluster, source.size) == 0, "normal metadata commit remains supported");
    CHECK(n.first_cluster == source.first_cluster && n.size == source.size && n.ftime_m != 123, "successful metadata commit publishes actual state");
    CHECK((n.attrs & FILE_ATTRIBUTE_ARCHIVE) && !(n.attrs & FILE_ATTRIBUTE_NORMAL), "successful commit publishes attributes");
    CHECK(disk_volume_info(&n, &serial, text, &total, &avail, &spc, &writable) == 0 && writable, "normal volume reports writable");
    CHECK(vol_flush(&volume.vol) == 0 && host_flushes == 1, "normal production flush reaches host device boundary");
    d.armed = 1; d.fail_write = 1; d.permanent = 1; d.mode = 2;
    rc = rename_call(&volume.fat, &s, &source);
    CHECK(rc == RECOVERY && d.hit, "real torn/permanent rollback poisons mounted FAT");
    before = n;
    CHECK(vol_write(&volume.vol, &n, 0, "x", 1) != 0, "bridge refuses write on poisoned FAT");
    CHECK(memcmp(&n, &before, sizeof n) == 0, "poisoned write leaves complete node/cache unchanged");
    CHECK(vol_truncate(&volume.vol, &n, 0) != 0, "bridge refuses truncate on poisoned FAT");
    CHECK(memcmp(&n, &before, sizeof n) == 0, "poisoned truncate leaves complete node/cache unchanged");
    CHECK(commit_entry(&volume, &n, 500, 1000) == RECOVERY, "direct metadata commit rejects recovery state");
    CHECK(memcmp(&n, &before, sizeof n) == 0, "direct recovery commit preserves cached metadata");
    CHECK(vol_remove(&volume.vol, &n) != 0, "actual temporary cleanup bridge refused");
    CHECK(memcmp(&n, &before, sizeof n) == 0, "failed cleanup preserves node/cache");
    CHECK(vol_flush(&volume.vol) != 0 && host_flushes == 1, "poisoned bridge refuses device flush");
    CHECK(vol_read(&volume.vol, &n, 0, &readbyte, 1, &done) != 0 && done == 0 && readbyte == '?', "poisoned bridge refuses stale-chain data reads");
    CHECK(memcmp(&n, &before, sizeof n) == 0, "poisoned data read leaves node/extent cache unchanged");
    CHECK(disk_volume_info(&n, &serial, text, &total, &avail, &spc, &writable) == 0 && !writable, "poisoned FAT reports not writable despite fsvol callback");
    d.armed = 0; fat32_unmount(&volume.fat); free(d.disk);
    printf("PASS: %u production disk quarantine checks\n", checks);
    return 0;
}
