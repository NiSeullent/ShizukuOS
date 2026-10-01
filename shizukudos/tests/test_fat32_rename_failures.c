/* SPDX-License-Identifier: GPL-2.0-only
 * The real FAT32 implementation runs on an independently formatted, RAM-only
 * 65525-cluster FAT32 device. Faults live below its sector/allocator boundary.
 * A failed rename must undo even a write which applied before reporting EIO.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../kernel64/fat32.h"

#define CLUSTERS 65525u
#define FATSZ 512u
#define RESERVED 32u
#define SECTORS (RESERVED + 2u * FATSZ + CLUSTERS)
#define BYTES ((size_t)SECTORS * 512u)
#define RECOVERY (-11)
#define BUSY (-12)
static unsigned checks, trials;
static const char *label;
#define CHECK(x, why) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL: %s: %s (line %d)\n", label, why, __LINE__); exit(1); } } while (0)

typedef struct {
    uint8_t *disk;
    unsigned reads, writes, allocations, fail_read, fail_write, fail_alloc;
    unsigned mode, hit, permanent, armed, nested, nested_done;
    unsigned fault_allocations, fault_writes, deny_alloc_after_fault;
    int nested_result;
    fat32_vol_t *live;
    fat32_dirent_t source;
    uint32_t srcdir;
} device;
static void fault(device *d)
{
    if (!d->hit) { d->fault_allocations = d->allocations; d->fault_writes = d->writes; }
    d->hit = 1;
}

static int rd(void *ctx, uint64_t lba, void *buf)
{
    device *d = ctx;
    if (lba >= SECTORS) return -1;
    if (d->armed && (++d->reads == d->fail_read || (d->hit && d->permanent == 3))) { fault(d); return -1; }
    memcpy(buf, d->disk + lba * 512u, 512);
    return 0;
}
static int wr(void *ctx, uint64_t lba, const void *buf)
{
    device *d = ctx;
    if (lba >= SECTORS) return -1;
    if (d->armed) {
        ++d->writes;
        if (d->nested && !d->nested_done) {
            d->nested_done = 1;
            d->nested_result = fat32_remove(d->live, d->srcdir,
                                           d->source.dir_cluster, d->source.dir_offset);
        }
        if (d->hit && d->permanent == 2) {
            memcpy(d->disk + lba * 512u, buf, 512);
            d->disk[lba * 512u + 2] ^= 0x5a; /* dishonest zero-result undo */
            return 0;
        }
        if ((d->writes == d->fail_write) || (d->permanent == 1 && d->hit)) {
            fault(d);
            if (d->mode == 1) memcpy(d->disk + lba * 512u, buf, 512);
            if (d->mode == 2) memcpy(d->disk + lba * 512u, buf, 173);
            return -1;
        }
    }
    memcpy(d->disk + lba * 512u, buf, 512);
    return 0;
}
static void *al(void *ctx, uint64_t bytes)
{
    device *d = ctx;
    if (d->armed && (++d->allocations == d->fail_alloc || (d->deny_alloc_after_fault && d->hit))) { fault(d); return NULL; }
    return calloc(1, (size_t)bytes);
}
static void fr(void *ctx, void *p, uint64_t bytes) { (void)ctx; (void)bytes; free(p); }
static void *pg(void *ctx) { return al(ctx, 4096); }
static void w16(uint8_t *p, unsigned x) { p[0] = (uint8_t)x; p[1] = (uint8_t)(x >> 8); }
static void w32(uint8_t *p, uint32_t x) { w16(p, x); w16(p + 2, x >> 16); }
static uint32_t u32(const uint8_t *p) { return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void format(device *d)
{
    uint8_t *s = d->disk;
    memset(s, 0, BYTES);
    s[0] = 0xeb; s[1] = 0x58; s[2] = 0x90; memcpy(s + 3, "FATTEST ", 8);
    w16(s + 11, 512); s[13] = 1; w16(s + 14, RESERVED); s[16] = 2;
    s[21] = 0xf8; w16(s + 24, 63); w16(s + 26, 255);
    w32(s + 32, SECTORS); w32(s + 36, FATSZ); w32(s + 44, 2);
    w16(s + 48, 1); w16(s + 50, 6); s[64] = 0x80; s[66] = 0x29;
    w32(s + 67, 0x6970); memcpy(s + 71, "RENAMETEST ", 11); memcpy(s + 82, "FAT32   ", 8);
    w16(s + 510, 0xaa55); memcpy(s + 6u * 512u, s, 512);
    s += 512; w32(s, 0x41615252); w32(s + 484, 0x61417272);
    w32(s + 488, CLUSTERS - 1); w32(s + 492, 3); w32(s + 508, 0xaa550000);
    memcpy(d->disk + 7u * 512u, s, 512);
    s = d->disk + RESERVED * 512u;
    w32(s, 0x0ffffff8); w32(s + 4, 0x0fffffff); w32(s + 8, 0x0fffffff);
    memcpy(d->disk + (RESERVED + FATSZ) * 512u, s, FATSZ * 512u);
}
static void mount_volume(device *d, fat32_vol_t *v)
{
    memset(v, 0, sizeof *v);
    v->read = rd; v->write = wr; v->alloc = al; v->free = fr; v->alloc_page = pg;
    v->ctx = d; v->disk_sectors = SECTORS;
    CHECK(fat32_mount(v) == 0, "valid independently formatted FAT32 mounts");
}
static unsigned wide(const char *name, uint16_t out[256])
{
    unsigned n = (unsigned)strlen(name), i;
    CHECK(n <= 255, "bounded fixture name");
    for (i = 0; i < n; ++i) out[i] = (uint8_t)name[i];
    return n;
}
static int find(fat32_vol_t *v, uint32_t dir, const char *name, fat32_dirent_t *out)
{
    fat32_dir_t cursor; int rc; unsigned n = (unsigned)strlen(name), i;
    fat32_dir_open(v, dir, &cursor);
    while ((rc = fat32_dir_next(v, &cursor, out)) == 1) {
        if (out->name_len != n) continue;
        for (i = 0; i < n && out->name[i] == (uint8_t)name[i]; ++i) {}
        if (i == n) return 1;
    }
    return rc < 0 ? rc : 0;
}
static fat32_dirent_t create(fat32_vol_t *v, uint32_t dir, const char *name, int is_dir, uint8_t body)
{
    uint16_t wn[256]; fat32_dirent_t e; unsigned n = wide(name, wn);
    CHECK(fat32_create(v, dir, wn, n, is_dir, 0, 0, &e) == 0, "fixture production create");
    if (!is_dir && body) {
        uint8_t bytes[777]; fat32_chain_t c; uint32_t first = e.first_cluster, size = 0;
        memset(bytes, body, sizeof bytes);
        CHECK(fat32_chain_build(v, first, &c) == 0, "fixture production chain");
        CHECK(fat32_write(v, &c, &first, &size, 0, bytes, sizeof bytes) == 0, "fixture production write");
        CHECK(fat32_set_entry(v, e.dir_cluster, e.dir_offset, first, size, 0, 0) == 0, "fixture production metadata");
        fat32_chain_free(v, &c);
        CHECK(find(v, dir, name, &e) == 1, "fixture readback");
    }
    return e;
}
typedef struct {
    const char *source_name, *target_name;
    uint32_t srcdir, dstdir, source_first, old_first;
    int has_old, directory;
} scenario;
static scenario seed(device *d, unsigned kind)
{
    fat32_vol_t v; scenario s; fat32_dirent_t e; unsigned i; char pad[16];
    memset(&s, 0, sizeof s); format(d); mount_volume(d, &v);
    s.source_name = "SHZTHNEW.CFG"; s.target_name = "SHZTHEME.CFG"; s.has_old = kind < 3;
    if (kind >= 2) { e = create(&v, 0, "DESTDIR", 1, 0); s.dstdir = e.first_cluster; }
    if (kind == 1 || kind == 2 || kind == 3) {
        for (i = 0; i < 14; ++i) { snprintf(pad, sizeof pad, "PAD%02u.TXT", i); create(&v, 0, pad, 0, 0); }
        s.source_name = "source_name_whose_long_entries_cross_the_directory_cluster_boundary_with_a_payload.cfg";
        s.target_name = "replacement_name_with_its_own_long_entries_and_payload.cfg";
    }
    if (kind == 3) {
        for (i = 0; i < 13; ++i) { snprintf(pad, sizeof pad, "DST%02u.TXT", i); create(&v, s.dstdir, pad, 0, 0); }
    }
    if (kind == 4) { s.source_name = "SRCFOLDER"; s.target_name = "Moved Folder"; s.directory = 1; }
    e = create(&v, 0, s.source_name, s.directory, s.directory ? 0 : 0x53);
    s.source_first = e.first_cluster;
    if (s.directory) create(&v, e.first_cluster, "CHILD.TXT", 0, 0x43);
    if (s.has_old) { e = create(&v, s.dstdir, s.target_name, 0, 0x4f); s.old_first = e.first_cluster; }
    CHECK(fat32_sync(&v) == 0, "seed synced"); fat32_unmount(&v); return s;
}
static void payload(fat32_vol_t *v, const fat32_dirent_t *e, uint8_t want)
{
    fat32_chain_t c; uint8_t buf[4096]; uint64_t done, off = 0; unsigned i;
    CHECK(e->size == 777 || (want == 0x4f && e->size == 100u * 512u), "payload size unchanged");
    CHECK(fat32_chain_build(v, e->first_cluster, &c) == 0, "live allocated payload chain");
    CHECK(c.total_clusters == (e->size == 777 ? 2u : 100u), "all payload clusters owned");
    while (off < e->size) {
        uint64_t need = e->size - off < sizeof buf ? e->size - off : sizeof buf;
        CHECK(fat32_read(v, &c, e->size, off, buf, need, &done) == 0 && done == need, "payload readable");
        for (i = 0; i < done; ++i) CHECK(buf[i] == want, "payload bytes unchanged");
        off += done;
    }
    fat32_chain_free(v, &c);
}
static void verify(device *d, const scenario *s, int success)
{
    fat32_vol_t fresh; fat32_dirent_t e; uint8_t *fat = d->disk + RESERVED * 512u; uint32_t i, free_count = 0;
    mount_volume(d, &fresh);
    CHECK(memcmp(fat, d->disk + (RESERVED + FATSZ) * 512u, FATSZ * 512u) == 0, "both FAT mirrors match");
    for (i = 2; i < CLUSTERS + 2; ++i) if (!(u32(fat + i * 4u) & 0x0fffffff)) ++free_count;
    CHECK(u32(d->disk + 512u + 488) == free_count, "FSInfo matches independent allocated-cluster count");
    CHECK(find(&fresh, s->srcdir, s->source_name, &e) == (success ? 0 : 1), "source namespace survives ordinary failure");
    if (!success && !s->directory) { CHECK(e.first_cluster == s->source_first, "original source chain preserved"); payload(&fresh, &e, 0x53); }
    CHECK(find(&fresh, s->dstdir, s->target_name, &e) == (success || s->has_old ? 1 : 0), "destination namespace correct");
    if (success) {
        CHECK(e.first_cluster == s->source_first, "destination owns original source chain");
        if (!s->directory) payload(&fresh, &e, 0x53);
        else {
            uint64_t lba = fat32_cluster_lba(&fresh, e.first_cluster);
            uint8_t *dd = d->disk + lba * 512u + 32;
            CHECK(dd[0] == '.' && dd[1] == '.', "directory parent entry exists");
            CHECK(((u32(dd + 20) & 0xffff) << 16 | (dd[26] | ((uint32_t)dd[27] << 8))) == s->dstdir, "moved directory parent points to target");
            CHECK(find(&fresh, e.first_cluster, "CHILD.TXT", &e) == 1, "moved directory child retained"); payload(&fresh, &e, 0x43);
        }
        if (s->has_old) CHECK(fat32_fat_entry(&fresh, s->old_first) == 0, "replaced old chain reclaimed");
    } else if (s->has_old) { CHECK(e.first_cluster == s->old_first, "old destination chain preserved"); payload(&fresh, &e, 0x4f); }
    fat32_unmount(&fresh);
}
static int rename_call(fat32_vol_t *v, const scenario *s, const fat32_dirent_t *source)
{
    fat32_dirent_t out; uint16_t wn[256]; unsigned n = wide(s->target_name, wn);
    return fat32_rename(v, s->srcdir, source->dir_cluster, source->dir_offset, s->dstdir, wn, n, s->has_old, &out);
}
static void quarantine(device *d, fat32_vol_t *v, const scenario *s, const fat32_dirent_t *source)
{
    uint16_t wn[256]; unsigned n = wide("BLOCKED.CFG", wn), oldwrites = d->writes;
    fat32_dirent_t out; fat32_chain_t c; uint32_t first = source->first_cluster, size = source->size;
    uint32_t free_before = v->free_clusters, hint_before = v->alloc_hint, info_before = v->fsinfo_dirty;
    size_t cache_bytes = (size_t)v->fat_npages * 4096u;
    uint8_t *cache = malloc(cache_bytes), *dirty = malloc(v->fat_npages + 1u);
    CHECK(cache && dirty, "test-only quarantine snapshot");
    for (unsigned page = 0; page < v->fat_npages; ++page) memcpy(cache + page * 4096u, v->fat_pages[page], 4096);
    memcpy(dirty, v->fat_dirty, v->fat_npages + 1u);
    memset(&c, 0, sizeof c);
    CHECK(fat32_sync(v) == RECOVERY, "quarantine blocks sync");
    CHECK(fat32_remove(v, s->srcdir, source->dir_cluster, source->dir_offset) == RECOVERY, "quarantine blocks actual caller temporary cleanup");
    CHECK(fat32_create(v, 0, wn, n, 0, 0, 0, &out) == RECOVERY, "quarantine blocks create");
    CHECK(rename_call(v, s, source) == RECOVERY, "quarantine blocks another rename");
    CHECK(fat32_set_entry(v, source->dir_cluster, source->dir_offset, first, size, 0, 0) == RECOVERY, "quarantine blocks stale metadata publication");
    CHECK(fat32_truncate(v, &c, &first, &size, 0) == RECOVERY, "quarantine blocks truncate");
    CHECK(fat32_write(v, &c, &first, &size, 0, "x", 1) == RECOVERY, "quarantine blocks payload write");
    CHECK(d->writes == oldwrites, "no I/O delegated after quarantine");
    CHECK(first == source->first_cluster && size == source->size, "quarantined APIs leave caller extent outputs unchanged");
    CHECK(v->free_clusters == free_before && v->alloc_hint == hint_before && v->fsinfo_dirty == info_before, "quarantined APIs leave allocator cache unchanged");
    CHECK(memcmp(v->fat_dirty, dirty, v->fat_npages + 1u) == 0, "quarantined APIs leave dirty bitmap unchanged");
    for (unsigned page = 0; page < v->fat_npages; ++page)
        CHECK(memcmp(cache + page * 4096u, v->fat_pages[page], 4096) == 0, "quarantined APIs leave all FAT cache pages unchanged");
    free(cache); free(dirty);
}
static void trial(uint8_t *original, const scenario *s, unsigned fail_read, unsigned fail_write,
                  unsigned fail_alloc, unsigned mode, unsigned permanent, unsigned nested,
                  unsigned *readcount, unsigned *writecount, unsigned *alloccount)
{
    device d; fat32_vol_t v; fat32_dirent_t source; int rc; uint32_t free_before, hint_before;
    memset(&d, 0, sizeof d); d.disk = malloc(BYTES); CHECK(d.disk != NULL, "RAM device allocation");
    memcpy(d.disk, original, BYTES); mount_volume(&d, &v);
    CHECK(find(&v, s->srcdir, s->source_name, &source) == 1, "source acquired before fault");
    free_before = v.free_clusters; hint_before = v.alloc_hint;
    d.fail_read = fail_read; d.fail_write = fail_write; d.fail_alloc = fail_alloc;
    d.mode = mode; d.permanent = permanent; d.nested = nested; d.live = &v; d.source = source; d.srcdir = s->srcdir;
    d.deny_alloc_after_fault = 1;
    d.armed = 1; rc = rename_call(&v, s, &source); ++trials;
    if (readcount) *readcount = d.reads;
    if (writecount) *writecount = d.writes;
    if (alloccount) *alloccount = d.allocations;
    if (nested) CHECK(d.nested_done && d.nested_result == BUSY, "callback reentrant mutation refused");
    if (d.hit) CHECK(d.allocations == d.fault_allocations, "rollback never attempts allocation after the first fault");
    if (permanent) { CHECK(d.hit && rc == RECOVERY, "failed rollback yields recovery-required"); quarantine(&d, &v, s, &source); }
    else if (fail_read || fail_write || fail_alloc) {
        CHECK(d.hit && rc < 0, "fault is consumed and genuinely reported");
        CHECK(memcmp(d.disk, original, BYTES) == 0, "rollback preserves all durable sectors after failed rename");
        CHECK(v.free_clusters == free_before && v.alloc_hint == hint_before, "rollback restores allocation cache counters");
        CHECK(v.fsinfo_dirty == 0, "rollback restores FSInfo dirty state");
        for (unsigned page = 0; page < v.fat_npages; ++page)
            CHECK(memcmp(v.fat_pages[page], original + (RESERVED + page * 8u) * 512u, 4096) == 0, "rollback restores every cached FAT page");
        for (unsigned byte = 0; byte < v.fat_npages + 1; ++byte)
            CHECK(v.fat_dirty[byte] == 0, "rollback restores every FAT dirty bit");
    } else CHECK(rc == 0, "successful production rename");
    d.armed = 0; fat32_unmount(&v);
    if (!permanent) {
        verify(&d, s, !(fail_read || fail_write || fail_alloc));
        if ((fail_read || fail_write || fail_alloc) && !s->directory) {
            fat32_vol_t clean; mount_volume(&d, &clean);
            CHECK(find(&clean, s->srcdir, s->source_name, &source) == 1, "caller can locate retained temporary source");
            CHECK(fat32_remove(&clean, s->srcdir, source.dir_cluster, source.dir_offset) == 0, "real caller cleanup removes only temporary source");
            fat32_unmount(&clean); mount_volume(&d, &clean);
            if (s->has_old) { CHECK(find(&clean, s->dstdir, s->target_name, &source) == 1, "old setting survives caller cleanup"); payload(&clean, &source, 0x4f); }
            else CHECK(find(&clean, s->dstdir, s->target_name, &source) == 0, "failed new target remains absent after cleanup");
            fat32_unmount(&clean);
        }
    }
    free(d.disk);
}
/* Pending cached FAT changes may exist after an earlier partial operation. A
 * rename failure restores that precise caller state, not a freshly-zeroed cache. */
static void pending_cache_trial(uint8_t *original, const scenario *s)
{
    device d; fat32_vol_t v, fresh; fat32_dirent_t source, old; fat32_chain_t c;
    uint8_t *cache, *dirty; uint32_t tail, free_before; unsigned page;
    memset(&d, 0, sizeof d); d.disk = malloc(BYTES); CHECK(d.disk != NULL, "pending RAM device");
    memcpy(d.disk, original, BYTES); mount_volume(&d, &v);
    CHECK(find(&v, 0, s->source_name, &source) == 1, "pending source exists");
    tail = fat32_fat_entry(&v, source.first_cluster);
    CHECK(fat32_fat_entry(&v, tail) >= 0x0ffffff8u && fat32_fat_entry(&v, 65520) == 0, "independent pending chain layout");
    v.fat_pages[tail >> 10][tail & 1023] = 65520;
    v.fat_pages[65520 >> 10][65520 & 1023] = 0x0fffffff;
    v.fat_dirty[(tail / 128u) >> 3] |= (uint8_t)(1u << ((tail / 128u) & 7));
    v.fat_dirty[(65520u / 128u) >> 3] |= (uint8_t)(1u << ((65520u / 128u) & 7));
    --v.free_clusters; v.alloc_hint = 65521; v.fsinfo_dirty = 1; free_before = v.free_clusters;
    cache = malloc((size_t)v.fat_npages * 4096u); dirty = malloc(v.fat_npages + 1u);
    CHECK(cache && dirty, "pending test snapshots");
    for (page = 0; page < v.fat_npages; ++page) memcpy(cache + page * 4096u, v.fat_pages[page], 4096);
    memcpy(dirty, v.fat_dirty, v.fat_npages + 1u);
    d.armed = 1; d.fail_write = 2; d.mode = 1; d.deny_alloc_after_fault = 1;
    CHECK(rename_call(&v, s, &source) == FAT32_E_IO && d.hit, "pending rename fails after an earlier successful write");
    CHECK(d.allocations == d.fault_allocations, "pending rollback does not allocate");
    CHECK(memcmp(d.disk, original, BYTES) == 0, "pending rollback preserves original durable sectors");
    CHECK(v.free_clusters == free_before && v.alloc_hint == 65521 && v.fsinfo_dirty == 1, "pending allocation/FSInfo state retained");
    CHECK(memcmp(dirty, v.fat_dirty, v.fat_npages + 1u) == 0, "pre-existing nonzero dirty bits retained");
    for (page = 0; page < v.fat_npages; ++page)
        CHECK(memcmp(cache + page * 4096u, v.fat_pages[page], 4096) == 0, "pre-existing pending FAT entries retained");
    d.armed = 0; verify(&d, s, 0);
    CHECK(fat32_chain_build(&v, source.first_cluster, &c) == 0 && c.total_clusters == 3, "live volume retains pending source extent");
    fat32_chain_free(&v, &c);
    CHECK(fat32_remove(&v, 0, source.dir_cluster, source.dir_offset) == 0, "live actual caller cleanup handles restored pending chain");
    fat32_unmount(&v); mount_volume(&d, &fresh);
    CHECK(find(&fresh, 0, s->source_name, &source) == 0, "live cleanup source absent after remount");
    CHECK(find(&fresh, 0, s->target_name, &old) == 1, "old destination remains after live cleanup"); payload(&fresh, &old, 0x4f);
    CHECK(fat32_fat_entry(&fresh, 65520) == 0, "pending source cluster safely reclaimed");
    CHECK(memcmp(d.disk + RESERVED * 512u, d.disk + (RESERVED + FATSZ) * 512u, FATSZ * 512u) == 0, "pending cleanup FAT mirrors agree");
    CHECK(u32(d.disk + 512u + 488) == fresh.free_clusters, "pending cleanup FSInfo readback agrees");
    fat32_unmount(&fresh); free(cache); free(dirty); free(d.disk); ++trials;
}
int main(void)
{
    unsigned kind, i, mode, reads, writes, allocations; device seeddev; scenario s;
    static const char *names[] = { "same-sector replacement", "cross-cluster LFN replacement", "cross-directory replacement", "new-target directory growth", "directory move parent update", "fragmented replacement beyond128 sectors" };
    memset(&seeddev, 0, sizeof seeddev); seeddev.disk = malloc(BYTES); label = "fixture";
    CHECK(seeddev.disk != NULL, "RAM-only seed device");
    for (kind = 0; kind < 6; ++kind) {
        label = names[kind]; s = seed(&seeddev, kind == 5 ? 0 : kind);
        if (kind == 5) {
            fat32_vol_t volume; fat32_dirent_t old; uint8_t *fat;
            mount_volume(&seeddev, &volume);
            CHECK(find(&volume, 0, s.target_name, &old) == 1, "fragmented destination located");
            fat = seeddev.disk + RESERVED * 512u;
            for (unsigned cur = old.first_cluster; cur < 0x0ffffff8u;) { unsigned next = u32(fat + cur * 4u) & 0x0fffffff; w32(fat + cur * 4u, 0); cur = next; }
            for (unsigned part = 0; part < 100; ++part) {
                unsigned cur = (part + 1u) * 128u;
                CHECK((u32(fat + cur * 4u) & 0x0fffffff) == 0, "independent fragmented cluster is unused");
                w32(fat + cur * 4u, part == 99 ? 0x0fffffffu : cur + 128u);
                memset(seeddev.disk + fat32_cluster_lba(&volume, cur) * 512u, 0x4f, 512);
            }
            uint8_t *entry = seeddev.disk + fat32_cluster_lba(&volume, old.dir_cluster) * 512u + old.dir_offset;
            w16(entry + 20, 0); w16(entry + 26, 128); w32(entry + 28, 100u * 512u); s.old_first = 128;
            memcpy(seeddev.disk + (RESERVED + FATSZ) * 512u, fat, FATSZ * 512u);
            unsigned available = 0; for (unsigned cur = 2; cur < CLUSTERS + 2; ++cur) if (!(u32(fat + cur * 4u) & 0x0fffffff)) ++available;
            w32(seeddev.disk + 512u + 488, available);
            fat32_unmount(&volume);
        }
        trial(seeddev.disk, &s, 0, 0, 0, 0, 0, 0, &reads, &writes, &allocations);
        for (mode = 0; mode < 3; ++mode)
            for (i = 1; i <= writes; ++i) trial(seeddev.disk, &s, 0, i, 0, mode, 0, 0, NULL, NULL, NULL);
        for (i = 1; i <= reads; ++i) trial(seeddev.disk, &s, i, 0, 0, 0, 0, 0, NULL, NULL, NULL);
        for (i = 1; i <= allocations; ++i) trial(seeddev.disk, &s, 0, 0, i, 0, 0, 0, NULL, NULL, NULL);
        for (mode = 0; mode < 3; ++mode) trial(seeddev.disk, &s, 0, writes, 0, mode, 1, 0, NULL, NULL, NULL);
        trial(seeddev.disk, &s, 0, 1, 0, 0, 2, 0, NULL, NULL, NULL);
        trial(seeddev.disk, &s, 0, 1, 0, 0, 3, 0, NULL, NULL, NULL);
        trial(seeddev.disk, &s, 0, 0, 0, 0, 0, 1, NULL, NULL, NULL);
        printf("scenario %u: %u reads, %u writes, %u allocations covered\n", kind, reads, writes, allocations);
        if (kind == 0) pending_cache_trial(seeddev.disk, &s);
    }
    free(seeddev.disk);
    printf("PASS: %u FAT32 rename checks across %u real-backend trials\n", checks, trials);
    return 0;
}
