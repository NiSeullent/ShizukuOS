/* SPDX-License-Identifier: GPL-2.0-only
 * Real fat32.c replacement saves on a byte-addressed sector transport.
 * Faults occur below the filesystem; no MoveFileEx or rename substitute.
 * The deliberately small FAT32-only BPB is accepted by fat32_mount's explicit
 * small-volume contract. No private image, kernel or Windows guest is used.
 */
#include "../kernel64/fat32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { CLUSTERS = 128, RESERVED = 2, FATSZ = 2, NFATS = 2,
       DATA = RESERVED + FATSZ * NFATS, SECTORS = DATA + CLUSTERS };
static unsigned assertions, cases;
static int verify_failed_output = 1;
#define CHECK(x) do { ++assertions; if (!(x)) { fprintf(stderr, "FAIL %u: %s\n", (unsigned)__LINE__, #x); exit(1); } } while (0)

enum fault { NONE, READ_N, WRITE_N, PUBLISH, ALLOC_N, PERSISTENT };
struct disk {
    unsigned char bytes[SECTORS * 512];
    enum fault fault;
    unsigned nth, reads, writes, attempts, allocations, live, fired, damage;
    uint64_t destination_lba;
    unsigned destination_offset;
    uint32_t source_cluster;
};
struct fixture {
    struct disk disk;
    fat32_vol_t volume;
    fat32_dirent_t src, dst;
    uint32_t src_dir, dst_dir;
    char src_name[256], dst_name[256];
    unsigned char old[1117], newer[1543];
};
static uint16_t r16(const unsigned char *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t r32(const unsigned char *p) { return (uint32_t)r16(p) | ((uint32_t)r16(p + 2) << 16); }
static void w16(unsigned char *p, unsigned x) { p[0] = (unsigned char)x; p[1] = (unsigned char)(x >> 8); }
static void w32(unsigned char *p, uint32_t x) { w16(p, x); w16(p + 2, x >> 16); }
static int rd(void *ctx, uint64_t lba, void *buffer)
{
    struct disk *d = ctx;
    CHECK(lba < SECTORS);
    ++d->reads;
    if (d->fault == READ_N && d->reads == d->nth) { ++d->fired; return -1; }
    memcpy(buffer, d->bytes + lba * 512, 512);
    return 0;
}
static int wr(void *ctx, uint64_t lba, const void *buffer)
{
    struct disk *d = ctx;
    const unsigned char *p = buffer;
    int fail;
    CHECK(lba < SECTORS);
    ++d->writes;
    fail = (d->fault == WRITE_N && d->writes == d->nth) ||
           (d->fault == PERSISTENT && d->writes >= d->nth) ||
           (d->fault == PUBLISH && lba == d->destination_lba &&
            ((uint32_t)r16(p + d->destination_offset + 20) << 16 |
             r16(p + d->destination_offset + 26)) == d->source_cluster && !d->fired);
    if (fail) {
        /* A failed write is allowed to have modified the sector. Subsequent
         * persistent failures leave it untouched, making the boundary exact.
         */
        if (!d->fired && d->damage) memcpy(d->bytes + lba * 512, buffer, d->damage == 1 ? 512 : 288);
        ++d->fired;
        return -1;
    }
    memcpy(d->bytes + lba * 512, buffer, 512);
    return 0;
}
static void *al(void *ctx, uint64_t bytes)
{
    struct disk *d = ctx; void *p;
    CHECK(bytes <= 1024 * 1024);
    ++d->allocations;
    if (d->fault == ALLOC_N && d->allocations == d->nth) { ++d->fired; return NULL; }
    p = calloc(1, (size_t)bytes);
    if (p) ++d->live;
    return p;
}
static void fr(void *ctx, void *p, uint64_t bytes)
{ struct disk *d = ctx; (void)bytes; CHECK(p && d->live); --d->live; free(p); }
static void *pg(void *ctx) { return al(ctx, 4096); }
static void mount(struct fixture *f)
{
    fat32_vol_t *v = &f->volume;
    memset(v, 0, sizeof(*v));
    v->read = rd; v->write = wr; v->alloc = al; v->free = fr; v->alloc_page = pg;
    v->ctx = &f->disk; v->disk_sectors = SECTORS;
    CHECK(fat32_mount(v) == FAT32_OK);
}
static void remount(struct fixture *f)
{
    f->disk.fault = NONE;
    fat32_unmount(&f->volume);
    CHECK(!f->disk.live);
    mount(f);
}
static unsigned wide(const char *name, uint16_t out[256])
{ unsigned i; for (i = 0; name[i]; ++i) { CHECK(i < 255); out[i] = (unsigned char)name[i]; } return i; }
static int lookup(struct fixture *f, uint32_t dir, const char *name, fat32_dirent_t *out)
{
    fat32_dir_t d; fat32_dirent_t e; int rc; unsigned i;
    fat32_dir_open(&f->volume, dir, &d);
    while ((rc = fat32_dir_next(&f->volume, &d, &e)) == 1) {
        for (i = 0; name[i] && i < e.name_len && (unsigned char)name[i] == e.name[i]; ++i) {}
        if (!name[i] && i == e.name_len) { *out = e; return 1; }
    }
    CHECK(rc == 0);
    return 0;
}
static fat32_dirent_t create(struct fixture *f, uint32_t dir, const char *name, int is_dir)
{
    uint16_t u[256]; fat32_dirent_t e; unsigned n = wide(name, u);
    CHECK(fat32_create(&f->volume, dir, u, n, is_dir, 0x5c9d, 0x6000, &e) == FAT32_OK);
    return e;
}
static void write_bytes(struct fixture *f, fat32_dirent_t *e, uint64_t off, const unsigned char *p, unsigned n)
{
    fat32_chain_t c;
    CHECK(fat32_chain_build(&f->volume, e->first_cluster, &c) == FAT32_OK);
    CHECK(fat32_write(&f->volume, &c, &e->first_cluster, &e->size, off, p, n) == FAT32_OK);
    fat32_chain_free(&f->volume, &c);
    CHECK(fat32_set_entry(&f->volume, e->dir_cluster, e->dir_offset, e->first_cluster, e->size, 0x5c9e, 0x6200) == FAT32_OK);
}
static void format(struct fixture *f)
{
    unsigned i; unsigned char *p = f->disk.bytes;
    memset(f, 0, sizeof(*f));
    p[0] = 0xeb; p[2] = 0x90; w16(p + 11, 512); p[13] = 1;
    w16(p + 14, RESERVED); p[16] = NFATS; w32(p + 32, SECTORS);
    w32(p + 36, FATSZ); w32(p + 44, 2); w16(p + 48, 1); p[66] = 0x29;
    memcpy(p + 71, "REPLACE    ", 11); w16(p + 510, 0xaa55);
    p += 512; w32(p, 0x41615252); w32(p + 484, 0x61417272);
    w32(p + 488, CLUSTERS - 1); w32(p + 492, 3); w32(p + 508, 0xaa550000);
    for (i = 0; i < NFATS; ++i) {
        p = f->disk.bytes + (RESERVED + i * FATSZ) * 512;
        w32(p, 0x0ffffff8); w32(p + 4, 0x0fffffff); w32(p + 8, 0x0fffffff);
    }
    for (i = 0; i < sizeof(f->old); ++i) f->old[i] = (unsigned char)(0x31 + i * 13);
    for (i = 0; i < sizeof(f->newer); ++i) f->newer[i] = (unsigned char)(0x93 + i * 17);
    mount(f);
}
static void setup(struct fixture *f, unsigned kind)
{
    unsigned i, off; fat32_dirent_t e; unsigned char filler[512];
    format(f); memset(filler, 0x7b, sizeof(filler));
    strcpy(f->src_name, "STAGED.TMP"); strcpy(f->dst_name, "SAVED.TXT");
    if (kind == 2 || kind == 3) {
        e = create(f, 0, "Source Folder", 1); f->src_dir = e.first_cluster;
        e = create(f, 0, "Destination Folder", 1); f->dst_dir = e.first_cluster;
    }
    if (kind == 1 || kind == 3) {
        memset(f->src_name, 'a', 251); memcpy(f->src_name + 251, ".tmp", 5);
        strcpy(f->dst_name, "Saved ShizukuOS appearance and Office document.txt");
    }
    f->dst = create(f, f->dst_dir, f->dst_name, 0);
    /* Separate extents by genuine allocations, then retain every filler as a
     * live independently checked file. No hand-edited chain is accepted.
     */
    for (off = 0; off < sizeof(f->old); off += 512) {
        char name[16]; unsigned n = (unsigned)sizeof(f->old) - off;
        if (n > 512) n = 512;
        write_bytes(f, &f->dst, off, f->old + off, n);
        snprintf(name, sizeof(name), "OLD%u.BIN", off / 512);
        e = create(f, 0, name, 0); write_bytes(f, &e, 0, filler, 512);
    }
    if (kind == 1 || kind == 3) for (i = 0; i < 11; ++i) {
        char name[16]; snprintf(name, sizeof(name), "PAD%u.TXT", i); (void)create(f, f->src_dir, name, 0);
    }
    f->src = create(f, f->src_dir, f->src_name, 0);
    for (off = 0; off < sizeof(f->newer); off += 512) {
        char name[16]; unsigned n = (unsigned)sizeof(f->newer) - off;
        if (n > 512) n = 512;
        write_bytes(f, &f->src, off, f->newer + off, n);
        snprintf(name, sizeof(name), "NEW%u.BIN", off / 512);
        e = create(f, 0, name, 0); write_bytes(f, &e, 0, filler, 512);
    }
    f->disk.destination_lba = fat32_cluster_lba(&f->volume, f->dst.dir_cluster) + f->dst.dir_offset / 512;
    f->disk.destination_offset = f->dst.dir_offset % 512;
    f->disk.source_cluster = f->src.first_cluster;
}
static void arm(struct fixture *f, enum fault type, unsigned nth, unsigned damage)
{
    f->disk.fault = type; f->disk.nth = nth; f->disk.damage = damage;
    f->disk.reads = f->disk.writes = f->disk.allocations = f->disk.fired = 0;
    f->volume.sector_lba = ~(uint64_t)0;
}
static int replace(struct fixture *f, fat32_dirent_t *out)
{
    uint16_t u[256]; unsigned n = wide(f->dst_name, u);
    return fat32_rename(&f->volume, f->src_dir, f->src.dir_cluster, f->src.dir_offset,
                        f->dst_dir, u, n, 1, out);
}
static void contents(struct fixture *f, uint32_t dir, const char *name, const unsigned char *want, unsigned n)
{
    fat32_dirent_t e; fat32_chain_t c; unsigned char data[1544]; uint64_t done;
    CHECK(lookup(f, dir, name, &e)); CHECK(e.size == n);
    CHECK(fat32_chain_build(&f->volume, e.first_cluster, &c) == FAT32_OK);
    memset(data, 0xa5, sizeof(data));
    CHECK(fat32_read(&f->volume, &c, e.size, 0, data, n, &done) == FAT32_OK && done == n);
    CHECK(!memcmp(data, want, n) && data[n] == 0xa5);
    fat32_chain_free(&f->volume, &c);
}
static void walk_ownership(struct fixture *f, uint32_t dir, unsigned char owner[CLUSTERS + 2], unsigned depth)
{
    fat32_dir_t d; fat32_dirent_t e; int rc;
    CHECK(depth < 8);
    fat32_dir_open(&f->volume, dir, &d);
    while ((rc = fat32_dir_next(&f->volume, &d, &e)) == 1) {
        uint32_t c = e.first_cluster; unsigned guard = 0;
        while (c >= 2 && c < 0x0ffffff8) {
            CHECK(c < CLUSTERS + 2 && ++guard <= CLUSTERS && !owner[c]);
            owner[c] = 1; c = fat32_fat_entry(&f->volume, c);
        }
        CHECK(!e.first_cluster || c >= 0x0ffffff8);
        if (e.attr & FAT32_ATTR_DIR) walk_ownership(f, e.first_cluster, owner, depth + 1);
    }
    CHECK(rc == 0);
}
static void integrity(struct fixture *f)
{
    unsigned char owner[CLUSTERS + 2] = {0}; unsigned i, free_count = 0;
    uint32_t c = f->volume.root_cluster;
    while (c < 0x0ffffff8) { CHECK(c >= 2 && c < CLUSTERS + 2 && !owner[c]); owner[c] = 1; c = fat32_fat_entry(&f->volume, c); }
    walk_ownership(f, 0, owner, 0);
    for (i = 2; i < CLUSTERS + 2; ++i) {
        const uint32_t value = r32(f->disk.bytes + RESERVED * 512 + i * 4) & 0x0fffffff;
        CHECK((value != 0) == (owner[i] != 0)); if (!value) ++free_count;
    }
    CHECK(!memcmp(f->disk.bytes + RESERVED * 512, f->disk.bytes + (RESERVED + FATSZ) * 512, FATSZ * 512));
    CHECK(free_count == f->volume.free_clusters && free_count == r32(f->disk.bytes + 512 + 488));
}
static void retained_failure(struct fixture *f, const unsigned char *before)
{
    fat32_dirent_t temporary;
    remount(f);
    /* The label identifies the real RED: old code deleted the original first. */
    if (!lookup(f, f->dst_dir, f->dst_name, &temporary)) {
        fprintf(stderr, "OLD_DESTINATION_SURVIVES_FAILED_REPLACE: missing after real remount\n"); exit(1);
    }
    contents(f, f->dst_dir, f->dst_name, f->old, sizeof(f->old));
    contents(f, f->src_dir, f->src_name, f->newer, sizeof(f->newer));
    CHECK(!memcmp(f->disk.bytes, before, sizeof(f->disk.bytes)));
    integrity(f);
    CHECK(lookup(f, f->src_dir, f->src_name, &temporary));
    CHECK(fat32_remove(&f->volume, f->src_dir, temporary.dir_cluster, temporary.dir_offset) == FAT32_OK);
    remount(f);
    contents(f, f->dst_dir, f->dst_name, f->old, sizeof(f->old));
    CHECK(!lookup(f, f->src_dir, f->src_name, &temporary)); integrity(f);
}
static void finish(struct fixture *f)
{ f->disk.fault = NONE; fat32_unmount(&f->volume); CHECK(!f->disk.live); ++cases; free(f); }
static void one_failure(unsigned kind, enum fault fault, unsigned nth, unsigned damage)
{
    struct fixture *f = calloc(1, sizeof(*f)); fat32_dirent_t out;
    unsigned char *before, out_before[sizeof(out)]; int rc;
    CHECK(f); setup(f, kind); before = malloc(sizeof(f->disk.bytes)); CHECK(before);
    memcpy(before, f->disk.bytes, sizeof(f->disk.bytes));
    memset(&out, 0xa5, sizeof(out)); memcpy(out_before, &out, sizeof(out)); arm(f, fault, nth, damage);
    rc = replace(f, &out); CHECK(f->disk.fired);
    CHECK(rc == (fault == ALLOC_N ? FAT32_E_NOMEM : FAT32_E_IO));
    if (verify_failed_output) CHECK(!memcmp(&out, out_before, sizeof(out)));
    CHECK(f->volume.write != NULL);
    printf("RECOVERABLE kind=%u fault=%u n=%u damage=%u rc=%d\n", kind, (unsigned)fault, nth, damage, rc);
    retained_failure(f, before); free(before); finish(f);
}
static void success(unsigned kind, int full, unsigned *reads, unsigned *writes, unsigned *allocs)
{
    struct fixture *f = calloc(1, sizeof(*f)); fat32_dirent_t out, absent, filler;
    unsigned free_before, old_clusters, i; fat32_chain_t old;
    CHECK(f); setup(f, kind);
    if (full) {
        unsigned char data[512]; memset(data, 0x42, sizeof(data)); filler = create(f, 0, "FULL.BIN", 0);
        for (i = 0; f->volume.free_clusters; ++i) write_bytes(f, &filler, (uint64_t)i * 512, data, 512);
        CHECK(f->volume.free_clusters == 0);
    }
    CHECK(fat32_chain_build(&f->volume, f->dst.first_cluster, &old) == FAT32_OK);
    old_clusters = old.total_clusters; fat32_chain_free(&f->volume, &old);
    free_before = f->volume.free_clusters; arm(f, NONE, 0, 0);
    CHECK(replace(f, &out) == FAT32_OK);
    *reads = f->disk.reads; *writes = f->disk.writes; *allocs = f->disk.allocations;
    CHECK(out.first_cluster == f->src.first_cluster && out.size == sizeof(f->newer));
    CHECK(out.dir_cluster == f->dst.dir_cluster && out.dir_offset == f->dst.dir_offset);
    CHECK(!memcmp(out.short_name, f->dst.short_name, 11) && out.has_lfn == f->dst.has_lfn);
    CHECK(out.mdate == 0x5c9e && out.mtime == 0x6200);
    remount(f); contents(f, f->dst_dir, f->dst_name, f->newer, sizeof(f->newer));
    CHECK(!lookup(f, f->src_dir, f->src_name, &absent));
    CHECK(f->volume.free_clusters == free_before + old_clusters); integrity(f);
    finish(f);
}
static void persistent_boundary(unsigned kind, unsigned nth, unsigned damage)
{
    struct fixture *f = calloc(1, sizeof(*f)); fat32_dirent_t out;
    unsigned char owner[CLUSTERS + 2] = {0}; unsigned c, orphaned = 0, free_count = 0, writes;
    CHECK(f); setup(f, kind); arm(f, PERSISTENT, nth, damage);
    CHECK(replace(f, &out) == FAT32_E_IO && f->disk.fired >= 2 && !f->volume.write);
    writes = f->disk.writes;
    CHECK(replace(f, &out) == FAT32_E_RDONLY);
    CHECK(fat32_remove(&f->volume, f->src_dir, f->src.dir_cluster, f->src.dir_offset) == FAT32_E_RDONLY);
    CHECK(f->disk.writes == writes);
    remount(f);
    /* Do not assert that rollback or free-space accounting succeeded here.
     * The transport refused rollback. Confirm live namespace chains do not
     * alias, then explicitly report this unguaranteed recovery boundary.
     */
    c = f->volume.root_cluster;
    while (c < 0x0ffffff8) { CHECK(c >= 2 && c < CLUSTERS + 2 && !owner[c]); owner[c] = 1; c = fat32_fat_entry(&f->volume, c); }
    walk_ownership(f, 0, owner, 0);
    for (c = 2; c < CLUSTERS + 2; ++c) {
        uint32_t value = fat32_fat_entry(&f->volume, c);
        if (value && !owner[c]) ++orphaned;
        if (!value) ++free_count;
    }
    printf("PERSISTENT_BOUNDARY kind=%u n=%u damage=%u orphaned=%u mirrors_equal=%u FSInfo_equal=%u: readonly/error; rollback/durability/crash NOT certified\n",
           kind, nth, damage, orphaned,
           !memcmp(f->disk.bytes + RESERVED * 512, f->disk.bytes + (RESERVED + FATSZ) * 512, FATSZ * 512),
           free_count == r32(f->disk.bytes + 512 + 488));
    finish(f);
}
static void empty_file(struct fixture *f, fat32_dirent_t *e)
{
    fat32_chain_t c;
    CHECK(fat32_chain_build(&f->volume, e->first_cluster, &c) == FAT32_OK);
    CHECK(fat32_truncate(&f->volume, &c, &e->first_cluster, &e->size, 0) == FAT32_OK);
    fat32_chain_free(&f->volume, &c);
    CHECK(fat32_set_entry(&f->volume, e->dir_cluster, e->dir_offset, 0, 0, 0x5c9e, 0x6200) == FAT32_OK);
}
static void empty_controls(void)
{
    unsigned old_empty, new_empty;
    for (old_empty = 0; old_empty < 2; ++old_empty) for (new_empty = 0; new_empty < 2; ++new_empty) {
        struct fixture *f = calloc(1, sizeof(*f)); fat32_dirent_t out, absent;
        CHECK(f); setup(f, 0);
        if (old_empty) empty_file(f, &f->dst);
        if (new_empty) empty_file(f, &f->src);
        CHECK(replace(f, &out) == FAT32_OK);
        CHECK(out.size == (new_empty ? 0u : (unsigned)sizeof(f->newer)));
        CHECK(out.first_cluster == f->src.first_cluster);
        remount(f); contents(f, f->dst_dir, f->dst_name, f->newer, new_empty ? 0 : sizeof(f->newer));
        CHECK(!lookup(f, f->src_dir, f->src_name, &absent)); integrity(f); finish(f);
    }
}
static void case_flags_control(void)
{
    struct fixture *f = calloc(1, sizeof(*f)); fat32_dirent_t out, absent;
    unsigned char sector[512]; uint16_t name[256]; unsigned n;
    CHECK(f); setup(f, 0);
    (void)create(f, 0, "SAVED~1.TXT", 0); /* unrelated legitimate alias must survive */
    /* Complete filesystem writes before editing the transport fixture. A
     * later create could otherwise rewrite these bytes from its sector cache.
     */
    memcpy(sector, f->disk.bytes + f->disk.destination_lba * 512, 512);
    sector[f->disk.destination_offset + 12] = 0x18; /* literal lower base/ext NT case flags */
    CHECK(wr(&f->disk, f->disk.destination_lba, sector) == 0);
    remount(f); CHECK(lookup(f, 0, "saved.txt", &f->dst));
    CHECK(f->disk.bytes[f->disk.destination_lba * 512 + f->disk.destination_offset + 12] == 0x18);
    n = wide("SAVED.TXT", name);
    CHECK(fat32_rename(&f->volume, 0, f->src.dir_cluster, f->src.dir_offset, 0, name, n, 1, &out) == FAT32_OK);
    CHECK(!memcmp(out.short_name, "SAVED   TXT", 11));
    CHECK(out.name_len == 9 && out.name[0] == 's' && out.name[8] == 't');
    remount(f); contents(f, 0, "saved.txt", f->newer, sizeof(f->newer));
    CHECK(f->disk.bytes[f->disk.destination_lba * 512 + f->disk.destination_offset + 12] == 0x18);
    CHECK(lookup(f, 0, "SAVED~1.TXT", &absent) && absent.size == 0);
    CHECK(!lookup(f, 0, f->src_name, &absent)); integrity(f); finish(f);
}
static void denied_types(unsigned kind)
{
    struct fixture *f = calloc(1, sizeof(*f)); fat32_dirent_t out;
    unsigned char before[SECTORS * 512], out_before[sizeof(out)]; uint16_t name[256]; unsigned n;
    CHECK(f); setup(f, 0);
    if (kind == 0) f->disk.bytes[f->disk.destination_lba * 512 + f->disk.destination_offset + 11] |= FAT32_ATTR_RO;
    if (kind == 1) { f->dst = create(f, 0, "TARGETDIR", 1); strcpy(f->dst_name, "TARGETDIR"); }
    if (kind == 2) { f->src = create(f, 0, "SOURCEDIR", 1); strcpy(f->src_name, "SOURCEDIR"); }
    remount(f); memcpy(before, f->disk.bytes, sizeof(before));
    memset(&out, 0xa5, sizeof(out)); memcpy(out_before, &out, sizeof(out));
    n = wide(f->dst_name, name); arm(f, NONE, 0, 0);
    CHECK(fat32_rename(&f->volume, f->src_dir, f->src.dir_cluster, f->src.dir_offset, f->dst_dir,
                       name, n, kind != 3, &out) == FAT32_E_EXISTS);
    CHECK(!f->disk.writes && !memcmp(&out, out_before, sizeof(out)) && !memcmp(before, f->disk.bytes, sizeof(before)));
    remount(f); contents(f, 0, "SAVED.TXT", f->old, sizeof(f->old)); integrity(f); finish(f);
}
static void shared_chain_control(int suffix)
{
    struct fixture *f = calloc(1, sizeof(*f)); fat32_dirent_t out; fat32_chain_t c;
    unsigned char before[SECTORS * 512], out_before[sizeof(out)]; unsigned i;
    CHECK(f); setup(f, 0);
    if (!suffix) {
        unsigned char *e = f->disk.bytes + (fat32_cluster_lba(&f->volume, f->src.dir_cluster) + f->src.dir_offset / 512) * 512 + f->src.dir_offset % 512;
        w16(e + 20, f->dst.first_cluster >> 16); w16(e + 26, f->dst.first_cluster); w32(e + 28, sizeof(f->old));
    } else {
        uint32_t last;
        CHECK(fat32_chain_build(&f->volume, f->src.first_cluster, &c) == FAT32_OK);
        last = c.runs[c.nruns - 1].start + c.runs[c.nruns - 1].count - 1;
        fat32_chain_free(&f->volume, &c);
        for (i = 0; i < NFATS; ++i) w32(f->disk.bytes + (RESERVED + i * FATSZ) * 512 + last * 4, f->dst.first_cluster);
        if (suffix == 2) {
            unsigned char *e = f->disk.bytes + (fat32_cluster_lba(&f->volume, f->src.dir_cluster) + f->src.dir_offset / 512) * 512 + f->src.dir_offset % 512;
            w32(e + 28, 0xffffffffu); /* size validation fails before overlap comparison */
        }
    }
    remount(f); memcpy(before, f->disk.bytes, sizeof(before));
    memset(&out, 0xa5, sizeof(out)); memcpy(out_before, &out, sizeof(out)); arm(f, NONE, 0, 0);
    CHECK(replace(f, &out) == FAT32_E_CORRUPT && !f->volume.write && !f->disk.writes);
    CHECK(!memcmp(&out, out_before, sizeof(out)) && !memcmp(before, f->disk.bytes, sizeof(before)));
    CHECK(fat32_remove(&f->volume, f->src_dir, f->src.dir_cluster, f->src.dir_offset) == FAT32_E_RDONLY);
    remount(f); contents(f, 0, f->dst_name, f->old, sizeof(f->old));
    puts(suffix == 2 ? "CORRUPT_OVERSIZE_SHARED_SUFFIX: poisoned before size error, caller cleanup refused, saved data retained" :
         suffix ? "CORRUPT_SHARED_SUFFIX: poisoned, caller cleanup refused, saved data retained; corrupt fixture not certified clean" :
                  "CORRUPT_SHARED_FIRST: poisoned, caller cleanup refused, saved data retained; corrupt fixture not certified clean");
    finish(f);
}
int main(int argc, char **argv)
{
    unsigned kind, n, damage, reads, writes, allocs;
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--red")));
    /* The original data-loss RED predates the additive output transaction
     * contract. Reach its real remount oracle rather than stop at that new
     * assertion; the complete GREEN run always verifies failed output.
     */
    if (argc == 2) verify_failed_output = 0;
    one_failure(0, PUBLISH, 0, 0);
    if (argc == 2) return 0; /* original source must fail the literal remount oracle */
    for (kind = 0; kind < 4; ++kind) {
        success(kind, 0, &reads, &writes, &allocs);
        for (n = 1; n <= reads; ++n) one_failure(kind, READ_N, n, 0);
        for (n = 1; n <= writes; ++n) for (damage = 0; damage < 3; ++damage) one_failure(kind, WRITE_N, n, damage);
        for (n = 1; n <= allocs; ++n) one_failure(kind, ALLOC_N, n, 0);
        if (kind == 0 || kind == 3) for (n = 1; n <= writes; ++n) for (damage = 0; damage < 3; ++damage)
            persistent_boundary(kind, n, damage);
        success(kind, 1, &reads, &writes, &allocs);
    }
    empty_controls(); case_flags_control();
    for (kind = 0; kind < 4; ++kind) denied_types(kind);
    shared_chain_control(0); shared_chain_control(1); shared_chain_control(2);
    printf("PASS_REAL_FAT_REPLACE: %u cases, %u assertions; fresh mounts + exact bytes + caller temp deletion; no kernel/guest/crash acceptance\n", cases, assertions);
    return 0;
}
