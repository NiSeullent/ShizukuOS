/* SPDX-License-Identifier: GPL-2.0-only
 * Host harness for kernel64/fat32.c: mounts a raw image file, walks every directory and prints one JSON line per
 * entry (path, attributes, size, mtime as FILETIME, CRC-32 of the content read through fat32_read with an odd chunk
 * pattern so partial-sector and cross-cluster reads are exercised). tests/test_fat32_host.py builds the image with
 * mkfs.vfat/mtools and compares against the source files. With --write it first runs a scripted sequence of creates,
 * writes (chunked, with gaps, in place, appending), truncations and directory growth through the fat32.c writer;
 * the Python side mirrors the script, then checks the image with fsck.fat -n and mtools as well as with this walker. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../kernel64/fat32.h"

static FILE *img;
static uint64_t nsectors, allocs, frees;

static uint64_t writes;
static uint64_t reads, batch_reads;
static int rd(void *ctx, uint64_t lba, void *buf)
{
    (void)ctx;
    ++reads;
    if (fseeko(img, (off_t)(lba * 512), SEEK_SET)) return -1;
    return fread(buf, 1, 512, img) == 512 ? 0 : -1;
}
static int rd_many(void *ctx, uint64_t lba, unsigned count, void *buf)
{
    (void)ctx;
    if (!count || count > FAT32_READ_MAX_SECTORS || lba >= nsectors || count > nsectors - lba) return -1;
    ++reads; ++batch_reads;
    if (fseeko(img, (off_t)(lba * 512), SEEK_SET)) return -1;
    return fread(buf, 512, count, img) == count ? 0 : -1;
}
static int wr(void *ctx, uint64_t lba, const void *buf)
{
    (void)ctx;
    if (lba >= nsectors || fseeko(img, (off_t)(lba * 512), SEEK_SET)) return -1;
    ++writes;
    return fwrite(buf, 1, 512, img) == 512 ? 0 : -1;
}
static void *al(void *ctx, uint64_t n) { (void)ctx; ++allocs; return calloc(1, (size_t)n); }
static void fr(void *ctx, void *p, uint64_t n) { (void)ctx; (void)n; ++frees; free(p); }
static void *pg(void *ctx) { (void)ctx; ++allocs; return calloc(1, 4096); }

static uint32_t crc_update(uint32_t c, const uint8_t *p, size_t n)
{
    size_t i; int k;
    c = ~c;
    for (i = 0; i < n; ++i) { c ^= p[i]; for (k = 0; k < 8; ++k) c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u))); }
    return ~c;
}

static void json_name(const uint16_t *w, unsigned n)
{
    unsigned i;
    putchar('"');
    for (i = 0; i < n; ++i) {
        if (w[i] == '"' || w[i] == '\\') printf("\\%c", w[i]);
        else if (w[i] < 0x20 || w[i] >= 0x7f) printf("\\u%04x", w[i]);
        else putchar(w[i]);
    }
    putchar('"');
}

static int walk(fat32_vol_t *v, uint32_t cluster, const char *prefix, int depth)
{
    fat32_dir_t d;
    fat32_dirent_t e;
    int rc, count = 0;
    if (depth > 8) return -1;
    fat32_dir_open(v, cluster, &d);
    while ((rc = fat32_dir_next(v, &d, &e)) == 1) {
        char path[1024];
        unsigned i, n = 0;
        for (i = 0; prefix[i]; ++i) path[n++] = prefix[i];
        if (n) path[n++] = '/';
        for (i = 0; i < e.name_len && n + 8 < sizeof path; ++i) path[n++] = e.name[i] < 0x80 ? (char)e.name[i] : '?';
        path[n] = 0;
        printf("{\"path\": \"%s\", \"name\": ", path);
        json_name(e.name, e.name_len);
        printf(", \"attr\": %u, \"size\": %u, \"lfn\": %u, \"cluster\": %u, \"mtime\": %llu", e.attr, e.size, e.has_lfn,
               e.first_cluster, (unsigned long long)fat32_filetime(e.mdate, e.mtime, 0));
        if (e.attr & FAT32_ATTR_DIR) {
            printf(", \"dir\": true}\n");
            if (walk(v, e.first_cluster, path, depth + 1) < 0) return -1;
        } else {
            fat32_chain_t c;
            uint32_t crc = 0;
            uint64_t off = 0, done, chunk = 1;
            uint8_t *buf = malloc(70000);
            if (fat32_chain_build(v, e.first_cluster, &c)) { printf(", \"error\": \"chain\"}\n"); free(buf); return -1; }
            while (off < e.size) {
                if (fat32_read(v, &c, e.size, off, buf, chunk, &done) || !done) { printf(", \"error\": \"read\"}\n"); free(buf); return -1; }
                crc = crc_update(crc, buf, (size_t)done);
                off += done;
                chunk = chunk * 3 + 511;                             /* 1, 514, 2053, ... up to 65536+ */
                if (chunk > 65536 + 511) chunk = 1;
            }
            /* second pass: a random-ish direct read in the middle must agree with the source (checked by size only here) */
            printf(", \"crc32\": %u, \"runs\": %u, \"clusters\": %u}\n", crc, c.nruns, c.total_clusters);
            fat32_chain_free(v, &c);
            free(buf);
        }
        ++count;
    }
    if (rc < 0) { printf("{\"error\": \"dir %d\"}\n", rc); return -1; }
    return count;
}

/* ---------------------------------------------------------------- write script (mirrored by test_fat32_host.py) */
static uint8_t *pat(uint32_t seed, size_t n)
{
    uint8_t *b = malloc(n + 4);
    uint32_t x = seed;
    size_t i;
    for (i = 0; i < n; i += 4) {
        x = x * 1103515245u + 12345u;
        b[i] = (uint8_t)x; b[i + 1] = (uint8_t)(x >> 8); b[i + 2] = (uint8_t)(x >> 16); b[i + 3] = (uint8_t)(x >> 24);
    }
    return b;
}
static unsigned w16name(const char *a, uint16_t *w) { unsigned n = 0; while (a[n]) { w[n] = (uint8_t)a[n]; ++n; } return n; }
#define WCHECK(x) do { int rc_ = (x); if (rc_) { printf("{\"error\": \"%s -> %d (line %d)\"}\n", #x, rc_, __LINE__); exit(1); } } while (0)
#define WEXPECT(x, want) do { int rc_ = (x); if (rc_ != (want)) { printf("{\"error\": \"%s -> %d, want %d\"}\n", #x, rc_, want); exit(1); } } while (0)

/* Finds `path` ("A/B/c.txt") and returns its entry; the chain is built into *c. */
static int find(fat32_vol_t *v, const char *path, fat32_dirent_t *out)
{
    uint32_t dir = 0;
    char comp[256];
    const char *p = path;
    for (;;) {
        fat32_dir_t d;
        unsigned n = 0, i;
        int rc, found = 0;
        while (*p && *p != '/') comp[n++] = *p++;
        comp[n] = 0;
        fat32_dir_open(v, dir, &d);
        while ((rc = fat32_dir_next(v, &d, out)) == 1) {
            if (out->name_len != n) continue;
            for (i = 0; i < n && (out->name[i] | 32) == ((uint8_t)comp[i] | 32); ++i) ;
            if (i == n) { found = 1; break; }
        }
        if (!found) return -1;
        if (!*p) return 0;
        ++p;
        dir = out->first_cluster;
    }
}
static void file_write(fat32_vol_t *v, const char *path, uint64_t off, const uint8_t *data, uint64_t len, unsigned chunked)
{
    fat32_dirent_t e;
    fat32_chain_t c;
    uint32_t first, size;
    uint64_t done = 0, chunk = 1;
    WCHECK(find(v, path, &e));
    WCHECK(fat32_chain_build(v, e.first_cluster, &c));
    first = e.first_cluster; size = e.size;
    while (done < len) {
        uint64_t n = chunked ? chunk : len - done;
        if (n > len - done) n = len - done;
        WCHECK(fat32_write(v, &c, &first, &size, off + done, data + done, n));
        done += n;
        chunk = chunk * 3 + 511;
        if (chunk > 70000) chunk = 1;
    }
    WCHECK(fat32_set_entry(v, e.dir_cluster, e.dir_offset, first, size, 0x5c9d, 0x6000));
    fat32_chain_free(v, &c);
}
static void file_truncate(fat32_vol_t *v, const char *path, uint32_t new_size)
{
    fat32_dirent_t e;
    fat32_chain_t c;
    uint32_t first, size;
    WCHECK(find(v, path, &e));
    WCHECK(fat32_chain_build(v, e.first_cluster, &c));
    first = e.first_cluster; size = e.size;
    WCHECK(fat32_truncate(v, &c, &first, &size, new_size));
    WCHECK(fat32_set_entry(v, e.dir_cluster, e.dir_offset, first, size, 0x5c9d, 0x6000));
    fat32_chain_free(v, &c);
}
static void create(fat32_vol_t *v, const char *dir, const char *name, int is_dir)
{
    uint16_t w[256];
    fat32_dirent_t e, d;
    uint32_t dc = 0;
    if (dir) { WCHECK(find(v, dir, &d)); dc = d.first_cluster; }
    WCHECK(fat32_create(v, dc, w, w16name(name, w), is_dir, 0x5c9d, 0x6000, &e));
}
/* First cluster of the directory that holds `path` (0 = root). */
static uint32_t parent_of(fat32_vol_t *v, const char *path)
{
    char parent[256];
    const char *slash = strrchr(path, '/');
    fat32_dirent_t d;
    if (!slash) return 0;
    memcpy(parent, path, (size_t)(slash - path));
    parent[slash - path] = 0;
    WCHECK(find(v, parent, &d));
    return d.first_cluster;
}
static int remove_path(fat32_vol_t *v, const char *path)
{
    fat32_dirent_t e;
    WCHECK(find(v, path, &e));
    return fat32_remove(v, parent_of(v, path), e.dir_cluster, e.dir_offset);
}
static int rename_path(fat32_vol_t *v, const char *path, const char *dst_dir, const char *name, int replace)
{
    uint16_t w[256];
    fat32_dirent_t e, d, out;
    uint32_t dc = 0;
    WCHECK(find(v, path, &e));
    if (dst_dir) { WCHECK(find(v, dst_dir, &d)); dc = d.first_cluster; }
    return fat32_rename(v, parent_of(v, path), e.dir_cluster, e.dir_offset, dc, w, w16name(name, w), replace, &out);
}
static int write_script(fat32_vol_t *v)
{
    uint16_t w[256];
    fat32_dirent_t e;
    unsigned i;
    uint32_t before = v->free_clusters;
    uint8_t *a = pat(21, 10000), *b = pat(22, 5000), *c3 = pat(23, 3000), *d1 = pat(24, 1000), *big = pat(25, 300000);
    create(v, 0, "Written By Kernel.txt", 0);
    file_write(v, "Written By Kernel.txt", 0, a, 10000, 1);
    create(v, 0, "UPPER.TXT", 0);
    file_write(v, "UPPER.TXT", 0, (const uint8_t *)"short name\r\n", 12, 0);
    create(v, 0, "New Folder", 1);
    create(v, "New Folder", "inner file.bin", 0);
    file_write(v, "New Folder/inner file.bin", 5000, c3, 3000, 0);          /* gap [0, 5000) reads zero ... */
    file_write(v, "New Folder/inner file.bin", 0, d1, 1000, 0);             /* ... except the first 1000 bytes */
    file_write(v, "SUB/inner.txt", 4095, b, 5000, 1);                        /* in place, across sectors and clusters */
    file_write(v, "HELLO.TXT", 7, (const uint8_t *)"appended\r\n", 10, 0);
    file_truncate(v, "multi_cluster_800k.bin", 5000);
    file_truncate(v, "empty.txt", 3000);
    create(v, 0, "big_written.bin", 0);
    file_write(v, "big_written.bin", 0, big, 300000, 1);
    free(a); free(b); free(c3); free(d1); free(big);
    for (i = 0; i < 50; ++i) {                                               /* grows "Long Directory Name" */
        char name[64], path[128], content[32];
        snprintf(name, sizeof name, "file number %02u with a long name.txt", i);
        snprintf(path, sizeof path, "Long Directory Name/%s", name);
        snprintf(content, sizeof content, "content %u\r\n", i);
        create(v, "Long Directory Name", name, 0);
        file_write(v, path, 0, (const uint8_t *)content, strlen(content), 0);
    }
    create(v, 0, "longname1.txt", 0);
    create(v, 0, "longname2.txt", 0);
    WEXPECT(fat32_create(v, 0, w, w16name("Written By Kernel.txt", w), 0, 0x5c9d, 0x6000, &e), FAT32_E_EXISTS);
    WEXPECT(fat32_create(v, 0, w, w16name("written by kernel.TXT", w), 0, 0x5c9d, 0x6000, &e), FAT32_E_EXISTS);
    WEXPECT(fat32_create(v, 0, w, w16name("UPPER.TXT", w), 0, 0x5c9d, 0x6000, &e), FAT32_E_EXISTS);
    WEXPECT(fat32_create(v, 0, w, w16name("a:b", w), 0, 0x5c9d, 0x6000, &e), FAT32_E_NAME);
    WEXPECT(fat32_create(v, 0, w, w16name("trailing.", w), 0, 0x5c9d, 0x6000, &e), FAT32_E_NAME);
    /* deletion: a non-empty directory is refused, a long-named file and then the emptied directory go (clusters freed) */
    {
        uint8_t *doomed = pat(26, 9000);
        create(v, 0, "Doomed Folder", 1);
        create(v, "Doomed Folder", "doomed file with a long name.txt", 0);
        file_write(v, "Doomed Folder/doomed file with a long name.txt", 0, doomed, 9000, 0);
        free(doomed);
    }
    WEXPECT(remove_path(v, "Doomed Folder"), FAT32_E_NOTEMPTY);
    WCHECK(remove_path(v, "Doomed Folder/doomed file with a long name.txt"));
    WCHECK(remove_path(v, "Doomed Folder"));
    /* renaming: long name in place, 8.3 file into a subdirectory, a directory with content into another parent (its ".."
     * follows), case-only rename, replace of an existing file (refused without the flag), a directory into its own
     * subtree (refused) */
    WCHECK(rename_path(v, "big_written.bin", 0, "Renamed Big File.bin", 0));
    WCHECK(rename_path(v, "UPPER.TXT", "SUB", "MOVED.TXT", 0));
    create(v, 0, "Movable Dir", 1);
    create(v, "Movable Dir", "x.txt", 0);
    file_write(v, "Movable Dir/x.txt", 0, (const uint8_t *)"x\r\n", 3, 0);
    WCHECK(rename_path(v, "Movable Dir", "SUB", "Moved Dir", 0));
    WCHECK(rename_path(v, "HELLO.TXT", 0, "Hello.txt", 0));
    create(v, 0, "replace me.txt", 0);
    file_write(v, "replace me.txt", 0, (const uint8_t *)"old", 3, 0);
    create(v, 0, "source of replace.txt", 0);
    file_write(v, "source of replace.txt", 0, (const uint8_t *)"new!", 4, 0);
    WEXPECT(rename_path(v, "source of replace.txt", 0, "replace me.txt", 0), FAT32_E_EXISTS);
    WCHECK(rename_path(v, "source of replace.txt", 0, "replace me.txt", 1));
    WEXPECT(rename_path(v, "SUB", "SUB/Moved Dir", "loop", 0), FAT32_E_NAME);
    printf("{\"write\": true, \"sector_writes\": %u, \"free_before\": %u, \"free_after\": %u}\n", v->sector_writes, before,
           v->free_clusters);
    return 0;
}

int main(int argc, char **argv)
{
    static fat32_vol_t v;
    int rc, i, write_mode = 0, batch_mode = 0;
    if (argc < 2 || argc > 4) { fprintf(stderr, "usage: test_fat32 image [--write] [--batch]\n"); return 2; }
    for (i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--write")) write_mode = 1;
        else if (!strcmp(argv[i], "--batch")) batch_mode = 1;
        else { fprintf(stderr, "unknown option: %s\n", argv[i]); return 2; }
    }
    img = fopen(argv[1], write_mode ? "r+b" : "rb");
    if (!img) { perror(argv[1]); return 2; }
    fseeko(img, 0, SEEK_END);
    nsectors = (uint64_t)ftello(img) / 512;
    v.read = rd; v.alloc = al; v.free = fr; v.alloc_page = pg; v.ctx = 0; v.disk_sectors = nsectors;
    if (batch_mode) v.read_many = rd_many;
    if (write_mode) v.write = wr;
    rc = fat32_mount(&v);
    if (rc) { printf("{\"error\": \"mount %d\"}\n", rc); return 1; }
    if (write_mode) {
        if (!v.write) { printf("{\"error\": \"volume mounted read-only\"}\n"); return 1; }
        write_script(&v);
    }
    printf("{\"volume\": {\"part_lba\": %llu, \"spc\": %u, \"clusters\": %u, \"root\": %u, \"label\": \"%s\", \"fat_pages\": %u}}\n",
           (unsigned long long)v.part_lba, v.spc, v.cluster_count, v.root_cluster, v.label, v.fat_npages);
    if (walk(&v, 0, "", 0) < 0) return 1;
    fat32_unmount(&v);
    printf("{\"done\": true, \"sector_reads\": %u, \"sector_writes\": %llu, \"allocs\": %llu, \"frees\": %llu, \"read_calls\": %llu, \"batch_calls\": %llu}\n", v.sector_reads,
           (unsigned long long)writes, (unsigned long long)allocs, (unsigned long long)frees,
           (unsigned long long)reads, (unsigned long long)batch_reads);
    fclose(img);
    return 0;
}
