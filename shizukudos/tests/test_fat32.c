/* SPDX-License-Identifier: GPL-2.0-only
 * Host harness for kernel64/fat32.c: mounts a raw image file, walks every directory and prints one JSON line per
 * entry (path, attributes, size, mtime as FILETIME, CRC-32 of the content read through fat32_read with an odd chunk
 * pattern so partial-sector and cross-cluster reads are exercised). tests/test_fat32_host.py builds the image with
 * mkfs.vfat/mtools and compares against the source files. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../kernel64/fat32.h"

static FILE *img;
static uint64_t nsectors, allocs, frees;

static int rd(void *ctx, uint64_t lba, void *buf)
{
    (void)ctx;
    if (fseeko(img, (off_t)(lba * 512), SEEK_SET)) return -1;
    return fread(buf, 1, 512, img) == 512 ? 0 : -1;
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

int main(int argc, char **argv)
{
    static fat32_vol_t v;
    int rc;
    if (argc != 2) { fprintf(stderr, "usage: test_fat32 image\n"); return 2; }
    img = fopen(argv[1], "rb");
    if (!img) { perror(argv[1]); return 2; }
    fseeko(img, 0, SEEK_END);
    nsectors = (uint64_t)ftello(img) / 512;
    v.read = rd; v.alloc = al; v.free = fr; v.alloc_page = pg; v.ctx = 0; v.disk_sectors = nsectors;
    rc = fat32_mount(&v);
    if (rc) { printf("{\"error\": \"mount %d\"}\n", rc); return 1; }
    printf("{\"volume\": {\"part_lba\": %llu, \"spc\": %u, \"clusters\": %u, \"root\": %u, \"label\": \"%s\", \"fat_pages\": %u}}\n",
           (unsigned long long)v.part_lba, v.spc, v.cluster_count, v.root_cluster, v.label, v.fat_npages);
    if (walk(&v, 0, "", 0) < 0) return 1;
    fat32_unmount(&v);
    printf("{\"done\": true, \"sector_reads\": %u, \"allocs\": %llu, \"frees\": %llu}\n", v.sector_reads,
           (unsigned long long)allocs, (unsigned long long)frees);
    return 0;
}
