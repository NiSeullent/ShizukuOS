/* SPDX-License-Identifier: GPL-2.0-only
 * Production fat32.c mount FAT-copy: callback count, one-sector fallback, short final chunk,
 * range/IO errors and page cleanup. Synthetic volume, no disk image.
 */
#include "../kernel64/fat32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned assertions;
#define CHECK(x) do { ++assertions; if (!(x)) { fprintf(stderr,"line %u: %s\n",(unsigned)__LINE__,#x); exit(1); } } while(0)
#define RES 32u
struct model { unsigned fatsz, clusters, singles, batches, maxcount, fail_single, fail_batch, calls; uint64_t last_lba; unsigned last_count;
               int poison; long pages, allocs, frees; };
static uint32_t fat_value(unsigned i) { return i == 0 ? 0x0ffffff8u : i == 1 ? 0x0fffffffu : i == 2 ? 0x0fffffffu : (i % 7 == 0 ? 0u : i + 1u); }
static void wr16(uint8_t *p, unsigned v) { p[0] = v; p[1] = v >> 8; }
static void wr32(uint8_t *p, uint32_t v) { wr16(p, v & 0xffff); wr16(p + 2, v >> 16); }
static void fill(struct model *m, uint64_t lba, uint8_t *b)
{
    memset(b, 0, 512);
    if (lba == 0) {
        b[0] = 0xeb; wr16(b + 11, 512); b[13] = 1; wr16(b + 14, RES); b[16] = 1; wr32(b + 32, RES + m->fatsz + m->clusters); wr32(b + 36, m->fatsz);
        wr32(b + 44, 2); b[66] = 0x29; b[510] = 0x55; b[511] = 0xaa; memcpy(b + 82, "FAT32   ", 8);
    } else if (lba >= RES && lba < RES + m->fatsz) {
        unsigned e0 = (unsigned)(lba - RES) * 128u, k;
        for (k = 0; k < 128; ++k) wr32(b + k * 4, fat_value(e0 + k));
    }
}
static int one(void *c, uint64_t lba, void *b)
{
    struct model *m = c; ++m->calls; ++m->singles; m->last_lba = lba; m->last_count = 1;
    if (m->fail_single && m->singles == m->fail_single) return -1;
    fill(m, lba, b); return 0;
}
static int many(void *c, uint64_t lba, unsigned n, void *b)
{
    struct model *m = c; unsigned i;
    CHECK(n >= 2 && n <= FAT32_READ_MAX_SECTORS);
    ++m->calls; ++m->batches; m->last_lba = lba; m->last_count = n; if (n > m->maxcount) m->maxcount = n;
    for (i = 0; i < n; ++i) fill(m, lba + i, (uint8_t *)b + i * 512);
    if (m->fail_batch && m->batches == m->fail_batch) { memset(b, 0xee, n * 512); return -1; }
    return 0;
}
static void *al(void *c, uint64_t n) { struct model *m = c; ++m->allocs; return calloc(1, n); }
static void *alp(void *c) { struct model *m = c; ++m->pages; return calloc(1, 4096); }
static void fr(void *c, void *p, uint64_t n) { struct model *m = c; (void)n; ++m->frees; free(p); }
static void setup(fat32_vol_t *v, struct model *m, unsigned fatsz, unsigned clusters, int use_many)
{
    memset(v, 0, sizeof *v); memset(m, 0, sizeof *m);
    m->fatsz = fatsz; m->clusters = clusters;
    v->read = one; v->read_many = use_many ? many : 0; v->ctx = m; v->alloc = al; v->alloc_page = alp; v->free = fr;
    v->disk_sectors = RES + fatsz + clusters;
}
static void verify(fat32_vol_t *v, unsigned clusters)
{
    unsigned i, f = 0;
    for (i = 0; i < clusters + 2; ++i) CHECK(fat32_fat_entry(v, i) == fat_value(i));
    for (i = 2; i < clusters + 2; ++i) if (!fat_value(i)) ++f;
    CHECK(v->free_clusters == f);
}
int main(void)
{
    fat32_vol_t v; struct model m;
    /* observed installed geometry: 1016 FAT sectors, 127 pages, 130000 clusters */
    setup(&v, &m, 1016, 130000, 1);
    CHECK(fat32_mount(&v) == 0 && v.fat_npages == 127);
    CHECK(m.singles == 1 && m.batches == 254 && m.maxcount == 4 && v.sector_reads == 1 + 1016);
    CHECK(m.calls == 255); verify(&v, 130000); fat32_unmount(&v);
    CHECK(m.frees == m.allocs + m.pages);
    setup(&v, &m, 1016, 130000, 0);
    CHECK(fat32_mount(&v) == 0 && m.singles == 1017 && !m.batches && v.sector_reads == 1017);
    verify(&v, 130000); fat32_unmount(&v);
    /* short final page: 1015 FAT sectors -> last page 7 sectors = 4 + 3; also a 1-sector tail (1009 = 126*8+1) */
    setup(&v, &m, 1015, 129900, 1);
    CHECK(fat32_mount(&v) == 0 && m.last_count == 3 && m.batches == 254);
    verify(&v, 129900); fat32_unmount(&v);
    setup(&v, &m, 1009, 129100, 1);
    CHECK(fat32_mount(&v) == 0 && v.fat_npages == 127 && m.singles == 2 && m.batches == 252 && v.sector_reads == 1010);
    verify(&v, 129100); fat32_unmount(&v);
    /* batch failure: IO, pages released, count counts the issued batch */
    setup(&v, &m, 1016, 130000, 1); m.fail_batch = 3;
    CHECK(fat32_mount(&v) == FAT32_E_IO && !v.fat_pages && v.sector_reads == 1 + 12);
    CHECK(m.frees == m.allocs + m.pages);
    /* single-sector failure on the 1-sector tail */
    setup(&v, &m, 1009, 129100, 1); m.fail_single = 2;
    CHECK(fat32_mount(&v) == FAT32_E_IO && !v.fat_pages && m.frees == m.allocs + m.pages);
    /* range: every request stays in the disk and FAT; the guard itself is unreachable for a valid BPB */
    setup(&v, &m, 1016, 130000, 1);
    CHECK(fat32_mount(&v) == 0 && m.last_lba + m.last_count == RES + 1016 && m.last_lba + m.last_count <= v.disk_sectors);
    fat32_unmount(&v);
    puts("mount FAT copy: 1016 sectors -> 254 four-sector callbacks (+VBR), fallback/short-tail/error/cleanup verified");
    printf("PASS: FAT32 mount batch %u assertions\n", assertions); return 0;
}
