/* SPDX-License-Identifier: GPL-2.0-only
 * Host unit test of kernel64/blk_part.c (MBR/GPT partition scanner) on synthetic tables built in memory.
 * Built and run by tests/run_blk_part_host.py with -fsanitize=address,undefined. Every check prints PASS:/FAIL:. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel64/blk_part.h"

static int failures, checks;
#define CHECK(cond, ...) do { ++checks; if (cond) { printf("PASS: " __VA_ARGS__); printf("\n"); } \
                              else { printf("FAIL: " __VA_ARGS__); printf("\n"); ++failures; } } while (0)

typedef struct { uint8_t *img; uint32_t ss; uint64_t sectors; uint64_t fail_lba; int reads; } disk_t;

static int rd(void *ctx, uint64_t lba, uint32_t count, void *buf)
{
    disk_t *d = ctx;
    ++d->reads;
    if (lba + count > d->sectors) return -1;
    if (d->fail_lba != (uint64_t)-1 && lba <= d->fail_lba && d->fail_lba < lba + count) return -1;
    memcpy(buf, d->img + lba * d->ss, (size_t)count * d->ss);
    return 0;
}

static void wr32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static void wr64(uint8_t *p, uint64_t v) { wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32)); }

static disk_t mkdisk(uint32_t ss, uint64_t sectors)
{
    disk_t d = { calloc(sectors, ss), ss, sectors, (uint64_t)-1, 0 };
    return d;
}

static void mbr_entry(uint8_t *sec, int slot, uint8_t boot, uint8_t type, uint32_t start, uint32_t n)
{
    uint8_t *e = sec + 446 + 16 * slot;
    e[0] = boot; e[4] = type; wr32(e + 8, start); wr32(e + 12, n);
    sec[510] = 0x55; sec[511] = 0xaa;
}

/* GPT writer: header at hdr_lba pointing at entries at ent_lba, backup mirrored at the last sector. */
typedef struct { uint64_t first, last; const char *name; uint8_t type; } gpart_t;
static void gpt_write(disk_t *d, const gpart_t *parts, unsigned n, uint32_t num_entries, uint32_t entry_size)
{
    const uint64_t ent_sectors = ((uint64_t)num_entries * entry_size + d->ss - 1) / d->ss;
    uint8_t *ents = calloc(ent_sectors, d->ss);
    uint32_t ecrc;
    unsigned i, copy;
    for (i = 0; i < n; ++i) {
        uint8_t *e = ents + i * entry_size;
        unsigned k;
        memset(e, 0xab, 16); e[0] = parts[i].type;            /* type GUID: distinct first byte */
        memset(e + 16, 0xcd, 16); e[16] = (uint8_t)i;
        wr64(e + 32, parts[i].first);
        wr64(e + 40, parts[i].last);
        for (k = 0; parts[i].name[k] && k < 36; ++k) { e[56 + 2 * k] = parts[i].name[k]; e[57 + 2 * k] = 0; }
    }
    ecrc = blk_crc32(0, ents, (size_t)num_entries * entry_size);
    memset(d->img, 0, d->ss);                                  /* protective MBR */
    mbr_entry(d->img, 0, 0, 0xee, 1, d->sectors - 1 > 0xffffffffu ? 0xffffffffu : (uint32_t)(d->sectors - 1));
    for (copy = 0; copy < 2; ++copy) {
        const uint64_t hdr_lba = copy ? d->sectors - 1 : 1;
        const uint64_t alt_lba = copy ? 1 : d->sectors - 1;
        const uint64_t ent_lba = copy ? d->sectors - 1 - ent_sectors : 2;
        uint8_t *h = d->img + hdr_lba * d->ss;
        memset(h, 0, d->ss);
        memcpy(h, "EFI PART", 8);
        wr32(h + 8, 0x00010000u);
        wr32(h + 12, 92);
        wr64(h + 24, hdr_lba);
        wr64(h + 32, alt_lba);
        wr64(h + 40, 2 + ent_sectors);
        wr64(h + 48, d->sectors - 2 - ent_sectors);
        memset(h + 56, 0x77, 16);
        wr64(h + 72, ent_lba);
        wr32(h + 80, num_entries);
        wr32(h + 84, entry_size);
        wr32(h + 88, ecrc);
        wr32(h + 16, blk_crc32(0, h, 92));
        memcpy(d->img + ent_lba * d->ss, ents, ent_sectors * d->ss);
    }
    free(ents);
}

static int scan(disk_t *d, blk_part_t *out, unsigned max, uint32_t *notes)
{
    uint8_t *scratch = malloc(2 * d->ss);
    int n = blk_part_scan(rd, d, d->ss, d->sectors, scratch, out, max, notes);
    free(scratch);
    return n;
}

int main(void)
{
    blk_part_t p[16];
    uint32_t notes;
    int n;

    CHECK(blk_crc32(0, "123456789", 9) == 0xcbf43926u, "CRC-32 check value 0xCBF43926 (IEEE, zlib compatible)");
    CHECK(blk_crc32(blk_crc32(0, "1234", 4), "56789", 5) == 0xcbf43926u, "CRC-32 chaining");

    /* --- plain MBR: 2 primaries (one bootable), an extended partition with 3 logicals, one empty slot --- */
    {
        disk_t d = mkdisk(512, 20000);
        uint8_t *ebr1 = d.img + 8000 * 512, *ebr2 = d.img + 10000 * 512, *ebr3 = d.img + 12000 * 512;
        mbr_entry(d.img, 0, 0x80, 0x0c, 2048, 2000);
        mbr_entry(d.img, 2, 0x00, 0x83, 4096, 2000);
        mbr_entry(d.img, 3, 0x00, 0x05, 8000, 8000);          /* extended: 8000..15999 */
        mbr_entry(ebr1, 0, 0, 0x83, 63, 1900);                  /* logical at 8063 */
        mbr_entry(ebr1, 1, 0, 0x05, 2000, 2000);                /* next EBR at 8000+2000 */
        mbr_entry(ebr2, 0, 0, 0x07, 63, 1900);                  /* logical at 10063 */
        mbr_entry(ebr2, 1, 0, 0x05, 4000, 2000);                /* next EBR at 12000 */
        mbr_entry(ebr3, 0, 0, 0x0b, 63, 1000);                  /* logical at 12063 */
        n = scan(&d, p, 16, &notes);
        CHECK(n == 5, "MBR + EBR chain: 5 partitions found (%d)", n);
        CHECK(n == 5 && p[0].start == 2048 && p[0].sectors == 2000 && p[0].mbr_type == 0x0c && (p[0].flags & PARTF_BOOTABLE) && p[0].index == 1,
              "MBR primary 1: start 2048, 2000 sectors, type 0x0c, bootable");
        CHECK(n == 5 && p[1].start == 4096 && p[1].sectors == 2000 && p[1].index == 2 && !(p[1].flags & PARTF_BOOTABLE),
              "MBR primary 2 (slot 3, empty slot 2 skipped): index 2");
        CHECK(n == 5 && p[2].start == 8063 && p[2].sectors == 1900 && (p[2].flags & PARTF_LOGICAL) && p[2].mbr_type == 0x83,
              "logical 1 at 8063 (EBR-relative offset applied)");
        CHECK(n == 5 && p[3].start == 10063 && p[3].mbr_type == 0x07 && p[4].start == 12063 && p[4].sectors == 1000 && p[4].index == 5,
              "logical 2 at 10063, logical 3 at 12063 (extended-relative EBR links)");
        CHECK((notes & (PSCAN_MBR_VALID | PSCAN_EBR_CHAIN)) == (PSCAN_MBR_VALID | PSCAN_EBR_CHAIN) && !(notes & (PSCAN_GPT_PRIMARY_OK | PSCAN_PROTECTIVE_MBR)),
              "notes: MBR valid, EBR chain walked, no GPT (%#x)", notes);
        /* EBR loop: ebr3 links back to ebr1 */
        mbr_entry(ebr3, 1, 0, 0x05, 0, 2000);
        n = scan(&d, p, 16, &notes);
        CHECK(n == 5 && (notes & PSCAN_EBR_LOOP), "EBR chain loop detected and stopped (%d partitions, notes %#x)", n, notes);
        /* out of range primary */
        mbr_entry(d.img, 1, 0, 0x83, 19000, 5000);
        n = scan(&d, p, 16, &notes);
        CHECK(n == 5 && (notes & PSCAN_OUT_OF_RANGE), "primary beyond the device is skipped (%d, notes %#x)", n, notes);
        /* max smaller than the table */
        n = scan(&d, p, 2, &notes);
        CHECK(n == 2 && (notes & PSCAN_TRUNCATED), "output limit honoured with PSCAN_TRUNCATED (%d)", n);
        free(d.img);
    }
    /* --- no signature at all --- */
    {
        disk_t d = mkdisk(512, 100);
        memset(d.img, 0x5a, 100 * 512);
        n = scan(&d, p, 16, &notes);
        CHECK(n == -1 && !(notes & (PSCAN_MBR_VALID | PSCAN_GPT_PRIMARY_OK | PSCAN_GPT_BACKUP_OK)), "no 0x55AA and no GPT: -1 (%d, notes %#x)", n, notes);
        d.fail_lba = 0;
        n = scan(&d, p, 16, &notes);
        CHECK(n == -1 && (notes & PSCAN_READ_ERROR), "read error on LBA 0: -1 with PSCAN_READ_ERROR");
        free(d.img);
    }
    /* --- GPT, 512-byte sectors, 3 partitions, 128 entries --- */
    {
        const gpart_t parts[3] = { {2048, 4095, "EFI system", 1}, {4096, 40959, "ShizukuFS", 2}, {40960, 60000, "data 3", 3} };
        disk_t d = mkdisk(512, 65536);
        uint8_t *h1;
        gpt_write(&d, parts, 3, 128, 128);
        n = scan(&d, p, 16, &notes);
        CHECK(n == 3, "GPT: 3 partitions (%d)", n);
        CHECK(n == 3 && p[0].start == 2048 && p[0].sectors == 2048 && p[1].start == 4096 && p[1].sectors == 36864 && p[2].sectors == 19041,
              "GPT ranges (last LBA inclusive)");
        CHECK(n == 3 && !strcmp(p[1].name, "ShizukuFS") && p[1].type_guid[0] == 2 && p[1].part_guid[0] == 1 && p[1].scheme == PART_SCHEME_GPT,
              "GPT name/type GUID/unique GUID decoded");
        CHECK((notes & (PSCAN_PROTECTIVE_MBR | PSCAN_GPT_PRIMARY_OK)) == (PSCAN_PROTECTIVE_MBR | PSCAN_GPT_PRIMARY_OK) && !(notes & PSCAN_GPT_USED_BACKUP),
              "notes: protective MBR, primary header used (%#x)", notes);
        /* corrupt the primary header CRC -> backup */
        h1 = d.img + 512;
        h1[20] ^= 1;
        n = scan(&d, p, 16, &notes);
        CHECK(n == 3 && (notes & PSCAN_GPT_PRIMARY_BAD) && (notes & PSCAN_GPT_USED_BACKUP) && (p[0].flags & PARTF_FROM_BACKUP_GPT),
              "primary header CRC bad -> backup header at the last LBA used (%d, notes %#x)", n, notes);
        h1[20] ^= 1;
        /* corrupt one entry byte of the primary array -> entries CRC mismatch -> backup */
        d.img[2 * 512 + 40] ^= 0x40;
        n = scan(&d, p, 16, &notes);
        CHECK(n == 3 && (notes & PSCAN_GPT_ENTRIES_CRC_BAD) && (notes & PSCAN_GPT_USED_BACKUP) && p[0].start == 2048,
              "primary entry array CRC bad -> backup used, original ranges (%d, notes %#x)", n, notes);
        d.img[2 * 512 + 40] ^= 0x40;
        /* MyLBA mismatch (header copied to the wrong place) */
        memcpy(d.img + 512, d.img + 65535ull * 512, 512);
        n = scan(&d, p, 16, &notes);
        CHECK(n == 3 && (notes & PSCAN_GPT_PRIMARY_BAD) && (notes & PSCAN_GPT_USED_BACKUP), "primary with wrong MyLBA rejected -> backup (%d)", n);
        gpt_write(&d, parts, 3, 128, 128);
        /* both headers bad + protective MBR -> 0 partitions, not the protective entry */
        d.img[512 + 20] ^= 1;
        d.img[65535ull * 512 + 20] ^= 1;
        n = scan(&d, p, 16, &notes);
        CHECK(n == 0 && (notes & PSCAN_GPT_BACKUP_BAD) && (notes & PSCAN_PROTECTIVE_MBR), "both GPT copies bad: 0 partitions, protective entry not exposed (%d, %#x)", n, notes);
        gpt_write(&d, parts, 3, 128, 128);
        /* hybrid: real MBR entries next to a valid GPT -> GPT wins, flagged */
        mbr_entry(d.img, 1, 0, 0x83, 2048, 2048);
        n = scan(&d, p, 16, &notes);
        CHECK(n == 3 && (notes & PSCAN_HYBRID_MBR) && p[0].scheme == PART_SCHEME_GPT, "hybrid MBR: GPT preferred and flagged");
        /* entry beyond the device */
        {
            const gpart_t bad[2] = { {2048, 4095, "ok", 1}, {60000, 70000, "beyond", 2} };
            gpt_write(&d, bad, 2, 128, 128);
            n = scan(&d, p, 16, &notes);
            CHECK(n == 1 && (notes & PSCAN_OUT_OF_RANGE), "GPT entry beyond the device skipped (%d)", n);
        }
        /* read error inside the entry array -> primary discarded, backup used */
        gpt_write(&d, parts, 3, 128, 128);
        d.fail_lba = 3;
        n = scan(&d, p, 16, &notes);
        CHECK(n == 3 && (notes & PSCAN_READ_ERROR) && (notes & PSCAN_GPT_USED_BACKUP), "read error in the primary array -> backup (%d, %#x)", n, notes);
        d.fail_lba = (uint64_t)-1;
        free(d.img);
    }
    /* --- GPT with 4096-byte sectors and 256-byte entries, 64 entries, backup only (primary zeroed) --- */
    {
        const gpart_t parts[2] = { {256, 511, "four-k-1", 9}, {512, 4000, "four-k-2", 10} };
        disk_t d = mkdisk(4096, 8192);
        gpt_write(&d, parts, 2, 64, 256);
        memset(d.img + 4096, 0, 4096);
        n = scan(&d, p, 16, &notes);
        CHECK(n == 2 && p[1].start == 512 && p[1].sectors == 3489 && !strcmp(p[0].name, "four-k-1") && (notes & PSCAN_GPT_USED_BACKUP),
              "4 KiB sectors, 256-byte entries, primary zeroed -> backup (%d)", n);
        free(d.img);
    }
    /* --- GPT with an entry array spanning many sectors (1024 entries) and a partition at entry 700 --- */
    {
        gpart_t parts[701];
        unsigned i;
        disk_t d = mkdisk(512, 1 << 20);
        for (i = 0; i < 701; ++i) { parts[i].first = 0; parts[i].last = 0; parts[i].name = ""; parts[i].type = 0; }
        parts[700].first = 100000; parts[700].last = 200000; parts[700].name = "late"; parts[700].type = 5;
        /* entries 0..699 have a zero type GUID except the writer stamps 0xab.. : force zero type for them */
        gpt_write(&d, parts, 701, 1024, 128);
        for (i = 0; i < 700; ++i) { memset(d.img + 2 * 512 + i * 128, 0, 16); }
        /* recompute the entries CRC in both headers after zeroing the types */
        {
            const uint32_t ecrc = blk_crc32(0, d.img + 2 * 512, 1024 * 128);
            uint64_t hdr;
            memcpy(d.img + (d.sectors - 1 - 256) * 512, d.img + 2 * 512, 1024 * 128);
            for (hdr = 1; ; hdr = d.sectors - 1) {
                uint8_t *h = d.img + hdr * 512;
                wr32(h + 88, ecrc);
                wr32(h + 16, 0);
                wr32(h + 16, blk_crc32(0, h, 92));
                if (hdr != 1) break;
            }
        }
        n = scan(&d, p, 16, &notes);
        CHECK(n == 1 && p[0].start == 100000 && !strcmp(p[0].name, "late") && (notes & PSCAN_GPT_PRIMARY_OK) && !(notes & PSCAN_GPT_USED_BACKUP),
              "1024-entry array (256 sectors) streamed with a correct CRC; used entry 700 found (%d, %#x)", n, notes);
        free(d.img);
    }
    /* --- argument validation --- */
    {
        disk_t d = mkdisk(512, 4);
        uint8_t scratch[1024];
        CHECK(blk_part_scan(rd, &d, 513, 4, scratch, p, 16, &notes) == -1, "non power-of-two sector size rejected");
        CHECK(blk_part_scan(rd, &d, 512, 1, scratch, p, 16, &notes) == -1, "1-sector device rejected");
        CHECK(blk_part_scan(0, &d, 512, 4, scratch, p, 16, 0) == -1, "NULL read function rejected (notes optional)");
        free(d.img);
    }
    printf("test_blk_part: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
