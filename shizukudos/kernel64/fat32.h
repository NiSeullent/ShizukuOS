/* SPDX-License-Identifier: GPL-2.0-only
 * Read-only FAT32 volume reader for Kernel64 (freestanding, host-testable: tests/test_fat32.c).
 *
 * Why not drivers/fat_native: its one entry point, ntwf_read_root83(), is a bounded boot-file reader by contract
 * (root directory only, 8.3 names, <= 512 KiB, no subdirectories, no LFN). A mountable volume needs directory
 * enumeration with VFAT long names, subdirectories and random-access reads of files of hundreds of MB, so this
 * is a separate original implementation of the public FAT32 layout (Microsoft FAT32 specification 1.03).
 *
 * Model: the whole FAT is copied into memory at mount (4 KiB pages), files are read through a per-file extent
 * list (runs of consecutive clusters) built once from the in-memory FAT, so a page of a 250 MB file costs
 * exactly its 8 sector reads. Supported: MBR partition of type 0x0B/0x0C or a superfloppy (no MBR), 512-byte
 * sectors, 1..128 sectors per cluster, one or two FATs (the first is used), LFN with checksum validation.
 * Not supported (by design, documented): writing of any kind, FAT12/16, exFAT, GPT, sector sizes != 512,
 * code-page conversion of 8.3 names (ASCII only; other bytes are mapped to '_'), names longer than 255 UTF-16 units.
 */
#ifndef K64_FAT32_H
#define K64_FAT32_H
#include <stddef.h>
#include <stdint.h>

#define FAT32_SECTOR 512u
#define FAT32_ATTR_RO 0x01
#define FAT32_ATTR_HIDDEN 0x02
#define FAT32_ATTR_SYSTEM 0x04
#define FAT32_ATTR_LABEL 0x08
#define FAT32_ATTR_DIR 0x10
#define FAT32_ATTR_ARCHIVE 0x20
#define FAT32_ATTR_LFN 0x0f

enum { FAT32_OK = 0, FAT32_E_IO = -1, FAT32_E_FORMAT = -2, FAT32_E_NOMEM = -3, FAT32_E_CORRUPT = -4, FAT32_E_RANGE = -5 };

typedef int (*fat32_read_fn)(void *ctx, uint64_t lba, void *buf512);         /* one sector, 0 = ok */
typedef void *(*fat32_alloc_fn)(void *ctx, uint64_t bytes);                  /* zeroed small allocation, NULL = none */
typedef void (*fat32_free_fn)(void *ctx, void *p, uint64_t bytes);
typedef void *(*fat32_page_fn)(void *ctx);                                   /* zeroed 4 KiB block for the FAT copy */

typedef struct {
    /* filled in by the caller before fat32_mount() */
    fat32_read_fn read;
    fat32_alloc_fn alloc;
    fat32_free_fn free;
    fat32_page_fn alloc_page;
    void *ctx;
    uint64_t disk_sectors;
    /* volume geometry (after mount) */
    uint64_t part_lba;
    uint32_t part_sectors, total_sectors, reserved, nfats, fat_sectors, spc, root_cluster, first_data, cluster_count;
    uint32_t bytes_per_cluster;
    uint32_t **fat_pages;                       /* 1024 entries per page */
    uint32_t fat_npages;
    uint32_t volume_id;
    char label[12];
    uint32_t sector_reads;
    uint64_t sector_lba;                        /* LBA held in `sector`, ~0 when nothing */
    uint8_t sector[FAT32_SECTOR];               /* bounce buffer: the caller serialises calls on one volume */
} fat32_vol_t;

typedef struct { uint32_t cluster, offset; int ended; } fat32_dir_t;   /* enumeration cursor (offset within the cluster) */

typedef struct {
    uint16_t name[256];                         /* LFN when present and valid, else the 8.3 name (lowercase flags applied) */
    uint16_t name_len;
    uint8_t attr;
    uint8_t has_lfn;
    uint32_t first_cluster, size;
    uint16_t cdate, ctime, mdate, mtime, adate;
    uint8_t ctenth;
    uint8_t short_name[11];
} fat32_dirent_t;

typedef struct { uint32_t start, count, first_index; } fat32_run_t;
typedef struct { fat32_run_t *runs; uint32_t nruns, cap, total_clusters; } fat32_chain_t;

int fat32_mount(fat32_vol_t *v);
void fat32_unmount(fat32_vol_t *v);
uint32_t fat32_fat_entry(const fat32_vol_t *v, uint32_t cluster);           /* 28-bit value, 0x0fffffff if out of range */
uint64_t fat32_cluster_lba(const fat32_vol_t *v, uint32_t cluster);

void fat32_dir_open(const fat32_vol_t *v, uint32_t first_cluster, fat32_dir_t *d);   /* 0 = root */
int fat32_dir_next(fat32_vol_t *v, fat32_dir_t *d, fat32_dirent_t *out);            /* 1 entry, 0 end, < 0 error */

int fat32_chain_build(fat32_vol_t *v, uint32_t first_cluster, fat32_chain_t *c);
void fat32_chain_free(fat32_vol_t *v, fat32_chain_t *c);
/* Reads [off, off+len) of a file whose extents are `c` and whose size is `size`; short reads at EOF. */
int fat32_read(fat32_vol_t *v, const fat32_chain_t *c, uint32_t size, uint64_t off, void *buf, uint64_t len, uint64_t *done);

/* DOS date/time (local time on FAT; treated as UTC here) -> Windows FILETIME (100 ns since 1601-01-01). */
uint64_t fat32_filetime(uint16_t date, uint16_t time, uint8_t tenth);
#endif
