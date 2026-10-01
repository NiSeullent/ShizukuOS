/* SPDX-License-Identifier: GPL-2.0-only
 * FAT32 volume reader/writer for Kernel64 (freestanding, host-testable: tests/test_fat32.c).
 *
 * Why not drivers/fat_native: its one entry point, ntwf_read_root83(), is a bounded boot-file reader by contract
 * (root directory only, 8.3 names, <= 512 KiB, no subdirectories, no LFN). A mountable volume needs directory
 * enumeration with VFAT long names, subdirectories and random-access reads of files of hundreds of MB, so this
 * is a separate original implementation of the public FAT32 layout (Microsoft FAT32 specification 1.03).
 *
 * Model: the whole FAT is copied into memory at mount (4 KiB pages), files are read through a per-file extent
 * list (runs of consecutive clusters) built once from the in-memory FAT, so a page of a 250 MB file costs
 * exactly its 8 sectors, optionally grouped into up to four sectors per read. Supported: MBR partition of type 0x0B/0x0C or a superfloppy (no MBR), 512-byte
 * sectors, 1..128 sectors per cluster, one or two FATs (the first is used), LFN with checksum validation.
 * Writing (when the caller supplies `write`): data writes with read-modify-write of partial sectors, file growth by
 * cluster allocation (gaps read as zero), truncation, creation of files and directories with VFAT long names and
 * generated unique 8.3 aliases (BASIS~N), directory growth by one zeroed cluster, deletion of files and empty
 * directories (long-name entries included, clusters freed), rename and move within the volume (a moved directory's
 * ".." follows it; an existing file of the new name may be replaced). FAT changes are kept in the
 * in-memory copy, tracked per FAT sector and written to every FAT copy (plus the FSInfo free count) by
 * fat32_sync(), which every mutating call ends with, so the volume on disk is consistent after each call.
 * Not supported (by design, documented): FAT12/16, exFAT, GPT, sector sizes != 512, volumes with
 * FAT mirroring disabled (mounted read-only), code-page conversion of 8.3 names (ASCII only; other bytes are mapped
 * to '_'), names longer than 255 UTF-16 units, files of 4 GiB or more.
 */
#ifndef K64_FAT32_H
#define K64_FAT32_H
#include <stddef.h>
#include <stdint.h>

#define FAT32_SECTOR 512u
#define FAT32_READ_MAX_SECTORS 4u
#define FAT32_ATTR_RO 0x01
#define FAT32_ATTR_HIDDEN 0x02
#define FAT32_ATTR_SYSTEM 0x04
#define FAT32_ATTR_LABEL 0x08
#define FAT32_ATTR_DIR 0x10
#define FAT32_ATTR_ARCHIVE 0x20
#define FAT32_ATTR_LFN 0x0f

enum { FAT32_OK = 0, FAT32_E_IO = -1, FAT32_E_FORMAT = -2, FAT32_E_NOMEM = -3, FAT32_E_CORRUPT = -4, FAT32_E_RANGE = -5,
       FAT32_E_RDONLY = -6, FAT32_E_FULL = -7, FAT32_E_NAME = -8, FAT32_E_EXISTS = -9, FAT32_E_NOTEMPTY = -10 };

typedef int (*fat32_read_fn)(void *ctx, uint64_t lba, void *buf512);         /* one sector, 0 = ok */
/* Optional consecutive-sector read. Never asked for more than four sectors or
 * for sectors outside the caller's actual file request. A failed call's buffer
 * is discarded: the caller receives only previously completed batches. */
typedef int (*fat32_read_many_fn)(void *ctx, uint64_t lba, unsigned count, void *buf);
typedef int (*fat32_write_fn)(void *ctx, uint64_t lba, const void *buf512);  /* one sector, 0 = ok; NULL: read-only */
typedef void *(*fat32_alloc_fn)(void *ctx, uint64_t bytes);                  /* zeroed small allocation, NULL = none */
typedef void (*fat32_free_fn)(void *ctx, void *p, uint64_t bytes);
typedef void *(*fat32_page_fn)(void *ctx);                                   /* zeroed 4 KiB block for the FAT copy */

typedef struct {
    /* filled in by the caller before fat32_mount() */
    fat32_read_fn read;
    fat32_read_many_fn read_many;               /* optional: NULL preserves one-sector callbacks */
    fat32_alloc_fn alloc;
    fat32_free_fn free;
    fat32_page_fn alloc_page;
    fat32_write_fn write;                       /* optional; cleared by fat32_mount when the volume cannot be written */
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
    uint32_t sector_reads, sector_writes;
    uint32_t fsinfo_sector;                     /* relative to the volume, 0 = none */
    uint32_t free_clusters;                     /* counted at mount, maintained by allocation and truncation */
    uint32_t alloc_hint;                        /* next cluster to try */
    uint32_t fsinfo_dirty;
    uint8_t *fat_dirty;                         /* one bit per FAT sector held in memory (writable volumes) */
    uint64_t sector_lba;                        /* LBA held in `sector`, ~0 when nothing */
    uint8_t sector[FAT32_SECTOR];               /* bounce buffer: the caller serialises calls on one volume */
    uint8_t read_batch[FAT32_SECTOR * FAT32_READ_MAX_SECTORS]; /* bounded staging; no failed-batch output leak */
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
    uint32_t dir_cluster, dir_offset;           /* where the short entry lives: directory cluster, byte offset in it */
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
/* Seconds since 1970-01-01 (UTC, stored as FAT local time) -> DOS date/time (2-second resolution, 1980..2107). */
void fat32_dostime(uint64_t unix_seconds, uint16_t *date, uint16_t *time);

/* ---- writing (all return FAT32_E_RDONLY on a read-only volume and end with fat32_sync) ---- */
/* Writes [off, off+len) of a file: grows the chain (first cluster allocated when *first_cluster is 0), zero-fills a
 * gap between *size and off, updates *first_cluster and *size. The caller then records them with fat32_set_entry. */
int fat32_write(fat32_vol_t *v, fat32_chain_t *c, uint32_t *first_cluster, uint32_t *size, uint64_t off, const void *buf,
                uint64_t len);
/* Sets the size: growing zero-fills, shrinking frees the clusters past the new end (all of them for size 0). */
int fat32_truncate(fat32_vol_t *v, fat32_chain_t *c, uint32_t *first_cluster, uint32_t *size, uint32_t new_size);
/* Rewrites the short entry at (dir_cluster, dir_offset): first cluster, size, write/access date and time, ARCHIVE. */
int fat32_set_entry(fat32_vol_t *v, uint32_t dir_cluster, uint32_t dir_offset, uint32_t first_cluster, uint32_t size,
                    uint16_t date, uint16_t time);
/* Creates an empty file (or a directory with "." and ".." when is_dir) named `name` (UTF-16, not NUL-terminated) in
 * the directory starting at dir_first_cluster (0 = root). LFN entries are written unless the name is an exact
 * upper-case 8.3 name; the alias is BASIS~N, unique in the directory. FAT32_E_EXISTS when a long or short name
 * matches (case-insensitive, ASCII). `out` receives the new entry as fat32_dir_next would return it. */
int fat32_create(fat32_vol_t *v, uint32_t dir_first_cluster, const uint16_t *name, unsigned name_len, int is_dir,
                 uint16_t date, uint16_t time, fat32_dirent_t *out);
/* Deletes the file or empty directory whose short entry is at (dir_cluster, dir_offset) in the directory starting at
 * dir_first_cluster (0 = root): its long-name and short entries are marked deleted and its clusters freed.
 * FAT32_E_NOTEMPTY for a directory that still holds entries. */
int fat32_remove(fat32_vol_t *v, uint32_t dir_first_cluster, uint32_t dir_cluster, uint32_t dir_offset);
/* Gives the file or directory whose short entry is at (dir_cluster, dir_offset) in src_dir_first the name `name` in
 * dst_dir_first (the same or another directory; 0 = root). Attributes, times, first cluster and size are kept; a
 * moved directory's ".." is updated. An existing file of the new name is deleted first when `replace` is set, else
 * FAT32_E_EXISTS (always for a directory or a read-only file); FAT32_E_NAME for a directory moved into its own
 * subtree. `out` receives the new entry. */
int fat32_rename(fat32_vol_t *v, uint32_t src_dir_first, uint32_t dir_cluster, uint32_t dir_offset, uint32_t dst_dir_first,
                 const uint16_t *name, unsigned name_len, int replace, fat32_dirent_t *out);
int fat32_sync(fat32_vol_t *v);                 /* dirty FAT sectors to every FAT copy, FSInfo free count */
#endif
