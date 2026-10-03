/* SPDX-License-Identifier: GPL-2.0-only
 * Setup-side FAT32 file writer: the target-volume file authority for SZOU
 * staging (szou_sink_ops_t). It performs I/O only through a volume-relative
 * sector device, which the installer binds to the claimed target's existing
 * guarded plat disk callbacks (szou_blk_from_plat). No raw legacy syscalls.
 *
 * Supported: FAT32 only (cluster count >= 65525), mirrored FATs, 8.3 short
 * names (stored upper-case), files < 4 GiB, mkdir, rmdir (empty), create +
 * write (one writer at a time), read, delete, rename/replace of files within
 * or across directories, attribute update, FSInfo maintenance.
 * VFAT LFN chains (v2) are created only for an explicit long name bound to an
 * existing valid 8.3 alias (mkdir_named/rename_named); no alias generation.
 * Refused with truthful errors: FAT12/16, non-mirrored FAT (ExtFlags bit 7),
 * non-8.3 short components, directory rename, full volume.
 *
 * Write ordering for new files: data -> device flush -> FAT chain (all copies)
 * -> device flush -> directory entry -> device flush. Deletion: directory entry
 * first, then FAT chain release (a crash leaks clusters, never cross-links).
 * Replace: destination entry overwritten in one sector write, then source
 * entry deleted, then the old destination chain freed (skipped if shared).
 */
#ifndef SHZ_SZOU_FAT32_H
#define SHZ_SZOU_FAT32_H
#include "szou_stage.h"

#define SZOU_FAT32_MAX_SECTOR 4096u
#define SZOU_FAT32_HANDLES 4u

typedef struct szou_blkdev {
    void *ctx;
    uint32_t sector_size;
    uint64_t sectors;                                   /* volume extent */
    uint32_t max_io_sectors;                            /* per call, >= 1 */
    int (*read)(void *ctx, uint64_t lba, uint32_t count, void *buf);
    int (*write)(void *ctx, uint64_t lba, uint32_t count, const void *buf);
    int (*flush)(void *ctx);
} szou_blkdev_t;

typedef struct szou_fat32_file {
    int used, writing;
    uint32_t first, ncl, *cl;          /* writing: preallocated cluster list */
    uint64_t size;
    uint32_t parent;
    uint8_t name[11];
    uint32_t cur_idx, cur_clus;        /* read-walk cache */
} szou_fat32_file_t;

typedef struct szou_fat32 {
    szou_blkdev_t dev;
    void *mctx;
    void *(*alloc)(void *mctx, size_t bytes);
    void (*free)(void *mctx, void *p);
    uint32_t bps, spc, cb, reserved, nfats, fatsz, root, fsinfo, nclusters;
    uint32_t free_count, next_free;
    uint64_t data_lba;
    uint16_t dos_date, dos_time;
    int mounted, writer_open;
    uint32_t fat_sec;
    int fat_valid, fat_dirty;
    uint8_t fatbuf[SZOU_FAT32_MAX_SECTOR];
    uint8_t dbuf[SZOU_FAT32_MAX_SECTOR];
    uint8_t sec[SZOU_FAT32_MAX_SECTOR];
    szou_fat32_file_t files[SZOU_FAT32_HANDLES];
} szou_fat32_t;

/* Validate the BPB/FSInfo and count actual free clusters from the FAT.
 * dos_date/dos_time stamp new entries (0 -> 1980-01-01 00:00). */
int szou_fat32_mount(szou_fat32_t *fs, const szou_blkdev_t *dev,
                     void *(*alloc)(void *, size_t), void (*free_fn)(void *, void *), void *mctx,
                     uint16_t dos_date, uint16_t dos_time);
/* Sync FAT cache + FSInfo + device flush; refuses while a writer is open. */
int szou_fat32_unmount(szou_fat32_t *fs);
/* Fill a szou_sink_ops_t backed by this mounted volume. */
void szou_fat32_sink(szou_fat32_t *fs, szou_sink_ops_t *out);

/* Read back the VFAT long name bound to path's short entry (0 units if none). */
int szou_fat32_long_name(szou_fat32_t *fs, const char *path, uint16_t out[SZLN_NAME_UNITS + 1], uint32_t *units);

/* Bind a volume-relative device to the claimed target's plat disk callbacks.
 * guard (optional but required by the installer) rechecks target authority
 * before and after every actual I/O, like native_install.c disk_io(). */
struct plat;
typedef struct szou_plat_blk {
    const struct plat *p;
    unsigned index;
    uint64_t first_lba, sectors;
    int (*guard)(void *gctx);
    void *gctx;
} szou_plat_blk_t;
int szou_blk_from_plat(szou_plat_blk_t *pb, szou_blkdev_t *out, uint32_t sector_size, uint32_t max_io_sectors);
#endif
