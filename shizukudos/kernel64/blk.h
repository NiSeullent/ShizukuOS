/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 block-device registry (generic; owned by the storage track, S1). Created minimal by the disk/FAT32 track
 * so every driver (AHCI today: ahci_blk.c; NVMe, SDHCI/eMMC next) and every file system (fat32.c/disk.c today,
 * ShizukuFS next) meets one shape. Extend, do not fork.
 *
 *   driver:      fills a blk_dev_t (name, sector_size, sectors, read[, write, flush, read_async]) and calls
 *                blk_register(); then blk_scan_partitions() exposes its MBR/GPT partitions as further devices.
 *   file system: takes a blk_dev_t * and uses blk_read()/blk_write()/blk_flush(); LBAs are relative to that
 *                device (a partition device adds its start LBA and bounds-checks before reaching the parent).
 *
 * Buffers are kernel virtual addresses (DIRECT_MAP or heap); a driver that needs physical addresses translates
 * (v2p_direct) or bounces internally. Calls may block (mutex/sleep): thread context with interrupts enabled.
 * Under the Supervisor no device is passed through, so the registry is simply empty there.
 */
#ifndef K64_BLK_H
#define K64_BLK_H
#include "k64.h"

#define BLK_NAME_MAX 16
#define BLK_MAX_DEVICES 32

typedef struct blk_dev blk_dev_t;
typedef void (*blk_done_fn)(void *ctx, int status);

struct blk_dev {
    char name[BLK_NAME_MAX];                    /* "ahci0", "ahci0p1", "nvme0n1", ... */
    uint32_t sector_size;                       /* bytes; 512 for every device so far */
    uint64_t sectors;                           /* capacity in sectors */
    uint64_t start_lba;                         /* partition: first sector within parent; whole device: 0 */
    blk_dev_t *parent;                          /* partition: the whole device; whole device: NULL */
    uint32_t flags;                             /* BLK_F_* */
    uint8_t mbr_type;                           /* MBR partition type byte (0x0b/0x0c FAT32, 0x83 Linux, 0xee = GPT) */
    uint8_t type_guid[16];                      /* GPT partition type GUID (zero for MBR) */
    uint32_t index;                             /* partition number within the parent (1-based), 0 for whole devices */
    /* driver operations (partition devices forward to the parent) */
    int (*read)(blk_dev_t *d, uint64_t lba, unsigned count, void *buf);          /* 0 = ok */
    int (*write)(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf);   /* NULL: read-only device */
    int (*flush)(blk_dev_t *d);                                                  /* NULL: nothing to flush */
    /* optional asynchronous read: returns 0 when queued (done() called later from a thread, never from an IRQ
     * handler with a lock held), -1 when unsupported/failed. NULL when the driver only polls. */
    int (*read_async)(blk_dev_t *d, uint64_t lba, unsigned count, void *buf, blk_done_fn done, void *ctx);
    void *priv;                                 /* driver private data */
    uint64_t reads, writes;                     /* sector counters (diagnostics) */
    blk_dev_t *next;                            /* registry list */
};
#define BLK_F_READONLY 1u
#define BLK_F_PARTITION 2u
#define BLK_F_REMOVABLE 4u

int blk_register(blk_dev_t *d);                 /* adds to the registry (name must be unique); 0 = ok */
blk_dev_t *blk_find(const char *name);
blk_dev_t *blk_first(void);                     /* iterate with ->next; whole devices and partitions, registration order */
unsigned blk_count(void);
int blk_read(blk_dev_t *d, uint64_t lba, unsigned count, void *buf);
int blk_write(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf);
int blk_flush(blk_dev_t *d);
/* Reads the MBR (and a protective-MBR GPT) of a whole device and registers each partition as "<name>p<n>".
 * Returns the number of partitions registered, 0 for an unpartitioned (superfloppy) or empty device, < 0 on I/O error. */
int blk_scan_partitions(blk_dev_t *whole);

/* Drivers (each registers its devices; called once from disk_init() in the standalone profile). */
int ahci_blk_init(void);                        /* ahci_blk.c: 0 when a disk was registered, -1 otherwise (logged) */
uint32_t ahci_blk_flushes(void);                /* FLUSH CACHE EXT commands completed (diagnostics) */
#endif
