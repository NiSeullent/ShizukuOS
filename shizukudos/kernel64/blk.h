/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 block-device registry (generic; owned by the storage track, S1). Created minimal by the disk/FAT32 track
 * so every driver (AHCI: ahci_blk.c; NVMe: nvme.c; SD/eMMC: sdhci.c) and every file system (fat32.c/disk.c today,
 * ShizukuFS next) meets one shape. Extend, do not fork.
 *
 *   driver:      fills a blk_dev_t (name, sector_size, sectors, read[, write, flush, read_async, write_async, discard,
 *                control]) and calls blk_register(); then blk_scan_partitions() exposes its MBR/GPT partitions as
 *                further devices.
 *   file system: takes a blk_dev_t * and uses blk_read()/blk_write()/blk_flush(); LBAs are relative to that
 *                device (a partition device adds its start LBA and bounds-checks before reaching the parent).
 *
 * Buffers are kernel virtual addresses (DIRECT_MAP, heap, kernel image, or any page mapped in the kernel half); a
 * driver that needs physical addresses translates them with blk_kva_to_pa() (handles 4 KiB / 2 MiB / 1 GiB pages) or
 * bounces internally. Calls may block (mutex/semaphore): thread context. Before the scheduler runs (disk_init() is
 * called from kmain() with interrupts off) drivers complete requests by polling, so the same calls work there.
 * Under the Supervisor no device is passed through, so the registry is simply empty there.
 *
 * Pipelining: read_async/write_async queue a request and return at once; done(ctx, status) runs later from a driver
 * thread (never from an interrupt handler), status 0 = ok. A driver with a real queue (NVMe) keeps many of them in
 * flight (queue_depth); a caller that gets -1 falls back to the synchronous call. blk_read_async/blk_write_async do
 * the partition offset and bounds checks and fall back to a synchronous call (done() then runs before they return)
 * when the driver has no async entry point.
 */
#ifndef K64_BLK_H
#define K64_BLK_H
#include "k64.h"
#include "blk_part.h"

#define BLK_NAME_MAX 16
#define BLK_MAX_DEVICES 32

typedef struct blk_dev blk_dev_t;
typedef void (*blk_done_fn)(void *ctx, int status);

struct blk_dev {
    char name[BLK_NAME_MAX];                    /* "ahci0", "nvme0n1", "nvme0n1p2", "mmcblk0", ... */
    uint32_t sector_size;                       /* bytes: 512 or 4096 (NVMe LBA format) */
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
    /* ---- storage-track extensions (all optional: zero/NULL = absent) ---- */
    int (*write_async)(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf, blk_done_fn done, void *ctx);
    int (*discard)(blk_dev_t *d, uint64_t lba, unsigned count);                  /* TRIM / DSM deallocate */
    int (*control)(blk_dev_t *d, unsigned op, uint64_t arg, uint64_t *out);      /* BLK_CTL_*: 0 ok, -1 error, -2 unsupported */
    const char *driver;                         /* "nvme", "sdhci", "ahci" */
    const char *irq_mode;                       /* "msix", "intx", "poll" (current completion mode) */
    char model[41], serial[21];
    uint32_t queue_depth;                       /* requests the driver keeps in flight (1 = serial) */
    uint32_t max_sectors;                       /* largest single transfer the driver issues (it splits bigger ones) */
    uint64_t read_ops, write_ops, flushes, discards, errors;
    uint32_t reg_index;                         /* position in the registry (0-based), set by blk_register() */
    uint32_t part_scheme, scan_notes;           /* partition: PART_SCHEME_*; whole device: PSCAN_* of its scan */
    int scan_result;                            /* whole device: partitions found, -1 = no table/not scanned */
    char part_name[37];                         /* GPT partition name (ASCII fold) */
};
#define BLK_F_READONLY 1u
#define BLK_F_PARTITION 2u
#define BLK_F_REMOVABLE 4u
#define BLK_F_MOUNTED 8u                        /* a file system uses it: raw writes from user mode are refused */
#define BLK_F_FLUSH 16u                         /* flush does real work (volatile write cache) */
#define BLK_F_DISCARD 32u                       /* discard supported */

/* Driver control operations (blk_control, NtShzBlkControl). */
enum {
    BLK_CTL_RESET = 1,                          /* controller reset + recovery while idle; out = resets so far */
    BLK_CTL_TIMEOUT_TEST = 2,                   /* NVMe: lose a command on purpose, detect the timeout, recover */
    BLK_CTL_IRQ_MODE = 3,                       /* arg: 0 = best (MSI-X), 1 = INTx, 2 = poll; out = mode now in use */
    BLK_CTL_STATS = 4,                          /* out[0..3]: NVMe interrupts, timeouts, resets, max in flight;
                                                   SDHCI ADMA2 transfers, timeouts, line resets, PIO transfers */
    BLK_CTL_SET_TIMEOUT_MS = 5,                 /* per-command timeout (default 5000 ms NVMe / 2000 ms SD) */
    BLK_CTL_XFER_MODE = 6,                      /* SDHCI: arg 0 = ADMA2 when possible, 1 = force PIO; out = 1 if ADMA2 */
    BLK_CTL_ERROR_TEST = 7                      /* send a command addressing past the end: must fail and leave the device usable */
};

int blk_register(blk_dev_t *d);                 /* adds to the registry (name must be unique); 0 = ok */
blk_dev_t *blk_find(const char *name);
blk_dev_t *blk_first(void);                     /* iterate with ->next; whole devices and partitions, registration order */
blk_dev_t *blk_get(unsigned index);             /* index-th device in registration order, NULL past the end */
unsigned blk_count(void);
int blk_read(blk_dev_t *d, uint64_t lba, unsigned count, void *buf);
int blk_write(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf);
int blk_flush(blk_dev_t *d);
int blk_discard(blk_dev_t *d, uint64_t lba, unsigned count);                 /* -1 when unsupported or failed */
int blk_control(blk_dev_t *d, unsigned op, uint64_t arg, uint64_t *out);     /* routed to the whole device's driver */
int blk_read_async(blk_dev_t *d, uint64_t lba, unsigned count, void *buf, blk_done_fn done, void *ctx);
int blk_write_async(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf, blk_done_fn done, void *ctx);
blk_dev_t *blk_whole(blk_dev_t *d);             /* the whole device under a partition (itself for a whole device) */
/* Reads the partition table of a whole device (blk_part.c: MBR + EBR chain, GPT with header/array CRC and backup
 * header) and registers each partition as "<name>p<n>". Returns the number of partitions registered, 0 for an
 * unpartitioned (superfloppy) or empty device, < 0 on I/O error. */
int blk_scan_partitions(blk_dev_t *whole);
/* Physical address behind a kernel virtual address (any kernel-half mapping), 0 when unmapped. */
uint64_t blk_kva_to_pa(const void *kva);

/* Drivers (each registers its devices; called once from disk_init() in the standalone profile). */
int ahci_blk_init(void);                        /* ahci_blk.c: 0 when a disk was registered, -1 otherwise (logged) */
int nvme_blk_init(void);                        /* nvme.c: number of namespaces registered (0 = none) */
int sdhci_blk_init(void);                       /* sdhci.c: number of cards registered (0 = none) */
#endif
