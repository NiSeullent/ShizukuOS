/* SPDX-License-Identifier: GPL-2.0-only
 * Installer glue: the block-device registry API of kernel64/blk.h (storage track S1/D1). When blk.h is part of the
 * tree this header simply includes it. Until then it declares the same shape (a subset of struct blk_dev with the
 * same member names and the same functions), implemented by a minimal registry in blk_ram.c, so blk_ram.c and the
 * installer syscalls (setup_sys.c) compile unchanged before and after the storage branch is merged.
 * Delete this file once blk.h is merged everywhere.
 */
#ifndef K64_BLK_COMPAT_H
#define K64_BLK_COMPAT_H
#if __has_include("blk.h")
#include "blk.h"
#define K64_HAVE_BLK_REGISTRY 1
#else
#include "k64.h"
#define BLK_NAME_MAX 16
typedef struct blk_dev blk_dev_t;
struct blk_dev {
    char name[BLK_NAME_MAX];
    uint32_t sector_size;
    uint64_t sectors;
    uint64_t start_lba;
    blk_dev_t *parent;
    uint32_t flags;
    uint8_t mbr_type;
    uint8_t type_guid[16];
    uint32_t index;
    int (*read)(blk_dev_t *d, uint64_t lba, unsigned count, void *buf);
    int (*write)(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf);
    int (*flush)(blk_dev_t *d);
    void *priv;
    uint64_t reads, writes;
    blk_dev_t *next;
};
#define BLK_F_READONLY 1u
#define BLK_F_PARTITION 2u
#define BLK_F_REMOVABLE 4u
int blk_register(blk_dev_t *d);
blk_dev_t *blk_first(void);
int blk_read(blk_dev_t *d, uint64_t lba, unsigned count, void *buf);
int blk_write(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf);
int blk_flush(blk_dev_t *d);
#endif

/* blk_ram.c: RAM block devices ("ram0", ...), standalone profile only. Idempotent; returns the number registered. */
int blk_ram_init(void);
/* Serial number of a RAM block device ("IVSHMEM-bb:dd.f"); 0 when d is one, -1 otherwise. */
int blk_ram_serial(const blk_dev_t *d, char *out, unsigned cap);
#endif
