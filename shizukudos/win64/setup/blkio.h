/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: raw block-device access on Kernel64 (plat_t disk callbacks). Today through the installer syscalls
 * (kernel64/setup_abi.h, 0xb0-0xb4); when the storage track's raw-sector syscalls (0xf0-0xff) are merged, only
 * blkio.c changes.
 */
#ifndef SHZ_BLKIO_H
#define SHZ_BLKIO_H
#include <stdint.h>
#include "plat.h"

#define BLKIO_MAX_SECTORS 2048u

int blkio_init(void);                                   /* 0 = ok (zero devices is not an error) */
unsigned blkio_count(void *ctx);
int blkio_info(void *ctx, unsigned index, plat_disk_t *out);
int blkio_read(void *ctx, unsigned index, uint64_t lba, uint32_t count, void *buf);
int blkio_write(void *ctx, unsigned index, uint64_t lba, uint32_t count, const void *buf);
int blkio_flush(void *ctx, unsigned index);
void blkio_power(int action);                           /* SETUP_POWER_* */
#endif
