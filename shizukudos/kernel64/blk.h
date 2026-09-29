/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 block device: one read-only SATA disk behind the original AHCI core (drivers/ahci_native, GPL-2.0-only).
 *
 * STANDALONE PROFILE ONLY. Under the Supervisor no disk device is passed through and port I/O is trapped, so this
 * layer reports "no device" there (blk_init() returns -1) and the FAT volume (fat32.c / fs.c "D:") is simply absent.
 * The QEMU fixture is `-device ahci -device ide-hd` (ICH9 8086:2922, class 010601); the driver is used unmodified
 * through the thin glue in blk.c: MMIO via mmio_map(), DMA memory from pmm_alloc() (identity physical, DIRECT_MAP
 * virtual), the TSC as the monotonic clock, polling completion (no IRQ: ahci_native polls PxCI itself).
 */
#ifndef K64_BLK_H
#define K64_BLK_H
#include "k64.h"

#define BLK_SECTOR 512u

int blk_init(void);                                 /* 0 when a disk is ready, -1 otherwise (logged) */
int blk_present(void);
uint64_t blk_sector_count(void);
const char *blk_model(void);
/* Reads one 512-byte sector into `buf` (any kernel address). Serialised by a mutex: call from thread context with
 * interrupts enabled (syscalls, kernel threads, or a #PF handler that re-enabled interrupts). 0 = ok. */
int blk_read_sector(uint64_t lba, void *buf);
/* Reads `count` consecutive sectors. */
int blk_read(uint64_t lba, unsigned count, void *buf);
uint64_t blk_read_count(void);                      /* sectors read so far (diagnostics) */
#endif
