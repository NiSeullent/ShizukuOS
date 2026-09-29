/* SPDX-License-Identifier: GPL-2.0-only
 * Installer system-call ABI (kernel64/setup_sys.c <-> win64/setup/blkio.c). Numbers: ntsys.h SYSCALL_LIST_SETUP,
 * installer range 0xb0-0xbf (0xe0-0xef belongs to the NT driver host, 0xf0-0xff to the storage track).
 *
 *   0xb0 NtShzSetupBlkQuery(index, shz_setup_blk_info_t *out, size)   STATUS_NO_MORE_ENTRIES past the last device
 *   0xb1 NtShzSetupBlkRead(index, lba, count, buffer)                  count sectors (<= SHZ_SETUP_MAX_SECTORS)
 *   0xb2 NtShzSetupBlkWrite(index, lba, count, buffer)
 *   0xb3 NtShzSetupBlkFlush(index)
 *   0xb4 NtShzSetupPower(action)                                       SHZ_SETUP_POWER_*, honoured after SHZSETUP exits
 *
 * `index` is the position in the kernel's block-device registry (whole devices and partitions, registration order).
 * This is the installer's interim path to raw sectors; the storage track's raw-sector syscalls (0xf0-0xff) replace
 * the Blk* calls when they are merged (only win64/setup/blkio.c has to change).
 */
#ifndef SHZ_SETUP_ABI_H
#define SHZ_SETUP_ABI_H
#include <stdint.h>

#define SHZ_SETUP_MAX_SECTORS 2048u             /* 1 MiB of 512-byte sectors per call */

#define SHZ_SETUP_BLK_PARTITION 1u
#define SHZ_SETUP_BLK_READONLY 2u
#define SHZ_SETUP_BLK_REMOVABLE 4u

typedef struct shz_setup_blk_info {
    uint32_t index;
    uint32_t flags;                             /* SHZ_SETUP_BLK_* */
    char name[16];                              /* "ram0", "ahci0", "nvme0n1", "ahci0p1" ... */
    char serial[32];                            /* driver-reported serial, "" when unknown */
    uint64_t sectors;
    uint32_t sector_size;
    uint32_t parent;                            /* partitions: index of the whole device; 0xffffffff otherwise */
} shz_setup_blk_info_t;

enum { SHZ_SETUP_POWER_NONE = 0, SHZ_SETUP_POWER_SHUTDOWN = 1, SHZ_SETUP_POWER_REBOOT = 2 };

_Static_assert(sizeof(shz_setup_blk_info_t) == 72, "setup blk info layout");
#endif
