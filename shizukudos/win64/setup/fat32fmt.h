/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: empty FAT32 volume formatter for the optional Windows 98 partition (p3). The partition is created empty:
 * no Microsoft file is ever bundled; the user installs their own Windows 98 there. Parameters follow Microsoft's
 * "FAT: General Overview of On-Disk Format" 1.03 (BPB, FAT size formula, FSInfo, backup boot sector).
 */
#ifndef SHZ_FAT32FMT_H
#define SHZ_FAT32FMT_H
#include <stdint.h>

typedef struct fat32_io {
    void *ctx;
    int (*write)(void *ctx, uint64_t sector, uint32_t count, const void *buf);    /* 512-byte sectors, volume-relative */
} fat32_io;

typedef struct fat32_params {
    uint64_t sectors;           /* volume size in 512-byte sectors */
    uint32_t hidden;            /* sectors before the volume on the disk (partition start LBA) */
    uint32_t volume_id;
    char label[11];             /* space padded */
} fat32_params;

/* Returns 0, or -1 (too small/large for FAT32), -2 (I/O). *clusters_out receives the data cluster count. */
int fat32_format(const fat32_io *io, const fat32_params *p, uint32_t *clusters_out);
#endif
