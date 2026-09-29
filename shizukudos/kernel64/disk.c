/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 disk bring-up (standalone profile): AHCI block device -> read-only FAT32 volume mounted as D:\.
 * Called once from kmain() after the RAM file system and the initrd are up. Without a disk (Supervisor profile,
 * or QEMU started without -device ahci) everything stays as before: C:\ only.
 *
 * Evidence (parsed by tests/run_k64_disk.py):
 *   slot 13: (sector count << 32) | CRC-32 of sector 0, computed in the guest from the DMA'd bytes
 */
#include "fs.h"
#include "blk.h"

uint32_t k64_crc32(const void *data, uint64_t n)
{
    const uint8_t *p = data;
    uint32_t c = 0xffffffffu;
    uint64_t i;
    int k;
    for (i = 0; i < n; ++i) {
        c ^= p[i];
        for (k = 0; k < 8; ++k) c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
    }
    return ~c;
}

void disk_init(void)
{
    uint8_t *sector;
    uint32_t crc;
    if (blk_init())
        return;
    sector = kmalloc(BLK_SECTOR);
    KASSERT(sector);
    if (blk_read_sector(0, sector)) { kfree(sector); return; }
    crc = k64_crc32(sector, BLK_SECTOR);
    kprintf("K64 disk: sector 0 crc32 %x, bytes 510..511 %x %x\n", crc, sector[510], sector[511]);
    shz_evidence(13, (blk_sector_count() << 32) | crc);
    kfree(sector);
}
