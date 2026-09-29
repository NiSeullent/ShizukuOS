/* SPDX-License-Identifier: GPL-2.0-only
 * Partition table scanner for the Kernel64 block layer (blk.c): MBR (primary entries and the EBR chain of an extended
 * partition) and GPT (protective MBR, primary header at LBA 1, backup header at the last LBA, CRC32 of the header and of
 * the entry array). Pure code: no kernel headers, no allocation, so tests/test_blk_part.c compiles it on the host with
 * -DBLK_HOST_TEST and drives it with synthetic tables.
 */
#ifndef K64_BLK_PART_H
#define K64_BLK_PART_H
#include <stddef.h>
#include <stdint.h>

enum { PART_SCHEME_NONE = 0, PART_SCHEME_MBR = 1, PART_SCHEME_GPT = 2 };
enum { PARTF_BOOTABLE = 1, PARTF_LOGICAL = 2, PARTF_FROM_BACKUP_GPT = 4 };

typedef struct {
    uint64_t start, sectors;            /* device sectors */
    uint32_t index;                     /* 1-based, the M of \Device\HarddiskN\PartitionM */
    uint32_t scheme;                    /* PART_SCHEME_* */
    uint8_t mbr_type;                   /* MBR: type byte; GPT: 0 */
    uint8_t flags;                      /* PARTF_* */
    uint8_t type_guid[16];              /* GPT partition type GUID (raw bytes as stored) */
    uint8_t part_guid[16];              /* GPT unique partition GUID */
    char name[37];                      /* GPT name folded to ASCII ('?' for anything else) */
} blk_part_t;

/* What the scan saw; logged by blk.c and asserted by the host tests. */
enum {
    PSCAN_MBR_VALID = 1 << 0,           /* LBA 0 carries the 0x55AA signature */
    PSCAN_PROTECTIVE_MBR = 1 << 1,      /* an MBR entry of type 0xEE */
    PSCAN_GPT_PRIMARY_OK = 1 << 2,
    PSCAN_GPT_PRIMARY_BAD = 1 << 3,     /* signature/CRC/geometry check failed at LBA 1 */
    PSCAN_GPT_BACKUP_OK = 1 << 4,
    PSCAN_GPT_BACKUP_BAD = 1 << 5,
    PSCAN_GPT_USED_BACKUP = 1 << 6,     /* partitions came from the backup header */
    PSCAN_GPT_ENTRIES_CRC_BAD = 1 << 7, /* entry array of the header that was otherwise fine failed its CRC */
    PSCAN_EBR_CHAIN = 1 << 8,           /* logical partitions were walked */
    PSCAN_OUT_OF_RANGE = 1 << 9,        /* an entry beyond the device was skipped */
    PSCAN_HYBRID_MBR = 1 << 10,         /* GPT used although the MBR is not (only) protective */
    PSCAN_READ_ERROR = 1 << 11,
    PSCAN_TRUNCATED = 1 << 12,          /* more partitions than `max` */
    PSCAN_EBR_LOOP = 1 << 13            /* EBR chain revisited a sector or exceeded the limit */
};

/* Reads `count` sectors starting at `lba` into buf; returns 0 on success. */
typedef int (*blk_part_read_fn)(void *ctx, uint64_t lba, uint32_t count, void *buf);

/* Scans the device. `scratch` must hold at least 2 sectors (2 * sector_size bytes). Returns the number of partitions
 * stored in out[] (0..max) or -1 when no table could be read at all. *notes (optional) receives PSCAN_* bits. */
int blk_part_scan(blk_part_read_fn read, void *ctx, uint32_t sector_size, uint64_t sectors, void *scratch,
                  blk_part_t *out, unsigned max, uint32_t *notes);

/* IEEE 802.3 CRC-32 (zlib compatible): blk_crc32(0, data, n) for a fresh checksum, chainable. */
uint32_t blk_crc32(uint32_t crc, const void *data, size_t n);
#endif
