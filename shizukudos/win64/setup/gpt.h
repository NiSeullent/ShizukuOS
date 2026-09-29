/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: GUID Partition Table + protective MBR (UEFI Specification 2.10, chapter 5) builder and checker.
 * Portable C99, no I/O: the caller writes the returned sectors. Shared by SHZSETUP.EXE and the host tests.
 */
#ifndef SHZ_GPT_H
#define SHZ_GPT_H
#include <stddef.h>
#include <stdint.h>

#define GPT_ENTRIES 128u
#define GPT_ENTRY_SIZE 128u
#define GPT_ARRAY_BYTES (GPT_ENTRIES * GPT_ENTRY_SIZE)      /* 16 KiB */
#define GPT_MAX_PARTS 4u
#define GPT_ATTR_REQUIRED 0x1ull
#define GPT_ATTR_LEGACY_BIOS_BOOTABLE 0x4ull

typedef struct gpt_part {
    uint8_t type[16];                   /* on-disk (mixed-endian) GUID bytes */
    uint8_t guid[16];
    uint64_t first_lba, last_lba;       /* inclusive */
    uint64_t attrs;
    char name[36];                      /* ASCII, stored as UTF-16LE */
    uint8_t mbr_type;                   /* hybrid MBR type for this partition, 0 = not mirrored */
} gpt_part_t;

typedef struct gpt_layout {
    uint32_t sector_size;               /* 512 or 4096 */
    uint64_t sectors;                   /* device capacity */
    uint8_t disk_guid[16];
    uint32_t mbr_signature;             /* MBR disk signature (offset 440) */
    const uint8_t *boot_code;           /* 440 bytes of legacy BIOS boot code, or NULL for zeros */
    unsigned count;
    gpt_part_t part[GPT_MAX_PARTS];
} gpt_layout_t;

/* Well-known partition type GUIDs (on-disk byte order). */
extern const uint8_t GPT_TYPE_ESP[16];              /* C12A7328-F81F-11D2-BA4B-00A0C93EC93B */
extern const uint8_t GPT_TYPE_LINUX_FS[16];         /* 0FC63DAF-8483-4772-8E79-3D69D8477DE4 (ext4 data; ShizukuFS v1) */
extern const uint8_t GPT_TYPE_MS_BASIC_DATA[16];    /* EBD0A0A2-B9E5-4433-87C0-68B6B72699C7 */

uint32_t gpt_crc32(const void *data, size_t n);
/* First/last LBA usable for partitions on a device of this geometry. */
uint64_t gpt_first_usable(uint32_t sector_size);
uint64_t gpt_last_usable(uint32_t sector_size, uint64_t sectors);
/* Fills: mbr (one sector), primary header (one sector, LBA 1), the entry array (GPT_ARRAY_BYTES, written at LBA 2 and
 * again before the backup header), backup header (one sector, last LBA). Returns 0 or a negative error. */
int gpt_build(const gpt_layout_t *l, uint8_t *mbr, uint8_t *primary, uint8_t *array, uint8_t *backup);
/* Checks a header sector + array read back from disk: signature, both CRCs, self/alternate LBA. 0 = valid. */
int gpt_check(const uint8_t *header, const uint8_t *array, uint32_t sector_size, uint64_t my_lba, uint64_t sectors);
/* "12345678-9abc-..." -> on-disk bytes; 0 = ok. */
int gpt_guid_parse(const char *text, uint8_t out[16]);
void gpt_guid_format(const uint8_t g[16], char out[37]);
#endif
