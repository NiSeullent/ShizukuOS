/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NATIVE_FAT32_RELOCATE_H
#define SHZ_NATIVE_FAT32_RELOCATE_H

#include <stddef.h>
#include <stdint.h>

#define SHZ_NATIVE_FAT32_SECTOR_BYTES 512u
#define SHZ_NATIVE_FAT32_MAX_SOURCE_BYTES (2304ull * 1024ull * 1024ull)

enum shz_native_fat32_result {
    SHZ_NATIVE_FAT32_OK = 0,
    SHZ_NATIVE_FAT32_ARGUMENT = -1,
    SHZ_NATIVE_FAT32_GEOMETRY = -2,
    SHZ_NATIVE_FAT32_TARGET = -3,
    SHZ_NATIVE_FAT32_PLAN = -4
};

typedef struct shz_native_fat32_relocate {
    uint64_t source_bytes;
    uint64_t target_first_lba;
    uint64_t target_last_lba;
    uint64_t backup_boot_offset;
    uint64_t fsinfo_offset;
    uint64_t backup_fsinfo_offset;
    uint32_t total_sectors;
    uint32_t cluster_count;
    uint8_t primary[SHZ_NATIVE_FAT32_SECTOR_BYTES];
    uint8_t backup[SHZ_NATIVE_FAT32_SECTOR_BYTES];
    uint8_t fsinfo[SHZ_NATIVE_FAT32_SECTOR_BYTES];
    uint8_t backup_fsinfo[SHZ_NATIVE_FAT32_SECTOR_BYTES];
} shz_native_fat32_relocate_t;

/* Native volume-image branch only: source_first_lba must be zero. Four exact
 * 512-byte snapshots must be read from the same held, validated source: primary
 * at offset zero, backup at BPB_BkBootSec, FSInfo at BPB_FSInfo and backup FSInfo
 * at their sum. This function cannot authenticate those caller claims.
 *
 * The two source VBRs must match byte for byte and have hidden-sector DWORD 0.
 * The target inclusive interval must contain exactly the original volume.
 * GPT usability, disk identity, current-OS exclusion and destructive authority
 * remain caller responsibilities. out_bytes must be exactly sizeof(*out);
 * output must be disjoint from the inputs. The chosen supported subset also
 * requires BPB reserved bytes 52..63 to be zero; existing images are not
 * certified by this interface declaration.
 * On failure every input and every output byte stays unchanged. On success only
 * offset 28..31 in each staged VBR changes; FSInfo snapshots are preserved.
 */
int shz_native_fat32_relocate_stage(
    const uint8_t *primary, size_t primary_bytes,
    const uint8_t *backup, size_t backup_bytes,
    const uint8_t *fsinfo, size_t fsinfo_bytes,
    const uint8_t *backup_fsinfo, size_t backup_fsinfo_bytes,
    uint64_t source_first_lba, uint64_t source_bytes,
    uint64_t target_first_lba, uint64_t target_last_lba,
    shz_native_fat32_relocate_t *out, size_t out_bytes);

/* Apply only the two four-byte hidden-sector overlays to a volume-relative
 * window. Arbitrary window boundaries, including split DWORDs, are supported.
 * plan_bytes must be exactly sizeof(*plan). A zero-length window permits NULL
 * only at an offset at or before source_bytes, with a valid plan. Other windows
 * must be valid writable
 * storage, fit inside source_bytes and be disjoint from the plan. The complete
 * plan is semantically revalidated before any byte is written; the plan is not
 * an authenticated custody token. Failure preserves the entire window.
 *
 * Caller hashes original S before overlays and relocated R after overlays.
 * Preflight both S/R before erase, hold source custody across a second pass,
 * verify second-pass S/R and flushed destination R independently. This helper
 * performs no I/O, hashing, allocation or destructive authorization.
 */
int shz_native_fat32_relocate_overlay(
    const shz_native_fat32_relocate_t *plan, size_t plan_bytes,
    uint64_t window_offset, uint8_t *window, size_t window_bytes);

#endif
