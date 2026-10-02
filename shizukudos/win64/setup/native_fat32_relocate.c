/* SPDX-License-Identifier: GPL-2.0-only */
#include "native_fat32_relocate.h"

typedef struct native_geometry {
    uint64_t backup_boot_offset;
    uint64_t fsinfo_offset;
    uint64_t backup_fsinfo_offset;
    uint32_t total_sectors;
    uint32_t cluster_count;
} native_geometry_t;

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t v)
{
    unsigned i;
    for (i = 0; i < 4; ++i)
        p[i] = (uint8_t)(v >> (i * 8));
}

static void copy_bytes(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        dst[i] = src[i];
}

static int equal_bytes(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (a[i] != b[i])
            return 0;
    return 1;
}

/* Arithmetic guards do not certify that an arbitrary non-NULL pointer is
 * mapped. As for other C buffer APIs, storage validity is a caller contract. */
static int valid_span(const void *p, size_t n)
{
    return p != NULL && n != 0 &&
           (uintptr_t)p <= UINTPTR_MAX - (n - 1);
}

static int overlap(const void *a, size_t a_bytes, const void *b, size_t b_bytes)
{
    uintptr_t aa = (uintptr_t)a, bb = (uintptr_t)b;
    if (aa <= bb)
        return bb - aa < a_bytes;
    return aa - bb < b_bytes;
}

static int target_valid(uint64_t first, uint64_t last, uint32_t sectors)
{
    return first != 0 && first <= UINT32_MAX && last >= first &&
           last - first == (uint64_t)sectors - 1;
}

static int fsinfo_valid(const uint8_t *p, uint32_t clusters)
{
    uint32_t free_count = rd32(p + 488), next = rd32(p + 492);
    return rd32(p) == 0x41615252u && rd32(p + 484) == 0x61417272u &&
           rd32(p + 508) == 0xaa550000u &&
           (free_count == UINT32_MAX || free_count <= clusters) &&
           (next == UINT32_MAX || (next >= 2 && next <= clusters + 1));
}

static int geometry_valid(const uint8_t *primary, const uint8_t *backup,
                          const uint8_t *fsinfo, const uint8_t *backup_fsinfo,
                          uint64_t source_bytes, uint32_t hidden,
                          native_geometry_t *geometry)
{
    uint32_t spc, reserved, fat_sectors, total, info, boot, root;
    uint64_t first_data, clusters, fat_bytes;
    unsigned i;
    if (source_bytes == 0 || source_bytes > SHZ_NATIVE_FAT32_MAX_SOURCE_BYTES ||
        source_bytes % SHZ_NATIVE_FAT32_SECTOR_BYTES != 0)
        return 0;
    if (!equal_bytes(primary, backup, SHZ_NATIVE_FAT32_SECTOR_BYTES) ||
        primary[510] != 0x55 || primary[511] != 0xaa ||
        rd16(primary + 11) != SHZ_NATIVE_FAT32_SECTOR_BYTES ||
        primary[16] != 2 || primary[21] != 0xf8 ||
        rd16(primary + 17) != 0 || rd16(primary + 19) != 0 ||
        rd16(primary + 22) != 0 || rd32(primary + 28) != hidden ||
        rd16(primary + 40) != 0 || rd16(primary + 42) != 0)
        return 0;
    for (i = 52; i < 64; ++i)
        if (primary[i] != 0)
            return 0;
    spc = primary[13];
    reserved = rd16(primary + 14);
    fat_sectors = rd32(primary + 36);
    total = rd32(primary + 32);
    info = rd16(primary + 48);
    boot = rd16(primary + 50);
    root = rd32(primary + 44);
    if (spc == 0 || spc > 128 || (spc & (spc - 1)) != 0 || reserved <= 1 ||
        fat_sectors == 0 || total == 0 ||
        (uint64_t)total != source_bytes / SHZ_NATIVE_FAT32_SECTOR_BYTES ||
        info == 0 || boot == 0 || info == boot || info >= reserved ||
        boot >= reserved || boot + info >= reserved)
        return 0;
    fat_bytes = (uint64_t)fat_sectors * SHZ_NATIVE_FAT32_SECTOR_BYTES;
    first_data = (uint64_t)reserved + 2ull * fat_sectors;
    if (fat_bytes > 32ull * 1024ull * 1024ull || first_data >= total)
        return 0;
    clusters = ((uint64_t)total - first_data) / spc;
    if (clusters < 65525 || clusters + 1 >= 0x0ffffff0ull ||
        (clusters + 2) * 4 > fat_bytes || root < 2 ||
        (uint64_t)root > clusters + 1 ||
        !fsinfo_valid(fsinfo, (uint32_t)clusters) ||
        !fsinfo_valid(backup_fsinfo, (uint32_t)clusters))
        return 0;
    geometry->backup_boot_offset = (uint64_t)boot * SHZ_NATIVE_FAT32_SECTOR_BYTES;
    geometry->fsinfo_offset = (uint64_t)info * SHZ_NATIVE_FAT32_SECTOR_BYTES;
    geometry->backup_fsinfo_offset =
        (uint64_t)(boot + info) * SHZ_NATIVE_FAT32_SECTOR_BYTES;
    geometry->total_sectors = total;
    geometry->cluster_count = (uint32_t)clusters;
    return 1;
}

int shz_native_fat32_relocate_stage(
    const uint8_t *primary, size_t primary_bytes,
    const uint8_t *backup, size_t backup_bytes,
    const uint8_t *fsinfo, size_t fsinfo_bytes,
    const uint8_t *backup_fsinfo, size_t backup_fsinfo_bytes,
    uint64_t source_first_lba, uint64_t source_bytes,
    uint64_t target_first_lba, uint64_t target_last_lba,
    shz_native_fat32_relocate_t *out, size_t out_bytes)
{
    shz_native_fat32_relocate_t staged;
    native_geometry_t geometry;
    size_t i;
    if (primary_bytes != SHZ_NATIVE_FAT32_SECTOR_BYTES ||
        backup_bytes != SHZ_NATIVE_FAT32_SECTOR_BYTES ||
        fsinfo_bytes != SHZ_NATIVE_FAT32_SECTOR_BYTES ||
        backup_fsinfo_bytes != SHZ_NATIVE_FAT32_SECTOR_BYTES ||
        out_bytes != sizeof(*out) || !valid_span(primary, primary_bytes) ||
        !valid_span(backup, backup_bytes) || !valid_span(fsinfo, fsinfo_bytes) ||
        !valid_span(backup_fsinfo, backup_fsinfo_bytes) ||
        !valid_span(out, out_bytes) ||
        overlap(out, out_bytes, primary, primary_bytes) ||
        overlap(out, out_bytes, backup, backup_bytes) ||
        overlap(out, out_bytes, fsinfo, fsinfo_bytes) ||
        overlap(out, out_bytes, backup_fsinfo, backup_fsinfo_bytes))
        return SHZ_NATIVE_FAT32_ARGUMENT;
    if (source_first_lba != 0 ||
        !geometry_valid(primary, backup, fsinfo, backup_fsinfo,
                        source_bytes, 0, &geometry))
        return SHZ_NATIVE_FAT32_GEOMETRY;
    if (!target_valid(target_first_lba, target_last_lba, geometry.total_sectors))
        return SHZ_NATIVE_FAT32_TARGET;
    /* Publish only after every check. Initialize padding as well as members. */
    for (i = 0; i < sizeof(staged); ++i)
        ((uint8_t *)&staged)[i] = 0;
    staged.source_bytes = source_bytes;
    staged.target_first_lba = target_first_lba;
    staged.target_last_lba = target_last_lba;
    staged.backup_boot_offset = geometry.backup_boot_offset;
    staged.fsinfo_offset = geometry.fsinfo_offset;
    staged.backup_fsinfo_offset = geometry.backup_fsinfo_offset;
    staged.total_sectors = geometry.total_sectors;
    staged.cluster_count = geometry.cluster_count;
    copy_bytes(staged.primary, primary, primary_bytes);
    copy_bytes(staged.backup, backup, backup_bytes);
    copy_bytes(staged.fsinfo, fsinfo, fsinfo_bytes);
    copy_bytes(staged.backup_fsinfo, backup_fsinfo, backup_fsinfo_bytes);
    wr32(staged.primary + 28, (uint32_t)target_first_lba);
    wr32(staged.backup + 28, (uint32_t)target_first_lba);
    copy_bytes((uint8_t *)out, (const uint8_t *)&staged, sizeof(staged));
    return SHZ_NATIVE_FAT32_OK;
}

int shz_native_fat32_relocate_overlay(
    const shz_native_fat32_relocate_t *plan, size_t plan_bytes,
    uint64_t window_offset, uint8_t *window, size_t window_bytes)
{
    native_geometry_t geometry;
    uint64_t patch_offset[2];
    unsigned patch, byte;
    if (plan_bytes != sizeof(*plan) || !valid_span(plan, plan_bytes) ||
        (window_bytes != 0 &&
         (!valid_span(window, window_bytes) ||
          overlap(plan, plan_bytes, window, window_bytes))))
        return SHZ_NATIVE_FAT32_ARGUMENT;
    if (plan->target_first_lba == 0 || plan->target_first_lba > UINT32_MAX ||
        !geometry_valid(plan->primary, plan->backup, plan->fsinfo,
                        plan->backup_fsinfo, plan->source_bytes,
                        (uint32_t)plan->target_first_lba, &geometry) ||
        !target_valid(plan->target_first_lba, plan->target_last_lba,
                      geometry.total_sectors) ||
        plan->backup_boot_offset != geometry.backup_boot_offset ||
        plan->fsinfo_offset != geometry.fsinfo_offset ||
        plan->backup_fsinfo_offset != geometry.backup_fsinfo_offset ||
        plan->total_sectors != geometry.total_sectors ||
        plan->cluster_count != geometry.cluster_count)
        return SHZ_NATIVE_FAT32_PLAN;
    if (window_offset > plan->source_bytes ||
        (uint64_t)window_bytes > plan->source_bytes - window_offset)
        return SHZ_NATIVE_FAT32_ARGUMENT;
    patch_offset[0] = 28;
    patch_offset[1] = geometry.backup_boot_offset + 28;
    /* All validation precedes this loop; neither patch depends on window data. */
    for (patch = 0; patch < 2; ++patch)
        for (byte = 0; byte < 4; ++byte) {
            uint64_t pos = patch_offset[patch] + byte;
            if (pos >= window_offset && pos - window_offset < window_bytes)
                window[(size_t)(pos - window_offset)] =
                    (uint8_t)(plan->target_first_lba >> (byte * 8));
        }
    return SHZ_NATIVE_FAT32_OK;
}
