/* SPDX-License-Identifier: GPL-2.0-only */
#include "native_fat32_install_bridge.h"
#include "native_fat32_relocate.h"

static int bridge_span(const void *p, size_t bytes)
{
    return p != NULL && bytes != 0 &&
           (uintptr_t)p <= UINTPTR_MAX - (bytes - 1);
}

static int bridge_overlap(const void *a, size_t a_bytes,
                          const void *b, size_t b_bytes)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return x <= y ? y - x < a_bytes : x - y < b_bytes;
}

int shz_native_fat32_install_prepare_relocation(
    void *ctx, const uint8_t primary[512], const uint8_t backup[512],
    const uint8_t fsinfo[512], const uint8_t backup_fsinfo[512],
    uint64_t source_bytes, uint64_t target_first, uint64_t target_last,
    native_setup_overlay_v1_t output[2])
{
    const uint8_t *inputs[4] = { primary, backup, fsinfo, backup_fsinfo };
    shz_native_fat32_relocate_t plan;
    native_setup_overlay_v1_t staged[2];
    size_t i;
    unsigned patch, byte;
    int rc;
    (void)ctx;
    if (!bridge_span(output, sizeof staged))
        return SHZ_NATIVE_FAT32_ARGUMENT;
    /* Every integer extent/alias refusal precedes any caller-byte access. */
    for (patch = 0; patch < 4; ++patch)
        if (!bridge_span(inputs[patch], 512) ||
            bridge_overlap(output, sizeof staged, inputs[patch], 512))
            return SHZ_NATIVE_FAT32_ARGUMENT;
    rc = shz_native_fat32_relocate_stage(
        primary, 512, backup, 512, fsinfo, 512, backup_fsinfo, 512,
        0, source_bytes, target_first, target_last, &plan, sizeof plan);
    if (rc != SHZ_NATIVE_FAT32_OK)
        return rc;
    /* Initialize the complete representation, including any ABI padding. */
    for (i = 0; i < sizeof staged; ++i)
        ((uint8_t *)staged)[i] = 0;
    staged[0].offset = 28;
    staged[1].offset = plan.backup_boot_offset + 28;
    for (patch = 0; patch < 2; ++patch)
        for (byte = 0; byte < 4; ++byte) {
            staged[patch].original[byte] = inputs[patch][28 + byte];
            staged[patch].replacement[byte] =
                (patch ? plan.backup : plan.primary)[28 + byte];
        }
    /* Failure atomicity, not a concurrent/hardware-atomic publication claim. */
    for (i = 0; i < sizeof staged; ++i)
        ((uint8_t *)output)[i] = ((const uint8_t *)staged)[i];
    return SHZ_NATIVE_FAT32_OK;
}
