/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NATIVE_FAT32_INSTALL_BRIDGE_H
#define SHZ_NATIVE_FAT32_INSTALL_BRIDGE_H

/* Adoption requires FADA's native_install.h and its plat.h. The callback is
 * intentionally typed against that interface rather than a duplicate ABI. */
#include "native_install.h"

/* Pure prepare_relocation callback. ctx is ignored. The four 512-byte inputs
 * must be valid snapshots held by the caller; output is two writable overlays,
 * disjoint from every input. Integer span checks do not establish mappedness.
 * Failure preserves all input/output bytes; success publishes deterministic
 * hidden-sector patches after the existing FAT32 stage validates the subset.
 * No source custody, target authority, I/O, allocation or hashing is provided.
 */
int shz_native_fat32_install_prepare_relocation(
    void *ctx, const uint8_t primary[512], const uint8_t backup[512],
    const uint8_t fsinfo[512], const uint8_t backup_fsinfo[512],
    uint64_t source_bytes, uint64_t target_first, uint64_t target_last,
    native_setup_overlay_v1_t output[2]);

#endif
