/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef K64_BLK_AUTHORITY_H
#define K64_BLK_AUTHORITY_H
#include "blk.h"
/* Kernel-only capabilities. Never accept these structures, device pointers,
 * owner pointers or role facts from userspace/manifest/answer files. Registry
 * identity is for this boot; generation changes on control/error/release. */
typedef struct blk_authority_identity {
    uint8_t whole_id[16];
    uint64_t generation, sectors;
    uint32_t sector_size, flags;
} blk_authority_identity_t;
typedef struct blk_authority_source {
    blk_dev_t *whole;
    blk_authority_identity_t identity;
} blk_authority_source_t;
typedef struct blk_authority_claim blk_authority_claim_t;
/* Internal registry and shared backend serialization, all enter successes must
 * leave exactly once. Driver callbacks cannot recursively invoke blk_* here. */
int blk_authority_register(blk_dev_t *);
int blk_authority_enter(blk_dev_t *, int mutation);
int blk_authority_mark_mounted(blk_dev_t *);
void blk_authority_leave(blk_dev_t *, int result, int changed_epoch);
/* Kernel boot/mount owner must derive BOTH devices from actual loader/storage
 * observations. No production caller currently has that complete provenance;
 * roles stay unknown and review/claim refuse. No bool for approving/ignoring an
 * unknown role exists. Facts cannot be updated while any target is claimed. */
int blk_authority_bind_boot_roles(blk_dev_t *boot, blk_dev_t *current_system);
int blk_authority_pin_source(blk_dev_t *, blk_authority_source_t *);
int blk_authority_review(blk_dev_t *, const blk_authority_source_t[2], blk_authority_identity_t *);
int blk_authority_claim_target(void *kernel_owner, blk_dev_t *, const blk_authority_identity_t *,
                               const blk_authority_source_t[2], blk_authority_claim_t **);
int blk_authority_check(void *, blk_authority_claim_t *, const blk_authority_identity_t *);
int blk_authority_read(void *, blk_authority_claim_t *, const blk_authority_identity_t *,
                       uint64_t, unsigned, void *);
int blk_authority_write(void *, blk_authority_claim_t *, const blk_authority_identity_t *,
                        uint64_t, unsigned, const void *);
int blk_authority_flush(void *, blk_authority_claim_t *, const blk_authority_identity_t *);
/* Any uncertain driver error poisons its claim. Release then refuses and
 * retains exclusive custody until reset/reboot; no fake quiescence/force API. */
int blk_authority_release(void *, blk_authority_claim_t *, const blk_authority_identity_t *);
#endif
