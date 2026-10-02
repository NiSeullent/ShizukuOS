/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel-only storage admission. No syscall, installer provider or physical
 * boot/source provenance is installed by this first phase. Shipping claims
 * therefore refuse; legacy filesystem IO remains a separate permission path.
 */
#ifndef K64_STORAGE_AUTHORITY_H
#define K64_STORAGE_AUTHORITY_H
#include "blk.h"
#include "fs.h"

typedef struct storage_claim storage_claim_t;
typedef struct storage_source_set storage_source_set_t;
typedef struct {
    uint64_t opaque;
    blk_dev_t *whole;
    uint64_t lba;
} storage_io_lease_t;
typedef struct { uint64_t opaque; } storage_mount_token_t;
typedef struct {
    blk_dev_t *whole;
    uint64_t registry_identity, generation;
} storage_identity_t;
enum {
    STORAGE_READ, STORAGE_WRITE, STORAGE_FLUSH, STORAGE_DISCARD,
    STORAGE_CONTROL
};
enum { STORAGE_ACCOUNT_CHAIN, STORAGE_ACCOUNT_REQUEST };

/* Called only by the actual block registry; publication shares the admission
 * ticket. Device/parent identity and geometry must remain stable thereafter.
 */
int storage_device_register(blk_dev_t *dev, blk_dev_t **head,
                            blk_dev_t **tail, unsigned *count);
int storage_device_identity(blk_dev_t *dev, storage_identity_t *out);
int storage_user_write_busy(blk_dev_t *dev);
int storage_io_begin(blk_dev_t *dev, unsigned operation, uint64_t lba,
                     unsigned count, unsigned control,
                     storage_claim_t *claim, const void *actual_owner,
                     storage_io_lease_t *out);
int storage_io_end(storage_io_lease_t *lease, int status, unsigned accounting);
/* Submission acceptance is uncertain: retain admission until the real driver
 * terminal callback, and permanently refuse new IO on that generation.
 */
void storage_io_uncertain(const storage_io_lease_t *lease);

int storage_mount_reserve(fsnode_t *root, fsvol_t *volume, blk_dev_t *dev,
                          storage_mount_token_t *out);
int storage_mount_commit(storage_mount_token_t *token);
int storage_mount_abort(storage_mount_token_t *token);
int storage_backing_snapshot(const fsnode_t *held_node, storage_identity_t *out);

int storage_claim_acquire(const void *referenced_owner, blk_dev_t *whole,
                          const storage_source_set_t *referenced_sources,
                          storage_claim_t **out);
int storage_claim_read(storage_claim_t *claim, const void *actual_owner,
                       uint64_t lba, unsigned count, void *buffer);
int storage_claim_write(storage_claim_t *claim, const void *actual_owner,
                        uint64_t lba, unsigned count, const void *buffer);
int storage_claim_flush(storage_claim_t *claim, const void *actual_owner);
int storage_claim_release(storage_claim_t *claim, const void *actual_owner);
void storage_claim_revoke_owner(const void *referenced_owner);

#ifdef SHZ_STORAGE_AUTHORITY_HOST_TEST
/* Explicit host-only modeled provenance substitution; not built by kbuild,
 * not an installer provider and not evidence of a real physical identity.
 */
const storage_source_set_t *storage_test_provenance(const void *owner,
                         blk_dev_t *const *excluded, unsigned count);
#endif
#endif
