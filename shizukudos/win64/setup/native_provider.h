/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NATIVE_PROVIDER_H
#define SHZ_NATIVE_PROVIDER_H
#include "native_install.h"

#define SHZ_NATIVE_PROVIDER_VERSION 1u
/* Trusted runtime backend, not a manifest or caller approval token.
 * Each target method must perform identity/generation/exclusions/exclusive-claim
 * validation atomically with the actual backend operation. In-flight failed I/O
 * remains owned by this backend until resolved; release consumes the client
 * handle but must retain unresolved physical authority. No legacy raw syscall
 * adapter satisfies this contract. Source admission must refer to independently
 * verified native producer lineage, not merely rehash a caller supplied pin.
 * All callbacks and their context must outlive the entire provider run. */
typedef struct shz_native_provider_backend_v1 {
    uint32_t version, bytes;
    native_setup_ops_v1_t authority;
    int (*target_info)(void *, void *, const native_setup_target_v1_t *, plat_disk_t *);
    int (*target_read)(void *, void *, const native_setup_target_v1_t *, uint64_t, uint32_t, void *);
    int (*target_write)(void *, void *, const native_setup_target_v1_t *, uint64_t, uint32_t, const void *);
    int (*target_flush)(void *, void *, const native_setup_target_v1_t *);
} shz_native_provider_backend_v1_t;

typedef struct shz_native_provider {
    plat_t platform, base;
    native_setup_ops_v1_t ops;
    shz_native_provider_backend_v1_t backend;
    void *source[3], *claim; /* roles 0,1 + 2 (SZOU) */
    unsigned admitted[2], opened, claim_attempted, started, initialized, io_failed;
    native_setup_target_v1_t target;
} shz_native_provider_t;

/* Pure helper adoption: unchanged output on any refusal; source snapshots and
 * output must be disjoint. The installer independently authenticates snapshots
 * and overlays. This function performs no admission, hashing or target I/O. */
int shz_native_provider_relocation(void *, const uint8_t[512], const uint8_t[512],
    const uint8_t[512], const uint8_t[512], uint64_t, uint64_t, uint64_t,
    native_setup_overlay_v1_t[2]);
/* Assemble only when ALL actual authority and atomic backend methods exist.
 * Zero fresh caller-owned output required, with no concurrent accesses. The
 * caller must keep this object stable; copied callbacks cannot grant authority.
 * Failure preserves output and invokes no supplied callback. */
int shz_native_provider_init(shz_native_provider_t *, const plat_t *,
                            const shz_native_provider_backend_v1_t *);
/* Single synchronous run. Retained backend obligations survive a failure;
 * neither source closure nor claim release is represented as disk rollback. */
void shz_native_provider_run(shz_native_provider_t *, const native_setup_request_v1_t *,
                             native_setup_result_v1_t *);
/* Same single-use provider, explicit SZOU phase or marker resume (sreq NULL). */
void shz_native_provider_run_original_userland(shz_native_provider_t *, const native_setup_szou_ops_v1_t *,
    const native_setup_request_v1_t *, const native_setup_szou_request_v1_t *,
    native_setup_result_v1_t *, native_setup_szou_result_v1_t *);
#endif
