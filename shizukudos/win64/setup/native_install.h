/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NATIVE_INSTALL_H
#define SHZ_NATIVE_INSTALL_H

#include "plat.h"

#define NATIVE_SETUP_VERSION 1u
#define NATIVE_SETUP_PATH_MAX 259u
#define NATIVE_SETUP_JSON_MAX (4u * 1024u * 1024u)
#define NATIVE_SETUP_IMAGE_MAX (4ull * 1024ull * 1024ull * 1024ull)

typedef struct native_setup_target_v1 {
    unsigned index;
    plat_disk_t disk;
    uint8_t whole_id[16];
    uint64_t generation;
} native_setup_target_v1_t;

/* The pure adapter can stage only these two four-byte, volume-relative
 * overlays. Original bytes must match actual held primary/backup VBRs.
 * Core independently derives both offsets and freezes all output bytes. */
typedef struct native_setup_overlay_v1 {
    uint64_t offset;
    uint8_t original[4], replacement[4];
} native_setup_overlay_v1_t;

typedef struct native_setup_request_v1 {
    uint32_t version, bytes;
    const char *manifest_path, *sim_path;
    uint8_t admitted_manifest_sha256[32];
    native_setup_target_v1_t reviewed_target;
    const char *confirmation;             /* exact "ERASE", reviewed tuple above */
} native_setup_request_v1_t;

/* Trusted runtime provider, never JSON/INI authority. Every status callback returns
 * zero only on actual completion. All methods are mandatory; NULL ops refuse
 * before opening input or issuing any target I/O.
 *
 * admit_source binds the independently admitted review pin and retains actual
 * input identity/read custody. check_source rechecks handle, named namespace
 * and custody; close_source always consumes the handle, reporting every close
 * or custody-finalization failure. The provider must not certify arbitrary
 * caller hashes as previous genuine-source/producer admission.
 *
 * review/claim/check_target independently prove exact current whole-device
 * identity/generation, whole eligibility, source backing exclusions and actual
 * boot/current-system whole exclusions. claim_target acquires exclusive write
 * authority; check_target retains it through each target I/O. Unknown backing
 * identities/exclusions refuse. release_target always consumes its claim and
 * reports finalization failures; provider retains unresolved underlying I/O.
 * Neither a stable array index nor a matching name/serial replaces this proof.
 * Matched native plat_t disk callbacks share the retained claim and atomically
 * check authority/generation/exclusions with each actual backend I/O. A separate
 * precheck followed by an unrelated legacy raw syscall is insufficient.
 *
 * The pure relocation adapter consumes four actual source snapshots and exact
 * target interval. Its future implementation wraps independently reviewed
 * c957 stage/overlay; it is deliberately absent in the current guest provider.
 * FSInfo pair need not be equal. No hardcoded backup sector is permitted. */
typedef struct native_setup_ops_v1 {
    uint32_t version, bytes;
    void *ctx;
    int (*admit_source)(void *, void *, const char *, uint64_t, const uint8_t[32]);
    int (*check_source)(void *, void *);
    int (*close_source)(void *, void *);
    void *(*sha_begin)(void *);
    int (*sha_update)(void *, void *, const void *, uint32_t);
    int (*sha_end)(void *, void *, uint8_t[32]); /* consumes, including on error */
    void (*sha_abort)(void *, void *);          /* consumes after other failure */
    int (*review_target)(void *, unsigned, void *const[2], native_setup_target_v1_t *);
    int (*claim_target)(void *, const native_setup_target_v1_t *, void *const[2], void **);
    int (*check_target)(void *, void *, const native_setup_target_v1_t *);
    int (*release_target)(void *, void *);
    int (*prepare_relocation)(void *, const uint8_t[512], const uint8_t[512],
                              const uint8_t[512], const uint8_t[512],
                              uint64_t, uint64_t, uint64_t,
                              native_setup_overlay_v1_t[2]);
} native_setup_ops_v1_t;

typedef struct native_setup_result_v1 {
    int ok;
    int target_write_attempted, target_readback_verified, GPT_readback_verified;
    uint64_t source_image_bytes, target_first_lba, target_last_lba;
    uint8_t manifest_sha256[32], sim_sha256[32], original_sha256[32], relocated_sha256[32];
    char reason[160];
    /* Deliberately false: storage copying cannot prove any of these. */
    int VM_executed, Windows98_boot_verified, MSDOS_replacement_under_Windows98;
    int native_apps_verified, coldboot_persistence_verified, SMP_acceptance, ISO_built;
} native_setup_result_v1_t;

/* Actual installer entry, implemented in native_install.c. Legacy plat/setup_run ABI
 * is unchanged. Success means target bytes/GPT read back, never native boot. */
void setup_run_native(const plat_t *, const native_setup_ops_v1_t *,
                      const native_setup_request_v1_t *, native_setup_result_v1_t *);
void native_install_run(const plat_t *, const native_setup_ops_v1_t *,
                        const native_setup_request_v1_t *, native_setup_result_v1_t *);

#endif
