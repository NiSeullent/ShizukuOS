/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SETUP_NATIVE_RELEASE_H
#define SHZ_SETUP_NATIVE_RELEASE_H
#include "archive_source.h"
/* Kernel build owner only. Runtime users cannot install admission records.
 * Bytes/SHA from sealed custody do not establish a trusted DOS/Windows producer. */
/* Fixed build-only format: no process can submit this structure. */
typedef struct {
 uint32_t magic,version,bytes,reserved;
 uint64_t manifest_bytes,sim_bytes;
 uint8_t manifest_sha256[32],sim_sha256[32],evidence_sha256[32];
} setup_native_release_record_v1;
_Static_assert(sizeof(setup_native_release_record_v1)==128,"release record ABI");
/* Optional role-2 original-userland (SZOU) source pin. Emitted by the same build-only generator
 * (install/native_release_admission.py) into the same private TU as shz_installer_release_v1, and only
 * when the held original-userland stage passed independent SZOU readback inside the v1 admission custody.
 * bytes == sizeof (96): self-describing size like v1 (128), never a truncated prefix.
 * evidence_sha256 must equal the v1 evidence, whose digest covers the original-userland manifest+stage pins.
 * shz_installer_phase_ref == 0 (generator default) => role 2 unavailable; roles 0/1 unchanged. */
#define SHZ_NATIVE_PHASE_MAGIC 0x50554f53u   /* 'SOUP' */
typedef struct {
 uint32_t magic,version,bytes,reserved;
 uint64_t szou_bytes,reserved2;
 uint8_t szou_sha256[32];
 uint8_t evidence_sha256[32];
} setup_native_phase_record_v1;
_Static_assert(sizeof(setup_native_phase_record_v1)==96,"phase record ABI");
#define SHZ_NATIVE_ROLE_MANIFEST 0u
#define SHZ_NATIVE_ROLE_SIM 1u
#define SHZ_NATIVE_ROLE_ORIGINAL_USERLAND 2u
#define SHZ_NATIVE_ROLE_MAX SHZ_NATIVE_ROLE_ORIGINAL_USERLAND
int setup_native_release_available(void);
/* 1 iff the v1 record is valid AND a valid role-2 phase record bound to it was compiled in. */
int setup_native_phase_available(void);
/* 0 absent; 1 valid independently compiled record; 2 configured but invalid. */
unsigned setup_native_release_state(void);
/* Read-only compiled role pin; no runtime registration or approval. */
int setup_native_release_info(unsigned role,uint64_t *bytes,uint8_t sha256[32]);
/* role 0 manifest, 1 SIM, 2 original-userland SZOU stage (only with a compiled phase record). */
int setup_native_release_source(const archive_source_info_t *,unsigned role);
int setup_native_release_pair(const archive_source_info_t manifest_and_sim[2]);
#endif
