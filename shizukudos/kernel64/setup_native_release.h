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
int setup_native_release_available(void);
/* 0 absent; 1 valid independently compiled record; 2 configured but invalid. */
unsigned setup_native_release_state(void);
/* Read-only compiled role pin; no runtime registration or approval. */
int setup_native_release_info(unsigned role,uint64_t *bytes,uint8_t sha256[32]);
int setup_native_release_source(const archive_source_info_t *,unsigned manifest_or_sim);
int setup_native_release_pair(const archive_source_info_t manifest_and_sim[2]);
#endif
