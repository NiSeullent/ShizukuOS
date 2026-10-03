/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NATIVE_RUNTIME_H
#define SHZ_NATIVE_RUNTIME_H
#include "native_provider.h"
#include "native_syscall.h"
typedef struct {
 uint64_t token;shz_native_source_v1 identity;
 unsigned live,admitted,role,preview;char path[SHZ_NATIVE_SYS_PATH];
} shz_native_runtime_source;
typedef struct { uint64_t token;unsigned live;native_setup_target_v1_t target;shz_native_target_v1 wire; } shz_native_runtime_claim;
typedef struct {
 shz_native_provider_t provider;
 plat_t original;
 shz_native_runtime_source source[2];
 shz_native_runtime_claim claim;
 uint64_t max_source_bytes;
 unsigned opened,initialized;
} shz_native_runtime;
/* Fresh zero storage. Returns -2 when real kernel independent admission is
 * absent. No source/target operation occurs on refusal, and output stays zero.
 * SHA uses the existing actual accounts SHA256 core, not void/error-losing
 * legacy callbacks. Target IO never calls base raw block callbacks. */
int shz_native_runtime_init(shz_native_runtime *,const plat_t *);
/* GUI preview retains the SAME sealed process-owned sources for the real run.
 * Release pins are read from compiled kernel records, never caller JSON/INI. */
int shz_native_runtime_preview(shz_native_runtime *,const char *,const char *,uint8_t manifest_sha256[32]);
int shz_native_runtime_preview_close(shz_native_runtime *);
#endif
