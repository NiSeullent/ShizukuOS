/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K64_ARCHIVE_SOURCE_H
#define SHZ_K64_ARCHIVE_SOURCE_H
#include "fs.h"
#include "../boot_profile/storage/provenance.h"
typedef struct archive_source archive_source_t;
typedef struct {
 uint8_t id[16];uint64_t generation,bytes;uint8_t sha256[32];
 shz_storage_locator_t physical_origin;
} archive_source_info_t;
/* Only the real entry/archive owner calls this, after fs_load_archive success.
 * It independently checks header/ranges and the versioned loader handoff.
 * No caller approval/hash substitutes for observed physical origin. */
int archive_source_bind_origin(const shz_bootinfo_t *,const uint8_t *,uint64_t);
int archive_source_origin(shz_storage_provenance_t *);
/* Resolves the actual C: namespace node and independently proves its exact
 * extent in the accepted loader archive, then snapshots into private PMM pages.
 * Kernel owner pointers/handles never cross a user ABI. SHA authenticates this
 * snapshot, NOT the DOS3 producer; that independent admission remains needed. */
/* Every operation carries the minted identity: stale reused slot pointers cannot
 * close/read a new source from the same process. */
int archive_source_open(void *kernel_owner,const char *path,archive_source_t **,archive_source_info_t *);
int archive_source_info(void *,archive_source_t *,const archive_source_info_t *,archive_source_info_t *);
int archive_source_read(void *,archive_source_t *,const archive_source_info_t *,uint64_t,void *,uint64_t);
int archive_source_close(void *,archive_source_t *,const archive_source_info_t *);
/* Block authority retains exact-generation snapshot custody across uncertain
 * target I/O and owner close; release only after its own safe target release. */
int archive_source_match(archive_source_t *,const uint8_t[16],uint64_t,uint64_t);
int archive_source_retain(void *,archive_source_t *,const uint8_t[16],uint64_t,uint64_t);
void archive_source_release(archive_source_t *,const uint8_t[16],uint64_t);
#endif
