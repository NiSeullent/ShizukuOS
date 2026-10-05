/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SETUP_TARGET_ABI_H
#define SHZ_SETUP_TARGET_ABI_H
#include <stdint.h>
#include <stddef.h>
#define SHZ_SETUP_TARGET_SYSCALL 0xb6u
#define SHZ_SETUP_TARGET_VERSION 1u
#define SHZ_SETUP_TARGET_PATH 260u
#define SHZ_SETUP_TARGET_IO_MAX 65536u
/* Public install engine authority. This is not private producer admission.
 * Only a kernel-prepared accepted-archive installer can use this service.
 * OPEN permits the actual accepted-archive manifest (role 0) and ESP.SIM
 * (role 1). VALIDATE_SOURCE validates those roles; caller approval is never
 * accepted. SYSTEM.ARC and executable origin are verified during prepare.
 * Sector offsets are LBAs; lengths for target I/O are bytes, 512-aligned.
 * CAPS.target_authority_available: 1 = prepared custody plus boot roles ready;
 * 0 = unavailable. Unknown values must refuse. Op 13 remains unsupported.
 * Handles are opaque and local to this service and exact process generation.
 * REVIEW performs zero writes. CLAIM atomically rechecks every exclusion. */
enum { SHZ_SETUP_TARGET_CAPS=0, SHZ_SETUP_TARGET_OPEN=1,
 SHZ_SETUP_TARGET_INFO=2, SHZ_SETUP_TARGET_READ=3, SHZ_SETUP_TARGET_CLOSE=4,
 SHZ_SETUP_TARGET_REVIEW=5, SHZ_SETUP_TARGET_CLAIM=6, SHZ_SETUP_TARGET_CHECK=7,
 SHZ_SETUP_TARGET_READ_SECTORS=8, SHZ_SETUP_TARGET_WRITE_SECTORS=9,
 SHZ_SETUP_TARGET_FLUSH=10, SHZ_SETUP_TARGET_RELEASE=11,
 SHZ_SETUP_TARGET_VALIDATE_SOURCE=12 };
typedef struct { uint8_t whole_id[16]; uint64_t generation,sectors;
 uint32_t sector_size,flags; } shz_setup_target_v1;
typedef struct { uint8_t id[16]; uint64_t generation,bytes;
 uint8_t sha256[32]; } shz_setup_target_source_v1;
typedef struct {
 uint32_t version,bytes,operation,reserved;
 uint64_t handle,other_handle,offset,buffer;
 uint32_t length,index;
 shz_setup_target_v1 target;
 shz_setup_target_source_v1 source;
 uint64_t max_source_bytes;
 uint32_t max_io_bytes,target_authority_available;
 char path[SHZ_SETUP_TARGET_PATH];
 uint32_t tail_reserved;
} shz_setup_target_call_v1;
_Static_assert(sizeof(shz_setup_target_v1)==40,"setup target layout");
_Static_assert(sizeof(shz_setup_target_source_v1)==64,"setup source layout");
_Static_assert(offsetof(shz_setup_target_call_v1,target)==56,"setup target offset");
_Static_assert(offsetof(shz_setup_target_call_v1,path)==176,"setup path offset");
_Static_assert(sizeof(shz_setup_target_call_v1)==440,"setup call layout");
#endif
