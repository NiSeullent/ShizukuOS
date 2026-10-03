/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SETUP_NATIVE_ABI_H
#define SHZ_SETUP_NATIVE_ABI_H
#include <stdint.h>
#include <stddef.h>
#define SHZ_NATIVE_SYS_VERSION 1u
#define SHZ_NATIVE_SYS_PATH 260u
#define SHZ_NATIVE_SYS_IO_MAX 65536u
#define SHZ_NATIVE_SYS_SOURCE_MAX (256ull<<20)
enum { SHZ_NATIVE_CAPS=0, SHZ_NATIVE_OPEN=1, SHZ_NATIVE_INFO=2, SHZ_NATIVE_READ=3,
 SHZ_NATIVE_CLOSE=4, SHZ_NATIVE_REVIEW=5, SHZ_NATIVE_CLAIM=6, SHZ_NATIVE_CHECK=7,
 SHZ_NATIVE_TARGET_READ=8, SHZ_NATIVE_TARGET_WRITE=9, SHZ_NATIVE_FLUSH=10, SHZ_NATIVE_RELEASE=11 };
/* Versioned wire ABI: addresses are user VA only, handles are opaque integers.
 * No process/device pointers or caller approval/role/producer flags cross it. */
typedef struct { uint8_t whole_id[16]; uint64_t generation,sectors; uint32_t sector_size,flags; } shz_native_target_v1;
typedef struct { uint8_t id[16]; uint64_t generation,bytes; uint8_t sha256[32]; } shz_native_source_v1;
typedef struct {
 uint32_t version,bytes,operation,reserved;
 uint64_t handle,other_handle,offset,buffer;
 uint32_t length,index;
 shz_native_target_v1 target;
 shz_native_source_v1 source;
 uint64_t max_source_bytes;
 uint32_t max_io_bytes,producer_admission_available;
 char path[SHZ_NATIVE_SYS_PATH];
 uint32_t tail_reserved;
} shz_native_call_v1;
_Static_assert(sizeof(shz_native_target_v1)==40,"native target wire layout");
_Static_assert(sizeof(shz_native_source_v1)==64,"native source wire layout");
_Static_assert(offsetof(shz_native_call_v1,target)==56,"native target offset");
_Static_assert(offsetof(shz_native_call_v1,path)==176,"native path offset");
_Static_assert(sizeof(shz_native_call_v1)==440,"native syscall wire layout");
#endif
