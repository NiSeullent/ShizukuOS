/* SPDX-License-Identifier: LGPL-3.0-only */
/* Private, opt-in SeaBIOS disk-bounce observations. No I/O or clock reads. */
#ifndef SHZ_STORAGE_STATISTICS_H
#define SHZ_STORAGE_STATISTICS_H

#include "shzstorage_profile.h"

/* All integers are little-endian. These offsets are part of ABI 1.0. */
struct shz_storage_statistics {
    u8 magic[8];                 /* 0: SHZSTAT1 */
    u16 major, minor;            /* 8, 10 */
    u32 bytes;                   /* 12: 224 */
    u32 sequence;                /* 16: odd while one request is active */
    u32 profile_capacity;        /* 20: requested allocation profile */
    u32 actual_capacity;         /* 24: last observed allocated capacity */
    u32 flags;                   /* 28: bit0 saturation, bit1 reentry */
    u32 requests, read_requests, write_requests; /* 32, 36, 40 */
    u32 blocksize_512, blocksize_2048, blocksize_other; /* 44, 48, 52 */
    u64 requested_blocks, requested_bytes; /* 56, 64 */
    u32 chunks, completed_chunks; /* 72, 76: dispatch attempts, full chunks */
    u64 completed_blocks, completed_bytes; /* 80, 88: certified completion */
    u32 partial_chunks, error_chunks; /* 96, 100 */
    u32 error_requests, partial_requests; /* 104, 108 */
    u32 rejected_requests, oversized_completions; /* 112, 116 */
    u32 zero_count_requests, max_requested_blocks; /* 120, 124 */
    u32 last_requested_blocks, last_blocksize, last_command; /* 128..136 */
    u32 last_completed_blocks, last_return_code, last_chunks; /* 140..148 */
    u64 last_lba;                /* 152: original, never changed by stats */
    u32 count_histogram[8];      /* 160: 0,1,2..4,5..8,9..16,17..32,33..64,65+ */
    u64 requested_read_bytes, requested_write_bytes; /* 192, 200 */
    u64 completed_read_bytes, completed_write_bytes; /* 208, 216 */
};

typedef char shz_stats_size_must_be_224[
    sizeof(struct shz_storage_statistics) == 224 ? 1 : -1];
struct shz_storage_statistics shz_storage_stats VARFSEG __aligned(16) = {
    .magic = {'S','H','Z','S','T','A','T','1'}, .major = 1,
    .bytes = sizeof(struct shz_storage_statistics),
    .profile_capacity = SHZ_STORAGE_PROFILE_CAPACITY,
};

/* Match GET_GLOBAL's segment/relocation address calculation. The only runtime
 * writer is the 16-bit caller; the 32-bit helper AP never updates this struct. */
#define SHZ_STAT_SET(field, value) do { \
    typeof(shz_storage_stats.field) _shz_value = (value); \
    SET_VAR(GLOBAL_SEGREG, *(typeof(&(shz_storage_stats.field))) \
        ((void *)&shz_storage_stats.field + get_global_offset()), _shz_value); \
} while (0)
#define SHZ_STAT_BARRIER() asm volatile("" ::: "memory")
#define SHZ_STAT_FLAGS(bits) \
    SHZ_STAT_SET(flags, GET_GLOBAL(shz_storage_stats.flags) | (bits))
#define SHZ_STAT_ADD32(field, amount) do { \
    u32 _old = GET_GLOBAL(shz_storage_stats.field); \
    u32 _add = (amount), _max = ~(u32)0; \
    if (_add > _max - _old) { \
        SHZ_STAT_SET(field, _max); SHZ_STAT_FLAGS(1); \
    } else { SHZ_STAT_SET(field, _old + _add); } \
} while (0)
#define SHZ_STAT_ADD64(field, amount) do { \
    u64 _old = GET_GLOBAL(shz_storage_stats.field); \
    u64 _add = (amount), _max = ~(u64)0; \
    if (_add > _max - _old) { \
        SHZ_STAT_SET(field, _max); SHZ_STAT_FLAGS(1); \
    } else { SHZ_STAT_SET(field, _old + _add); } \
} while (0)

static int
shz_stats_begin(struct disk_op_s *op, u16 blocksize, u32 capacity)
{
    if (op->command != CMD_READ && op->command != CMD_WRITE)
        return 0;
    u32 sequence = GET_GLOBAL(shz_storage_stats.sequence);
    if (sequence & 1) {
        /* Do not change disk behavior for unexpected nested requests. Mark the
         * observations ineligible for a matched comparison instead. */
        SHZ_STAT_FLAGS(2);
        return 0;
    }
    SHZ_STAT_SET(sequence, sequence + 1);
    SHZ_STAT_BARRIER();
    SHZ_STAT_SET(actual_capacity, capacity);
    SHZ_STAT_SET(last_requested_blocks, op->count);
    SHZ_STAT_SET(last_blocksize, blocksize);
    SHZ_STAT_SET(last_command, op->command);
    SHZ_STAT_SET(last_completed_blocks, 0);
    SHZ_STAT_SET(last_return_code, 0);
    SHZ_STAT_SET(last_chunks, 0);
    SHZ_STAT_SET(last_lba, op->lba);
    SHZ_STAT_ADD32(requests, 1);
    u64 bytes = (u64)op->count * blocksize;
    if (op->command == CMD_WRITE) {
        SHZ_STAT_ADD32(write_requests, 1);
        SHZ_STAT_ADD64(requested_write_bytes, bytes);
    } else {
        SHZ_STAT_ADD32(read_requests, 1);
        SHZ_STAT_ADD64(requested_read_bytes, bytes);
    }
    if (blocksize == 512)
        SHZ_STAT_ADD32(blocksize_512, 1);
    else if (blocksize == 2048)
        SHZ_STAT_ADD32(blocksize_2048, 1);
    else
        SHZ_STAT_ADD32(blocksize_other, 1);
    SHZ_STAT_ADD64(requested_blocks, op->count);
    SHZ_STAT_ADD64(requested_bytes, bytes);
    if (!op->count)
        SHZ_STAT_ADD32(zero_count_requests, 1);
    if (op->count > GET_GLOBAL(shz_storage_stats.max_requested_blocks))
        SHZ_STAT_SET(max_requested_blocks, op->count);
    u32 bucket = !op->count ? 0 : op->count == 1 ? 1 :
                 op->count <= 4 ? 2 : op->count <= 8 ? 3 :
                 op->count <= 16 ? 4 : op->count <= 32 ? 5 :
                 op->count <= 64 ? 6 : 7;
    SHZ_STAT_ADD32(count_histogram[bucket], 1);
    return 1;
}

static void
shz_stats_dispatch(int active)
{
    if (!active)
        return;
    SHZ_STAT_ADD32(chunks, 1);
    SHZ_STAT_ADD32(last_chunks, 1);
}

static void
shz_stats_chunk(int active, u16 requested, u16 completed, u16 blocksize,
                int command, int rc, int oversized)
{
    if (!active)
        return;
    if (completed == requested)
        SHZ_STAT_ADD32(completed_chunks, 1);
    else if (completed)
        SHZ_STAT_ADD32(partial_chunks, 1);
    if (rc)
        SHZ_STAT_ADD32(error_chunks, 1);
    if (oversized)
        SHZ_STAT_ADD32(oversized_completions, 1);
    SHZ_STAT_ADD64(completed_blocks, completed);
    u64 bytes = (u64)completed * blocksize;
    SHZ_STAT_ADD64(completed_bytes, bytes);
    if (command == CMD_WRITE)
        SHZ_STAT_ADD64(completed_write_bytes, bytes);
    else
        SHZ_STAT_ADD64(completed_read_bytes, bytes);
}

static void
shz_stats_finish(int active, u16 completed, int rc, int rejected)
{
    if (!active)
        return;
    SHZ_STAT_SET(last_completed_blocks, completed);
    SHZ_STAT_SET(last_return_code, rc);
    if (rc)
        SHZ_STAT_ADD32(error_requests, 1);
    if (completed && completed < GET_GLOBAL(shz_storage_stats.last_requested_blocks))
        SHZ_STAT_ADD32(partial_requests, 1);
    if (rejected)
        SHZ_STAT_ADD32(rejected_requests, 1);
    SHZ_STAT_BARRIER();
    /* Sequence wraps modulo2^32; numeric counters saturate. A reader must bound
     * its capture below2^31 completed requests so a full-cycle ABA is excluded. */
    SHZ_STAT_SET(sequence, GET_GLOBAL(shz_storage_stats.sequence) + 1);
}
#endif
