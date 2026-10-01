/* SPDX-License-Identifier: GPL-2.0-only -- original versioned PMA service contract.
 * Payload family over the unchanged Shizuku IPC 1.1 64-byte outer header.
 * Fixed-width, little-endian, no pointers and identical i486/x86-64 layouts.
 */
#ifndef SHZ_VMM_PMA_H
#define SHZ_VMM_PMA_H
#include "shz_abi.h"

#define SHZ_PMA_MAGIC 0x31414d50u /* "PMA1" */
#define SHZ_PMA_ABI_MAJOR 1u
#define SHZ_PMA_ABI_MINOR 0u
#define SHZ_PMA_CLOCK_UNIT_NS 1u
#define SHZ_PMA_EVENT_MANUAL_RESET 1u
#define SHZ_PMA_EVENT_SIGNALED 2u
#define SHZ_PMA_FEATURE_EVENTS UINT64_C(1)
#define SHZ_PMA_FEATURE_DEFERRED_WAIT UINT64_C(2)
#define SHZ_PMA_FEATURE_DEADLINES UINT64_C(4)
#define SHZ_PMA_FEATURE_CANCEL UINT64_C(8)
#define SHZ_PMA_FEATURE_LIFECYCLE UINT64_C(16)
#define SHZ_PMA_FEATURES UINT64_C(31)

enum shz_pma_opcode {
    SHZ_OP_PMA_QUERY = 0x300,
    SHZ_OP_PMA_EVENT_CREATE = 0x301,
    SHZ_OP_PMA_EVENT_WAIT = 0x302,
    SHZ_OP_PMA_EVENT_SIGNAL = 0x303,
    SHZ_OP_PMA_EVENT_RESET = 0x304,
    SHZ_OP_PMA_EVENT_CLOSE = 0x305,
    SHZ_OP_PMA_CANCEL = 0x306,
    SHZ_OP_PMA_THREAD_EXIT = 0x307,
    SHZ_OP_PMA_PROCESS_EXIT = 0x308
};

static inline int shz_pma_is_opcode(uint32_t opcode)
{
    return opcode >= 0x300u && opcode <= 0x3ffu;
}

typedef struct {
    uint32_t magic;
    uint16_t abi_major, abi_minor;
    uint32_t size, flags;
    uint64_t required_features; /* Unknown required features reject without side effects. */
    uint32_t domain, pid, tid, owner_generation;
    uint32_t thread_generation, object;
    uint64_t deadline_ns;       /* Absolute monotonic ns; 0=poll, UINT64_MAX=infinite. */
    uint64_t target_sequence;   /* CANCEL: one WAIT of this same process/thread lifetime. */
} shz_pma_request_t;

typedef struct {
    uint32_t magic;
    uint16_t abi_major, abi_minor;
    uint32_t size, flags;
    uint64_t features;
    uint32_t domain, pid, tid, owner_generation;
    uint32_t thread_generation, object;
    uint64_t sequence;
    int32_t status;
    uint32_t reserved;
} shz_pma_completion_t;

typedef struct {
    uint32_t magic;
    uint16_t abi_major, abi_minor;
    uint32_t size, flags;
    uint64_t features;
    uint32_t max_owners, max_threads, max_objects, max_waits;
    uint64_t now_ns; /* Service monotonic clock snapshot for finite absolute deadlines. */
    uint32_t generation, self_domain, peer_domain, max_completions;
} shz_pma_info_t;

_Static_assert(sizeof(shz_pma_request_t) == 64, "PMA request wire size");
_Static_assert(sizeof(shz_pma_completion_t) == 64, "PMA completion wire size");
_Static_assert(sizeof(shz_pma_info_t) == 64, "PMA info wire size");
_Static_assert(__builtin_offsetof(shz_pma_request_t, required_features) == 16, "PMA feature offset");
_Static_assert(__builtin_offsetof(shz_pma_request_t, deadline_ns) == 48, "PMA deadline offset");
_Static_assert(__builtin_offsetof(shz_pma_completion_t, sequence) == 48, "PMA sequence offset");
_Static_assert(__builtin_offsetof(shz_pma_info_t, now_ns) == 40, "PMA clock snapshot offset");
#endif
