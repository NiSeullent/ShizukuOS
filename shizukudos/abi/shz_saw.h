/* SPDX-License-Identifier: GPL-2.0-only
 * NtShzSaw(request, sizeof request, reply, sizeof reply), private syscall 0x105.
 * Mutations require exact PID and generation; NT termination is unchanged.
 */
#ifndef SHZ_SAW_H
#define SHZ_SAW_H
#include <stdint.h>
#define SHZ_SAW_VERSION 1u
#define SHZ_SAW_MAX_ROWS 64u
#define SHZ_SAW_SYSCALL 0x105u
#define SHZ_SAW_DESTRUCTIVE_ACK 0x53415721u
#define SHZ_SAW_MAX_WAIT_MS 2000u
enum { SHZ_SAW_QUERY=1, SHZ_SAW_SINGLE=2, SHZ_SAW_NUKE=3, SHZ_SAW_CHARBOMBA=4 };
enum { SHZ_SAW_NORMAL=0, SHZ_SAW_ZOMBIE=1, SHZ_SAW_ADMISSED=2, SHZ_SAW_ARMORED=3 };
enum { SHZ_SAW_RUNNING=1, SHZ_SAW_EXIT_PENDING=2, SHZ_SAW_EXITED=3 };
#define SHZ_SAW_PROTECT_ROOT 1u
#define SHZ_SAW_PROTECT_CRITICAL 2u
#define SHZ_SAW_CONTEXT_KERNEL64 1u
#define SHZ_SAW_CONTEXT_ADDRESS_SPACE 2u
#define SHZ_SAW_CONTEXT_HANDLES 4u
#define SHZ_SAW_CONTEXT_IPC 8u
#define SHZ_SAW_REASON_WAIT_REFS 1u
#define SHZ_SAW_REASON_EXIT_PENDING 2u
#define SHZ_SAW_REASON_NO_TEARDOWN 4u
#define SHZ_SAW_REASON_LIVE_AFTER_SIGNAL 8u
#define SHZ_SAW_REASON_RESOURCES_AFTER_TEARDOWN 16u
#define SHZ_SAW_REASON_KERNEL_WAIT 32u
#define SHZ_SAW_REASON_ROOT_BOUNDARY 64u
#define SHZ_SAW_REASON_IDENTITY 128u
#define SHZ_SAW_REASON_ACCESS 256u
#define SHZ_SAW_REASON_TEARDOWN_BUSY 512u
#define SHZ_SAW_REASON_ANCESTRY 1024u
#define SHZ_SAW_REASON_FORCE_ACK 2048u
#define SHZ_SAW_REASON_SELF 4096u
#define SHZ_SAW_REASON_THREAD_ACCOUNTING 8192u
#define SHZ_SAW_STEP_TERMINATION_REQUESTED 1u
#define SHZ_SAW_STEP_THREADS_QUIESCENT 2u
#define SHZ_SAW_STEP_MEMORY_RELEASED 4u
#define SHZ_SAW_STEP_HANDLES_CLOSED 8u
#define SHZ_SAW_STEP_IPC_RELEASED 16u
#define SHZ_SAW_REPLY_PENDING 1u
#define SHZ_SAW_REPLY_ADMITTED 2u
#define SHZ_SAW_REPLY_PROTECTED 4u
#define SHZ_SAW_REPLY_FORCED 8u
typedef struct shz_saw_request {
    uint32_t version, size, operation, flags;
    uint64_t pid, generation;
    uint32_t acknowledgement, wait_ms;
    uint64_t reserved;
} shz_saw_request;
typedef struct shz_saw_row {
    uint64_t pid, parent_pid, generation;
    uint32_t classification, lifecycle, protection, contexts;
    uint32_t reasons, references, threads, handles;
    uint32_t vads;
    int32_t status;
    uint32_t steps, reserved;
    char name[32];
} shz_saw_row;
typedef struct shz_saw_reply {
    uint32_t version, size, count, targets, completed, flags;
    int32_t status;
    uint32_t reserved;
    shz_saw_row rows[SHZ_SAW_MAX_ROWS];
} shz_saw_reply;
_Static_assert(sizeof(shz_saw_request)==48, "SAW request ABI");
_Static_assert(sizeof(shz_saw_row)==104, "SAW row ABI");
_Static_assert(sizeof(shz_saw_reply)==6688, "SAW reply ABI");
#endif
