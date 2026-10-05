/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CHAINSAW_REPLY_H
#define SHZ_CHAINSAW_REPLY_H
#include "../../../abi/shz_saw.h"
#define CS_REASON_MASK 16383u
#define CS_PROTECTION_MASK (SHZ_SAW_PROTECT_ROOT | SHZ_SAW_PROTECT_CRITICAL)
#define CS_CONTEXT_MASK (SHZ_SAW_CONTEXT_KERNEL64 | SHZ_SAW_CONTEXT_ADDRESS_SPACE | SHZ_SAW_CONTEXT_HANDLES | SHZ_SAW_CONTEXT_IPC)
#define CS_STEP_MASK (SHZ_SAW_STEP_TERMINATION_REQUESTED | SHZ_SAW_STEP_THREADS_QUIESCENT | SHZ_SAW_STEP_MEMORY_RELEASED | SHZ_SAW_STEP_HANDLES_CLOSED | SHZ_SAW_STEP_IPC_RELEASED)
#define CS_REPLY_MASK (SHZ_SAW_REPLY_PENDING | SHZ_SAW_REPLY_ADMITTED | SHZ_SAW_REPLY_PROTECTED | SHZ_SAW_REPLY_FORCED)
/* Fail closed before using row count, name strings or completion assertions. */
static inline int cs_reply_valid(const shz_saw_reply *r)
{
    uint32_t i, j;
    if (r->version != SHZ_SAW_VERSION || r->size != sizeof *r || r->reserved ||
        r->count > SHZ_SAW_MAX_ROWS || r->targets > SHZ_SAW_MAX_ROWS ||
        r->completed > r->targets || (!r->status && r->count > r->targets) || (r->flags & ~CS_REPLY_MASK)) return 0;
    for (i = 0; i < r->count; ++i) {
        const shz_saw_row *p = &r->rows[i];
        if (p->pid > 2147483647u || p->parent_pid > 2147483647u ||
            p->reserved || p->classification > SHZ_SAW_ARMORED ||
            p->lifecycle > SHZ_SAW_EXITED ||
            (p->protection & ~CS_PROTECTION_MASK) || (p->contexts & ~CS_CONTEXT_MASK) ||
            (p->reasons & ~CS_REASON_MASK) || (p->steps & ~CS_STEP_MASK)) return 0;
        /* A refused/denied target can have deliberately redacted identity and
         * lifecycle. It can never pass cs_reply_sawed or QUERY validation. */
        if ((!p->generation || p->lifecycle < SHZ_SAW_RUNNING) && !p->status) return 0;
        if (!p->pid && (!p->status || p->reasons != SHZ_SAW_REASON_ACCESS || p->generation ||
            p->parent_pid || p->contexts || p->threads || p->handles || p->vads || p->references ||
            p->steps || p->protection || p->name[0])) return 0;
        for (j = 0; j < sizeof p->name && p->name[j]; ++j) { }
        if (j == sizeof p->name) return 0;
        for (j = 0; j < i; ++j) if (p->pid && r->rows[j].pid == p->pid) return 0;
    }
    return 1;
}
static inline int cs_reply_sawed(const shz_saw_reply *r)
{
    uint32_t i;
    if (!cs_reply_valid(r) || r->status || !r->targets || r->count != r->targets ||
        r->completed != r->targets || (r->flags & (SHZ_SAW_REPLY_PENDING | SHZ_SAW_REPLY_ADMITTED | SHZ_SAW_REPLY_PROTECTED))) return 0;
    for (i = 0; i < r->count; ++i)
        if (r->rows[i].status || r->rows[i].lifecycle != SHZ_SAW_EXITED) return 0;
    return 1;
}
#endif
