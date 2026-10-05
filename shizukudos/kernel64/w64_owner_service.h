/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 WIN64 subsystem: Core-side binding of subsystem slots to the generational native endpoint owner
 * (abi/shz_w64_owner.h). Header-only (static inline) so subsys64.c stays a single translation unit for the
 * existing source-bound host controls; it holds kernel pointers and is never put on the wire.
 *
 * A slot created by CREATE_PROCESS is bound to (owner id from the header capability_id that NTWRAP9X.VXD
 * overwrote from the actual VWIN32 DIOC context, channel generation, slot generation, actual process pointer
 * and pid). Every later lookup (CONSOLE_ACK/INPUT, KILL, RELEASE) and every async frame consumes that binding:
 * a request from another owner, from an older channel epoch or for a recycled slot finds nothing (NOENT, no
 * disclosure of other owners' pids). The owner id is a routing lifetime, not a SID: account admission is decided
 * separately (development path or authenticated endpoint broker in sysk32_auth.c).
 */
#ifndef SHZ_K64_W64_OWNER_SERVICE_H
#define SHZ_K64_W64_OWNER_SERVICE_H
#include "../abi/shz_w64_owner.h"

typedef struct {
    uint32_t owner_id;          /* SHZ_W64_OWNER_NONE = unbound */
    uint32_t chan_gen;          /* channel epoch the CREATE arrived under */
    uint32_t slot_gen;          /* w64 slot generation at bind time */
    int pid;                    /* admitted pid */
    void *proc;                 /* actual process_t at admission; cleared by the private reaper */
    uint64_t broker_owner;      /* nonzero: admitted through shz_auth_endpoint_* under this key */
    uint64_t broker_epoch;
} w64_owner_binding_t;

/* Highest revoked generation per owner slot in the current channel epoch. Owner generations only grow on the
 * VxD side, so every id whose generation is <= this mark is departed. Bounded: one u32 per owner slot. */
typedef struct {
    uint32_t chan_gen;
    uint32_t revoked_gen[SHZ_W64_OWNER_MAX];
} w64_owner_revocations_t;

/* Broker key: unique across epochs because the VxD never reuses an owner id inside one epoch and the epoch
 * occupies the high word. Never 0 for a valid owner. */
static inline uint64_t w64_owner_broker_key(uint32_t owner_id, uint32_t chan_gen)
{
    return shz_w64_owner_id_valid(owner_id) ? ((uint64_t)chan_gen << 32) | owner_id : 0;
}

static inline void w64_owner_revocations_epoch(w64_owner_revocations_t *r, uint32_t chan_gen)
{
    unsigned i;
    if (r->chan_gen == chan_gen)
        return;
    r->chan_gen = chan_gen;
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i)
        r->revoked_gen[i] = 0;
}

static inline int w64_owner_is_revoked(const w64_owner_revocations_t *r, uint32_t owner_id, uint32_t chan_gen)
{
    if (!shz_w64_owner_id_valid(owner_id))
        return 1;
    if (r->chan_gen != chan_gen)
        return 0;
    return shz_w64_owner_gen(owner_id) <= r->revoked_gen[shz_w64_owner_slot(owner_id)];
}

static inline void w64_owner_mark_revoked(w64_owner_revocations_t *r, uint32_t owner_id, uint32_t chan_gen)
{
    uint32_t *g;
    if (!shz_w64_owner_id_valid(owner_id))
        return;
    w64_owner_revocations_epoch(r, chan_gen);
    g = &r->revoked_gen[shz_w64_owner_slot(owner_id)];
    if (shz_w64_owner_gen(owner_id) > *g)
        *g = shz_w64_owner_gen(owner_id);
}

static inline void w64_owner_bind(w64_owner_binding_t *b, uint32_t owner_id, uint32_t chan_gen, uint32_t slot_gen)
{
    b->owner_id = owner_id;
    b->chan_gen = chan_gen;
    b->slot_gen = slot_gen;
    b->pid = 0;
    b->proc = 0;
    b->broker_owner = 0;
    b->broker_epoch = 0;
}

static inline void w64_owner_attach_process(w64_owner_binding_t *b, void *proc, int pid)
{
    b->proc = proc;
    b->pid = pid;
}

/* Exact binding match for a request: same owner, same live channel epoch, same slot generation, and the slot
 * still refers to the admitted process (or it was privately reaped, proc == 0, pid unchanged). */
static inline int w64_owner_binding_match(const w64_owner_binding_t *b, uint32_t owner_id, uint32_t chan_gen,
                                          uint32_t slot_gen, const void *slot_proc, int slot_pid)
{
    if (!shz_w64_owner_id_valid(owner_id) || b->owner_id != owner_id || b->chan_gen != chan_gen ||
        b->slot_gen != slot_gen || !b->pid || b->pid != slot_pid)
        return 0;
    return slot_proc == 0 || slot_proc == b->proc;
}

/* Async frames may only be emitted for a binding of the live epoch; the frame carries the bound owner id. */
static inline int w64_owner_binding_live(const w64_owner_binding_t *b, uint32_t chan_gen)
{
    return shz_w64_owner_id_valid(b->owner_id) && b->chan_gen == chan_gen;
}
#endif
