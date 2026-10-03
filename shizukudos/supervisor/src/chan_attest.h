/* SPDX-License-Identifier: GPL-2.0-only
 * Supervisor channel attestation decisions (abi/shz_abi.h SHZ_HC_CHANNEL_ATTEST / ATTESTED). Original code.
 * Pure functions over a Supervisor-owned record so the exact policy is host-checked (tests/chan_attest_host.c);
 * domain.c supplies the VMCS-derived facts (caller kind, CPL0 protected mode, channel peer kind, header generation). */
#ifndef SHZ_SUP_CHAN_ATTEST_H
#define SHZ_SUP_CHAN_ATTEST_H
#include <stdint.h>
#include "../../abi/shz_abi.h"

typedef struct { uint64_t bits; uint32_t generation, attester, attester_gen; } shz_chan_attest_rec_t;

/* caller_ok: caller is the Win98 domain at CPL0 in protected mode (not V86); peer_ok: channel peer is Kernel64. */
static inline int64_t shz_chan_attest_decide(shz_chan_attest_rec_t *r, int mapped, int caller_ok, int peer_ok,
                                             uint64_t gen, uint32_t header_gen, uint64_t bits, uint32_t self,
                                             uint32_t self_gen, uint64_t *out)
{
    *out = 0;
    if (!mapped) return SHZ_E_NOENT;
    if (!caller_ok || !peer_ok) return SHZ_E_DENIED;
    if (!bits || (bits & ~(uint64_t)SHZ_CHAN_ATTEST_KNOWN)) return SHZ_E_INVALID;
    if (!gen || gen > UINT32_MAX || gen != header_gen || gen < r->generation) return SHZ_E_STALE;
    if (r->generation == gen && r->attester == self && r->attester_gen == self_gen) {
        *out = r->bits;
        return r->bits == bits ? SHZ_OK : SHZ_E_BUSY;           /* set-once per generation */
    }
    if (r->generation == gen) return SHZ_E_BUSY;                /* another attester instance already bound this one */
    r->bits = bits;
    r->generation = (uint32_t)gen;
    r->attester = self;
    r->attester_gen = self_gen;
    *out = bits;
    return SHZ_OK;
}

/* Liveness of the recorded attester as domain.c derives it from its own domain table: the slot must still hold the
 * same domain generation and must not be UNUSED/EXITED/FAILED. Any such transition revokes the attestation without
 * changing the channel header generation, so Kernel64 must re-query at every authorization. */
static inline int shz_chan_attester_alive(const shz_chan_attest_rec_t *r, int slot_exists, uint32_t dom_gen,
                                          uint32_t dom_state)
{
    return r && r->generation && slot_exists && dom_gen == r->attester_gen && dom_state != SHZ_DS_UNUSED &&
           dom_state != SHZ_DS_EXITED && dom_state != SHZ_DS_FAILED;
}

/* attester_alive: the recorded attester domain still runs with exactly r->attester_gen. */
static inline int64_t shz_chan_attest_lookup(const shz_chan_attest_rec_t *r, int mapped, int attester_alive,
                                             uint64_t *bits, uint64_t *gen)
{
    *bits = *gen = 0;
    if (!mapped || !r->generation || !attester_alive) return SHZ_E_NOENT;
    *bits = r->bits;
    *gen = r->generation;
    return SHZ_OK;
}
#endif
