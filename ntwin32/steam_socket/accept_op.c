/* SPDX-License-Identifier: GPL-2.0-only
 * Independently authored provider-side AcceptEx registry and block writer.
 * Layout reference only (no copied code): Wine df15af3652511150490934682202d45af892f887
 * server/sock.c:fill_accept_output writes, at receive reservation offset, a
 * little-endian int32 length followed by the sockaddr, local then remote.
 * Microsoft AcceptEx: each address reservation >= sockaddr size + 16, and
 * GetAcceptExSockaddrs must be given the same reservations. ReactOS
 * 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8 mswsock/extensions.c shows both
 * functions belong to the socket provider. See README.md.
 */
#include "accept_op.h"

static uint32_t family_bytes(uint16_t family)
{
    if (family == NTW_ACCEPT_AF_INET) return NTW_ACCEPT_IPV4_BYTES;
    if (family == NTW_ACCEPT_AF_INET6) return NTW_ACCEPT_IPV6_BYTES;
    return 0;
}

static int ref_valid(struct ntw_ref r) { return r.generation != 0; }
static int ref_equal(struct ntw_ref a, struct ntw_ref b)
{
    return a.id == b.id && a.generation == b.generation;
}

enum ntw_acceptex_status ntw_acceptex_plan_make(
    uint16_t family, uint32_t receive_reserved, uint32_t local_reserved,
    uint32_t remote_reserved, struct ntw_acceptex_plan *out)
{
    uint32_t need = family_bytes(family);
    if (!out) return NTW_ACCEPTEX_ARGUMENT;
    if (!need) return NTW_ACCEPTEX_FAMILY;
    if (local_reserved < need + NTW_ACCEPT_EXTRA_BYTES ||
        remote_reserved < need + NTW_ACCEPT_EXTRA_BYTES)
        return NTW_ACCEPTEX_RESERVATION;
    if (local_reserved > UINT32_MAX - receive_reserved ||
        remote_reserved > UINT32_MAX - (receive_reserved + local_reserved))
        return NTW_ACCEPTEX_OVERFLOW;
    out->receive_reserved = receive_reserved;
    out->local_reserved = local_reserved;
    out->remote_reserved = remote_reserved;
    out->total = receive_reserved + local_reserved + remote_reserved;
    out->family = family;
    return NTW_ACCEPTEX_OK;
}

static int sockaddr_ok(const struct ntw_acceptex_plan *plan, const uint8_t *sa, uint32_t len)
{
    return sa && len == family_bytes(plan->family) &&
           ((uint16_t)sa[0] | (uint16_t)sa[1] << 8) == plan->family;
}

static void put_block(uint8_t *dst, uint32_t reserved, const uint8_t *sa, uint32_t len)
{
    uint32_t i;
    dst[0] = (uint8_t)len; dst[1] = (uint8_t)(len >> 8);
    dst[2] = (uint8_t)(len >> 16); dst[3] = (uint8_t)(len >> 24);
    for (i = 0; i < len; ++i) dst[NTW_ACCEPT_LENGTH_BYTES + i] = sa[i];
    for (i += NTW_ACCEPT_LENGTH_BYTES; i < reserved; ++i) dst[i] = 0;
}

enum ntw_acceptex_status ntw_acceptex_encode_blocks(
    const struct ntw_acceptex_plan *plan,
    const uint8_t *local_sockaddr, uint32_t local_len,
    const uint8_t *remote_sockaddr, uint32_t remote_len,
    uint8_t *out, size_t out_bytes)
{
    uint32_t need = 0;
    if (!plan || !out || !family_bytes(plan->family)) return NTW_ACCEPTEX_ARGUMENT;
    need = family_bytes(plan->family) + NTW_ACCEPT_EXTRA_BYTES;
    /* Re-check the plan: it may be caller-constructed storage. */
    if (plan->local_reserved < need || plan->remote_reserved < need)
        return NTW_ACCEPTEX_RESERVATION;
    if (plan->local_reserved > UINT32_MAX - plan->remote_reserved)
        return NTW_ACCEPTEX_OVERFLOW;
    if ((uint64_t)plan->local_reserved + plan->remote_reserved > (uint64_t)out_bytes)
        return NTW_ACCEPTEX_ARGUMENT;
    if (!sockaddr_ok(plan, local_sockaddr, local_len) ||
        !sockaddr_ok(plan, remote_sockaddr, remote_len))
        return NTW_ACCEPTEX_FAMILY;
    put_block(out, plan->local_reserved, local_sockaddr, local_len);
    put_block(out + plan->local_reserved, plan->remote_reserved, remote_sockaddr, remote_len);
    return NTW_ACCEPTEX_OK;
}

void ntw_acceptex_table_init(struct ntw_acceptex_table *table)
{
    uint32_t i;
    if (!table) return;
    for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i) {
        struct ntw_acceptex_op zero = {0};
        zero.generation = 1;
        table->op[i] = zero;
    }
}

static ntw_acceptex_token token_of(const struct ntw_acceptex_table *t, const struct ntw_acceptex_op *op)
{
    return (uint32_t)(op - t->op) | (uint32_t)op->generation << 16;
}

static struct ntw_acceptex_op *op_of(struct ntw_acceptex_table *t, ntw_acceptex_token token)
{
    uint32_t slot = token & 0xffffu;
    struct ntw_acceptex_op *op;
    if (!t || slot >= NTW_ACCEPTEX_SLOTS) return 0;
    op = &t->op[slot];
    if (op->state == NTW_ACCEPTEX_FREE || op->state == NTW_ACCEPTEX_RETIRED ||
        op->generation != (uint16_t)(token >> 16)) return 0;
    return op;
}

static void op_free(struct ntw_acceptex_op *op)
{
    uint16_t gen = op->generation;
    struct ntw_acceptex_op zero = {0};
    *op = zero;
    if (gen == UINT16_MAX) {             /* never wrap: retire the slot for good */
        op->generation = gen;
        op->state = NTW_ACCEPTEX_RETIRED;
        return;
    }
    op->generation = (uint16_t)(gen + 1u);
}

static int ranges_overlap(uint64_t a, uint32_t an, uint64_t b, uint32_t bn)
{
    /* Zero-length ranges still name their address so equal buffers collide. */
    uint64_t ae = a + (an ? an : 1u), be = b + (bn ? bn : 1u);
    return a < be && b < ae;
}

enum ntw_acceptex_status ntw_acceptex_submit(
    struct ntw_acceptex_table *table, struct ntw_ref owner,
    struct ntw_ref listen, struct ntw_ref accept, uint64_t buffer,
    const struct ntw_acceptex_plan *plan, ntw_acceptex_token *token)
{
    struct ntw_acceptex_op *slot = 0;
    struct ntw_acceptex_plan checked;
    uint32_t i, retired = 0;
    if (!table || !plan || !token || !buffer || !ref_valid(owner) ||
        !ref_valid(listen) || !ref_valid(accept) || ref_equal(listen, accept))
        return NTW_ACCEPTEX_ARGUMENT;
    if (ntw_acceptex_plan_make(plan->family, plan->receive_reserved, plan->local_reserved,
                               plan->remote_reserved, &checked) != NTW_ACCEPTEX_OK ||
        checked.total != plan->total)
        return NTW_ACCEPTEX_ARGUMENT;
    if (buffer > UINT64_MAX - checked.total) return NTW_ACCEPTEX_OVERFLOW;
    /* All refusals are decided before any retirement side effect. */
    for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i) {
        const struct ntw_acceptex_op *op = &table->op[i];
        if (op->state == NTW_ACCEPTEX_RETIRED) { ++retired; continue; }
        if (op->state == NTW_ACCEPTEX_FREE) { if (!slot) slot = &table->op[i]; continue; }
        if (ref_equal(op->accept, accept) || ref_equal(op->listen, accept) ||
            ref_equal(op->accept, listen))
            return NTW_ACCEPTEX_BUSY;
        if (op->state == NTW_ACCEPTEX_PENDING && ref_equal(op->owner, owner) &&
            ranges_overlap(op->buffer, op->plan.total, buffer, checked.total))
            return NTW_ACCEPTEX_BUSY;
    }
    for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i) {
        struct ntw_acceptex_op *op = &table->op[i];
        if (op->state == NTW_ACCEPTEX_COMPLETED && ref_equal(op->owner, owner) &&
            ranges_overlap(op->buffer, op->plan.total, buffer, checked.total)) {
            op_free(op);
            if (!slot) slot = op;
        }
    }
    if (!slot) return retired == NTW_ACCEPTEX_SLOTS ? NTW_ACCEPTEX_EXHAUSTED : NTW_ACCEPTEX_FULL;
    slot->state = NTW_ACCEPTEX_PENDING;
    slot->context_updated = 0;
    slot->owner = owner;
    slot->listen = listen;
    slot->accept = accept;
    slot->buffer = buffer;
    slot->plan = checked;
    slot->accepted_bytes = 0;
    *token = token_of(table, slot);
    return NTW_ACCEPTEX_OK;
}

enum ntw_acceptex_status ntw_acceptex_complete(
    struct ntw_acceptex_table *table, ntw_acceptex_token token, uint32_t accepted_bytes)
{
    struct ntw_acceptex_op *op = op_of(table, token);
    if (!op) return NTW_ACCEPTEX_STALE;
    if (op->state != NTW_ACCEPTEX_PENDING) return NTW_ACCEPTEX_STATE;
    if (accepted_bytes > op->plan.receive_reserved) return NTW_ACCEPTEX_RECEIVED;
    op->accepted_bytes = accepted_bytes;
    op->state = NTW_ACCEPTEX_COMPLETED;
    return NTW_ACCEPTEX_OK;
}

enum ntw_acceptex_status ntw_acceptex_cancel(
    struct ntw_acceptex_table *table, ntw_acceptex_token token)
{
    struct ntw_acceptex_op *op = op_of(table, token);
    if (!op) return NTW_ACCEPTEX_STALE;
    if (op->state != NTW_ACCEPTEX_PENDING) return NTW_ACCEPTEX_STATE;
    op_free(op);
    return NTW_ACCEPTEX_OK;
}

enum ntw_acceptex_status ntw_acceptex_release(
    struct ntw_acceptex_table *table, struct ntw_ref owner, ntw_acceptex_token token)
{
    struct ntw_acceptex_op *op = op_of(table, token);
    if (!op || !ref_equal(op->owner, owner)) return NTW_ACCEPTEX_STALE;
    if (op->state == NTW_ACCEPTEX_PENDING) return NTW_ACCEPTEX_STATE; /* use cancel */
    op_free(op);
    return NTW_ACCEPTEX_OK;
}

uint32_t ntw_acceptex_forget(
    struct ntw_acceptex_table *table, struct ntw_ref subject, int is_process,
    void (*cancelled)(void *ctx, ntw_acceptex_token token), void *ctx)
{
    uint32_t i, freed = 0;
    if (!table || !ref_valid(subject)) return 0;
    for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i) {
        struct ntw_acceptex_op *op = &table->op[i];
        int match;
        if (op->state == NTW_ACCEPTEX_FREE || op->state == NTW_ACCEPTEX_RETIRED) continue;
        match = is_process ? ref_equal(op->owner, subject)
                           : (ref_equal(op->listen, subject) || ref_equal(op->accept, subject));
        if (!match) continue;
        if (op->state == NTW_ACCEPTEX_PENDING && cancelled) cancelled(ctx, token_of(table, op));
        op_free(op);
        ++freed;
    }
    return freed;
}

enum ntw_acceptex_status ntw_acceptex_update_context(
    struct ntw_acceptex_table *table, struct ntw_ref owner,
    struct ntw_ref accept, struct ntw_ref listen)
{
    uint32_t i;
    if (!table || !ref_valid(owner) || !ref_valid(accept) || !ref_valid(listen))
        return NTW_ACCEPTEX_ARGUMENT;
    for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i) {
        struct ntw_acceptex_op *op = &table->op[i];
        if (op->state == NTW_ACCEPTEX_FREE || op->state == NTW_ACCEPTEX_RETIRED ||
            !ref_equal(op->accept, accept)) continue;
        if (!ref_equal(op->owner, owner) || !ref_equal(op->listen, listen))
            return NTW_ACCEPTEX_STALE;
        if (op->state != NTW_ACCEPTEX_COMPLETED) return NTW_ACCEPTEX_STATE;
        op->context_updated = 1;
        return NTW_ACCEPTEX_OK;
    }
    return NTW_ACCEPTEX_NOT_FOUND;
}

enum ntw_acceptex_status ntw_acceptex_lookup(
    const struct ntw_acceptex_table *table, struct ntw_ref owner,
    uint64_t buffer, uint32_t receive_reserved, uint32_t local_reserved,
    uint32_t remote_reserved, const struct ntw_acceptex_op **op_out)
{
    uint32_t i;
    if (!table || !op_out || !buffer || !ref_valid(owner)) return NTW_ACCEPTEX_ARGUMENT;
    for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i) {
        const struct ntw_acceptex_op *op = &table->op[i];
        if (op->state != NTW_ACCEPTEX_COMPLETED || op->buffer != buffer ||
            !ref_equal(op->owner, owner))
            continue;
        if (op->plan.receive_reserved != receive_reserved ||
            op->plan.local_reserved != local_reserved ||
            op->plan.remote_reserved != remote_reserved)
            return NTW_ACCEPTEX_RESERVATION;
        *op_out = op;
        return NTW_ACCEPTEX_OK;
    }
    return NTW_ACCEPTEX_NOT_FOUND;
}
