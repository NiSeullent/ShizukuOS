/* SPDX-License-Identifier: GPL-2.0-only
 * Freestanding IPC library for the ShizukuDOS inter-kernel ABI (shz_abi.h).
 * Header-only and libc-free so Kernel32 (i486), Kernel64 (x86-64) and host tests
 * compile the very same code. Define SHZ_IPC_MEMCPY/SHZ_IPC_MEMSET before including
 * to supply the environment's routines.
 *
 * Guarantees:
 *  - A receiver never trusts the sender: every field is range-checked with
 *    overflow-safe arithmetic, malformed slots are consumed and reported, so a
 *    hostile or crashed peer cannot wedge the ring.
 *  - Sender and receiver need no shared lock: one producer and one consumer per ring.
 *  - Requests are tracked by id with a deadline; duplicate, late and stale-generation
 *    replies are refused rather than delivered twice.
 */
#ifndef SHZ_IPC_H
#define SHZ_IPC_H
#include <stddef.h>
#include <stdint.h>
#include "shz_abi.h"

#ifndef SHZ_IPC_MEMCPY
#define SHZ_IPC_MEMCPY(d, s, n) __builtin_memcpy((d), (s), (n))
#endif
#ifndef SHZ_IPC_MEMSET
#define SHZ_IPC_MEMSET(d, c, n) __builtin_memset((d), (c), (n))
#endif

#define SHZ_IPC_INLINE static inline __attribute__((unused))

/* ------------------------------------------------------------------ CRC-32 */
SHZ_IPC_INLINE uint32_t shz_crc32(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xffffffffu;
    while (len--) {
        unsigned bit;
        crc ^= *p++;
        for (bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

SHZ_IPC_INLINE uint32_t shz_msg_checksum(const shz_msg_hdr_t *hdr)
{
    shz_msg_hdr_t copy;
    uint8_t buf[SHZ_MSG_SLOT_SIZE];
    SHZ_IPC_MEMCPY(&copy, hdr, sizeof copy);
    copy.checksum = 0;
    SHZ_IPC_MEMCPY(buf, &copy, sizeof copy);
    if (hdr->message_size > sizeof copy && hdr->message_size <= SHZ_MSG_SLOT_SIZE)
        SHZ_IPC_MEMCPY(buf + sizeof copy, (const uint8_t *)hdr + sizeof copy, hdr->message_size - sizeof copy);
    return shz_crc32(buf, hdr->message_size <= SHZ_MSG_SLOT_SIZE ? hdr->message_size : sizeof copy);
}

/* ------------------------------------------------------------------ range helper */
SHZ_IPC_INLINE int shz_range_ok(uint64_t offset, uint64_t length, uint64_t limit)
{
    return offset <= limit && length <= limit - offset;
}

/* ------------------------------------------------------------------ rings */
SHZ_IPC_INLINE size_t shz_ring_bytes(uint32_t slot_count)
{
    return sizeof(shz_ring_hdr_t) + (size_t)slot_count * SHZ_MSG_SLOT_SIZE;
}

SHZ_IPC_INLINE int shz_ring_init(void *base, size_t bytes, uint32_t slot_count)
{
    shz_ring_hdr_t *r = (shz_ring_hdr_t *)base;
    if (!base || slot_count < 2 || (slot_count & (slot_count - 1)) || bytes < shz_ring_bytes(slot_count))
        return SHZ_E_INVALID;
    SHZ_IPC_MEMSET(base, 0, shz_ring_bytes(slot_count));
    r->slot_count = slot_count;
    r->slot_size = SHZ_MSG_SLOT_SIZE;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    r->magic = SHZ_RING_MAGIC;
    return SHZ_OK;
}

SHZ_IPC_INLINE uint8_t *shz_ring_slot(shz_ring_hdr_t *r, uint32_t index)
{
    return (uint8_t *)r + sizeof *r + (size_t)(index & (r->slot_count - 1)) * SHZ_MSG_SLOT_SIZE;
}

SHZ_IPC_INLINE int shz_ring_valid(const shz_ring_hdr_t *r)
{
    return r && r->magic == SHZ_RING_MAGIC && r->slot_size == SHZ_MSG_SLOT_SIZE && r->slot_count >= 2 &&
           !(r->slot_count & (r->slot_count - 1));
}

SHZ_IPC_INLINE uint32_t shz_ring_count(const shz_ring_hdr_t *r)
{
    return __atomic_load_n(&r->head, __ATOMIC_ACQUIRE) - __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
}

/* Producer side. payload may be NULL when payload_length is 0. */
SHZ_IPC_INLINE int shz_ring_push(shz_ring_hdr_t *r, shz_msg_hdr_t *hdr, const void *payload)
{
    uint32_t head, tail;
    uint8_t *slot;
    if (!shz_ring_valid(r) || !hdr)
        return SHZ_E_INVALID;
    if (hdr->payload_length > SHZ_MSG_MAX_INLINE || (hdr->payload_length && !payload))
        return SHZ_E_RANGE;
    head = r->head;
    tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    if (head - tail >= r->slot_count)
        return SHZ_E_QUEUE_FULL;
    hdr->magic = SHZ_MSG_MAGIC;
    hdr->abi_major = SHZ_ABI_MAJOR;
    hdr->abi_minor = SHZ_ABI_MINOR;
    hdr->header_size = sizeof *hdr;
    hdr->payload_offset = hdr->payload_length ? (uint16_t)sizeof *hdr : 0;
    hdr->message_size = (uint32_t)sizeof *hdr + hdr->payload_length;
    hdr->checksum = 0;
    slot = shz_ring_slot(r, head);
    SHZ_IPC_MEMSET(slot, 0, SHZ_MSG_SLOT_SIZE);
    SHZ_IPC_MEMCPY(slot, hdr, sizeof *hdr);
    if (hdr->payload_length && payload)
        SHZ_IPC_MEMCPY(slot + sizeof *hdr, payload, hdr->payload_length);
    hdr->checksum = shz_msg_checksum((const shz_msg_hdr_t *)slot);
    ((shz_msg_hdr_t *)slot)->checksum = hdr->checksum;
    __atomic_store_n(&r->head, head + 1, __ATOMIC_RELEASE);
    return SHZ_OK;
}

/* Consumer side. Copies one message out and always consumes the slot when one is
 * present, even if it is malformed (then returns SHZ_E_PROTO and reports why via
 * *reason). Returns SHZ_E_NOENT when the ring is empty. */
enum shz_proto_reason {
    SHZ_PR_NONE = 0, SHZ_PR_MAGIC = 1, SHZ_PR_VERSION = 2, SHZ_PR_HEADER_SIZE = 3, SHZ_PR_MESSAGE_SIZE = 4,
    SHZ_PR_PAYLOAD_RANGE = 5, SHZ_PR_CHECKSUM = 6, SHZ_PR_HEAD_CORRUPT = 7
};

SHZ_IPC_INLINE int shz_ring_pop(shz_ring_hdr_t *r, shz_msg_hdr_t *out, void *payload_out, size_t payload_cap,
                                int *reason)
{
    uint32_t head, tail;
    const shz_msg_hdr_t *m;
    int why = SHZ_PR_NONE;
    if (reason)
        *reason = SHZ_PR_NONE;
    if (!shz_ring_valid(r) || !out)
        return SHZ_E_INVALID;
    tail = r->tail;
    head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    if (head == tail)
        return SHZ_E_NOENT;
    if (head - tail > r->slot_count) {          /* producer index is corrupt: cannot trust anything */
        if (reason)
            *reason = SHZ_PR_HEAD_CORRUPT;
        return SHZ_E_PROTO;
    }
    m = (const shz_msg_hdr_t *)shz_ring_slot(r, tail);
    SHZ_IPC_MEMCPY(out, m, sizeof *out);        /* work on a private copy: the peer may keep writing */
    if (out->magic != SHZ_MSG_MAGIC)
        why = SHZ_PR_MAGIC;
    else if (out->abi_major != SHZ_ABI_MAJOR)
        why = SHZ_PR_VERSION;
    else if (out->header_size != sizeof *out)
        why = SHZ_PR_HEADER_SIZE;
    else if (out->message_size < sizeof *out || out->message_size > SHZ_MSG_SLOT_SIZE ||
             out->message_size != (uint32_t)out->header_size + out->payload_length)
        why = SHZ_PR_MESSAGE_SIZE;
    else if (out->payload_length > SHZ_MSG_MAX_INLINE ||
             (out->payload_length && out->payload_offset != out->header_size) ||
             !shz_range_ok(out->payload_offset, out->payload_length, out->message_size))
        why = SHZ_PR_PAYLOAD_RANGE;
    else {
        uint8_t copy[SHZ_MSG_SLOT_SIZE];
        SHZ_IPC_MEMCPY(copy, m, out->message_size);
        ((shz_msg_hdr_t *)copy)->checksum = 0;
        if (shz_crc32(copy, out->message_size) != out->checksum)
            why = SHZ_PR_CHECKSUM;
        else if (out->payload_length) {
            if (!payload_out || payload_cap < out->payload_length) {
                why = SHZ_PR_PAYLOAD_RANGE;
            } else {
                SHZ_IPC_MEMCPY(payload_out, copy + out->payload_offset, out->payload_length);
            }
        }
    }
    __atomic_store_n(&r->tail, tail + 1, __ATOMIC_RELEASE);   /* consume regardless */
    if (why) {
        if (reason)
            *reason = why;
        return SHZ_E_PROTO;
    }
    return SHZ_OK;
}

/* ------------------------------------------------------------------ channel layout */
#define SHZ_POOL_BLOCK 4096u

SHZ_IPC_INLINE uint32_t shz_pool_blocks(const shz_channel_hdr_t *c) { return (uint32_t)(c->pool_size / SHZ_POOL_BLOCK); }

/* Layout: [channel hdr 128][owner table][ring a->b][ring b->a][pool, 4 KiB blocks]. The owner
 * table has one byte per pool block: 0 = free, else the owning domain id. */
SHZ_IPC_INLINE int shz_channel_init(void *base, size_t bytes, uint32_t channel_id, uint32_t dom_a, uint32_t dom_b,
                                    uint32_t slot_count, uint32_t generation)
{
    shz_channel_hdr_t *c = (shz_channel_hdr_t *)base;
    const size_t ring = shz_ring_bytes(slot_count);
    size_t pool_off, table_bytes, blocks;
    if (!base || bytes < 65536 || (slot_count & (slot_count - 1)) || slot_count < 2)
        return SHZ_E_INVALID;
    /* first pass: assume pool starts after both rings and a table sized for the remainder */
    blocks = (bytes - sizeof *c - 2 * ring) / (SHZ_POOL_BLOCK + 1);
    table_bytes = (blocks + 63) & ~(size_t)63;
    pool_off = (sizeof *c + table_bytes + 2 * ring + SHZ_POOL_BLOCK - 1) & ~(size_t)(SHZ_POOL_BLOCK - 1);
    if (pool_off >= bytes)
        return SHZ_E_RANGE;
    blocks = (bytes - pool_off) / SHZ_POOL_BLOCK;
    if (blocks > table_bytes)
        blocks = table_bytes;
    SHZ_IPC_MEMSET(base, 0, pool_off);
    c->abi_major = SHZ_ABI_MAJOR;
    c->abi_minor = SHZ_ABI_MINOR;
    c->channel_id = channel_id;
    c->generation = generation;
    c->domain_a = dom_a;
    c->domain_b = dom_b;
    c->slot_count = slot_count;
    c->ring_ab_offset = sizeof *c + table_bytes;
    c->ring_ba_offset = c->ring_ab_offset + ring;
    c->pool_offset = pool_off;
    c->pool_size = blocks * SHZ_POOL_BLOCK;
    if (shz_ring_init((uint8_t *)base + c->ring_ab_offset, ring, slot_count) ||
        shz_ring_init((uint8_t *)base + c->ring_ba_offset, ring, slot_count))
        return SHZ_E_INVALID;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    c->magic = SHZ_CHANNEL_MAGIC;
    return SHZ_OK;
}

SHZ_IPC_INLINE int shz_channel_valid(const shz_channel_hdr_t *c, size_t bytes)
{
    return c && c->magic == SHZ_CHANNEL_MAGIC && c->abi_major == SHZ_ABI_MAJOR &&
           shz_range_ok(c->ring_ab_offset, shz_ring_bytes(c->slot_count), bytes) &&
           shz_range_ok(c->ring_ba_offset, shz_ring_bytes(c->slot_count), bytes) &&
           shz_range_ok(c->pool_offset, c->pool_size, bytes);
}

SHZ_IPC_INLINE shz_ring_hdr_t *shz_channel_ring_tx(void *base, const shz_channel_hdr_t *c, uint32_t self)
{
    return (shz_ring_hdr_t *)((uint8_t *)base + (self == c->domain_a ? c->ring_ab_offset : c->ring_ba_offset));
}
SHZ_IPC_INLINE shz_ring_hdr_t *shz_channel_ring_rx(void *base, const shz_channel_hdr_t *c, uint32_t self)
{
    return (shz_ring_hdr_t *)((uint8_t *)base + (self == c->domain_a ? c->ring_ba_offset : c->ring_ab_offset));
}

/* ------------------------------------------------------------------ shared buffer pool */
/* The owner table lives directly after the channel header. */
SHZ_IPC_INLINE volatile uint8_t *shz_pool_owner_table(void *base) { return (volatile uint8_t *)base + sizeof(shz_channel_hdr_t); }

/* Allocates `len` bytes (rounded to blocks) as contiguous blocks owned by `owner`.
 * Returns the byte offset into the channel region, or 0 on failure (offset 0 is the header). */
SHZ_IPC_INLINE uint64_t shz_pool_alloc(void *base, const shz_channel_hdr_t *c, uint32_t owner, uint32_t len)
{
    volatile uint8_t *table = shz_pool_owner_table(base);
    const uint32_t need = (len + SHZ_POOL_BLOCK - 1) / SHZ_POOL_BLOCK;
    const uint32_t total = shz_pool_blocks(c);
    uint32_t i, run = 0;
    if (!len || !need || need > total || owner == 0 || owner > 255)
        return 0;
    for (i = 0; i < total; ++i) {
        uint8_t expect = 0;
        if (table[i] != 0) {
            run = 0;
            continue;
        }
        ++run;
        if (run == need) {
            uint32_t first = i + 1 - need, j;
            for (j = first; j <= i; ++j) {
                expect = 0;
                if (!__atomic_compare_exchange_n(&table[j], &expect, (uint8_t)owner, 0, __ATOMIC_ACQ_REL,
                                                 __ATOMIC_ACQUIRE)) {
                    while (j > first)                   /* lost a race: roll back */
                        __atomic_store_n(&table[--j], (uint8_t)0, __ATOMIC_RELEASE);
                    run = 0;
                    break;
                }
            }
            if (run)
                return c->pool_offset + (uint64_t)first * SHZ_POOL_BLOCK;
        }
    }
    return 0;
}

/* Only the current owner may free or hand a block range to the peer. */
SHZ_IPC_INLINE int shz_pool_release(void *base, const shz_channel_hdr_t *c, uint32_t owner, uint64_t offset,
                                    uint32_t len, uint32_t new_owner)
{
    volatile uint8_t *table = shz_pool_owner_table(base);
    const uint32_t need = (len + SHZ_POOL_BLOCK - 1) / SHZ_POOL_BLOCK;
    uint64_t first;
    uint32_t i;
    if (!len || offset < c->pool_offset || ((offset - c->pool_offset) % SHZ_POOL_BLOCK))
        return SHZ_E_RANGE;
    first = (offset - c->pool_offset) / SHZ_POOL_BLOCK;
    if (!shz_range_ok(first, need, shz_pool_blocks(c)))
        return SHZ_E_RANGE;
    for (i = 0; i < need; ++i)
        if (table[first + i] != owner)
            return SHZ_E_DENIED;                        /* double free or not the owner */
    for (i = 0; i < need; ++i)
        __atomic_store_n(&table[first + i], (uint8_t)new_owner, __ATOMIC_RELEASE);
    return SHZ_OK;
}

/* Validates a message's buffer reference from the receiver's point of view: in range and
 * currently owned by `expected_owner` (the sender until it transfers the buffer). */
SHZ_IPC_INLINE int shz_pool_check(void *base, const shz_channel_hdr_t *c, const shz_msg_hdr_t *m,
                                  uint32_t expected_owner)
{
    volatile uint8_t *table = shz_pool_owner_table(base);
    uint64_t first;
    uint32_t i, need;
    if (!m->buffer_length)
        return SHZ_OK;
    if (m->buffer_offset < c->pool_offset)
        return SHZ_E_RANGE;
    if (!shz_range_ok(m->buffer_offset - c->pool_offset, m->buffer_length, c->pool_size))
        return SHZ_E_RANGE;
    first = (m->buffer_offset - c->pool_offset) / SHZ_POOL_BLOCK;
    need = (uint32_t)((m->buffer_offset - c->pool_offset) % SHZ_POOL_BLOCK + m->buffer_length + SHZ_POOL_BLOCK - 1) / SHZ_POOL_BLOCK;
    for (i = 0; i < need; ++i)
        if (table[first + i] != expected_owner)
            return SHZ_E_DENIED;
    return SHZ_OK;
}

/* ------------------------------------------------------------------ request tracking */
#define SHZ_REQ_SLOTS 16
enum { SHZ_REQ_FREE = 0, SHZ_REQ_PENDING = 1, SHZ_REQ_CANCELLED = 2 };
typedef struct {
    struct { uint64_t id; uint64_t deadline; uint32_t state; uint32_t generation; } slot[SHZ_REQ_SLOTS];
    uint64_t next_id;
    uint32_t peer_generation;
} shz_reqtab_t;

SHZ_IPC_INLINE void shz_reqtab_init(shz_reqtab_t *t, uint32_t peer_generation, uint64_t first_id)
{
    SHZ_IPC_MEMSET(t, 0, sizeof *t);
    t->next_id = first_id;
    t->peer_generation = peer_generation;
}

/* Returns the new request id or 0 if the table is full. */
SHZ_IPC_INLINE uint64_t shz_req_begin(shz_reqtab_t *t, uint64_t deadline)
{
    unsigned i;
    for (i = 0; i < SHZ_REQ_SLOTS; ++i)
        if (t->slot[i].state == SHZ_REQ_FREE) {
            t->slot[i].id = t->next_id++;
            t->slot[i].deadline = deadline;
            t->slot[i].state = SHZ_REQ_PENDING;
            t->slot[i].generation = t->peer_generation;
            return t->slot[i].id;
        }
    return 0;
}

/* Matches a reply. Returns SHZ_OK when it completes a pending request; SHZ_E_STALE for a
 * generation mismatch; SHZ_E_NOENT for an unknown/duplicate/late id; SHZ_E_CANCELLED when
 * the requester already cancelled (the reply is consumed and dropped). */
SHZ_IPC_INLINE int shz_req_complete(shz_reqtab_t *t, const shz_msg_hdr_t *reply)
{
    unsigned i;
    if (reply->generation != t->peer_generation)
        return SHZ_E_STALE;
    for (i = 0; i < SHZ_REQ_SLOTS; ++i)
        if (t->slot[i].state != SHZ_REQ_FREE && t->slot[i].id == reply->request_id) {
            const int cancelled = t->slot[i].state == SHZ_REQ_CANCELLED;
            t->slot[i].state = SHZ_REQ_FREE;
            return cancelled ? SHZ_E_CANCELLED : SHZ_OK;
        }
    return SHZ_E_NOENT;
}

SHZ_IPC_INLINE int shz_req_cancel(shz_reqtab_t *t, uint64_t id)
{
    unsigned i;
    for (i = 0; i < SHZ_REQ_SLOTS; ++i)
        if (t->slot[i].state == SHZ_REQ_PENDING && t->slot[i].id == id) {
            t->slot[i].state = SHZ_REQ_CANCELLED;
            return SHZ_OK;
        }
    return SHZ_E_NOENT;
}

/* Expires pending requests whose deadline passed; returns how many. A late reply to an
 * expired request will be reported SHZ_E_CANCELLED-equivalent (NOENT after the slot is freed
 * only if the slot was reused), so expiry keeps the slot as CANCELLED until the reply arrives
 * or `shz_reqtab_reset` runs after a peer restart. */
SHZ_IPC_INLINE unsigned shz_req_expire(shz_reqtab_t *t, uint64_t now)
{
    unsigned i, n = 0;
    for (i = 0; i < SHZ_REQ_SLOTS; ++i)
        if (t->slot[i].state == SHZ_REQ_PENDING && now >= t->slot[i].deadline) {
            t->slot[i].state = SHZ_REQ_CANCELLED;
            ++n;
        }
    return n;
}

/* After a peer restart: bump generation, drop every outstanding request. */
SHZ_IPC_INLINE void shz_reqtab_reset(shz_reqtab_t *t, uint32_t new_generation)
{
    SHZ_IPC_MEMSET(t->slot, 0, sizeof t->slot);
    t->peer_generation = new_generation;
}
#endif
