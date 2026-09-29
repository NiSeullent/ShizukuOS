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

/* ================================================================== WIN64 subsystem (ABI 1.1)
 * Message family 0x200..0x2ff between a 32-bit client (the Windows 98 domain, via NTWRAP9X.VXD and
 * NTW32.DLL) and the Kernel64 domain, which runs Win64 PE32+ programs. Kernel64 is the server.
 *
 *   client -> K64   QUERY           (no payload)                        reply: shz_w64_info_t
 *   client -> K64   CREATE_PROCESS  shz_w64_create_t + UTF-16 block    reply: shz_w64_event_t (STARTED or FAILED)
 *                   The block (path, command line, cwd; no terminators) is inline when it fits, otherwise
 *                   the message carries SHZ_MSGF_BUFFER and the block lives in a pool buffer owned by the
 *                   sender (shz_pool_alloc) for the duration of the request ("chunked" through the pool).
 *   K64 -> client   CONSOLE_OUTPUT  shz_w64_console_t + bytes           one-way, ordered per process by seq
 *   client -> K64   CONSOLE_ACK     shz_w64_console_t (seq = highest consumed)   one-way: flow control. K64
 *                   never has more than SHZ_W64_CONSOLE_WINDOW unacknowledged OUTPUT messages per process.
 *   client -> K64   CONSOLE_INPUT   shz_w64_console_t + bytes (flags EOF closes stdin)   reply: status
 *   K64 -> client   PROCESS_EXITED  shz_w64_event_t                     one-way, sent after the last OUTPUT
 *   client -> K64   KILL_PROCESS    shz_w64_kill_t                      reply: status
 *   client -> K64   RELEASE         shz_w64_kill_t (pid only)           reply: status; frees the slot after EXITED
 *   client -> K64   SHUTDOWN        (no payload)                        reply: status; the service stops
 *
 * Every payload is validated by the receiver with the shz_w64_*_check helpers below; nothing in a
 * payload is a pointer or a handle. The reply to a request echoes its opcode (SHZ_MSGF_REPLY). */
#define SHZ_W64_OP_BASE 0x200u
#define SHZ_W64_OP_LAST 0x2ffu
enum shz_w64_opcode {
    SHZ_OP_W64_QUERY = 0x200,
    SHZ_OP_W64_CREATE_PROCESS = 0x201,
    SHZ_OP_W64_PROCESS_EXITED = 0x202,
    SHZ_OP_W64_CONSOLE_OUTPUT = 0x203,
    SHZ_OP_W64_CONSOLE_ACK = 0x204,
    SHZ_OP_W64_CONSOLE_INPUT = 0x205,
    SHZ_OP_W64_KILL_PROCESS = 0x206,
    SHZ_OP_W64_RELEASE = 0x207,
    SHZ_OP_W64_SHUTDOWN = 0x208
};

#define SHZ_W64_SUBSYS_VERSION 0x00010000u          /* subsystem 1.0 */
enum shz_w64_caps {
    SHZ_W64_CAP_CREATE = 1, SHZ_W64_CAP_CONSOLE_OUTPUT = 2, SHZ_W64_CAP_CONSOLE_INPUT = 4, SHZ_W64_CAP_KILL = 8,
    SHZ_W64_CAP_POOL_ARGS = 16
};
#define SHZ_W64_MAX_ARGS_BYTES 4096u                /* UTF-16 block limit (path + command line + cwd) */
#define SHZ_W64_CONSOLE_WINDOW 8u                   /* unacknowledged CONSOLE_OUTPUT messages per process */
#define SHZ_W64_CONSOLE_CHUNK (SHZ_MSG_MAX_INLINE - 16u)   /* 176 bytes per CONSOLE_OUTPUT/INPUT */
#define SHZ_W64_MAX_PATH_CHARS 260u

typedef struct {
    uint16_t abi_major, abi_minor;      /* 0x00 */
    uint32_t subsystem_version;         /* 0x04 SHZ_W64_SUBSYS_VERSION */
    uint32_t capabilities;              /* 0x08 shz_w64_caps */
    uint32_t max_processes;             /* 0x0c bridged processes at once */
    uint32_t max_args_bytes;            /* 0x10 SHZ_W64_MAX_ARGS_BYTES as served */
    uint32_t console_window;            /* 0x14 */
    uint32_t console_chunk;             /* 0x18 */
    uint32_t active_processes;          /* 0x1c */
    uint64_t uptime_ns;                 /* 0x20 */
} shz_w64_info_t;

enum shz_w64_create_flags { SHZ_W64_CF_NONE = 0 };
typedef struct {
    uint32_t flags;                     /* 0x00 shz_w64_create_flags */
    uint16_t path_chars;                /* 0x04 UTF-16 code units, no terminator, >= 1 */
    uint16_t cmdline_chars;             /* 0x06 */
    uint16_t cwd_chars;                 /* 0x08 */
    uint16_t reserved;                  /* 0x0a */
    uint32_t block_bytes;               /* 0x0c 2 * (path + cmdline + cwd) */
} shz_w64_create_t;                     /* followed by the UTF-16 block (inline or in the pool) */

enum shz_w64_proc_state { SHZ_W64_PS_STARTED = 1, SHZ_W64_PS_EXITED = 2, SHZ_W64_PS_FAILED = 3, SHZ_W64_PS_KILLED = 4 };
typedef struct {
    uint32_t pid;                       /* 0x00 Kernel64 process id, 0 when creation failed */
    uint32_t state;                     /* 0x04 shz_w64_proc_state */
    int32_t status;                     /* 0x08 NTSTATUS of creation */
    uint32_t fault_status;              /* 0x0c NTSTATUS of the exception that killed it, 0 = clean exit */
    int64_t exit_code;                  /* 0x10 */
    uint32_t console_seq;               /* 0x18 last CONSOLE_OUTPUT sequence number sent for it */
    uint32_t console_dropped;           /* 0x1c output bytes dropped because the client never acknowledged */
} shz_w64_event_t;

enum shz_w64_console_flags { SHZ_W64_CONF_EOF = 1 };
typedef struct {
    uint32_t pid;                       /* 0x00 */
    uint32_t seq;                       /* 0x04 OUTPUT: 1-based per process. ACK: highest consumed. INPUT: 0 */
    uint16_t length;                    /* 0x08 data bytes following this header */
    uint8_t stream;                     /* 0x0a 0 = stdin, 1 = stdout, 2 = stderr */
    uint8_t flags;                      /* 0x0b shz_w64_console_flags */
    uint32_t reserved;                  /* 0x0c */
} shz_w64_console_t;

typedef struct {
    uint32_t pid;                       /* 0x00 */
    int32_t exit_code;                  /* 0x04 KILL: exit code the process reports; RELEASE: ignored */
} shz_w64_kill_t;

_Static_assert(sizeof(shz_w64_info_t) == 40, "w64 info layout");
_Static_assert(sizeof(shz_w64_create_t) == 16, "w64 create layout");
_Static_assert(sizeof(shz_w64_event_t) == 32, "w64 event layout");
_Static_assert(sizeof(shz_w64_console_t) == 16, "w64 console layout");
_Static_assert(sizeof(shz_w64_kill_t) == 8, "w64 kill layout");
_Static_assert(sizeof(shz_w64_create_t) + SHZ_W64_CONSOLE_CHUNK == SHZ_MSG_MAX_INLINE, "w64 inline capacity");

/* Builds a CREATE_PROCESS payload. `inline_out` receives the header (+ block when it fits, see *inline_len);
 * `block_out`/`block_cap` receive the whole UTF-16 block for the pool path. Returns the block size in bytes
 * or 0 when the strings are unusable (empty path, over the limits, embedded NUL). *needs_pool tells the caller
 * whether the block must travel in a pool buffer. */
SHZ_IPC_INLINE uint32_t shz_w64_create_pack(shz_w64_create_t *hdr, const uint16_t *path, uint32_t path_chars,
                                            const uint16_t *cmdline, uint32_t cmdline_chars, const uint16_t *cwd,
                                            uint32_t cwd_chars, uint16_t *block_out, uint32_t block_cap,
                                            int *needs_pool)
{
    uint32_t i, n = 0;
    const uint32_t total = path_chars + cmdline_chars + cwd_chars;
    if (!hdr || !path || path_chars == 0 || path_chars > SHZ_W64_MAX_PATH_CHARS || cwd_chars > SHZ_W64_MAX_PATH_CHARS ||
        (cmdline_chars && !cmdline) || (cwd_chars && !cwd) || total * 2u > SHZ_W64_MAX_ARGS_BYTES ||
        !block_out || block_cap < total)
        return 0;
    for (i = 0; i < path_chars; ++i) { if (!path[i]) return 0; block_out[n++] = path[i]; }
    for (i = 0; i < cmdline_chars; ++i) { if (!cmdline[i]) return 0; block_out[n++] = cmdline[i]; }
    for (i = 0; i < cwd_chars; ++i) { if (!cwd[i]) return 0; block_out[n++] = cwd[i]; }
    SHZ_IPC_MEMSET(hdr, 0, sizeof *hdr);
    hdr->flags = SHZ_W64_CF_NONE;
    hdr->path_chars = (uint16_t)path_chars;
    hdr->cmdline_chars = (uint16_t)cmdline_chars;
    hdr->cwd_chars = (uint16_t)cwd_chars;
    hdr->block_bytes = total * 2u;
    if (needs_pool)
        *needs_pool = hdr->block_bytes > SHZ_MSG_MAX_INLINE - (uint32_t)sizeof *hdr;
    return hdr->block_bytes;
}

/* Receiver-side validation of a CREATE_PROCESS message. `payload` is the inline payload (payload_length bytes).
 * On success *block receives where the UTF-16 block is: inside the inline payload, or (SHZ_MSGF_BUFFER) at
 * pool_base + buffer_offset after the caller has passed shz_pool_check(). The caller supplies `pool_base`
 * (the channel base) or NULL to refuse pool references. */
SHZ_IPC_INLINE int shz_w64_create_check(const shz_msg_hdr_t *m, const void *payload, const shz_channel_hdr_t *c,
                                        void *pool_base, shz_w64_create_t *hdr_out, const uint16_t **block)
{
    shz_w64_create_t h;
    uint32_t i, total;
    const uint16_t *b;
    if (!m || !payload || !hdr_out || !block || m->payload_length < sizeof h)
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&h, payload, sizeof h);
    total = (uint32_t)h.path_chars + h.cmdline_chars + h.cwd_chars;
    if (h.flags != SHZ_W64_CF_NONE || h.reserved || h.path_chars == 0 || h.path_chars > SHZ_W64_MAX_PATH_CHARS ||
        h.cwd_chars > SHZ_W64_MAX_PATH_CHARS || h.block_bytes != total * 2u)
        return SHZ_E_INVALID;
    if (h.block_bytes > SHZ_W64_MAX_ARGS_BYTES)
        return SHZ_E_RANGE;
    if (m->flags & SHZ_MSGF_BUFFER) {
        if (!pool_base || !c || m->buffer_length != h.block_bytes || m->payload_length != sizeof h)
            return SHZ_E_INVALID;
        if (shz_pool_check(pool_base, c, m, m->src_domain) != SHZ_OK)
            return SHZ_E_DENIED;
        b = (const uint16_t *)((const uint8_t *)pool_base + m->buffer_offset);
    } else {
        if (m->buffer_length || m->payload_length != sizeof h + h.block_bytes)
            return SHZ_E_INVALID;
        b = (const uint16_t *)((const uint8_t *)payload + sizeof h);
    }
    for (i = 0; i < total; ++i)
        if (!b[i])
            return SHZ_E_INVALID;           /* embedded NUL: never trust string lengths that disagree */
    *hdr_out = h;
    *block = b;
    return SHZ_OK;
}

SHZ_IPC_INLINE int shz_w64_console_check(const shz_msg_hdr_t *m, const void *payload, shz_w64_console_t *out)
{
    shz_w64_console_t h;
    if (!m || !payload || !out || m->payload_length < sizeof h)
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&h, payload, sizeof h);
    if (h.reserved || h.stream > 2 || (h.flags & ~(uint8_t)SHZ_W64_CONF_EOF) || h.length > SHZ_W64_CONSOLE_CHUNK ||
        m->payload_length != sizeof h + h.length || m->buffer_length)
        return SHZ_E_INVALID;
    *out = h;
    return SHZ_OK;
}

SHZ_IPC_INLINE int shz_w64_is_opcode(uint32_t op) { return op >= SHZ_W64_OP_BASE && op <= SHZ_W64_OP_LAST; }
#endif
