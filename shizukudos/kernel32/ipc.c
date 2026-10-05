/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 IPC endpoint: serves requests from other domains over an inter-kernel ABI
 * channel (shz_abi.h / shz_ipc.h) and can issue its own requests.
 *
 * Service opcodes (K32 is the server for channel 0's peer):
 *   0x100 ECHO      inline payload returned unchanged
 *   0x101 SUM32     buffer-pool reference: sum of the u32 words, returned inline
 *   0x102 CRC32     buffer-pool reference: CRC-32 of the bytes
 *   0x103 TIME      monotonic nanoseconds
 *   0x1f0 SESSION_END  peer finished its tests; K32 may exit
 * Malformed input is counted and dropped without a reply: a reply to an untrusted or
 * corrupt header would hand the sender a confused-deputy primitive.
 */
#include "k32.h"
#include "../abi/shz_ipc.h"
#include "ipc_endpoint.h"

#define OP_ECHO 0x100
#define OP_SUM32 0x101
#define OP_CRC32 0x102
#define OP_TIME 0x103
#define OP_SESSION_END 0x1f0
#define RX_PASS_BUDGET 32u

static void *chan_base;
static size_t chan_size;
static shz_channel_hdr_t *chan;
static shz_ring_hdr_t *rx, *tx;
/* Geometry and K32-owned cursors are admitted once. The peer can write the
 * transport, so live header fields never supply an address or slot mask. */
static shz_channel_hdr_t bound_layout;
static size_t bound_ring_bytes;
static uint32_t rx_tail, tx_head;
static int epoch_lost;
static uint32_t peer;
static ksem_t doorbell_sem;
static volatile uint32_t doorbells;
static uint32_t served, proto_errors, refused_buffers, stale_msgs;
static int persistent_service;
volatile uint32_t ipc_session_end;

uint32_t ipc_requests_served(void) { return served; }
uint32_t ipc_protocol_errors(void) { return proto_errors; }
uint32_t ipc_refused_buffers(void) { return refused_buffers; }
uint32_t ipc_stale(void) { return stale_msgs; }
uint32_t ipc_doorbells(void) { return doorbells; }

static void copy_layout(shz_channel_hdr_t *out, const shz_channel_hdr_t *shared)
{
    volatile const uint8_t *src = (volatile const uint8_t *)shared;
    uint8_t *dst = (uint8_t *)out;
    size_t i;
    /* A racing writer may yield a mixed snapshot. Only a fully checked private
     * snapshot is used below; repeated checks must reload peer-writable bytes. */
    for (i = 0; i < sizeof *out; ++i) dst[i] = src[i];
}

static int layout_valid(const shz_channel_hdr_t *c, size_t bytes)
{
    size_t ring;
    uint64_t owners;
    if (c->magic != SHZ_CHANNEL_MAGIC || c->abi_major != SHZ_ABI_MAJOR ||
        c->channel_id >= SHZ_MAX_CHANNELS ||
        !shz_channel_has_domain(c, c->domain_a) || !shz_channel_has_domain(c, c->domain_b) ||
        c->domain_a == c->domain_b || c->slot_count < 2 ||
        (c->slot_count & (c->slot_count - 1))) return 0;
    ring = shz_ring_bytes(c->slot_count);
    if (!ring || !c->pool_size || c->pool_size % SHZ_POOL_BLOCK ||
        c->pool_offset % SHZ_POOL_BLOCK ||
        c->ring_ab_offset % __alignof__(shz_msg_hdr_t) ||
        c->ring_ba_offset % __alignof__(shz_msg_hdr_t) ||
        !shz_range_ok(c->ring_ab_offset, ring, bytes) ||
        !shz_range_ok(c->ring_ba_offset, ring, bytes) ||
        !shz_range_ok(c->pool_offset, c->pool_size, bytes)) return 0;
    owners = c->pool_size / SHZ_POOL_BLOCK;
    return owners <= UINT32_MAX && c->ring_ab_offset >= sizeof *c + owners &&
           c->ring_ba_offset >= c->ring_ab_offset + ring &&
           c->pool_offset >= c->ring_ba_offset + ring;
}

static int ring_geometry_valid(const shz_ring_hdr_t *r, uint32_t count)
{
    return __atomic_load_n(&r->magic, __ATOMIC_ACQUIRE) == SHZ_RING_MAGIC &&
           __atomic_load_n(&r->slot_size, __ATOMIC_ACQUIRE) == SHZ_MSG_SLOT_SIZE &&
           __atomic_load_n(&r->slot_count, __ATOMIC_ACQUIRE) == count;
}

static int layout_status(const shz_channel_hdr_t *shared, const shz_channel_hdr_t *admitted,
                         const shz_ring_hdr_t *receive, const shz_ring_hdr_t *transmit)
{
    shz_channel_hdr_t current;
    copy_layout(&current, shared);
    if (current.generation != admitted->generation) return SHZ_E_STALE;
    if (current.magic != admitted->magic || current.abi_major != admitted->abi_major ||
        current.abi_minor != admitted->abi_minor || current.channel_id != admitted->channel_id ||
        current.domain_a != admitted->domain_a || current.domain_b != admitted->domain_b ||
        current.ring_ab_offset != admitted->ring_ab_offset ||
        current.ring_ba_offset != admitted->ring_ba_offset ||
        current.pool_offset != admitted->pool_offset || current.pool_size != admitted->pool_size ||
        current.slot_count != admitted->slot_count) return SHZ_E_PROTO;
    if (!ring_geometry_valid(receive, admitted->slot_count) ||
        !ring_geometry_valid(transmit, admitted->slot_count)) return SHZ_E_INVALID;
    return SHZ_OK;
}

static int binding_status(void)
{
    int rc;
    if (!chan_base || !chan || !rx || !tx || peer != SHZ_DOM_KERNEL64 ||
        !bound_ring_bytes || bound_ring_bytes != shz_ring_bytes(bound_layout.slot_count) ||
        !layout_valid(&bound_layout, chan_size)) return SHZ_E_INVALID;
    if (epoch_lost) return SHZ_E_STALE;
    rc = layout_status(chan, &bound_layout, rx, tx);
    if (rc == SHZ_E_STALE) epoch_lost = 1;
    if (rc != SHZ_OK) return rc;
    /* Reinitializing a ring without a new epoch, or writing the consumer's /
     * producer's private cursor, cannot silently restart the K32 endpoint. */
    if (__atomic_load_n(&rx->tail, __ATOMIC_ACQUIRE) != rx_tail ||
        __atomic_load_n(&tx->head, __ATOMIC_ACQUIRE) != tx_head) return SHZ_E_PROTO;
    return SHZ_OK;
}

static uint8_t *bound_slot(shz_ring_hdr_t *ring, uint32_t index)
{
    const size_t offset = sizeof *ring +
        (size_t)(index & (bound_layout.slot_count - 1)) * SHZ_MSG_SLOT_SIZE;
    /* Both count and the ring pointer came from the checked private layout.
     * No peer-writable geometry is read while computing this address. */
    if (!shz_range_ok(offset, SHZ_MSG_SLOT_SIZE, bound_ring_bytes)) return NULL;
    return (uint8_t *)ring + offset;
}

static int bound_ring_pop(shz_msg_hdr_t *out, void *payload_out, size_t payload_cap, int *reason)
{
    union { shz_msg_hdr_t header; uint8_t bytes[SHZ_MSG_SLOT_SIZE]; } snapshot;
    uint32_t head, tail = rx_tail;
    const uint8_t *slot;
    int why = SHZ_PR_NONE, rc;
    if (reason) *reason = SHZ_PR_NONE;
    if (!out) return SHZ_E_INVALID;
    rc = binding_status();
    if (rc != SHZ_OK) return rc;
    head = __atomic_load_n(&rx->head, __ATOMIC_ACQUIRE);
    if (head == tail) return SHZ_E_NOENT;
    if (head - tail > bound_layout.slot_count) {
        if (reason) *reason = SHZ_PR_HEAD_CORRUPT;
        return SHZ_E_PROTO;
    }
    slot = bound_slot(rx, tail);
    if (!slot) return SHZ_E_RANGE;
    SHZ_IPC_MEMCPY(snapshot.bytes, slot, sizeof snapshot);
    rc = binding_status();
    if (rc != SHZ_OK) return rc;
    SHZ_IPC_MEMCPY(out, &snapshot.header, sizeof *out);
    if (out->magic != SHZ_MSG_MAGIC) why = SHZ_PR_MAGIC;
    else if (out->abi_major != SHZ_ABI_MAJOR) why = SHZ_PR_VERSION;
    else if (out->header_size != sizeof *out) why = SHZ_PR_HEADER_SIZE;
    else if (out->message_size < sizeof *out || out->message_size > SHZ_MSG_SLOT_SIZE ||
             out->message_size != (uint32_t)out->header_size + out->payload_length)
        why = SHZ_PR_MESSAGE_SIZE;
    else if (out->payload_length > SHZ_MSG_MAX_INLINE ||
             (out->payload_length && out->payload_offset != out->header_size) ||
             !shz_range_ok(out->payload_offset, out->payload_length, out->message_size))
        why = SHZ_PR_PAYLOAD_RANGE;
    else {
        snapshot.header.checksum = 0;
        if (shz_crc32(snapshot.bytes, out->message_size) != out->checksum) why = SHZ_PR_CHECKSUM;
        else if (out->payload_length) {
            if (!payload_out || payload_cap < out->payload_length) why = SHZ_PR_PAYLOAD_RANGE;
            else SHZ_IPC_MEMCPY(payload_out, snapshot.bytes + out->payload_offset, out->payload_length);
        }
    }
    rc = binding_status();
    if (rc != SHZ_OK) return rc;
    rx_tail = tail + 1;
    __atomic_store_n(&rx->tail, rx_tail, __ATOMIC_RELEASE);
    if (why) {
        if (reason) *reason = why;
        return SHZ_E_PROTO;
    }
    return SHZ_OK;
}

static int bound_ring_push(shz_msg_hdr_t *hdr, const void *payload)
{
    union { shz_msg_hdr_t header; uint8_t bytes[SHZ_MSG_SLOT_SIZE]; } snapshot;
    uint32_t head = tx_head, tail;
    uint8_t *slot;
    int rc;
    if (!hdr) return SHZ_E_INVALID;
    if (hdr->payload_length > SHZ_MSG_MAX_INLINE || (hdr->payload_length && !payload)) return SHZ_E_RANGE;
    rc = binding_status();
    if (rc != SHZ_OK) return rc;
    tail = __atomic_load_n(&tx->tail, __ATOMIC_ACQUIRE);
    if (head - tail > bound_layout.slot_count) return SHZ_E_PROTO;
    if (head - tail == bound_layout.slot_count) return SHZ_E_QUEUE_FULL;
    hdr->magic = SHZ_MSG_MAGIC;
    hdr->abi_major = SHZ_ABI_MAJOR;
    hdr->abi_minor = SHZ_ABI_MINOR;
    hdr->header_size = sizeof *hdr;
    hdr->payload_offset = hdr->payload_length ? (uint16_t)sizeof *hdr : 0;
    hdr->message_size = (uint32_t)sizeof *hdr + hdr->payload_length;
    hdr->checksum = 0;
    SHZ_IPC_MEMSET(snapshot.bytes, 0, sizeof snapshot);
    SHZ_IPC_MEMCPY(&snapshot.header, hdr, sizeof *hdr);
    if (hdr->payload_length) SHZ_IPC_MEMCPY(snapshot.bytes + sizeof *hdr, payload, hdr->payload_length);
    hdr->checksum = shz_crc32(snapshot.bytes, hdr->message_size);
    snapshot.header.checksum = hdr->checksum;
    rc = binding_status();
    if (rc != SHZ_OK) return rc;
    slot = bound_slot(tx, head);
    if (!slot) return SHZ_E_RANGE;
    SHZ_IPC_MEMCPY(slot, snapshot.bytes, sizeof snapshot);
    rc = binding_status();
    if (rc != SHZ_OK) return rc;
    tx_head = head + 1;
    __atomic_store_n(&tx->head, tx_head, __ATOMIC_RELEASE);
    return SHZ_OK;
}

void ipc_doorbell_irq(void)
{
    if (!chan) return; /* No endpoint has published a semaphore owner. */
    ++doorbells;
    sem_post(&doorbell_sem);
}

int ipc_init(const shz_bootinfo_t *bi)
{
    unsigned selected;
    int mode, result;
    void *base;
    size_t bytes;
    shz_channel_hdr_t *header;
    shz_channel_hdr_t admitted;
    shz_ring_hdr_t *receive, *transmit;
    uint32_t receive_tail, transmit_head;
    long vector_status;
    if (chan_base || chan || rx || tx || peer) return SHZ_E_BUSY;
    result = k32_ipc_select_endpoint(bi, &selected, &mode);
    if (result <= 0) return result;
    base = (void *)(uintptr_t)bi->channel[selected].gpa;
    bytes = (size_t)bi->channel[selected].size;
    header = (shz_channel_hdr_t *)base;
    copy_layout(&admitted, header);
    if (!layout_valid(&admitted, bytes)) return SHZ_E_PROTO;
    if (admitted.channel_id != bi->channel[selected].channel_id ||
        admitted.generation != bi->generation) return SHZ_E_STALE;
    if (!((admitted.domain_a == SHZ_DOM_KERNEL32 && admitted.domain_b == SHZ_DOM_KERNEL64) ||
          (admitted.domain_b == SHZ_DOM_KERNEL32 && admitted.domain_a == SHZ_DOM_KERNEL64)))
        return SHZ_E_DENIED;
    receive = shz_channel_ring_rx(base, &admitted, SHZ_DOM_KERNEL32);
    transmit = shz_channel_ring_tx(base, &admitted, SHZ_DOM_KERNEL32);
    result = layout_status(header, &admitted, receive, transmit);
    if (result != SHZ_OK) return result;
    receive_tail = __atomic_load_n(&receive->tail, __ATOMIC_ACQUIRE);
    transmit_head = __atomic_load_n(&transmit->head, __ATOMIC_ACQUIRE);
    if (__atomic_load_n(&receive->head, __ATOMIC_ACQUIRE) - receive_tail > admitted.slot_count ||
        transmit_head - __atomic_load_n(&transmit->tail, __ATOMIC_ACQUIRE) > admitted.slot_count)
        return SHZ_E_PROTO;
    sem_init(&doorbell_sem, 0);
    vector_status = shz_set_doorbell_vector(VEC_DOORBELL);
    if (vector_status != SHZ_OK)
        return vector_status < 0 && vector_status >= INT32_MIN ? (int)vector_status : SHZ_E_INVALID;
    result = layout_status(header, &admitted, receive, transmit);
    if (result != SHZ_OK) return result;
    if (__atomic_load_n(&receive->tail, __ATOMIC_ACQUIRE) != receive_tail ||
        __atomic_load_n(&transmit->head, __ATOMIC_ACQUIRE) != transmit_head) return SHZ_E_PROTO;
    bound_layout = admitted;
    bound_ring_bytes = shz_ring_bytes(admitted.slot_count);
    rx_tail = receive_tail;
    tx_head = transmit_head;
    chan_base = base;
    chan_size = bytes;
    chan = header;
    rx = receive;
    tx = transmit;
    peer = SHZ_DOM_KERNEL64;
    persistent_service = mode == 1;
    return 1;
}

static void reply(const shz_msg_hdr_t *req, int32_t status, const void *payload, uint16_t len)
{
    shz_msg_hdr_t h;
    int rc;
    memset(&h, 0, sizeof h);
    h.flags = SHZ_MSGF_REPLY;
    h.opcode = req->opcode;
    h.request_id = req->request_id;
    h.src_domain = SHZ_DOM_KERNEL32;
    h.dst_domain = req->src_domain;
    h.generation = bound_layout.generation;
    h.status = status;
    h.payload_length = len;
    h.capability_id = req->capability_id;
    while ((rc = bound_ring_push(&h, payload)) == SHZ_E_QUEUE_FULL)
        thread_sleep_ms(1);
    if (rc != SHZ_OK) {
        ++proto_errors;
        return;
    }
    shz_notify(peer, 1);
}

static void handle(const shz_msg_hdr_t *m, const uint8_t *payload)
{
    if (binding_status() != SHZ_OK) {
        ++proto_errors;
        return;
    }
    /* Ring CRC validates bytes, not caller authority. A K64 request cannot
     * impersonate K32 to read its pool or inject a reply/control role. */
    if (m->src_domain != peer || (m->flags & ~SHZ_MSGF_BUFFER)) {
        ++proto_errors;
        return;
    }
    if (m->generation != bound_layout.generation || m->dst_domain != SHZ_DOM_KERNEL32) {
        ++stale_msgs;
        reply(m, SHZ_E_STALE, 0, 0);
        return;
    }
    switch (m->opcode) {
    case OP_ECHO:
        reply(m, SHZ_OK, payload, m->payload_length);
        break;
    case OP_SUM32:
    case OP_CRC32: {
        uint32_t result = 0, i;
        const uint8_t *buf;
        if (!(m->flags & SHZ_MSGF_BUFFER) || m->buffer_length == 0 ||
            !shz_range_ok(m->buffer_offset, m->buffer_length, chan_size) ||
            shz_pool_check(chan_base, &bound_layout, m, peer) != SHZ_OK) {
            ++refused_buffers;
            reply(m, SHZ_E_DENIED, 0, 0);
            break;
        }
        buf = (const uint8_t *)chan_base + m->buffer_offset;
        if (m->opcode == OP_SUM32) {
            for (i = 0; i + 4 <= m->buffer_length; i += 4) {
                uint32_t word;
                /* Pool references may begin between aligned u32 words. */
                memcpy(&word, buf + i, sizeof word);
                result += word;
            }
        } else {
            result = shz_crc32(buf, m->buffer_length);
        }
        reply(m, SHZ_OK, &result, sizeof result);
        break;
    }
    case OP_TIME: {
        const uint64_t ns = shz_time_ns();
        reply(m, SHZ_OK, &ns, sizeof ns);
        break;
    }
    case OP_SESSION_END:
        if (persistent_service) {
            /* This opcode ends the QA peer session, not a Win98-owned service.
             * Do not acknowledge a shutdown that this profile did not perform.
             */
            reply(m, SHZ_E_UNSUPPORTED, 0, 0);
        } else {
            ipc_session_end = 1;
            reply(m, SHZ_OK, 0, 0);
        }
        break;
    default:
        reply(m, SHZ_E_UNSUPPORTED, 0, 0);
    }
    ++served;
}

void ipc_server_thread(void *arg)
{
    (void)arg;
    if (!chan_base || !chan || !rx || !tx || peer != SHZ_DOM_KERNEL64) return;
    for (;;) {
        shz_msg_hdr_t m;
        uint8_t payload[SHZ_MSG_MAX_INLINE];
        int reason, rc;
        unsigned budget;
        sem_wait_timeout(&doorbell_sem, 20);          /* also polls: a doorbell may race the wait */
        shz_doorbell_ack();
        /* Bound work even when a peer replenishes the ring continuously. */
        for (budget = 0; budget < RX_PASS_BUDGET; ++budget) {
            const uint32_t before = rx_tail;
            rc = bound_ring_pop(&m, payload, sizeof payload, &reason);
            if (rc == SHZ_E_NOENT)
                break;
            if (rc == SHZ_OK)
                handle(&m, payload);
            else {
                ++proto_errors;
                /* Malformed frames are consumed; invalid metadata and a
                 * corrupt producer index are not. Retry them after a wait. */
                if (rc != SHZ_E_PROTO || reason == SHZ_PR_HEAD_CORRUPT || rx_tail == before)
                    break;
            }
        }
        thread_yield();                             /* pending doorbells can make the next wait immediate */
    }
}
