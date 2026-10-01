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
static uint32_t peer;
static ksem_t doorbell_sem;
static volatile uint32_t doorbells;
static uint32_t served, proto_errors, refused_buffers, stale_msgs;
volatile uint32_t ipc_session_end;

uint32_t ipc_requests_served(void) { return served; }
uint32_t ipc_protocol_errors(void) { return proto_errors; }
uint32_t ipc_refused_buffers(void) { return refused_buffers; }
uint32_t ipc_stale(void) { return stale_msgs; }
uint32_t ipc_doorbells(void) { return doorbells; }

void ipc_doorbell_irq(void)
{
    ++doorbells;
    sem_post(&doorbell_sem);
}

void ipc_init(const shz_bootinfo_t *bi)
{
    unsigned c;
    sem_init(&doorbell_sem, 0);
    for (c = 0; c < bi->channel_count; ++c) {
        if (bi->channel[c].peer_domain != SHZ_DOM_KERNEL64)
            continue;
        chan_base = (void *)(uintptr_t)bi->channel[c].gpa;
        chan_size = (size_t)bi->channel[c].size;
        chan = (shz_channel_hdr_t *)chan_base;
        KASSERT(shz_channel_valid(chan, chan_size));
        peer = bi->channel[c].peer_domain;
        rx = shz_channel_ring_rx(chan_base, chan, SHZ_DOM_KERNEL32);
        tx = shz_channel_ring_tx(chan_base, chan, SHZ_DOM_KERNEL32);
        KASSERT(shz_ring_valid(rx) && shz_ring_valid(tx));
    }
    KASSERT(shz_set_doorbell_vector(VEC_DOORBELL) == 0);
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
    h.generation = chan->generation;
    h.status = status;
    h.payload_length = len;
    h.capability_id = req->capability_id;
    while ((rc = shz_ring_push(tx, &h, payload)) == SHZ_E_QUEUE_FULL)
        thread_sleep_ms(1);
    KASSERT(rc == SHZ_OK);
    shz_notify(peer, 1);
}

static void handle(const shz_msg_hdr_t *m, const uint8_t *payload)
{
    if (m->generation != chan->generation || m->dst_domain != SHZ_DOM_KERNEL32) {
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
        if (shz_pool_check(chan_base, chan, m, m->src_domain) != SHZ_OK || m->buffer_length == 0) {
            ++refused_buffers;
            reply(m, SHZ_E_DENIED, 0, 0);
            break;
        }
        buf = (const uint8_t *)chan_base + m->buffer_offset;
        if (m->opcode == OP_SUM32) {
            for (i = 0; i + 4 <= m->buffer_length; i += 4)
                result += *(const uint32_t *)(buf + i);
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
        ipc_session_end = 1;
        reply(m, SHZ_OK, 0, 0);
        break;
    default:
        reply(m, SHZ_E_UNSUPPORTED, 0, 0);
    }
    ++served;
}

void ipc_server_thread(void *arg)
{
    (void)arg;
    for (;;) {
        shz_msg_hdr_t m;
        uint8_t payload[SHZ_MSG_MAX_INLINE];
        int reason, rc;
        unsigned budget;
        sem_wait_timeout(&doorbell_sem, 20);          /* also polls: a doorbell may race the wait */
        shz_doorbell_ack();
        /* Bound work even when a peer replenishes the ring continuously. */
        for (budget = 0; budget < RX_PASS_BUDGET; ++budget) {
            rc = shz_ring_pop(rx, &m, payload, sizeof payload, &reason);
            if (rc == SHZ_E_NOENT)
                break;
            if (rc == SHZ_OK)
                handle(&m, payload);
            else {
                ++proto_errors;
                /* Malformed frames are consumed; invalid metadata and a
                 * corrupt producer index are not. Retry them after a wait. */
                if (rc != SHZ_E_PROTO || reason == SHZ_PR_HEAD_CORRUPT)
                    break;
            }
        }
        thread_yield();                             /* pending doorbells can make the next wait immediate */
    }
}
