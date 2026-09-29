/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 IPC client for the inter-kernel ABI: sends requests to the Kernel32 domain over
 * a shared-memory channel and waits for replies. The tests here deliberately include hostile
 * traffic (malformed slots, foreign buffers, stale generations, queue saturation) because
 * the peer must reject it without misbehaving.
 */
#include "k64.h"
#include "../abi/shz_ipc.h"

#define OP_ECHO 0x100
#define OP_SUM32 0x101
#define OP_CRC32 0x102
#define OP_TIME 0x103
#define OP_SESSION_END 0x1f0
#define OP_BOGUS 0x7777

static void *chan_base;
static size_t chan_size;
static shz_channel_hdr_t *chan;
static shz_ring_hdr_t *rx, *tx;
static shz_reqtab_t reqtab;
static ksem_t doorbell_sem;
static uint32_t peer;
uint32_t ipc64_results[16];
static unsigned failures;

void __attribute__((weak)) subsys64_doorbell(void) { }       /* subsys64.c: the WIN64 bridge shares the doorbell vector */
void ipc64_doorbell_irq(void) { sem_post(&doorbell_sem); subsys64_doorbell(); }

void ipc64_init(const shz_bootinfo_t *bi)
{
    unsigned c;
    sem_init(&doorbell_sem, 0);
    for (c = 0; c < bi->channel_count; ++c) {
        if (bi->channel[c].peer_domain != SHZ_DOM_KERNEL32)
            continue;
        chan_base = (void *)(DIRECT_MAP + bi->channel[c].gpa);
        chan_size = (size_t)bi->channel[c].size;
        chan = (shz_channel_hdr_t *)chan_base;
        KASSERT(shz_channel_valid(chan, chan_size));
        peer = bi->channel[c].peer_domain;
        rx = shz_channel_ring_rx(chan_base, chan, SHZ_DOM_KERNEL64);
        tx = shz_channel_ring_tx(chan_base, chan, SHZ_DOM_KERNEL64);
        KASSERT(shz_ring_valid(rx) && shz_ring_valid(tx));
        shz_reqtab_init(&reqtab, chan->generation, 1000);
    }
    KASSERT(chan != 0);
    KASSERT(shz_set_doorbell_vector(VEC_DOORBELL) == 0);
}

/* Synchronous call. Returns the reply status; *reply_len receives the inline reply size. */
static int call(uint32_t opcode, const void *payload, uint16_t len, uint64_t buf_off, uint32_t buf_len,
                uint32_t generation, void *reply, uint16_t *reply_len, uint32_t timeout_ms)
{
    shz_msg_hdr_t h, r;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    uint64_t id;
    int rc, reason;
    uint64_t deadline = ticks_now() + timeout_ms;
    memset(&h, 0, sizeof h);
    id = shz_req_begin(&reqtab, deadline);
    if (!id) return SHZ_E_QUEUE_FULL;
    h.opcode = opcode;
    h.request_id = id;
    h.src_domain = SHZ_DOM_KERNEL64;
    h.dst_domain = peer;
    h.generation = generation;
    h.payload_length = len;
    h.buffer_offset = buf_off;
    h.buffer_length = buf_len;
    if (buf_len) h.flags |= SHZ_MSGF_BUFFER;
    while ((rc = shz_ring_push(tx, &h, payload)) == SHZ_E_QUEUE_FULL)
        thread_sleep_ms(1);
    if (rc != SHZ_OK) { shz_req_cancel(&reqtab, id); return rc; }
    shz_notify(peer, 1);
    for (;;) {
        while ((rc = shz_ring_pop(rx, &r, pl, sizeof pl, &reason)) != SHZ_E_NOENT) {
            int done;
            if (rc != SHZ_OK) continue;
            done = shz_req_complete(&reqtab, &r);
            if (done == SHZ_OK && r.request_id == id) {
                if (reply && r.payload_length) memcpy(reply, pl, r.payload_length);
                if (reply_len) *reply_len = r.payload_length;
                return r.status;
            }
            if (done == SHZ_E_CANCELLED)
                ++ipc64_results[5];                /* late reply to a cancelled request was dropped */
        }
        if (sem_wait_timeout(&doorbell_sem, 5) && ticks_now() > deadline) {
            shz_req_cancel(&reqtab, id);
            return SHZ_E_TIMEOUT;
        }
    }
}

#define CHECK(name, cond, bit) do { if (cond) { kprintf("K64 ipc PASS: %s\n", name); ipc64_results[0] |= 1u << (bit); } \
    else { kprintf("K64 ipc FAIL: %s\n", name); ++failures; } } while (0)

static void inject_raw(void (*mutate)(uint8_t *slot))
{
    /* Writes a slot directly into our own transmit ring, as a buggy or hostile domain could. */
    const uint32_t head = tx->head;
    uint8_t *slot = (uint8_t *)tx + sizeof *tx + (size_t)(head & (tx->slot_count - 1)) * SHZ_MSG_SLOT_SIZE;
    shz_msg_hdr_t h;
    uint8_t pl[16] = "corrupt-me";
    memset(&h, 0, sizeof h);
    h.opcode = OP_ECHO; h.src_domain = SHZ_DOM_KERNEL64; h.dst_domain = peer; h.generation = chan->generation;
    h.payload_length = 10; h.request_id = 99999;
    KASSERT(shz_ring_push(tx, &h, pl) == SHZ_OK);       /* builds a valid slot, then we damage it */
    slot = (uint8_t *)tx + sizeof *tx + (size_t)(head & (tx->slot_count - 1)) * SHZ_MSG_SLOT_SIZE;
    mutate(slot);
}
static void bad_magic(uint8_t *s) { s[0] ^= 0xff; }
static void bad_checksum(uint8_t *s) { s[70] ^= 0x01; }
static void bad_size(uint8_t *s) { *(uint32_t *)(s + 0x0c) = 4000; }
static void bad_version(uint8_t *s) { *(uint16_t *)(s + 4) = 7; }

int ipc64_run_tests(void)
{
    uint8_t out[SHZ_MSG_MAX_INLINE], in[SHZ_MSG_MAX_INLINE];
    uint16_t rl;
    unsigned i, ok = 0, full = 0;
    uint64_t verified = 0, t_before, t_after;
    int rc;

    /* 1. echo with every inline size class */
    for (i = 0; i <= SHZ_MSG_MAX_INLINE; i += 8) {
        unsigned k;
        for (k = 0; k < i; ++k) in[k] = (uint8_t)(i * 7 + k);
        memset(out, 0, sizeof out);
        rc = call(OP_ECHO, in, (uint16_t)i, 0, 0, chan->generation, out, &rl, 1000);
        if (rc == SHZ_OK && rl == i && !memcmp(in, out, i)) { ++ok; verified += i; }
    }
    ipc64_results[1] = ok;
    CHECK("ECHO round trips for every payload size 0..192", ok == 25, 0);

    /* 2. shared buffer: K32 sums and checksums memory that K64 allocated in the pool */
    {
        const uint32_t words = 3000, bytes = words * 4;
        uint32_t expect = 0, got = 0;
        const uint64_t off = shz_pool_alloc(chan_base, chan, SHZ_DOM_KERNEL64, bytes);
        uint32_t *buf = (uint32_t *)((uint8_t *)chan_base + off);
        KASSERT(off);
        for (i = 0; i < words; ++i) { buf[i] = i * 2654435761u; expect += buf[i]; }
        rc = call(OP_SUM32, 0, 0, off, bytes, chan->generation, &got, &rl, 1000);
        CHECK("SUM32 over a 12000-byte shared buffer matches K64's own sum", rc == SHZ_OK && got == expect, 1);
        rc = call(OP_CRC32, 0, 0, off, bytes, chan->generation, &got, &rl, 1000);
        CHECK("CRC32 over the shared buffer matches K64's own CRC", rc == SHZ_OK && got == shz_crc32(buf, bytes), 2);
        verified += bytes;
        KASSERT(shz_pool_release(chan_base, chan, SHZ_DOM_KERNEL64, off, bytes, 0) == SHZ_OK);
        CHECK("double free of the buffer is refused", shz_pool_release(chan_base, chan, SHZ_DOM_KERNEL64, off, bytes, 0)
              == SHZ_E_DENIED, 3);
    }

    /* 3. buffer references that must be refused by the peer */
    rc = call(OP_SUM32, 0, 0, chan->pool_offset, 4096, chan->generation, 0, &rl, 1000);   /* nobody owns it */
    CHECK("reference to an unowned block is DENIED", rc == SHZ_E_DENIED, 4);
    rc = call(OP_SUM32, 0, 0, 0x100000000ull + chan->pool_offset, 64, chan->generation, 0, &rl, 1000);
    CHECK("buffer offset above 4 GiB is refused, not truncated", rc == SHZ_E_DENIED, 5);
    rc = call(OP_SUM32, 0, 0, chan->pool_offset + chan->pool_size - 16, 4096, chan->generation, 0, &rl, 1000);
    CHECK("buffer running past the pool is refused", rc == SHZ_E_DENIED, 6);

    /* 4. protocol errors */
    rc = call(OP_BOGUS, 0, 0, 0, 0, chan->generation, 0, &rl, 1000);
    CHECK("unknown opcode returns UNSUPPORTED", rc == SHZ_E_UNSUPPORTED, 7);
    rc = call(OP_ECHO, in, 4, 0, 0, chan->generation - 1, 0, &rl, 1000);
    CHECK("stale generation is rejected", rc == SHZ_E_STALE, 8);

    /* 5. hostile slots: the peer must drop them and keep serving */
    inject_raw(bad_magic); inject_raw(bad_checksum); inject_raw(bad_size); inject_raw(bad_version);
    shz_notify(peer, 1);
    thread_sleep_ms(30);
    rc = call(OP_ECHO, in, 8, 0, 0, chan->generation, out, &rl, 1000);
    CHECK("peer survives four malformed slots and still answers", rc == SHZ_OK && rl == 8 && !memcmp(in, out, 8), 9);

    /* 6. cancellation: the late reply is recognised and dropped */
    {
        shz_msg_hdr_t h;
        uint64_t id = shz_req_begin(&reqtab, ticks_now() + 1000);
        memset(&h, 0, sizeof h);
        h.opcode = OP_ECHO; h.request_id = id; h.src_domain = SHZ_DOM_KERNEL64; h.dst_domain = peer;
        h.generation = chan->generation; h.payload_length = 4;
        KASSERT(shz_ring_push(tx, &h, in) == SHZ_OK);
        KASSERT(shz_req_cancel(&reqtab, id) == SHZ_OK);
        shz_notify(peer, 1);
        thread_sleep_ms(30);
        {
            shz_msg_hdr_t r;
            uint8_t pl[SHZ_MSG_MAX_INLINE];
            int reason, popped = 0, cancelled = 0;
            while (shz_ring_pop(rx, &r, pl, sizeof pl, &reason) == SHZ_OK) {
                ++popped;
                if (shz_req_complete(&reqtab, &r) == SHZ_E_CANCELLED) ++cancelled;
            }
            CHECK("reply to a cancelled request is delivered to the tracker as CANCELLED", popped >= 1 && cancelled == 1, 10);
        }
    }

    /* 7. queue saturation without doorbells, then drain */
    {
        shz_msg_hdr_t h;
        unsigned sent = 0;
        memset(&h, 0, sizeof h);
        h.opcode = OP_ECHO; h.src_domain = SHZ_DOM_KERNEL64; h.dst_domain = peer; h.generation = chan->generation;
        h.payload_length = 4;
        for (i = 0; i < 400; ++i) {
            h.request_id = 5000 + i;
            rc = shz_ring_push(tx, &h, in);
            if (rc == SHZ_OK) ++sent; else if (rc == SHZ_E_QUEUE_FULL) ++full;
            if (i % 40 == 39) shz_notify(peer, 1);
        }
        shz_notify(peer, 1);
        {
            shz_msg_hdr_t r;
            uint8_t pl[SHZ_MSG_MAX_INLINE];
            int reason;
            unsigned got = 0;
            const uint64_t give_up = ticks_now() + 2000;
            /* The peer's reply ring is also finite: it blocks (back-pressure) until we drain it. */
            while (got < sent && ticks_now() < give_up) {
                if (shz_ring_pop(rx, &r, pl, sizeof pl, &reason) == SHZ_OK) ++got;
                else thread_sleep_ms(1);
            }
            ipc64_results[2] = sent; ipc64_results[3] = full; ipc64_results[4] = got;
            CHECK("ring saturation reports QUEUE_FULL and every accepted request is answered", full > 0 && got == sent, 11);
        }
    }

    /* 8. time service is monotonic across domains */
    {
        uint64_t t1 = 0, t2 = 0;
        t_before = shz_time_ns();
        rc = call(OP_TIME, 0, 0, 0, 0, chan->generation, &t1, &rl, 1000);
        thread_sleep_ms(5);
        call(OP_TIME, 0, 0, 0, 0, chan->generation, &t2, &rl, 1000);
        t_after = shz_time_ns();
        ipc64_results[6] = (uint32_t)((t2 - t1) / 1000);
        CHECK("cross-domain clock: K32 reports time between two K64 samples", rc == SHZ_OK && t1 >= t_before &&
              t2 > t1 && t2 <= t_after, 12);
    }

    ipc64_results[7] = (uint32_t)verified;
    shz_evidence(10, ipc64_results[1]);
    shz_evidence(13, ipc64_results[0]);
    shz_evidence(14, ipc64_results[2] | ((uint64_t)ipc64_results[3] << 16));
    shz_evidence(15, ipc64_results[4]);
    shz_evidence(25, verified);
    shz_evidence(26, ipc64_results[5]);
    shz_evidence(27, ipc64_results[6]);
    /* tell the peer we are done so it can exit */
    call(OP_SESSION_END, 0, 0, 0, 0, chan->generation, 0, &rl, 1000);
    return failures ? -1 : 0;
}
