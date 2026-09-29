/* SPDX-License-Identifier: GPL-2.0-only
 * Host unit test for the split virtqueue ring model (kernel64/virtq.c) against a simulated device that follows the
 * Virtio 1.2 device-side rules: it walks descriptor chains from the available ring, checks the driver's descriptor
 * flags (readable buffers first, then writable ones, F_NEXT on every descriptor but the last), fills the writable
 * buffers, and returns chains through the used ring in a random order, sometimes with VIRTQ_USED_F_NO_NOTIFY set.
 * Physical addresses are host pointers here. Run by tests/test_virtio_host.py with ASan/UBSan. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../virtq.h"

static unsigned long long failures, checks;
#define CHECK(cond, ...) do { ++checks; if (!(cond)) { ++failures; printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(void) { rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17; return (uint32_t)(rng_state >> 11); }

/* ---- the driver side: a chain = one request record ---- */
typedef struct {
    uint32_t id;
    unsigned n_out, n_in;
    uint8_t out[4][64];
    uint8_t in[4][64];
    unsigned out_len[4], in_len[4];
    int in_flight;
    uint32_t written;                       /* what the device reported */
} req_t;

/* ---- the simulated device ---- */
typedef struct { uint16_t head; uint32_t written; } pending_t;
typedef struct {
    virtq_t *q;
    uint16_t last_avail;
    pending_t pending[VIRTQ_MAX_SIZE];
    unsigned n_pending;
    unsigned long long chains_seen, bytes_read;
    int seen_ids[VIRTQ_MAX_SIZE];           /* per head: how many times it was handed to the device while in flight */
} simdev_t;

static void dev_fetch(simdev_t *d)
{
    virtq_t *q = d->q;
    while (d->last_avail != q->avail->idx) {
        const uint16_t head = q->avail->ring[d->last_avail % q->size];
        uint16_t cur = head;
        unsigned n = 0, seen_write = 0;
        uint32_t written = 0;
        uint8_t sum = 0;
        CHECK(head < q->size, "device: avail ring entry %u out of range", head);
        CHECK(d->seen_ids[head] == 0, "device: head %u handed out twice while in flight", head);
        d->seen_ids[head] = 1;
        for (;;) {
            const virtq_desc_t *desc = &q->desc[cur];
            uint8_t *p = (uint8_t *)(uintptr_t)desc->addr;
            unsigned k;
            ++n;
            CHECK(n <= q->size, "device: chain longer than the ring");
            CHECK(!(desc->flags & VIRTQ_DESC_F_INDIRECT), "device: indirect descriptors were not negotiated");
            if (desc->flags & VIRTQ_DESC_F_WRITE) {
                seen_write = 1;
                for (k = 0; k < desc->len; ++k) p[k] = (uint8_t)(0xA0 + k + sum);      /* the device's answer depends on the request */
                written += desc->len;
            } else {
                CHECK(!seen_write, "device: readable descriptor after a writable one");
                for (k = 0; k < desc->len; ++k) sum = (uint8_t)(sum + p[k]);
                d->bytes_read += desc->len;
            }
            if (!(desc->flags & VIRTQ_DESC_F_NEXT)) break;
            CHECK(desc->next < q->size, "device: bad next link");
            cur = desc->next;
        }
        d->pending[d->n_pending].head = head;
        d->pending[d->n_pending].written = written;
        ++d->n_pending;
        ++d->chains_seen;
        ++d->last_avail;
    }
}

static void dev_complete(simdev_t *d, unsigned max)
{
    virtq_t *q = d->q;
    while (d->n_pending && max--) {
        const unsigned pick = rnd() % d->n_pending;      /* out of order, as a real device may */
        const pending_t e = d->pending[pick];
        d->pending[pick] = d->pending[--d->n_pending];
        q->used->ring[q->used->idx % q->size].id = e.head;
        q->used->ring[q->used->idx % q->size].len = e.written;
        VIRTQ_WMB();
        q->used->idx = (uint16_t)(q->used->idx + 1);
        d->seen_ids[e.head] = 0;
    }
}

/* ---- driver-side reaping ---- */
static void reap(virtq_t *q, unsigned *in_flight)
{
    void *c;
    uint32_t written;
    while ((c = virtq_get_used(q, &written)) != 0) {
        req_t *r = c;
        unsigned k, i, expect = 0;
        uint8_t sum = 0;
        CHECK(r->in_flight == 1, "reaped a request that was not in flight (id %u)", r->id);
        r->in_flight = 0;
        for (i = 0; i < r->n_out; ++i) for (k = 0; k < r->out_len[i]; ++k) sum = (uint8_t)(sum + r->out[i][k]);
        for (i = 0; i < r->n_in; ++i) {
            expect += r->in_len[i];
            for (k = 0; k < r->in_len[i]; ++k)
                if (r->in[i][k] != (uint8_t)(0xA0 + k + sum)) { CHECK(0, "device answer corrupted (req %u buf %u byte %u)", r->id, i, k); break; }
        }
        CHECK(written == expect, "written length %u, expected %u (req %u)", written, expect, r->id);
        --*in_flight;
    }
}

static int alloc_ring(virtq_t *q, uint16_t index, uint16_t size)
{
    void *desc = aligned_alloc(16, (virtq_desc_bytes(size) + 15) & ~15u);
    void *avail = aligned_alloc(16, (virtq_avail_bytes(size) + 15) & ~15u);
    void *used = aligned_alloc(16, (virtq_used_bytes(size) + 15) & ~15u);
    void **cookies = calloc(size, sizeof(void *));
    uint16_t *chain = calloc(size, sizeof(uint16_t));
    memset(desc, 0, virtq_desc_bytes(size));
    memset(avail, 0, virtq_avail_bytes(size));
    memset(used, 0, virtq_used_bytes(size));
    return virtq_init(q, index, size, desc, (uint64_t)(uintptr_t)desc, avail, (uint64_t)(uintptr_t)avail, used,
                      (uint64_t)(uintptr_t)used, cookies, chain);
}

static void free_ring(virtq_t *q) { free(q->desc); free(q->avail); free(q->used); free(q->cookie); free(q->chain_len); }

static int submit(virtq_t *q, req_t *r, unsigned n_out, unsigned n_in)
{
    virtq_sg_t out[4], in[4];
    unsigned i, k;
    r->n_out = n_out;
    r->n_in = n_in;
    for (i = 0; i < n_out; ++i) {
        r->out_len[i] = 1 + rnd() % 64;
        for (k = 0; k < r->out_len[i]; ++k) r->out[i][k] = (uint8_t)rnd();
        out[i].pa = (uint64_t)(uintptr_t)r->out[i];
        out[i].len = r->out_len[i];
    }
    for (i = 0; i < n_in; ++i) {
        r->in_len[i] = 1 + rnd() % 64;
        memset(r->in[i], 0, sizeof r->in[i]);
        in[i].pa = (uint64_t)(uintptr_t)r->in[i];
        in[i].len = r->in_len[i];
    }
    return virtq_add(q, out, n_out, in, n_in, r);
}

/* Scenario 1: fill the ring completely, verify -1 when full, complete everything, verify all descriptors return. */
static void test_fill_and_drain(uint16_t size)
{
    virtq_t q;
    simdev_t dev;
    req_t reqs[64];
    unsigned i, n = 0, in_flight = 0;
    CHECK(alloc_ring(&q, 0, size) == 0, "init size %u", size);
    memset(&dev, 0, sizeof dev);
    dev.q = &q;
    for (i = 0; i < 64; ++i) {
        reqs[i].id = i;
        if (submit(&q, &reqs[i], 1, 1) < 0) break;
        reqs[i].in_flight = 1;
        ++in_flight;
        ++n;
    }
    CHECK(n == size / 2, "size %u: %u two-descriptor chains fit (expected %u)", size, n, size / 2);
    CHECK(virtq_num_free(&q) == 0, "ring is full");
    CHECK(submit(&q, &reqs[63], 1, 0) == -1, "add on a full ring fails");
    CHECK(virtq_kick_prepare(&q) == 1, "the first kick is needed");
    CHECK(virtq_kick_prepare(&q) == 0, "nothing new: no kick");
    CHECK(q.avail->idx == n, "avail idx published %u", q.avail->idx);
    CHECK(!virtq_has_used(&q), "nothing used yet");
    dev_fetch(&dev);
    CHECK(dev.chains_seen == n, "device saw every chain (%llu)", dev.chains_seen);
    dev_complete(&dev, 1000);
    CHECK(virtq_has_used(&q), "used ring has entries");
    reap(&q, &in_flight);
    CHECK(in_flight == 0, "all %u requests completed", n);
    CHECK(virtq_num_free(&q) == size, "every descriptor is free again (%u)", virtq_num_free(&q));
    CHECK(q.n_added == n && q.n_completed == n && q.n_kicks == 1, "statistics %llu %llu %llu", (unsigned long long)q.n_added, (unsigned long long)q.n_completed, (unsigned long long)q.n_kicks);
    free_ring(&q);
}

/* Scenario 2: a long random interleaving on a small ring: index wrap-around (>65536 chains), out-of-order completion,
 * chains of 1..8 descriptors, notification suppression by the device. */
static void test_long_random(uint16_t size, unsigned iterations)
{
    virtq_t q;
    simdev_t dev;
    req_t *reqs = calloc(size, sizeof(req_t));
    unsigned it, in_flight = 0, submitted = 0, kicks = 0, suppressed = 0;
    CHECK(alloc_ring(&q, 1, size) == 0, "init size %u", size);
    memset(&dev, 0, sizeof dev);
    dev.q = &q;
    for (it = 0; it < iterations; ++it) {
        const unsigned op = rnd() % 10;
        if (op < 5) {                                       /* driver: submit a random chain into a free request slot */
            unsigned s;
            for (s = 0; s < size; ++s) if (!reqs[s].in_flight) break;
            if (s < size) {
                const unsigned n_out = rnd() % 5, n_in = rnd() % 5;
                if (n_out + n_in) {
                    const int head = submit(&q, &reqs[s], n_out, n_in);
                    const unsigned before = virtq_num_free(&q);
                    (void)before;
                    if (head >= 0) {
                        reqs[s].id = submitted++;
                        reqs[s].in_flight = 1;
                        ++in_flight;
                    } else {
                        CHECK(virtq_num_free(&q) < n_out + n_in, "add failed although %u descriptors are free", virtq_num_free(&q));
                    }
                }
            }
        } else if (op < 7) {                                /* driver: kick */
            const int want = virtq_kick_prepare(&q);
            const int dev_wants = !(q.used->flags & VIRTQ_USED_F_NO_NOTIFY);
            if (want) ++kicks; else if (q.avail_pending == 0) ++suppressed;
            if (want) CHECK(dev_wants, "kick requested while the device suppressed notifications");
        } else if (op == 7) {                               /* device: fetch what was published, maybe toggle NO_NOTIFY */
            dev_fetch(&dev);
            q.used->flags = (rnd() & 1) ? VIRTQ_USED_F_NO_NOTIFY : 0;
        } else if (op == 8) {                               /* device: complete a few, out of order */
            dev_complete(&dev, 1 + rnd() % 4);
        } else {                                            /* driver: reap */
            reap(&q, &in_flight);
        }
        if (failures > 20) break;
    }
    q.used->flags = 0;
    virtq_kick_prepare(&q);
    dev_fetch(&dev);
    dev_complete(&dev, 100000);
    reap(&q, &in_flight);
    CHECK(in_flight == 0, "drained: %u still in flight", in_flight);
    CHECK(virtq_num_free(&q) == size, "drained: %u of %u descriptors free", virtq_num_free(&q), size);
    CHECK(submitted > 70000, "index wrap-around exercised: %u chains on a %u-entry ring", submitted, size);
    CHECK(q.n_completed == submitted, "completed %llu of %u", (unsigned long long)q.n_completed, submitted);
    printf("  long run: size %u, %u chains, %u kicks, %llu bytes read by the device, avail idx %u used idx %u\n", size, submitted,
           kicks, dev.bytes_read, q.avail->idx, q.used->idx);
    free(reqs);
    free_ring(&q);
}

/* Scenario 3: interrupt suppression flag and a used entry with a bogus id. */
static void test_flags_and_bogus(void)
{
    virtq_t q;
    req_t r;
    uint32_t w = 7;
    CHECK(alloc_ring(&q, 2, 4) == 0, "init");
    virtq_suppress_interrupts(&q, 1);
    CHECK(q.avail->flags == VIRTQ_AVAIL_F_NO_INTERRUPT, "NO_INTERRUPT set");
    virtq_suppress_interrupts(&q, 0);
    CHECK(q.avail->flags == 0, "NO_INTERRUPT cleared");
    memset(&r, 0, sizeof r);
    CHECK(submit(&q, &r, 2, 0) == 0, "first chain starts at descriptor 0");
    q.used->ring[0].id = 3;                             /* never handed out */
    q.used->ring[0].len = 99;
    q.used->idx = 1;
    CHECK(virtq_get_used(&q, &w) == 0 && w == 0, "a used entry for a descriptor the driver never exposed is ignored");
    CHECK(virtq_num_free(&q) == 2, "the bogus completion freed nothing");
    q.used->ring[1].id = 0;
    q.used->ring[1].len = 0;
    q.used->idx = 2;
    CHECK(virtq_get_used(&q, &w) == &r, "the real completion is returned");
    CHECK(virtq_num_free(&q) == 4, "its two descriptors are free again");
    CHECK(virtq_init(&q, 0, 0, q.desc, 0, q.avail, 0, q.used, 0, q.cookie, q.chain_len) == -1, "size 0 rejected");
    free_ring(&q);
}

int main(void)
{
    test_fill_and_drain(8);
    test_fill_and_drain(64);
    test_flags_and_bogus();
    test_long_random(16, 800000);
    test_long_random(256, 300000);
    printf("virtq: %llu checks, %llu failed\n", checks, failures);
    return failures ? 1 : 0;
}
