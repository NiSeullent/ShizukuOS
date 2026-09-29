/* SPDX-License-Identifier: GPL-2.0-only
 * Host tests for the inter-kernel ABI library: layout, ring semantics, malformed
 * message rejection, request tracking, shared buffer ownership and an SPSC stress run.
 */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shz_ipc.h"

static unsigned long checks;
#define CHECK(cond) do { ++checks; if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); exit(1); } } while (0)

static uint8_t ring_mem[65536] __attribute__((aligned(64)));
static uint8_t chan_mem[1 << 20] __attribute__((aligned(4096)));

static void make(shz_msg_hdr_t *h, uint32_t op, uint64_t id, const void *payload, uint16_t len)
{
    memset(h, 0, sizeof *h);
    h->opcode = op;
    h->request_id = id;
    h->src_domain = SHZ_DOM_KERNEL32;
    h->dst_domain = SHZ_DOM_KERNEL64;
    h->payload_length = len;
    (void)payload;
}

static void test_ring_basic(void)
{
    shz_ring_hdr_t *r = (shz_ring_hdr_t *)ring_mem;
    shz_msg_hdr_t h, out;
    uint8_t payload[SHZ_MSG_MAX_INLINE], got[SHZ_MSG_MAX_INLINE];
    int reason, i;
    CHECK(shz_ring_init(ring_mem, sizeof ring_mem, 8) == SHZ_OK);
    CHECK(shz_ring_pop(r, &out, got, sizeof got, &reason) == SHZ_E_NOENT);
    for (i = 0; i < 8; ++i) {
        memset(payload, i, sizeof payload);
        make(&h, 100 + i, 1000 + i, payload, (uint16_t)(i * 20));
        CHECK(shz_ring_push(r, &h, payload) == SHZ_OK);
    }
    make(&h, 1, 1, 0, 0);
    CHECK(shz_ring_push(r, &h, 0) == SHZ_E_QUEUE_FULL);
    for (i = 0; i < 8; ++i) {
        CHECK(shz_ring_pop(r, &out, got, sizeof got, &reason) == SHZ_OK);
        CHECK(out.opcode == (uint32_t)(100 + i) && out.request_id == (uint64_t)(1000 + i));
        CHECK(out.payload_length == i * 20);
        if (out.payload_length) CHECK(got[0] == i && got[out.payload_length - 1] == i);
    }
    CHECK(shz_ring_pop(r, &out, got, sizeof got, &reason) == SHZ_E_NOENT);
    /* wrap-around across many index overflows of the 32-bit counters */
    r->head = r->tail = 0xfffffff0u;
    for (i = 0; i < 100; ++i) {
        make(&h, 7, (uint64_t)i, 0, 0);
        CHECK(shz_ring_push(r, &h, 0) == SHZ_OK);
        CHECK(shz_ring_pop(r, &out, 0, 0, &reason) == SHZ_OK && out.request_id == (uint64_t)i);
    }
    /* oversize inline payload is refused by the sender */
    make(&h, 1, 1, payload, SHZ_MSG_MAX_INLINE + 1);
    CHECK(shz_ring_push(r, &h, payload) == SHZ_E_RANGE);
    make(&h, 1, 1, 0, 4);
    CHECK(shz_ring_push(r, &h, 0) == SHZ_E_RANGE);          /* length without data */
    CHECK(shz_ring_init(ring_mem, sizeof ring_mem, 6) == SHZ_E_INVALID);   /* not a power of two */
    CHECK(shz_ring_init(ring_mem, 100, 8) == SHZ_E_INVALID);               /* too small */
}

static void corrupt_and_expect(const char *name, void (*mutate)(shz_msg_hdr_t *, uint8_t *), int want)
{
    shz_ring_hdr_t *r = (shz_ring_hdr_t *)ring_mem;
    shz_msg_hdr_t h, out;
    uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8}, got[64];
    int reason = -1;
    CHECK(shz_ring_init(ring_mem, sizeof ring_mem, 8) == SHZ_OK);
    make(&h, 5, 55, payload, 8);
    CHECK(shz_ring_push(r, &h, payload) == SHZ_OK);
    mutate((shz_msg_hdr_t *)shz_ring_slot(r, 0), shz_ring_slot(r, 0));
    make(&h, 6, 66, 0, 0);
    CHECK(shz_ring_push(r, &h, 0) == SHZ_OK);               /* a good message behind the bad one */
    CHECK(shz_ring_pop(r, &out, got, sizeof got, &reason) == SHZ_E_PROTO);
    if (reason != want) { fprintf(stderr, "%s: reason %d want %d\n", name, reason, want); exit(1); }
    CHECK(shz_ring_pop(r, &out, got, sizeof got, &reason) == SHZ_OK && out.opcode == 6);   /* not wedged */
}
static void m_magic(shz_msg_hdr_t *h, uint8_t *s) { (void)s; h->magic ^= 1; }
static void m_major(shz_msg_hdr_t *h, uint8_t *s) { (void)s; h->abi_major = 9; }
static void m_hsize(shz_msg_hdr_t *h, uint8_t *s) { (void)s; h->header_size = 32; }
static void m_msize_small(shz_msg_hdr_t *h, uint8_t *s) { (void)s; h->message_size = 8; }
static void m_msize_big(shz_msg_hdr_t *h, uint8_t *s) { (void)s; h->message_size = 4096; }
static void m_plen(shz_msg_hdr_t *h, uint8_t *s) { (void)s; h->payload_length = 60000; }
static void m_poff(shz_msg_hdr_t *h, uint8_t *s) { (void)s; h->payload_offset = 200; }
static void m_payload_bit(shz_msg_hdr_t *h, uint8_t *s) { (void)h; s[70] ^= 0x10; }
static void m_status_bit(shz_msg_hdr_t *h, uint8_t *s) { (void)s; h->status ^= 0x100; }

static void test_malformed(void)
{
    corrupt_and_expect("magic", m_magic, SHZ_PR_MAGIC);
    corrupt_and_expect("major", m_major, SHZ_PR_VERSION);
    corrupt_and_expect("header_size", m_hsize, SHZ_PR_HEADER_SIZE);
    corrupt_and_expect("message_size small", m_msize_small, SHZ_PR_MESSAGE_SIZE);
    corrupt_and_expect("message_size big", m_msize_big, SHZ_PR_MESSAGE_SIZE);
    corrupt_and_expect("payload_length", m_plen, SHZ_PR_MESSAGE_SIZE);
    corrupt_and_expect("payload_offset", m_poff, SHZ_PR_PAYLOAD_RANGE);
    corrupt_and_expect("payload bit flip", m_payload_bit, SHZ_PR_CHECKSUM);
    corrupt_and_expect("header bit flip", m_status_bit, SHZ_PR_CHECKSUM);
    /* corrupt producer index */
    {
        shz_ring_hdr_t *r = (shz_ring_hdr_t *)ring_mem;
        shz_msg_hdr_t out;
        int reason;
        CHECK(shz_ring_init(ring_mem, sizeof ring_mem, 8) == SHZ_OK);
        r->head = 1000;
        CHECK(shz_ring_pop(r, &out, 0, 0, &reason) == SHZ_E_PROTO && reason == SHZ_PR_HEAD_CORRUPT);
    }
    /* receiver buffer too small for the payload */
    {
        shz_ring_hdr_t *r = (shz_ring_hdr_t *)ring_mem;
        shz_msg_hdr_t h, out;
        uint8_t pl[32] = {0}, small[8];
        int reason;
        CHECK(shz_ring_init(ring_mem, sizeof ring_mem, 8) == SHZ_OK);
        make(&h, 1, 1, pl, 32);
        CHECK(shz_ring_push(r, &h, pl) == SHZ_OK);
        CHECK(shz_ring_pop(r, &out, small, sizeof small, &reason) == SHZ_E_PROTO && reason == SHZ_PR_PAYLOAD_RANGE);
    }
}

static void test_fuzz(void)
{
    shz_ring_hdr_t *r = (shz_ring_hdr_t *)ring_mem;
    shz_msg_hdr_t out;
    uint8_t got[SHZ_MSG_MAX_INLINE];
    unsigned long accepted = 0, iter;
    unsigned seed = 12345;
    CHECK(shz_ring_init(ring_mem, sizeof ring_mem, 8) == SHZ_OK);
    for (iter = 0; iter < 200000; ++iter) {
        uint8_t *slot = shz_ring_slot(r, r->head);
        size_t i;
        int reason, rc;
        for (i = 0; i < SHZ_MSG_SLOT_SIZE; ++i) {
            seed = seed * 1103515245u + 12345u;
            slot[i] = (uint8_t)(seed >> 16);
        }
        if (iter & 1) {                     /* half the time start from a plausible header */
            shz_msg_hdr_t h;
            make(&h, 9, iter, 0, 0);
            h.magic = SHZ_MSG_MAGIC; h.abi_major = SHZ_ABI_MAJOR; h.header_size = 64; h.message_size = 64;
            h.checksum = 0;
            memcpy(slot, &h, sizeof h);
            slot[iter % 64] ^= (uint8_t)(1u << (iter % 8));   /* single flipped bit somewhere in the header */
        }
        r->head += 1;
        rc = shz_ring_pop(r, &out, got, sizeof got, &reason);
        if (rc == SHZ_OK) {
            /* An accepted message must be internally consistent and carry a valid checksum. */
            uint8_t copy[SHZ_MSG_SLOT_SIZE];
            ++accepted;
            CHECK(out.message_size == 64u + out.payload_length);
            memcpy(copy, &out, sizeof out);
            ((shz_msg_hdr_t *)copy)->checksum = 0;
            memcpy(copy + 64, got, out.payload_length);
            CHECK(shz_crc32(copy, out.message_size) == out.checksum);
        }
        CHECK(r->tail == r->head);          /* the slot is always consumed */
    }
    CHECK(accepted == 0);                   /* random data must not produce valid CRC + structure */
}

static void test_requests(void)
{
    shz_reqtab_t t;
    shz_msg_hdr_t reply;
    uint64_t a, b, ids[SHZ_REQ_SLOTS];
    unsigned i;
    shz_reqtab_init(&t, 5, 100);
    a = shz_req_begin(&t, 1000);
    b = shz_req_begin(&t, 2000);
    CHECK(a == 100 && b == 101);
    memset(&reply, 0, sizeof reply);
    reply.generation = 5; reply.request_id = a;
    CHECK(shz_req_complete(&t, &reply) == SHZ_OK);
    CHECK(shz_req_complete(&t, &reply) == SHZ_E_NOENT);            /* duplicate */
    reply.request_id = 9999;
    CHECK(shz_req_complete(&t, &reply) == SHZ_E_NOENT);            /* unknown */
    reply.request_id = b; reply.generation = 4;
    CHECK(shz_req_complete(&t, &reply) == SHZ_E_STALE);            /* stale generation */
    CHECK(shz_req_cancel(&t, b) == SHZ_OK);
    reply.generation = 5;
    CHECK(shz_req_complete(&t, &reply) == SHZ_E_CANCELLED);        /* cancelled then answered */
    CHECK(shz_req_cancel(&t, b) == SHZ_E_NOENT);
    a = shz_req_begin(&t, 50);
    CHECK(shz_req_expire(&t, 49) == 0 && shz_req_expire(&t, 50) == 1);
    reply.request_id = a;
    CHECK(shz_req_complete(&t, &reply) == SHZ_E_CANCELLED);        /* timed out then answered late */
    for (i = 0; i < SHZ_REQ_SLOTS; ++i) { ids[i] = shz_req_begin(&t, 1); CHECK(ids[i]); }
    CHECK(shz_req_begin(&t, 1) == 0);                              /* table full */
    shz_reqtab_reset(&t, 6);                                       /* peer restarted */
    reply.request_id = ids[0]; reply.generation = 5;
    CHECK(shz_req_complete(&t, &reply) == SHZ_E_STALE);
    reply.generation = 6;
    CHECK(shz_req_complete(&t, &reply) == SHZ_E_NOENT);            /* old id no longer valid */
}

static void test_channel_and_pool(void)
{
    shz_channel_hdr_t *c = (shz_channel_hdr_t *)chan_mem;
    shz_msg_hdr_t m;
    uint64_t o1, o2, o3;
    uint32_t i;
    CHECK(shz_channel_init(chan_mem, sizeof chan_mem, 1, SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64, 16, 3) == SHZ_OK);
    CHECK(shz_channel_valid(c, sizeof chan_mem));
    CHECK(c->pool_offset % SHZ_POOL_BLOCK == 0 && c->pool_offset + c->pool_size <= sizeof chan_mem);
    CHECK(c->ring_ab_offset >= sizeof *c + shz_pool_blocks(c));    /* table fits before the rings */
    CHECK(shz_channel_ring_tx(chan_mem, c, SHZ_DOM_KERNEL32) != shz_channel_ring_tx(chan_mem, c, SHZ_DOM_KERNEL64));
    CHECK(shz_channel_ring_tx(chan_mem, c, SHZ_DOM_KERNEL32) == shz_channel_ring_rx(chan_mem, c, SHZ_DOM_KERNEL64));
    o1 = shz_pool_alloc(chan_mem, c, SHZ_DOM_KERNEL32, 5000);      /* two blocks */
    o2 = shz_pool_alloc(chan_mem, c, SHZ_DOM_KERNEL64, 4096);
    CHECK(o1 && o2 && o2 == o1 + 8192);
    CHECK(shz_pool_release(chan_mem, c, SHZ_DOM_KERNEL64, o1, 5000, 0) == SHZ_E_DENIED);   /* not owner */
    CHECK(shz_pool_release(chan_mem, c, SHZ_DOM_KERNEL32, o1, 5000, 0) == SHZ_OK);
    CHECK(shz_pool_release(chan_mem, c, SHZ_DOM_KERNEL32, o1, 5000, 0) == SHZ_E_DENIED);   /* double free */
    CHECK(shz_pool_release(chan_mem, c, SHZ_DOM_KERNEL32, o1 + 1, 16, 0) == SHZ_E_RANGE);  /* unaligned */
    memset(&m, 0, sizeof m);
    m.buffer_offset = o2; m.buffer_length = 4096;
    CHECK(shz_pool_check(chan_mem, c, &m, SHZ_DOM_KERNEL64) == SHZ_OK);
    CHECK(shz_pool_check(chan_mem, c, &m, SHZ_DOM_KERNEL32) == SHZ_E_DENIED);
    CHECK(shz_pool_release(chan_mem, c, SHZ_DOM_KERNEL64, o2, 4096, SHZ_DOM_KERNEL32) == SHZ_OK);   /* transfer */
    CHECK(shz_pool_check(chan_mem, c, &m, SHZ_DOM_KERNEL32) == SHZ_OK);
    /* references that would wrap or exceed the pool, including offsets above 4 GiB */
    m.buffer_offset = 0xfffffffffffff000ull; m.buffer_length = 0x2000;
    CHECK(shz_pool_check(chan_mem, c, &m, SHZ_DOM_KERNEL32) == SHZ_E_RANGE);
    m.buffer_offset = 0x100000000ull + c->pool_offset; m.buffer_length = 16;
    CHECK(shz_pool_check(chan_mem, c, &m, SHZ_DOM_KERNEL32) == SHZ_E_RANGE);     /* not truncated to 32 bits */
    m.buffer_offset = c->pool_offset; m.buffer_length = 0xffffffffu;
    CHECK(shz_pool_check(chan_mem, c, &m, SHZ_DOM_KERNEL32) == SHZ_E_RANGE);
    /* exhaustion and reuse */
    for (i = 0; i < shz_pool_blocks(c); ++i)
        if (!shz_pool_alloc(chan_mem, c, SHZ_DOM_KERNEL32, 1)) break;
    CHECK(shz_pool_alloc(chan_mem, c, SHZ_DOM_KERNEL32, 1) == 0);
    o3 = c->pool_offset;
    CHECK(shz_pool_release(chan_mem, c, SHZ_DOM_KERNEL32, o3, 1, 0) == SHZ_OK);
    CHECK(shz_pool_alloc(chan_mem, c, SHZ_DOM_KERNEL32, 1) == o3);
    /* corrupt headers are rejected */
    c->magic ^= 1;
    CHECK(!shz_channel_valid(c, sizeof chan_mem));
    c->magic ^= 1;
    c->pool_size = 0xffffffffffffffffull;
    CHECK(!shz_channel_valid(c, sizeof chan_mem));
    /* a 64-bit buffer offset survives a round trip unchanged */
    {
        shz_ring_hdr_t *r;
        shz_msg_hdr_t out, h;
        int reason;
        CHECK(shz_channel_init(chan_mem, sizeof chan_mem, 1, SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64, 16, 3) == SHZ_OK);
        c = (shz_channel_hdr_t *)chan_mem;
        r = shz_channel_ring_tx(chan_mem, c, SHZ_DOM_KERNEL32);
        make(&h, 1, 1, 0, 0);
        h.buffer_offset = 0x123456789abcdef0ull; h.buffer_length = 77;
        CHECK(shz_ring_push(r, &h, 0) == SHZ_OK);
        CHECK(shz_ring_pop(shz_channel_ring_rx(chan_mem, c, SHZ_DOM_KERNEL64), &out, 0, 0, &reason) == SHZ_OK);
        CHECK(out.buffer_offset == 0x123456789abcdef0ull && out.buffer_length == 77);
    }
}

#define STRESS_N 1000000u
static shz_ring_hdr_t *g_ring;
static void *producer(void *arg)
{
    uint32_t i;
    (void)arg;
    for (i = 0; i < STRESS_N; ++i) {
        shz_msg_hdr_t h;
        uint8_t pl[24];
        int rc;
        memset(&h, 0, sizeof h);
        h.opcode = 1; h.request_id = i; h.payload_length = sizeof pl;
        memset(pl, (int)(i & 0xff), sizeof pl);
        while ((rc = shz_ring_push(g_ring, &h, pl)) == SHZ_E_QUEUE_FULL) { }
        assert(rc == SHZ_OK);
    }
    return 0;
}
static void test_stress(void)
{
    pthread_t t;
    uint32_t next = 0;
    CHECK(shz_ring_init(ring_mem, sizeof ring_mem, 64) == SHZ_OK);
    g_ring = (shz_ring_hdr_t *)ring_mem;
    pthread_create(&t, 0, producer, 0);
    while (next < STRESS_N) {
        shz_msg_hdr_t out;
        uint8_t got[64];
        int reason, rc = shz_ring_pop(g_ring, &out, got, sizeof got, &reason);
        if (rc == SHZ_E_NOENT) continue;
        CHECK(rc == SHZ_OK);
        CHECK(out.request_id == next && got[0] == (uint8_t)(next & 0xff) && got[23] == (uint8_t)(next & 0xff));
        ++next;
    }
    pthread_join(t, 0);
    CHECK(shz_ring_count(g_ring) == 0);
}

static void emit_sample(const char *path)
{
    shz_ring_hdr_t *r = (shz_ring_hdr_t *)ring_mem;
    shz_msg_hdr_t h;
    uint8_t pl[16] = "wire-format-v1!";
    FILE *f;
    CHECK(shz_ring_init(ring_mem, sizeof ring_mem, 4) == SHZ_OK);
    make(&h, 0x1234, 0x1122334455667788ull, pl, 16);
    h.generation = 7; h.status = -3; h.capability_id = 0xabcd; h.buffer_offset = 0x100000010ull; h.buffer_length = 99;
    CHECK(shz_ring_push(r, &h, pl) == SHZ_OK);
    f = fopen(path, "wb");
    CHECK(f && fwrite(shz_ring_slot(r, 0), 1, SHZ_MSG_SLOT_SIZE, f) == SHZ_MSG_SLOT_SIZE);
    fclose(f);
}

int main(int argc, char **argv)
{
    test_ring_basic();
    test_malformed();
    test_fuzz();
    test_requests();
    test_channel_and_pool();
    test_stress();
    if (argc > 1)
        emit_sample(argv[1]);
    printf("ABI host model: %lu checks passed (sizeof msg=%zu ring=%zu channel=%zu bootinfo=%zu)\n", checks,
           sizeof(shz_msg_hdr_t), sizeof(shz_ring_hdr_t), sizeof(shz_channel_hdr_t), sizeof(shz_bootinfo_t));
    return 0;
}
