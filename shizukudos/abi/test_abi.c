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

/* ------------------------------------------------------------------ WIN64 subsystem family (ABI 1.1) */
static void w64_str(uint16_t *out, const char *s, uint32_t *n)
{
    uint32_t i;
    for (i = 0; s[i]; ++i) out[i] = (uint8_t)s[i];
    *n = i;
}

/* Round trip: pack -> push -> pop -> check, inline and through the pool, then every hostile variation. */
static void test_w64_family(void)
{
    shz_channel_hdr_t *c = (shz_channel_hdr_t *)chan_mem;
    shz_ring_hdr_t *tx;
    shz_msg_hdr_t h, out;
    shz_w64_create_t ch, got_hdr;
    uint16_t path[64], cmd[2100], cwd[64], block[2200];
    uint8_t pl[SHZ_MSG_MAX_INLINE], rx[SHZ_MSG_MAX_INLINE];
    uint32_t np, nc, nw, bytes, i;
    const uint16_t *blk;
    int pool, reason;
    uint64_t off;

    CHECK(shz_channel_init(chan_mem, sizeof chan_mem, 2, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, 1) == SHZ_OK);
    tx = shz_channel_ring_tx(chan_mem, c, SHZ_DOM_WIN98);
    CHECK(tx == shz_channel_ring_rx(chan_mem, c, SHZ_DOM_KERNEL64));
    w64_str(path, "C:\\SHZ\\TESTS\\T_HELLO.EXE", &np);
    w64_str(cmd, "T_HELLO.EXE first", &nc);
    w64_str(cwd, "C:\\SHZ\\TESTS", &nw);

    /* 1. inline block */
    bytes = shz_w64_create_pack(&ch, path, np, cmd, nc, cwd, nw, block, 2200, &pool);
    CHECK(bytes == 2 * (np + nc + nw) && !pool && ch.block_bytes == bytes);
    memcpy(pl, &ch, sizeof ch);
    memcpy(pl + sizeof ch, block, bytes);
    make(&h, SHZ_OP_W64_CREATE_PROCESS, 1, pl, (uint16_t)(sizeof ch + bytes));
    h.src_domain = SHZ_DOM_WIN98; h.dst_domain = SHZ_DOM_KERNEL64;
    CHECK(shz_ring_push(tx, &h, pl) == SHZ_OK);
    CHECK(shz_ring_pop(tx, &out, rx, sizeof rx, &reason) == SHZ_OK && out.abi_minor == 1);
    CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_OK);
    CHECK(got_hdr.path_chars == np && got_hdr.cmdline_chars == nc && got_hdr.cwd_chars == nw);
    CHECK(!memcmp(blk, block, bytes) && blk[np] == 'T' && blk[np + nc] == 'C');
    CHECK(shz_w64_create_check(&out, rx, c, 0, &got_hdr, &blk) == SHZ_OK);       /* inline needs no pool */

    /* 2. block too big for a slot: goes through the pool, owned by the sender */
    for (i = 0; i < 1000; ++i) cmd[i] = (uint16_t)('a' + i % 26);
    nc = 1000;
    bytes = shz_w64_create_pack(&ch, path, np, cmd, nc, cwd, nw, block, 2200, &pool);
    CHECK(bytes == 2 * (np + nc + nw) && pool);
    off = shz_pool_alloc(chan_mem, c, SHZ_DOM_WIN98, bytes);
    CHECK(off != 0);
    memcpy(chan_mem + off, block, bytes);
    make(&h, SHZ_OP_W64_CREATE_PROCESS, 2, &ch, sizeof ch);
    h.src_domain = SHZ_DOM_WIN98; h.dst_domain = SHZ_DOM_KERNEL64;
    h.flags = SHZ_MSGF_BUFFER; h.buffer_offset = off; h.buffer_length = bytes;
    CHECK(shz_ring_push(tx, &h, &ch) == SHZ_OK);
    CHECK(shz_ring_pop(tx, &out, rx, sizeof rx, &reason) == SHZ_OK);
    CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_OK);
    CHECK(blk == (const uint16_t *)(chan_mem + off) && got_hdr.cmdline_chars == 1000);
    CHECK(shz_w64_create_check(&out, rx, c, 0, &got_hdr, &blk) == SHZ_E_INVALID);          /* receiver without pool */
    /* the same reference from the wrong owner, released, or pointing elsewhere is refused */
    out.src_domain = SHZ_DOM_KERNEL32;
    CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_E_DENIED);
    out.src_domain = SHZ_DOM_WIN98;
    out.buffer_length = bytes - 2;
    CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_E_INVALID);
    out.buffer_length = bytes;
    out.buffer_offset = c->pool_offset + c->pool_size - 16;
    CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_E_DENIED);
    out.buffer_offset = 0x100000000ull + off;
    CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_E_DENIED);
    out.buffer_offset = off;
    CHECK(shz_pool_release(chan_mem, c, SHZ_DOM_WIN98, off, bytes, 0) == SHZ_OK);
    CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_E_DENIED);    /* freed: unowned */

    /* 3. hostile inline headers */
    nc = 17;
    bytes = shz_w64_create_pack(&ch, path, np, cmd, nc, cwd, nw, block, 2200, &pool);
    memcpy(pl, &ch, sizeof ch);
    memcpy(pl + sizeof ch, block, bytes);
    make(&h, SHZ_OP_W64_CREATE_PROCESS, 3, pl, (uint16_t)(sizeof ch + bytes));
    h.src_domain = SHZ_DOM_WIN98;
    CHECK(shz_ring_push(tx, &h, pl) == SHZ_OK);
    CHECK(shz_ring_pop(tx, &out, rx, sizeof rx, &reason) == SHZ_OK);
    {
        shz_w64_create_t bad;
        uint8_t tmp[SHZ_MSG_MAX_INLINE];
#define HOSTILE(mutate, want) do { memcpy(tmp, rx, sizeof tmp); memcpy(&bad, tmp, sizeof bad); mutate; \
        memcpy(tmp, &bad, sizeof bad); CHECK(shz_w64_create_check(&out, tmp, c, chan_mem, &got_hdr, &blk) == (want)); } while (0)
        HOSTILE(bad.block_bytes += 2, SHZ_E_INVALID);                       /* lengths disagree */
        HOSTILE(bad.path_chars = 0, SHZ_E_INVALID);
        HOSTILE(bad.path_chars = 261; bad.block_bytes = 2 * (261 + nc + nw), SHZ_E_INVALID);
        HOSTILE(bad.flags = 0x80, SHZ_E_INVALID);
        HOSTILE(bad.reserved = 1, SHZ_E_INVALID);
        HOSTILE(bad.cwd_chars = 261; bad.block_bytes = 2 * (np + nc + 261), SHZ_E_INVALID);
        HOSTILE(bad.path_chars = 250; bad.cmdline_chars = 2000; bad.cwd_chars = 0; bad.block_bytes = 4500, SHZ_E_RANGE);
        HOSTILE(tmp[sizeof bad + 4] = 0; tmp[sizeof bad + 5] = 0, SHZ_E_INVALID);   /* embedded NUL */
#undef HOSTILE
        out.payload_length = (uint16_t)(sizeof bad - 1);
        CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_E_PROTO);
        out.payload_length = (uint16_t)(sizeof bad + bytes + 2);
        CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_E_INVALID);
        out.payload_length = (uint16_t)(sizeof bad + bytes);
        out.buffer_length = 8;                                              /* stray buffer without the flag */
        CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_E_INVALID);
        out.buffer_length = 0;
        CHECK(shz_w64_create_check(&out, rx, c, chan_mem, &got_hdr, &blk) == SHZ_OK);
    }
    /* pack refuses what the receiver would refuse */
    CHECK(shz_w64_create_pack(&ch, path, 0, cmd, nc, cwd, nw, block, 2200, &pool) == 0);
    CHECK(shz_w64_create_pack(&ch, path, 261, cmd, nc, cwd, nw, block, 2200, &pool) == 0);
    CHECK(shz_w64_create_pack(&ch, path, np, cmd, 2100, cwd, nw, block, 2200, &pool) == 0);   /* > 4096 bytes */
    CHECK(shz_w64_create_pack(&ch, path, np, cmd, nc, cwd, nw, block, 10, &pool) == 0);       /* caller buffer */
    path[3] = 0;
    CHECK(shz_w64_create_pack(&ch, path, np, cmd, nc, cwd, nw, block, 2200, &pool) == 0);     /* embedded NUL */
    path[3] = 'S';

    /* 4. console frames */
    {
        shz_w64_console_t co, got;
        uint8_t data[SHZ_W64_CONSOLE_CHUNK];
        memset(&co, 0, sizeof co);
        co.pid = 8; co.seq = 1; co.length = SHZ_W64_CONSOLE_CHUNK; co.stream = 1;
        for (i = 0; i < sizeof data; ++i) data[i] = (uint8_t)i;
        memcpy(pl, &co, sizeof co);
        memcpy(pl + sizeof co, data, sizeof data);
        make(&h, SHZ_OP_W64_CONSOLE_OUTPUT, 0, pl, (uint16_t)(sizeof co + sizeof data));
        h.flags = SHZ_MSGF_ONEWAY;
        CHECK(sizeof co + sizeof data == SHZ_MSG_MAX_INLINE);
        CHECK(shz_ring_push(tx, &h, pl) == SHZ_OK);
        CHECK(shz_ring_pop(tx, &out, rx, sizeof rx, &reason) == SHZ_OK);
        CHECK(shz_w64_console_check(&out, rx, &got) == SHZ_OK && got.length == SHZ_W64_CONSOLE_CHUNK && got.seq == 1);
        CHECK(!memcmp(rx + sizeof co, data, sizeof data));
        memcpy(&co, rx, sizeof co); co.length = SHZ_W64_CONSOLE_CHUNK + 1; memcpy(pl, rx, sizeof rx); memcpy(pl, &co, sizeof co);
        CHECK(shz_w64_console_check(&out, pl, &got) == SHZ_E_INVALID);
        memcpy(&co, rx, sizeof co); co.stream = 3; memcpy(pl, rx, sizeof rx); memcpy(pl, &co, sizeof co);
        CHECK(shz_w64_console_check(&out, pl, &got) == SHZ_E_INVALID);
        memcpy(&co, rx, sizeof co); co.flags = 2; memcpy(pl, rx, sizeof rx); memcpy(pl, &co, sizeof co);
        CHECK(shz_w64_console_check(&out, pl, &got) == SHZ_E_INVALID);
        memcpy(&co, rx, sizeof co); co.reserved = 5; memcpy(pl, rx, sizeof rx); memcpy(pl, &co, sizeof co);
        CHECK(shz_w64_console_check(&out, pl, &got) == SHZ_E_INVALID);
        memcpy(&co, rx, sizeof co); co.length = 10; memcpy(pl, rx, sizeof rx); memcpy(pl, &co, sizeof co);
        CHECK(shz_w64_console_check(&out, pl, &got) == SHZ_E_INVALID);      /* payload longer than length */
        out.payload_length = 8;
        CHECK(shz_w64_console_check(&out, rx, &got) == SHZ_E_PROTO);
        out.payload_length = SHZ_MSG_MAX_INLINE;
        out.buffer_length = 1;
        CHECK(shz_w64_console_check(&out, rx, &got) == SHZ_E_INVALID);
    }
    CHECK(shz_w64_is_opcode(SHZ_OP_W64_QUERY) && shz_w64_is_opcode(SHZ_OP_W64_SHUTDOWN) && !shz_w64_is_opcode(0x100) &&
          !shz_w64_is_opcode(0x300));
}

/* Random payloads through the checkers: an accepted CREATE must be self-consistent (lengths agree, no NUL) and
 * never reference memory outside the inline payload or an owned pool block; sanitizer builds catch any overread. */
static void test_w64_fuzz(void)
{
    shz_channel_hdr_t *c = (shz_channel_hdr_t *)chan_mem;
    shz_msg_hdr_t m;
    shz_w64_create_t hdr;
    shz_w64_console_t co;
    const uint16_t *blk;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    unsigned seed = 777, iter, accepted_create = 0, accepted_console = 0;
    uint64_t owned;
    CHECK(shz_channel_init(chan_mem, sizeof chan_mem, 2, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, 1) == SHZ_OK);
    owned = shz_pool_alloc(chan_mem, c, SHZ_DOM_WIN98, SHZ_W64_MAX_ARGS_BYTES);
    CHECK(owned);
    memset(chan_mem + owned, 'x', SHZ_W64_MAX_ARGS_BYTES);         /* NUL-free so owned references can be accepted */
    for (iter = 0; iter < 300000; ++iter) {
        size_t i;
        int rc;
        for (i = 0; i < sizeof pl; ++i) { seed = seed * 1103515245u + 12345u; pl[i] = (uint8_t)(seed >> 16); }
        memset(&m, 0, sizeof m);
        seed = seed * 1103515245u + 12345u;
        m.payload_length = (uint16_t)((seed >> 16) % (SHZ_MSG_MAX_INLINE + 1));
        m.src_domain = (iter & 4) ? SHZ_DOM_WIN98 : SHZ_DOM_KERNEL32;
        if ((iter & 3) == 1) {                              /* plausible CREATE header, random block */
            shz_w64_create_t h;
            memset(&h, 0, sizeof h);
            seed = seed * 1103515245u + 12345u;
            h.path_chars = (uint16_t)(1 + (seed >> 16) % 40);
            seed = seed * 1103515245u + 12345u;
            h.cmdline_chars = (uint16_t)((seed >> 16) % 60);
            h.block_bytes = 2u * (h.path_chars + h.cmdline_chars);
            if (iter & 16) { h.block_bytes += (uint16_t)((seed >> 8) & 6); }
            memcpy(pl, &h, sizeof h);
            if (iter & 8) { m.flags = SHZ_MSGF_BUFFER; m.buffer_offset = owned + ((seed >> 4) & 0x1fff); m.buffer_length = h.block_bytes; m.payload_length = sizeof h; }
            else m.payload_length = (uint16_t)(sizeof h + h.block_bytes);
            if (m.payload_length > SHZ_MSG_MAX_INLINE) m.payload_length = SHZ_MSG_MAX_INLINE;
        } else if ((iter & 3) == 3) {                       /* plausible console header, random data */
            shz_w64_console_t h;
            memset(&h, 0, sizeof h);
            seed = seed * 1103515245u + 12345u;
            h.pid = (seed >> 16) & 0xff; h.seq = seed & 0xff;
            seed = seed * 1103515245u + 12345u;
            h.length = (uint16_t)((seed >> 16) % (SHZ_W64_CONSOLE_CHUNK + 4));
            h.stream = (uint8_t)((seed >> 8) & 3);
            h.flags = (uint8_t)((seed >> 12) & 3);
            memcpy(pl, &h, sizeof h);
            m.payload_length = (uint16_t)(sizeof h + h.length);
            if (iter & 16) m.buffer_length = 4;
            if (m.payload_length > SHZ_MSG_MAX_INLINE) m.payload_length = SHZ_MSG_MAX_INLINE;
        }
        rc = shz_w64_create_check(&m, pl, c, chan_mem, &hdr, &blk);
        if (rc == SHZ_OK) {
            uint32_t total = (uint32_t)hdr.path_chars + hdr.cmdline_chars + hdr.cwd_chars, k;
            ++accepted_create;
            CHECK(hdr.block_bytes == total * 2 && hdr.path_chars && hdr.block_bytes <= SHZ_W64_MAX_ARGS_BYTES);
            if (m.flags & SHZ_MSGF_BUFFER) {
                CHECK((const uint8_t *)blk >= chan_mem + c->pool_offset &&
                      (const uint8_t *)blk + hdr.block_bytes <= chan_mem + c->pool_offset + c->pool_size);
                CHECK(m.src_domain == SHZ_DOM_WIN98);
            } else {
                CHECK((const uint8_t *)blk == pl + sizeof hdr && sizeof hdr + hdr.block_bytes == m.payload_length);
            }
            for (k = 0; k < total; ++k) CHECK(blk[k] != 0);
        }
        rc = shz_w64_console_check(&m, pl, &co);
        if (rc == SHZ_OK) {
            ++accepted_console;
            CHECK(co.length + sizeof co == m.payload_length && co.stream <= 2 && co.length <= SHZ_W64_CONSOLE_CHUNK);
        }
    }
    CHECK(accepted_create > 100 && accepted_console > 0);      /* the plausible half must be reachable */
}

/* --verify: decode frames produced by an independent (Python) encoder and report the verdicts back, so the two
 * implementations of the wire rules can be compared. Input: N x 256-byte slots. Output: per frame
 * "<pop rc> <reason> <create rc> <console rc>\n" after a first line with the pool geometry. */
static int verify_frames(const char *in_path, const char *out_path)
{
    shz_channel_hdr_t *c = (shz_channel_hdr_t *)chan_mem;
    shz_ring_hdr_t *r;
    FILE *in = fopen(in_path, "rb"), *out = fopen(out_path, "w");
    uint8_t slot[SHZ_MSG_SLOT_SIZE];
    uint64_t owned;
    if (!in || !out) return 2;
    CHECK(shz_channel_init(chan_mem, sizeof chan_mem, 2, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, 1) == SHZ_OK);
    owned = shz_pool_alloc(chan_mem, c, SHZ_DOM_WIN98, 8192);
    memset(chan_mem + owned, 'x', 8192);                                /* readable, NUL-free UTF-16 content */
    r = shz_channel_ring_tx(chan_mem, c, SHZ_DOM_WIN98);
    fprintf(out, "pool %llu %llu owned %llu 8192\n", (unsigned long long)c->pool_offset,
            (unsigned long long)c->pool_size, (unsigned long long)owned);
    while (fread(slot, 1, sizeof slot, in) == sizeof slot) {
        shz_msg_hdr_t m;
        shz_w64_create_t hdr;
        shz_w64_console_t co;
        const uint16_t *blk;
        uint8_t pl[SHZ_MSG_MAX_INLINE];
        int reason = 0, rc, crc = 99, coc = 99;
        memcpy(shz_ring_slot(r, r->head), slot, sizeof slot);
        r->head += 1;
        rc = shz_ring_pop(r, &m, pl, sizeof pl, &reason);
        if (rc == SHZ_OK) {
            crc = shz_w64_create_check(&m, pl, c, chan_mem, &hdr, &blk);
            coc = shz_w64_console_check(&m, pl, &co);
        }
        fprintf(out, "%d %d %d %d\n", rc, reason, crc, coc);
    }
    fclose(in);
    fclose(out);
    return 0;
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

/* Four WIN64 frames as Kernel64/the VxD would emit them, for the independent Python decode. */
static void emit_w64_samples(const char *path)
{
    shz_ring_hdr_t *r = (shz_ring_hdr_t *)ring_mem;
    shz_msg_hdr_t h;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    uint16_t block[128];
    uint32_t np, nc, nw, bytes, i;
    int pool;
    FILE *f;
    shz_w64_create_t ch;
    shz_w64_info_t info;
    shz_w64_event_t ev;
    shz_w64_console_t co;
    CHECK(shz_ring_init(ring_mem, sizeof ring_mem, 8) == SHZ_OK);
    {
        uint16_t path[32], cmd[32], cwd[32];
        w64_str(path, "C:\\SHZ\\TESTS\\T_HELLO.EXE", &np);
        w64_str(cmd, "T_HELLO.EXE first", &nc);
        w64_str(cwd, "C:\\SHZ\\TESTS", &nw);
        bytes = shz_w64_create_pack(&ch, path, np, cmd, nc, cwd, nw, block, 128, &pool);
        CHECK(bytes && !pool);
    }
    memcpy(pl, &ch, sizeof ch); memcpy(pl + sizeof ch, block, bytes);
    make(&h, SHZ_OP_W64_CREATE_PROCESS, 0x1001, pl, (uint16_t)(sizeof ch + bytes));
    h.src_domain = SHZ_DOM_WIN98; h.dst_domain = SHZ_DOM_KERNEL64; h.generation = 1;
    CHECK(shz_ring_push(r, &h, pl) == SHZ_OK);
    memset(&info, 0, sizeof info);
    info.abi_major = SHZ_ABI_MAJOR; info.abi_minor = SHZ_ABI_MINOR; info.subsystem_version = SHZ_W64_SUBSYS_VERSION;
    info.capabilities = SHZ_W64_CAP_CREATE | SHZ_W64_CAP_CONSOLE_OUTPUT | SHZ_W64_CAP_CONSOLE_INPUT | SHZ_W64_CAP_KILL | SHZ_W64_CAP_POOL_ARGS;
    info.max_processes = 4; info.max_args_bytes = SHZ_W64_MAX_ARGS_BYTES; info.console_window = SHZ_W64_CONSOLE_WINDOW;
    info.console_chunk = SHZ_W64_CONSOLE_CHUNK; info.active_processes = 1; info.uptime_ns = 0x123456789ull;
    make(&h, SHZ_OP_W64_QUERY, 0x1002, &info, sizeof info);
    h.flags = SHZ_MSGF_REPLY; h.src_domain = SHZ_DOM_KERNEL64; h.dst_domain = SHZ_DOM_WIN98; h.generation = 1;
    CHECK(shz_ring_push(r, &h, &info) == SHZ_OK);
    memset(&co, 0, sizeof co);
    co.pid = 20; co.seq = 3; co.stream = 1; co.length = 24;
    memcpy(pl, &co, sizeof co);
    memcpy(pl + sizeof co, "hello from Win64 PE32+!\n", 24);
    make(&h, SHZ_OP_W64_CONSOLE_OUTPUT, 0, pl, (uint16_t)(sizeof co + 24));
    h.flags = SHZ_MSGF_ONEWAY; h.src_domain = SHZ_DOM_KERNEL64; h.dst_domain = SHZ_DOM_WIN98; h.generation = 1;
    CHECK(shz_ring_push(r, &h, pl) == SHZ_OK);
    memset(&ev, 0, sizeof ev);
    ev.pid = 20; ev.state = SHZ_W64_PS_EXITED; ev.exit_code = 7; ev.console_seq = 3; ev.fault_status = 0;
    make(&h, SHZ_OP_W64_PROCESS_EXITED, 0, &ev, sizeof ev);
    h.flags = SHZ_MSGF_ONEWAY; h.src_domain = SHZ_DOM_KERNEL64; h.dst_domain = SHZ_DOM_WIN98; h.generation = 1;
    CHECK(shz_ring_push(r, &h, &ev) == SHZ_OK);
    f = fopen(path, "wb");
    CHECK(f != 0);
    for (i = 0; i < 4; ++i) CHECK(fwrite(shz_ring_slot(r, i), 1, SHZ_MSG_SLOT_SIZE, f) == SHZ_MSG_SLOT_SIZE);
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "--verify"))
        return verify_frames(argv[2], argv[3]);
    test_ring_basic();
    test_malformed();
    test_fuzz();
    test_requests();
    test_channel_and_pool();
    test_w64_family();
    test_w64_fuzz();
    test_stress();
    if (argc > 1)
        emit_sample(argv[1]);
    if (argc > 2)
        emit_w64_samples(argv[2]);
    printf("ABI host model: %lu checks passed (sizeof msg=%zu ring=%zu channel=%zu bootinfo=%zu, ABI %d.%d)\n", checks,
           sizeof(shz_msg_hdr_t), sizeof(shz_ring_hdr_t), sizeof(shz_channel_hdr_t), sizeof(shz_bootinfo_t),
           SHZ_ABI_MAJOR, SHZ_ABI_MINOR);
    return 0;
}
