/* SPDX-License-Identifier: GPL-2.0-only
 * Host regression for accept_op.c: writer -> accept_buffer.c reader round trip,
 * accepted-byte bounds and generation-bound owner/socket/token lifetimes.
 * Host-only evidence; no socket, provider, Windows or Steam execution.
 */
#include <stdio.h>
#include <string.h>
#include "accept_op.h"

static unsigned checks, failures;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; \
    fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #x); } } while (0)

static const uint8_t v4_local[16] = {2,0, 0x1f,0x90, 127,0,0,1};
static const uint8_t v4_remote[16] = {2,0, 0xc3,0x50, 127,0,0,1};
static uint8_t v6_local[28] = {23,0, 0x69,0x87};
static uint8_t v6_remote[28] = {23,0, 0x01,0xbb};

static unsigned cancel_calls;
static ntw_acceptex_token last_cancel;
static void on_cancel(void *ctx, ntw_acceptex_token t) { (void)ctx; ++cancel_calls; last_cancel = t; }

static void round_trip(uint16_t fam, const uint8_t *l, const uint8_t *r, uint32_t n,
                       uint32_t recv_res, uint32_t lres, uint32_t rres)
{
    struct ntw_acceptex_plan plan;
    struct ntw_accept_addresses got;
    uint8_t buf[512];
    memset(buf, 0xcc, sizeof buf);
    CHECK(ntw_acceptex_plan_make(fam, recv_res, lres, rres, &plan) == NTW_ACCEPTEX_OK);
    CHECK(plan.total == recv_res + lres + rres && plan.total <= sizeof buf);
    CHECK(ntw_acceptex_encode_blocks(&plan, l, n, r, n, buf + recv_res, lres + rres) == NTW_ACCEPTEX_OK);
    if (recv_res) CHECK(buf[recv_res - 1] == 0xcc);          /* receive area untouched */
    CHECK(buf[plan.total] == 0xcc);                          /* nothing past reservations */
    CHECK(buf[recv_res + lres - 1] == 0);                    /* reservation tail zeroed */
    CHECK(ntw_accept_decode(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, buf, plan.total,
                            recv_res, lres, rres, &got) == NTW_ACCEPT_OK);
    CHECK(got.local.length == n && got.remote.length == n && got.local.family == fam);
    CHECK(memcmp(got.local.bytes, l, n) == 0 && memcmp(got.remote.bytes, r, n) == 0);
    CHECK(got.local.bytes == buf + recv_res + 4 && got.remote.bytes == buf + recv_res + lres + 4);
}

int main(void)
{
    static struct ntw_acceptex_table table;
    struct ntw_acceptex_plan plan, bad;
    const struct ntw_acceptex_op *op;
    struct ntw_ref proc = {10, 1}, proc_reused = {10, 2}, other = {11, 1};
    struct ntw_ref lsn = {100, 7}, acc = {101, 3}, acc_reused = {101, 4}, acc2 = {102, 1};
    ntw_acceptex_token t1, t2, t3;
    uint8_t blocks[64];
    uint32_t i;

    /* Plan validation: Microsoft sockaddr + 16 rule and DWORD overflow. */
    CHECK(ntw_acceptex_plan_make(2, 0, 31, 32, &plan) == NTW_ACCEPTEX_RESERVATION);
    CHECK(ntw_acceptex_plan_make(23, 0, 44, 44, &plan) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_plan_make(23, 0, 43, 44, &plan) == NTW_ACCEPTEX_RESERVATION);
    CHECK(ntw_acceptex_plan_make(1, 0, 64, 64, &plan) == NTW_ACCEPTEX_FAMILY);
    CHECK(ntw_acceptex_plan_make(2, UINT32_MAX - 40, 32, 32, &plan) == NTW_ACCEPTEX_OVERFLOW);
    CHECK(ntw_acceptex_plan_make(2, UINT32_MAX - 64, 32, 33, &plan) == NTW_ACCEPTEX_OVERFLOW);

    /* Round trips with unequal reservations and nonzero receive area. */
    v6_local[23] = 1; v6_remote[23] = 1;
    round_trip(2, v4_local, v4_remote, 16, 0, 32, 32);
    round_trip(2, v4_local, v4_remote, 16, 37, 33, 48);
    round_trip(23, v6_local, v6_remote, 28, 100, 44, 60);

    /* Writer refuses wrong family/length/short output and leaves output unchanged. */
    CHECK(ntw_acceptex_plan_make(2, 0, 32, 32, &plan) == NTW_ACCEPTEX_OK);
    memset(blocks, 0xab, sizeof blocks);
    CHECK(ntw_acceptex_encode_blocks(&plan, v6_local, 28, v4_remote, 16, blocks, 64) == NTW_ACCEPTEX_FAMILY);
    CHECK(ntw_acceptex_encode_blocks(&plan, v4_local, 15, v4_remote, 16, blocks, 64) == NTW_ACCEPTEX_FAMILY);
    CHECK(ntw_acceptex_encode_blocks(&plan, v4_local, 16, v4_remote, 16, blocks, 63) == NTW_ACCEPTEX_ARGUMENT);
    bad = plan; bad.local_reserved = 20;
    CHECK(ntw_acceptex_encode_blocks(&bad, v4_local, 16, v4_remote, 16, blocks, 64) == NTW_ACCEPTEX_RESERVATION);
    for (i = 0; i < sizeof blocks; ++i) CHECK(blocks[i] == 0xab);

    /* Registry lifecycle. */
    ntw_acceptex_table_init(&table);
    CHECK(ntw_acceptex_plan_make(2, 64, 32, 32, &plan) == NTW_ACCEPTEX_OK);
    bad = plan; bad.total += 1;
    CHECK(ntw_acceptex_submit(&table, proc, lsn, acc, 0x10000, &bad, &t1) == NTW_ACCEPTEX_ARGUMENT);
    CHECK(ntw_acceptex_submit(&table, proc, lsn, lsn, 0x10000, &plan, &t1) == NTW_ACCEPTEX_ARGUMENT);
    CHECK(ntw_acceptex_submit(&table, proc, lsn, acc, 0, &plan, &t1) == NTW_ACCEPTEX_ARGUMENT);
    CHECK(ntw_acceptex_submit(&table, proc, lsn, acc, UINT64_MAX - 100, &plan, &t1) == NTW_ACCEPTEX_OVERFLOW);
    CHECK(ntw_acceptex_submit(&table, proc, lsn, acc, 0x10000, &plan, &t1) == NTW_ACCEPTEX_OK);
    /* Same accept socket or overlapping pending buffer: refused. */
    CHECK(ntw_acceptex_submit(&table, proc, lsn, acc, 0x20000, &plan, &t2) == NTW_ACCEPTEX_BUSY);
    CHECK(ntw_acceptex_submit(&table, proc, lsn, acc2, 0x10000 + 127, &plan, &t2) == NTW_ACCEPTEX_BUSY);
    CHECK(ntw_acceptex_submit(&table, other, lsn, acc2, 0x10000, &plan, &t2) == NTW_ACCEPTEX_OK); /* other address space */
    CHECK(ntw_acceptex_cancel(&table, t2) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_cancel(&table, t2) == NTW_ACCEPTEX_STALE);
    /* Not completed: no lookup, no context. */
    CHECK(ntw_acceptex_lookup(&table, proc, 0x10000, 64, 32, 32, &op) == NTW_ACCEPTEX_NOT_FOUND);
    CHECK(ntw_acceptex_update_context(&table, proc, acc, lsn) == NTW_ACCEPTEX_STATE);
    /* Accepted bytes are actual, bounded by the receive reservation. */
    CHECK(ntw_acceptex_complete(&table, t1, 65) == NTW_ACCEPTEX_RECEIVED);
    CHECK(ntw_acceptex_complete(&table, t1, 5) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_complete(&table, t1, 5) == NTW_ACCEPTEX_STATE);
    CHECK(ntw_acceptex_cancel(&table, t1) == NTW_ACCEPTEX_STATE);
    CHECK(ntw_acceptex_lookup(&table, proc, 0x10000, 64, 32, 32, &op) == NTW_ACCEPTEX_OK);
    CHECK(op && op->accepted_bytes == 5 && op->plan.total == 128 && op->plan.receive_reserved == 64);
    /* Received count passed in place of reservation is refused. */
    CHECK(ntw_acceptex_lookup(&table, proc, 0x10000, 5, 32, 32, &op) == NTW_ACCEPTEX_RESERVATION);
    CHECK(ntw_acceptex_lookup(&table, proc_reused, 0x10000, 64, 32, 32, &op) == NTW_ACCEPTEX_NOT_FOUND);
    /* SO_UPDATE_ACCEPT_CONTEXT is generation bound. */
    CHECK(ntw_acceptex_update_context(&table, proc, acc_reused, lsn) == NTW_ACCEPTEX_NOT_FOUND);
    CHECK(ntw_acceptex_update_context(&table, proc, acc, (struct ntw_ref){100, 8}) == NTW_ACCEPTEX_STALE);
    CHECK(ntw_acceptex_update_context(&table, proc_reused, acc, lsn) == NTW_ACCEPTEX_STALE);
    CHECK(ntw_acceptex_update_context(&table, proc, acc, lsn) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_lookup(&table, proc, 0x10000, 64, 32, 32, &op) == NTW_ACCEPTEX_OK && op->context_updated);
    /* Release requires the owner generation; then token is stale. */
    CHECK(ntw_acceptex_release(&table, proc_reused, t1) == NTW_ACCEPTEX_STALE);
    CHECK(ntw_acceptex_release(&table, proc, t1) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_release(&table, proc, t1) == NTW_ACCEPTEX_STALE);
    CHECK(ntw_acceptex_complete(&table, t1, 0) == NTW_ACCEPTEX_STALE);

    /* Buffer reuse retires the old completed record; old token goes stale. */
    CHECK(ntw_acceptex_submit(&table, proc, lsn, acc, 0x30000, &plan, &t1) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_complete(&table, t1, 0) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_submit(&table, proc, lsn, acc2, 0x30000 + 8, &plan, &t2) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_lookup(&table, proc, 0x30000, 64, 32, 32, &op) == NTW_ACCEPTEX_NOT_FOUND);
    CHECK(ntw_acceptex_release(&table, proc, t1) == NTW_ACCEPTEX_STALE);

    /* Closing the listen socket cancels pending ops through the callback. */
    cancel_calls = 0;
    CHECK(ntw_acceptex_forget(&table, (struct ntw_ref){100, 6}, 0, on_cancel, 0) == 0);
    CHECK(ntw_acceptex_forget(&table, lsn, 0, on_cancel, 0) == 1);
    CHECK(cancel_calls == 1 && last_cancel == t2);
    CHECK(ntw_acceptex_complete(&table, t2, 0) == NTW_ACCEPTEX_STALE);

    /* Process exit frees completed and pending records without cross-owner effect. */
    CHECK(ntw_acceptex_submit(&table, proc, lsn, acc, 0x40000, &plan, &t1) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_complete(&table, t1, 64) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_submit(&table, other, (struct ntw_ref){200, 1}, (struct ntw_ref){201, 1},
                              0x40000, &plan, &t3) == NTW_ACCEPTEX_OK);
    cancel_calls = 0;
    CHECK(ntw_acceptex_forget(&table, proc, 1, on_cancel, 0) == 1 && cancel_calls == 0);
    CHECK(ntw_acceptex_lookup(&table, proc, 0x40000, 64, 32, 32, &op) == NTW_ACCEPTEX_NOT_FOUND);
    CHECK(ntw_acceptex_forget(&table, other, 1, on_cancel, 0) == 1 && cancel_calls == 1 && last_cancel == t3);

    /* Capacity: full table refuses, and generations never reissue token 0 gen. */
    for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i)
        CHECK(ntw_acceptex_submit(&table, proc, lsn, (struct ntw_ref){1000 + i, 1},
                                  0x100000 + (uint64_t)i * 0x1000, &plan, &t1) == NTW_ACCEPTEX_OK);
    CHECK(ntw_acceptex_submit(&table, proc, lsn, acc2, 0x900000, &plan, &t2) == NTW_ACCEPTEX_FULL);
    CHECK(ntw_acceptex_forget(&table, proc, 1, 0, 0) == NTW_ACCEPTEX_SLOTS);
    for (i = 0; i < 70000u; ++i) {
        CHECK(ntw_acceptex_submit(&table, proc, lsn, acc, 0x10000, &plan, &t1) == NTW_ACCEPTEX_OK);
        if ((t1 >> 16) == 0) { CHECK(0); break; }
        CHECK(ntw_acceptex_cancel(&table, t1) == NTW_ACCEPTEX_OK);
    }

    /* Exact 16-bit exhaustion: preset one FREE slot to generation 65535 (public
     * struct, no 65k loop), spend it, and prove no stale alias can ever match. */
    {
        static struct ntw_acceptex_table ex;
        ntw_acceptex_token old, last, nt;
        ntw_acceptex_table_init(&ex);
        CHECK(ntw_acceptex_submit(&ex, proc, lsn, acc, 0x10000, &plan, &old) == NTW_ACCEPTEX_OK);
        CHECK(old == 0x00010000u);                        /* slot 0, generation 1 */
        CHECK(ntw_acceptex_cancel(&ex, old) == NTW_ACCEPTEX_OK);
        ex.op[0].generation = 0xfffe;
        CHECK(ntw_acceptex_submit(&ex, proc, lsn, acc, 0x10000, &plan, &last) == NTW_ACCEPTEX_OK);
        CHECK(last == 0xfffe0000u);
        CHECK(ntw_acceptex_cancel(&ex, last) == NTW_ACCEPTEX_OK);   /* -> 65535 */
        CHECK(ntw_acceptex_submit(&ex, proc, lsn, acc, 0x10000, &plan, &last) == NTW_ACCEPTEX_OK);
        CHECK(last == 0xffff0000u);
        CHECK(ntw_acceptex_cancel(&ex, last) == NTW_ACCEPTEX_OK);   /* retire slot 0 */
        CHECK(ex.op[0].state == NTW_ACCEPTEX_RETIRED);
        /* Slot 0 is never reissued; the next op lands in slot 1. */
        CHECK(ntw_acceptex_submit(&ex, proc, lsn, acc, 0x10000, &plan, &nt) == NTW_ACCEPTEX_OK);
        CHECK((nt & 0xffffu) == 1u);
        CHECK(ntw_acceptex_complete(&ex, old, 0) == NTW_ACCEPTEX_STALE);
        CHECK(ntw_acceptex_complete(&ex, last, 0) == NTW_ACCEPTEX_STALE);
        CHECK(ntw_acceptex_cancel(&ex, 0x00010001u ^ 0x1u) == NTW_ACCEPTEX_STALE);
        CHECK(ntw_acceptex_release(&ex, proc, last) == NTW_ACCEPTEX_STALE);
        CHECK(ntw_acceptex_forget(&ex, proc, 1, 0, 0) == 1);        /* retired slot untouched */
        /* Retire every slot: submit reports exhaustion, not FULL or a reissue. */
        for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i) {
            if (ex.op[i].state == NTW_ACCEPTEX_RETIRED) continue;
            ex.op[i].generation = 0xffff;
            CHECK(ntw_acceptex_submit(&ex, proc, lsn, acc, 0x10000, &plan, &nt) == NTW_ACCEPTEX_OK);
            CHECK(ntw_acceptex_cancel(&ex, nt) == NTW_ACCEPTEX_OK);
        }
        for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i) CHECK(ex.op[i].state == NTW_ACCEPTEX_RETIRED);
        CHECK(ntw_acceptex_submit(&ex, proc, lsn, acc, 0x10000, &plan, &nt) == NTW_ACCEPTEX_EXHAUSTED);
        CHECK(ntw_acceptex_update_context(&ex, proc, acc, lsn) == NTW_ACCEPTEX_NOT_FOUND);
        CHECK(ntw_acceptex_forget(&ex, proc, 1, 0, 0) == 0);
    }

    printf("accept_op: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
