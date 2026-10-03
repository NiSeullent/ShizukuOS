/* SPDX-License-Identifier: GPL-2.0-only -- host test of the production (NTWV_W64_DERIVED_OWNER) VxD W64 bridge.
 * bridge.c + w64_owner.c are the real sources; the channel is a real shz_channel_init() region checked with the
 * Kernel64 wire library. Modelled: VMM page services, VWIN32 DIOCParams, Supervisor hypercalls incl.
 * SHZ_HC_CHANNEL_ATTEST. Host-only: no VxD load, no VWIN32, no Supervisor, no K64, no VM. */
#include "../bridge.h"
#include "../w64_owner.h"
#include "../../../shizukudos/abi/shz_ipc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SYS_VM 0xc1000000u
#define DOS_VM 0xc2000000u
#define PROC_A 0x81a00010u
#define PROC_B 0x81b00020u
static unsigned checks, protected_now;
static unsigned char buffers[3][8192];          /* user pages 0x500.. output, 0x600.. returned, 0x700.. input */
static uint8_t channel[SHZ_IPC_REGION_SIZE] __attribute__((aligned(4096)));
static int32_t attest_status;
static uint32_t attest_calls, attest_c, attest_gen, attest_bits;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "line %u: %s\n", (unsigned)__LINE__, #x); exit(1); } } while (0)

static uintptr_t enter(void *p) { (void)p; CHECK(!protected_now); protected_now = 1; return 0x202; }
static void leave(void *p, uintptr_t saved) { (void)p; CHECK(protected_now && saved == 0x202); protected_now = 0; }
static uintptr_t lock_enter(void *p) { (void)p; return 0; }
static void lock_leave(void *p, uintptr_t s) { (void)p; (void)s; }
static unsigned which(uint32_t page)
{
    if (page == 0x500 || page == 0xc1000) return 0;
    if (page == 0x600 || page == 0xc2000) return 1;
    CHECK(page == 0x700 || page == 0xc3000);
    return 2;
}
static uint32_t check_range(uint32_t page, uint32_t count, uint32_t flags) { (void)which(page); (void)flags; return count; }
static uint32_t lock_range(uint32_t page, uint32_t count, uint32_t flags)
{ (void)count; (void)flags; return 0xc1000000u + 0x1000000u * which(page); }
static uint32_t unlock_range(uint32_t page, uint32_t count, uint32_t flags) { (void)which(page); (void)count; (void)flags; return 1; }
static uint32_t ptes(uint32_t page, uint32_t count, uint32_t *out, uint32_t flags)
{
    unsigned i, b = which(page);
    (void)flags;
    for (i = 0; i < count; ++i) out[i] = 0x00100000u * (b + 1) + i * 4096u + (b == 2 ? 5u : 7u);
    return 1;
}
static void write_alias(uint32_t a, const void *s, uint32_t n) { CHECK(protected_now); memcpy(buffers[which(a >> 12)] + (a & 0xffff), s, n); }
static void read_alias(void *d, uint32_t a, uint32_t n) { CHECK(protected_now); memcpy(d, buffers[which(a >> 12)] + (a & 0xffff), n); }
static int present(void) { return 1; }
static int32_t hcall(uint32_t op, uint32_t a, uint32_t b, uint32_t *ebx, uint32_t *ecx)
{
    (void)b;
    switch (op) {
    case SHZ_HC_ABI_VERSION: if (ebx) *ebx = (1u << 16) | 1u; return SHZ_OK;
    case SHZ_HC_CHANNEL_INFO: if (a != 2) return SHZ_E_NOENT; if (ebx) *ebx = 0xe0200000u; if (ecx) *ecx = SHZ_DOM_KERNEL64; return SHZ_OK;
    case SHZ_HC_NOTIFY: return SHZ_OK;
    case SHZ_HC_DOORBELL_ACK: if (ebx) *ebx = 0; return SHZ_OK;
    default: return SHZ_E_UNSUPPORTED;
    }
}
static int32_t hcall3(uint32_t op, uint32_t a, uint32_t b, uint32_t c, uint32_t *ebx, uint32_t *ecx)
{
    (void)ecx;
    CHECK(op == SHZ_HC_CHANNEL_ATTEST && !protected_now);
    ++attest_calls; attest_c = a; attest_gen = b; attest_bits = c;
    if (attest_status == SHZ_OK && ebx) *ebx = c;
    return attest_status;
}
static void *map_phys(uint32_t phys, uint32_t bytes) { CHECK(phys == 0xe0200000u && bytes == SHZ_IPC_REGION_SIZE); return channel; }
static const struct ntwv_pages ops = { check_range, lock_range, unlock_range, ptes, enter, leave, write_alias, read_alias };
static const struct ntwv_hv hv = { present, hcall, map_phys, hcall3 };
static const struct ntwv_hv hv_no3 = { present, hcall, map_phys, 0 };
static shz_channel_hdr_t *chdr(void) { return (shz_channel_hdr_t *)channel; }

static uint32_t dioc_as(const struct ntwv_hv *h, uint32_t vm, uint32_t process, uint32_t code, const void *in, uint32_t in_bytes,
                        uint32_t out_bytes, void *out)
{
    struct ntwv_dioc r = { 0 };
    uint32_t result;
    r.vm = vm; r.process = process; r.code = code;
    r.output = 0x00500ff0; r.output_bytes = out_bytes; r.returned = 0x00600ffe;
    if (in_bytes) { r.input = 0x00700ff0; r.input_bytes = in_bytes; memcpy(buffers[2] + 0xff0, in, in_bytes); }
    result = ntwv_dioc_ex(&r, &ops, h);
    if (out) memcpy(out, buffers[0] + 0xff0, out_bytes);
    return result;
}
/* A user SEND from (vm, process) with an application-chosen capability_id; returns the cap K64 receives. */
static uint32_t send_as(uint32_t vm, uint32_t process, uint32_t app_cap, uint64_t request_id, uint32_t *result)
{
    shz_msg_hdr_t h = { 0 }, got;
    uint8_t payload[SHZ_MSG_MAX_INLINE];
    int32_t status;
    int reason;
    h.opcode = SHZ_OP_W64_QUERY; h.request_id = request_id; h.capability_id = app_cap;
    *result = dioc_as(&hv, vm, process, NTWV_IOCTL_W64_SEND, &h, sizeof h, 4, &status);
    if (*result) return 0xffffffffu;
    CHECK(shz_ring_pop(shz_channel_ring_rx(channel, chdr(), SHZ_DOM_KERNEL64), &got, payload, sizeof payload, &reason) == SHZ_OK);
    return got.capability_id;
}
static void k64_post(uint32_t cap, uint64_t request_id, uint16_t flags)
{
    shz_msg_hdr_t h = { 0 };
    h.flags = flags; h.opcode = SHZ_OP_W64_QUERY; h.request_id = request_id; h.capability_id = cap;
    h.src_domain = SHZ_DOM_KERNEL64; h.dst_domain = SHZ_DOM_WIN98; h.generation = chdr()->generation;
    CHECK(shz_ring_push(shz_channel_ring_tx(channel, chdr(), SHZ_DOM_KERNEL64), &h, 0) == SHZ_OK);
}
static uint32_t recv_as(uint32_t process, uint64_t *request_id)
{
    uint8_t slot[SHZ_MSG_SLOT_SIZE];
    shz_msg_hdr_t h;
    const uint32_t r = dioc_as(&hv, SYS_VM, process, NTWV_IOCTL_W64_RECV, 0, 0, sizeof slot, slot);
    memcpy(&h, slot, sizeof h);
    if (!r && request_id) *request_id = h.request_id;
    return r;
}
static void fresh_channel(uint32_t generation)
{
    const struct ntw_lock_ops locks = { enter, leave, 0 };
    ntwv_w64_reset();
    (void)ntwv_shutdown();
    CHECK(shz_channel_init(channel, sizeof channel, 2, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, generation) == SHZ_OK);
    CHECK(ntwv_initialize(&locks));
}

/* ---- batch 6: multi-owner request keys, stash arrival order, stash-full retention, remote process custody ---- */
#define PROC_C 0x81c00040u
static uint32_t send_msg(uint32_t process, uint32_t opcode, uint64_t id, const void *payload, uint16_t plen, uint32_t extra)
{
    uint8_t in[512];
    shz_msg_hdr_t h = { 0 };
    int32_t status;
    h.opcode = opcode; h.request_id = id; h.payload_length = plen; h.capability_id = 0x55u;
    memcpy(in, &h, sizeof h);
    if (plen) memcpy(in + sizeof h, payload, plen);
    memset(in + sizeof h + plen, 0xa5, extra);
    return dioc_as(&hv, SYS_VM, process, NTWV_IOCTL_W64_SEND, in, (uint32_t)sizeof h + plen + extra, 4, &status);
}
static shz_msg_hdr_t k64_pop(void *payload)
{
    shz_msg_hdr_t got;
    uint8_t p[SHZ_MSG_MAX_INLINE];
    int reason;
    CHECK(shz_ring_pop(shz_channel_ring_rx(channel, chdr(), SHZ_DOM_KERNEL64), &got, p, sizeof p, &reason) == SHZ_OK);
    if (payload) memcpy(payload, p, got.payload_length);
    return got;
}
static uint32_t k64_pending(void) { return shz_ring_count(shz_channel_ring_rx(channel, chdr(), SHZ_DOM_KERNEL64)); }
static void k64_msg(uint32_t cap, uint64_t id, uint32_t opcode, uint16_t flags, int32_t status, const void *payload, uint16_t plen)
{
    shz_msg_hdr_t h = { 0 };
    h.flags = flags; h.opcode = opcode; h.request_id = id; h.capability_id = cap; h.status = status;
    h.payload_length = plen;
    h.src_domain = SHZ_DOM_KERNEL64; h.dst_domain = SHZ_DOM_WIN98; h.generation = chdr()->generation;
    CHECK(shz_ring_push(shz_channel_ring_tx(channel, chdr(), SHZ_DOM_KERNEL64), &h, payload) == SHZ_OK);
}
static void k64_frame(uint32_t cap, uint64_t seq) { k64_msg(cap, seq, SHZ_OP_W64_CONSOLE_OUTPUT, SHZ_MSGF_ONEWAY, 0, 0, 0); }
static uint32_t recv_hdr(uint32_t process, shz_msg_hdr_t *h)
{
    uint8_t slot[SHZ_MSG_SLOT_SIZE];
    const uint32_t r = dioc_as(&hv, SYS_VM, process, NTWV_IOCTL_W64_RECV, 0, 0, sizeof slot, slot);
    memcpy(h, slot, sizeof *h);
    return r;
}
static struct ntwv_w64_open open_info(void)
{
    struct ntwv_w64_open o;
    CHECK(dioc_as(&hv, SYS_VM, PROC_A, NTWV_IOCTL_W64_OPEN, 0, 0, sizeof o, &o) == 0);
    return o;
}
static shz_w64_event_t started(uint32_t pid, uint32_t state)
{
    shz_w64_event_t ev;
    memset(&ev, 0, sizeof ev); ev.pid = pid; ev.state = state;
    return ev;
}

static void batch6(void)
{
    shz_msg_hdr_t h;
    shz_w64_create_t cr;
    shz_w64_event_t ev;
    shz_w64_kill_t k;
    uint32_t cap_a, cap_b, cap_b3, proto, i;
    uint64_t kill_id, release_id;

    fresh_channel(7);
    attest_status = SHZ_OK;
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_C) == 0);
    proto = open_info().proto_errors;
    memset(&cr, 0, sizeof cr);

    /* P1-B: A inline QUERY 0x100 and B pooled CREATE 0x100 coexist (same client id base, different owners). */
    CHECK(send_msg(PROC_A, SHZ_OP_W64_QUERY, 0x100, 0, 0, 0) == 0);
    cap_a = k64_pop(0).capability_id;
    CHECK(send_msg(PROC_B, SHZ_OP_W64_CREATE_PROCESS, 0x100, &cr, sizeof cr, 64) == 0);
    h = k64_pop(0);
    cap_b = h.capability_id;
    CHECK(shz_w64_owner_cap_derived(cap_a) && shz_w64_owner_cap_derived(cap_b) && cap_a != cap_b);
    CHECK((h.flags & SHZ_MSGF_BUFFER) && h.buffer_length == 64 && open_info().pending_pool == 1);
    /* The same owner may not reuse an id that holds a pool lease (pooled or inline). */
    CHECK(send_msg(PROC_B, SHZ_OP_W64_CREATE_PROCESS, 0x100, &cr, sizeof cr, 64) == NTWV_ERROR_BUSY);
    CHECK(send_msg(PROC_B, SHZ_OP_W64_QUERY, 0x100, 0, 0, 0) == NTWV_ERROR_BUSY && k64_pending() == 0);
    /* Reversed replies plus foreign ones: B-cap QUERY reply (wrong opcode for B's lease) is dropped and keeps the
     * lease; an unknown owner's CREATE reply 0x100 neither releases B's pool nor reaches anyone. */
    ev = started(7, SHZ_W64_PS_STARTED);
    k64_msg(cap_b, 0x100, SHZ_OP_W64_QUERY, SHZ_MSGF_REPLY, 0, 0, 0);
    k64_msg(SHZ_W64_OWNER_CAP_DERIVED | 0x7ffff0u, 0x100, SHZ_OP_W64_CREATE_PROCESS, SHZ_MSGF_REPLY, 0, &ev, sizeof ev);
    CHECK(recv_hdr(PROC_C, &h) == NTWV_ERROR_NO_MORE_ITEMS);
    CHECK(open_info().pending_pool == 1 && open_info().proto_errors == proto + 1 && ntwv_w64_tracked() == 1);  /* B's CREATE only */
    k64_msg(cap_b, 0x100, SHZ_OP_W64_CREATE_PROCESS, SHZ_MSGF_REPLY, 0, &ev, sizeof ev);
    k64_msg(cap_a, 0x100, SHZ_OP_W64_QUERY, SHZ_MSGF_REPLY, 0, 0, 0);
    CHECK(recv_hdr(PROC_A, &h) == 0 && h.request_id == 0x100 && h.opcode == SHZ_OP_W64_QUERY && h.capability_id == cap_a);
    CHECK(open_info().pending_pool == 0 && open_info().proto_errors == proto + 1);
    CHECK(recv_hdr(PROC_B, &h) == 0 && h.request_id == 0x100 && h.opcode == SHZ_OP_W64_CREATE_PROCESS);
    CHECK(recv_hdr(PROC_A, &h) == NTWV_ERROR_NO_MORE_ITEMS && ntwv_w64_tracked() == 1);   /* B's pid 7 */

    /* P1-A: A1/A2 stashed at slots 1/2, B frees slot 0, A3 lands in slot 0: A still gets 1,2,3. */
    k64_frame(cap_b, 1); k64_frame(cap_a, 1); k64_frame(cap_a, 2);
    CHECK(recv_hdr(PROC_C, &h) == NTWV_ERROR_NO_MORE_ITEMS);
    CHECK(recv_hdr(PROC_B, &h) == 0 && h.request_id == 1 && h.capability_id == cap_b);
    k64_frame(cap_a, 3);
    CHECK(recv_hdr(PROC_C, &h) == NTWV_ERROR_NO_MORE_ITEMS);
    for (i = 1; i <= 3; ++i) CHECK(recv_hdr(PROC_A, &h) == 0 && h.request_id == i && h.capability_id == cap_a);
    CHECK(recv_hdr(PROC_A, &h) == NTWV_ERROR_NO_MORE_ITEMS && recv_hdr(PROC_B, &h) == NTWV_ERROR_NO_MORE_ITEMS);

    /* Stash full of B: A's own head is still delivered; another live owner's head stays queued (BUSY). */
    for (i = 10; i < 18; ++i) k64_frame(cap_b, i);
    CHECK(recv_hdr(PROC_C, &h) == NTWV_ERROR_NO_MORE_ITEMS);
    k64_frame(cap_a, 30); k64_frame(cap_b, 18); k64_frame(cap_a, 31);
    CHECK(recv_hdr(PROC_A, &h) == 0 && h.request_id == 30);
    CHECK(recv_hdr(PROC_A, &h) == NTWV_ERROR_BUSY && recv_hdr(PROC_C, &h) == NTWV_ERROR_BUSY);
    for (i = 10; i <= 18; ++i) CHECK(recv_hdr(PROC_B, &h) == 0 && h.request_id == i && h.capability_id == cap_b);
    CHECK(recv_hdr(PROC_A, &h) == 0 && h.request_id == 31 && recv_hdr(PROC_A, &h) == NTWV_ERROR_NO_MORE_ITEMS);

    /* Owner's own RELEASE ends custody on its OK reply (no VxD kill afterwards). */
    CHECK(send_msg(PROC_A, SHZ_OP_W64_CREATE_PROCESS, 0x200, &cr, sizeof cr, 0) == 0 && k64_pop(0).capability_id == cap_a);
    ev = started(9, SHZ_W64_PS_STARTED);
    k64_msg(cap_a, 0x200, SHZ_OP_W64_CREATE_PROCESS, SHZ_MSGF_REPLY, 0, &ev, sizeof ev);
    CHECK(recv_hdr(PROC_A, &h) == 0 && h.request_id == 0x200 && ntwv_w64_tracked() == 2);
    k.pid = 9; k.exit_code = 0;
    CHECK(send_msg(PROC_A, SHZ_OP_W64_RELEASE, 0x201, &k, sizeof k, 0) == 0 && k64_pop(0).opcode == SHZ_OP_W64_RELEASE);
    k64_msg(cap_a, 0x201, SHZ_OP_W64_RELEASE, SHZ_MSGF_REPLY, 0, 0, 0);
    CHECK(recv_hdr(PROC_A, &h) == 0 && h.request_id == 0x201 && ntwv_w64_tracked() == 1);

    /* Retired owner: its stashed frames and queued head are dropped, A proceeds; then P1-C reclaims B's pid 7. */
    for (i = 40; i < 48; ++i) k64_frame(cap_b, i);
    CHECK(recv_hdr(PROC_C, &h) == NTWV_ERROR_NO_MORE_ITEMS);
    k64_frame(cap_b, 48); k64_frame(cap_a, 50);
    CHECK(recv_hdr(PROC_A, &h) == NTWV_ERROR_BUSY);
    ntwv_w64_owner_handle_close(PROC_B);                       /* B's last handle: identity retired */
    CHECK(recv_hdr(PROC_A, &h) == 0 && h.request_id == 50 && h.capability_id == cap_a);
    h = k64_pop(&k);                                           /* the reap at that DIOC: trusted KILL pid 7 */
    CHECK(h.opcode == SHZ_OP_W64_KILL_PROCESS && h.capability_id == 0 && k.pid == 7 && h.payload_length == sizeof k);
    CHECK(h.generation == 7 && h.src_domain == SHZ_DOM_WIN98 && !(h.flags & SHZ_MSGF_REPLY));
    kill_id = h.request_id;
    CHECK(recv_hdr(PROC_A, &h) == NTWV_ERROR_NO_MORE_ITEMS && k64_pending() == 0);   /* KILL not repeated */
    k64_msg(0, kill_id, SHZ_OP_W64_KILL_PROCESS, SHZ_MSGF_REPLY, 0, 0, 0);
    ev = started(7, SHZ_W64_PS_KILLED);
    k64_msg(cap_b, 0, SHZ_OP_W64_PROCESS_EXITED, SHZ_MSGF_ONEWAY, 0, &ev, sizeof ev);
    CHECK(recv_hdr(PROC_A, &h) == NTWV_ERROR_NO_MORE_ITEMS);  /* both orphaned, never shown to A */
    CHECK(recv_hdr(PROC_A, &h) == NTWV_ERROR_NO_MORE_ITEMS);  /* next DIOC's reap: RELEASE */
    h = k64_pop(&k);
    CHECK(h.opcode == SHZ_OP_W64_RELEASE && h.capability_id == 0 && k.pid == 7 && h.request_id != kill_id);
    release_id = h.request_id;
    k64_msg(0, release_id, SHZ_OP_W64_RELEASE, SHZ_MSGF_REPLY, 0, 0, 0);
    CHECK(recv_hdr(PROC_A, &h) == NTWV_ERROR_NO_MORE_ITEMS && ntwv_w64_tracked() == 0 && k64_pending() == 0);

    /* A retired owner's pooled request keeps its pool block until its own terminal reply, then frees it. */
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_B) == 0);
    CHECK(send_msg(PROC_B, SHZ_OP_W64_CREATE_PROCESS, 0x100, &cr, sizeof cr, 64) == 0);
    cap_b3 = k64_pop(0).capability_id;
    CHECK(cap_b3 != cap_b && open_info().pending_pool == 1);
    ntwv_w64_owner_handle_close(PROC_B);
    CHECK(recv_hdr(PROC_A, &h) == NTWV_ERROR_NO_MORE_ITEMS && open_info().pending_pool == 1);
    ev = started(0, SHZ_W64_PS_FAILED);
    k64_msg(cap_b3, 0x100, SHZ_OP_W64_CREATE_PROCESS, SHZ_MSGF_REPLY, -1, &ev, sizeof ev);
    CHECK(recv_hdr(PROC_A, &h) == NTWV_ERROR_NO_MORE_ITEMS && open_info().pending_pool == 0 && ntwv_w64_tracked() == 0);
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_B) == 0);   /* leave B with a handle for later phases */
}

int main(void)
{
    struct ntwv_w64_open info;
    uint32_t r, cap_a, cap_b, cap_b2, i;
    uint64_t id = 0;

    ntwv_w64_owner_bind_lock(lock_enter, lock_leave);
    ntwv_w64_owner_bind_system_vm(SYS_VM);
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_A) == 0 && ntwv_w64_owner_handle_open(SYS_VM, PROC_B) == 0);

    /* Attested bind: ATTEST(c=2, generation, W64_DERIVED_OWNER) before any send; reported to NTW32. */
    fresh_channel(3);
    attest_status = SHZ_OK;
    CHECK(dioc_as(&hv, SYS_VM, PROC_A, NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info) == 0);
    CHECK(attest_calls == 1 && attest_c == 2 && attest_gen == 3 && attest_bits == SHZ_CHAN_ATTEST_W64_DERIVED_OWNER);
    CHECK(info.attested == SHZ_CHAN_ATTEST_W64_DERIVED_OWNER && info.generation == 3);

    /* Every user SEND carries the VxD-derived identity, never the application's value. */
    cap_a = send_as(SYS_VM, PROC_A, 0x1234u, 1, &r);
    CHECK(r == 0 && shz_w64_owner_cap_derived(cap_a));
    cap_b = send_as(SYS_VM, PROC_B, cap_a, 2, &r);                /* B forges A's capability */
    CHECK(r == 0 && shz_w64_owner_cap_derived(cap_b) && cap_b != cap_a);
    CHECK(send_as(DOS_VM, PROC_A, 0, 3, &r) == 0xffffffffu && r == NTWV_ERROR_ACCESS_DENIED);
    CHECK(send_as(SYS_VM, 0x81c00030u, 0, 4, &r) == 0xffffffffu && r == NTWV_ERROR_ACCESS_DENIED); /* no handle */

    /* RECV demultiplex: B's reply popped by A waits for B; A gets only its own. */
    k64_post(cap_b, 2, SHZ_MSGF_REPLY);
    k64_post(cap_a, 1, SHZ_MSGF_REPLY);
    CHECK(recv_as(PROC_A, &id) == 0 && id == 1);
    CHECK(recv_as(PROC_A, &id) == NTWV_ERROR_NO_MORE_ITEMS);
    CHECK(recv_as(PROC_B, &id) == 0 && id == 2);
    /* Non-derived (anonymous) and retired-owner messages are never shown to a user process. */
    k64_post(0, 9, SHZ_MSGF_ONEWAY);
    CHECK(recv_as(PROC_B, &id) == NTWV_ERROR_NO_MORE_ITEMS);
    ntwv_w64_owner_handle_close(PROC_B);                          /* B's last handle */
    k64_post(cap_b, 10, SHZ_MSGF_ONEWAY);
    CHECK(recv_as(PROC_A, &id) == NTWV_ERROR_NO_MORE_ITEMS);
    CHECK(send_as(SYS_VM, PROC_B, cap_b, 11, &r) == 0xffffffffu && r == NTWV_ERROR_ACCESS_DENIED);
    /* B reopens: fresh identity; a full stash makes RECV refuse to pop rather than lose a message. */
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_B) == 0);
    cap_b2 = send_as(SYS_VM, PROC_B, cap_b, 12, &r);
    CHECK(r == 0 && cap_b2 != cap_b && shz_w64_owner_cap_derived(cap_b2));
    for (i = 0; i < 9; ++i) k64_post(cap_b2, 100 + i, SHZ_MSGF_ONEWAY);
    k64_post(cap_a, 200, SHZ_MSGF_ONEWAY);
    CHECK(recv_as(PROC_A, &id) == NTWV_ERROR_BUSY);               /* 8 stashed for B, 9th stays queued */
    for (i = 0; i < 9; ++i) CHECK(recv_as(PROC_B, &id) == 0 && id == 100 + i);
    CHECK(recv_as(PROC_A, &id) == 0 && id == 200);
    /* A's identity survives B's churn; a channel reset retires all identities. */
    CHECK(send_as(SYS_VM, PROC_A, 0, 13, &r) == cap_a && r == 0);

    /* Old Supervisor (E_UNSUPPORTED): channel opens unattested (K64 denies GUI); no EDX hypercall: same. */
    fresh_channel(4);
    attest_status = SHZ_E_UNSUPPORTED;
    CHECK(dioc_as(&hv, SYS_VM, PROC_A, NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info) == 0 && info.attested == 0);
    CHECK(send_as(SYS_VM, PROC_A, 0, 14, &r) != cap_a && r == 0);  /* reset retired the old identity */
    fresh_channel(5);
    CHECK(dioc_as(&hv_no3, SYS_VM, PROC_A, NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info) == 0 && info.attested == 0);
    /* Supervisor refuses the attestation (denied / stale / busy): the channel is not used at all. */
    fresh_channel(6);
    attest_status = SHZ_E_DENIED;
    CHECK(dioc_as(&hv, SYS_VM, PROC_A, NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info) == NTWV_ERROR_GEN_FAILURE);
    CHECK(send_as(SYS_VM, PROC_A, 0, 15, &r) == 0xffffffffu && r == NTWV_ERROR_NOT_READY);
    attest_status = SHZ_E_STALE;
    CHECK(dioc_as(&hv, SYS_VM, PROC_A, NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info) == NTWV_ERROR_GEN_FAILURE);

    batch6();
    printf("test_w64_derived_bridge: %u checks, 0 failures\n", checks);
    return 0;
}
