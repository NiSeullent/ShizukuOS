/* SPDX-License-Identifier: GPL-2.0-only -- combined host regression: production VxD bridge (bridge.c, w64_owner.c,
 * NTWV_W64_DERIVED_OWNER) against the production Kernel64 console relay bodies of shizukudos/kernel64/subsys64.c.
 * tests/test_vxd.py extracts those definitions VERBATIM (slot table, console write, push/reply/event, handle,
 * handle_create/query/console_ack/console_input/kill/release, pump_slot) into subsys64_console_slice.c; nothing in the
 * console credit / EXITED / RELEASE logic is re-implemented here. Both sides share one real shz_channel_init() region.
 * Modelled (prelude below): VMM page services, VWIN32 DIOCParams, Supervisor hypercalls (ATTEST and the live
 * ATTESTED answer), the K64 loader/process lifetime (ldr_create_process, process_terminate, proc_wait), the GUI
 * service and the service-loop scheduling (core_step). No PROCESS_EXITED, KILL reply or ACK is injected by the test:
 * every one of them is produced by the production code. Host-only: no VxD load, no VM, no K64 boot. */
#include "../bridge.h"
#include "../w64_owner.h"
#include "../../../shizukudos/abi/shz_ipc.h"
#include "../../../shizukudos/abi/shz_w64_gui.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SYS_VM 0xc1000000u
#define PROC_A 0x81a00010u
#define PROC_B 0x81b00020u
#define PROC_C 0x81c00040u
static unsigned checks, protected_now;
static unsigned char buffers[3][8192];
static uint8_t channel[SHZ_IPC_REGION_SIZE] __attribute__((aligned(4096)));
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "line %u: %s\n", (unsigned)__LINE__, #x); exit(1); } } while (0)

/* ------------------------------------------------------------ Win98 side model (as test_w64_derived_bridge.c) */
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
    (void)a; (void)b; (void)ecx;
    CHECK(op == SHZ_HC_CHANNEL_ATTEST && !protected_now);
    if (ebx) *ebx = c;
    return SHZ_OK;
}
static void *map_phys(uint32_t phys, uint32_t bytes) { CHECK(phys == 0xe0200000u && bytes == SHZ_IPC_REGION_SIZE); return channel; }
static const struct ntwv_pages ops = { check_range, lock_range, unlock_range, ptes, enter, leave, write_alias, read_alias };
static const struct ntwv_hv hv = { present, hcall, map_phys, hcall3 };
static shz_channel_hdr_t *chdr(void) { return (shz_channel_hdr_t *)channel; }

static uint32_t dioc_as(uint32_t process, uint32_t code, const void *in, uint32_t in_bytes, uint32_t out_bytes, void *out)
{
    struct ntwv_dioc r = { 0 };
    uint32_t result;
    r.vm = SYS_VM; r.process = process; r.code = code;
    r.output = 0x00500ff0; r.output_bytes = out_bytes; r.returned = 0x00600ffe;
    if (in_bytes) { r.input = 0x00700ff0; r.input_bytes = in_bytes; memcpy(buffers[2] + 0xff0, in, in_bytes); }
    result = ntwv_dioc_ex(&r, &ops, &hv);
    if (out) memcpy(out, buffers[0] + 0xff0, out_bytes);
    return result;
}
static uint32_t send_msg(uint32_t process, uint32_t opcode, uint16_t flags, uint64_t id, const void *payload, uint16_t plen)
{
    uint8_t in[256];
    shz_msg_hdr_t h = { 0 };
    int32_t status;
    h.opcode = opcode; h.flags = flags; h.request_id = id; h.payload_length = plen; h.capability_id = 0x55u;
    memcpy(in, &h, sizeof h);
    if (plen) memcpy(in + sizeof h, payload, plen);
    return dioc_as(process, NTWV_IOCTL_W64_SEND, in, (uint32_t)sizeof h + plen, 4, &status);
}
static uint32_t recv_into(uint32_t process, shz_msg_hdr_t *h, void *payload, size_t size)
{
    uint8_t slot[SHZ_MSG_SLOT_SIZE];
    const uint32_t r = dioc_as(process, NTWV_IOCTL_W64_RECV, 0, 0, sizeof slot, slot);
    memcpy(h, slot, sizeof *h);
    if (payload) memcpy(payload, slot + sizeof *h, size);
    return r;
}

/* ------------------------------------------------------------ Kernel64 side: modelled kernel services */
typedef struct thread thread_t;
typedef struct process {
    int pid;
    char name[16];
    volatile int terminated;
    int threads_alive, teardown;
    void *console_sink;
    uint32_t console_sink_gen;
    int64_t exit_code;
} process_t;
#define STATUS_SUCCESS 0
#define KASSERT(x) CHECK(x)
typedef int shz_pma_service_t;
static shz_pma_service_t pma_service;
static process_t procs[16];
static unsigned nprocs;
static uint64_t irq_save(void) { return 0; }
static void irq_restore(uint64_t f) { (void)f; }
static void thread_sleep_ms(unsigned ms) { (void)ms; }
static uint64_t ticks_now(void) { return 0; }
static void kprintf(const char *fmt, ...) { (void)fmt; }
static int pma_pump(void) { return 0; }
static int shz_notify(uint32_t dom, uint32_t vector) { (void)dom; (void)vector; return SHZ_E_UNSUPPORTED; }
static int shz_pma_service_shutdown(shz_pma_service_t *s) { (void)s; return SHZ_OK; }
static int w64_gui_enabled(void) { return 0; }
static unsigned gui_revokes;
static void w64_gui_revoke(uint32_t pid, uint32_t gen) { (void)pid; (void)gen; ++gui_revokes; }
static void w64_gui_revoke_all(void) { CHECK(!"channel revoked"); }
static int chan_auth(void) { return SHZ_CHAN_AUTH_ATTESTED; }  /* the Supervisor's live answer for this generation */
static int utf16_to_utf8(const uint16_t *src, uint64_t chars, char *dst, uint64_t cap)
{
    uint64_t i;
    if (chars >= cap) return -1;
    for (i = 0; i < chars; ++i) { if (src[i] > 0x7f) return -1; dst[i] = (char)src[i]; }
    dst[i] = 0;
    return (int)i;
}
static int32_t ldr_create_process(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                                  process_t **out_proc, thread_t **out_thread)
{
    process_t *p;
    (void)cmdline; (void)cwd;
    CHECK(nprocs < 16);
    p = &procs[nprocs++];
    memset(p, 0, sizeof *p);
    p->pid = 40 + (int)nprocs;
    strncpy(p->name, image_path, sizeof p->name - 1);
    p->threads_alive = 1;
    p->console_sink = parent->console_sink;            /* the real loader inherits the bridge parent's sink */
    p->console_sink_gen = parent->console_sink_gen;
    *out_proc = p;
    *out_thread = 0;
    return 0;
}
static process_t *proc_of(int pid) { unsigned i; for (i = 0; i < nprocs; ++i) if (procs[i].pid == pid) return &procs[i]; return 0; }
static void process_terminate(process_t *p, int64_t code, int faulted)
{
    (void)faulted;
    p->exit_code = code; p->terminated = 1; p->threads_alive = 0; p->teardown = 2;
}
static int proc_wait(int pid, int64_t *exit_code, int *faulted)
{
    process_t *p = proc_of(pid);
    CHECK(p && p->terminated);
    *exit_code = p->exit_code; *faulted = 0;
    return 0;
}
/* subsys64.c service globals (types as in the production file). */
static void *chan_base;
static shz_channel_hdr_t *chan;
static shz_ring_hdr_t *rx, *tx;
static uint32_t peer;
static int notify_supported = 1;
static volatile int shutdown_requested;
static uint64_t shutdown_deadline;
static uint32_t served, refused, stale_msgs, out_frames, in_frames;   /* proto_errors: unused by the extracted bodies */
static uint64_t start_tick;
static process_t bridge_parent;         /* pseudo parent: ldr_create_process() inherits its console sink */
static void handle_gui(const shz_msg_hdr_t *m, const uint8_t *payload) { (void)m; (void)payload; CHECK(!"no GUI here"); }

#ifndef NTWV_CONSOLE_SLICE_DEPSCAN
#include "subsys64_console_slice.c"   /* generated verbatim from shizukudos/kernel64/subsys64.c by tests/test_vxd.py */

/* One service-loop pass: dispatch every queued Win98 message, then pump every slot (service_loop's order). */
static void core_step(void)
{
    shz_msg_hdr_t m;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    int reason;
    unsigned i;
    while (shz_ring_pop(rx, &m, pl, sizeof pl, &reason) == SHZ_OK)
        handle(&m, pl);
    for (i = 0; i < W64_MAX_PROCS; ++i)
        if (slots[i].used) (void)pump_slot(&slots[i]);
}
static uint32_t create_as(uint32_t process, uint64_t id)
{
    uint8_t pl[sizeof(shz_w64_create_t) + 10];
    shz_w64_create_t c;
    shz_w64_event_t ev;
    shz_msg_hdr_t h;
    const uint16_t path[5] = { 'A', '.', 'E', 'X', 'E' };
    memset(&c, 0, sizeof c);
    c.path_chars = 5; c.block_bytes = 10;
    memcpy(pl, &c, sizeof c); memcpy(pl + sizeof c, path, sizeof path);
    CHECK(send_msg(process, SHZ_OP_W64_CREATE_PROCESS, 0, id, pl, sizeof pl) == 0);
    core_step();
    CHECK(recv_into(process, &h, &ev, sizeof ev) == 0 && h.opcode == SHZ_OP_W64_CREATE_PROCESS && h.request_id == id);
    CHECK(h.status == SHZ_OK && ev.state == SHZ_W64_PS_STARTED && ev.pid);
    return ev.pid;
}
static uint32_t used_slots(void) { uint32_t i, n = 0; for (i = 0; i < W64_MAX_PROCS; ++i) n += slots[i].used ? 1u : 0u; return n; }
/* A live third client keeps polling (as NTW32 does); each of its DIOCs runs the VxD reaper. Bounded. */
static unsigned poll_until_released(uint32_t pid)
{
    shz_msg_hdr_t h;
    unsigned round;
    for (round = 0; round < 16; ++round) {
        while (recv_into(PROC_C, &h, 0, 0) == 0) CHECK(!"retired owner's traffic must never reach C");
        core_step();
        if (!slot_by_pid(pid)) {                            /* C consumes the RELEASE reply: custody ends */
            CHECK(recv_into(PROC_C, &h, 0, 0) == NTWV_ERROR_NO_MORE_ITEMS);
            return round;
        }
    }
    return round;
}
static void fill_out(uint32_t pid, uint32_t bytes)
{
    static uint8_t data[4096];
    process_t *p = proc_of((int)pid);
    CHECK(p && bytes <= sizeof data);
    memset(data, 'x', bytes);
    CHECK(subsys64_console_write(p, 1, data, bytes) == 1);
}
#endif

int main(void)
{
#ifndef NTWV_CONSOLE_SLICE_DEPSCAN
    const struct ntw_lock_ops locks = { enter, leave, 0 };
    struct ntwv_w64_open info;
    shz_msg_hdr_t h, junk;
    shz_w64_console_t c;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    uint32_t pid_a, pid_b, i, refused0, stale0, pushed, popped;
    unsigned rounds;
    w64_slot_t *sa, *sb;
    shz_ring_hdr_t *w98_tx;
    int reason;

    ntwv_w64_owner_bind_lock(lock_enter, lock_leave);
    ntwv_w64_owner_bind_system_vm(SYS_VM);
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_A) == 0 && ntwv_w64_owner_handle_open(SYS_VM, PROC_B) == 0 &&
          ntwv_w64_owner_handle_open(SYS_VM, PROC_C) == 0);
    ntwv_w64_reset();
    (void)ntwv_shutdown();
    CHECK(shz_channel_init(channel, sizeof channel, 2, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, 7) == SHZ_OK);
    CHECK(ntwv_initialize(&locks));
    CHECK(dioc_as(PROC_A, NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info) == 0 &&
          info.attested == SHZ_CHAN_ATTEST_W64_DERIVED_OWNER);
    /* Kernel64 binds the same region (bind_channel): K64 tx = Win98 rx and vice versa. */
    chan_base = channel; chan = chdr(); peer = SHZ_DOM_WIN98;
    tx = shz_channel_ring_tx(channel, chdr(), SHZ_DOM_KERNEL64);
    rx = shz_channel_ring_rx(channel, chdr(), SHZ_DOM_KERNEL64);
    w98_tx = shz_channel_ring_tx(channel, chdr(), SHZ_DOM_WIN98);

    pid_b = create_as(PROC_B, 0x100);
    pid_a = create_as(PROC_A, 0x100);                       /* same client id base, different owner */
    sb = slot_by_pid(pid_b); sa = slot_by_pid(pid_a);
    CHECK(sb && sa && sb != sa && ntwv_w64_tracked() == 2);
    /* B: 2048 bytes = window of 8 frames (1408) + 640 still buffered; A: 9 frames' worth (one buffered). */
    fill_out(pid_b, 2048);
    fill_out(pid_a, 9 * SHZ_W64_CONSOLE_CHUNK);
    core_step();
    CHECK(sb->seq_sent == 8 && sb->seq_acked == 0 && sb->out[0].head - sb->out[0].tail == 640);
    fill_out(pid_b, 2048 - 640);                            /* B's FIFO full again behind a full credit window */
    core_step();
    CHECK(sb->seq_sent == 8 && sb->out[0].head - sb->out[0].tail == 2048);
    CHECK(sa->seq_sent == 8 && sa->seq_acked == 0);

    /* Foreign / malformed / stale ACKs are refused by the production core: A acking B's pid (stamped with A's
     * derived identity), A acking with a non-empty payload, and a foreign-generation ACK on the wire. */
    refused0 = refused; stale0 = stale_msgs;
    memset(&c, 0, sizeof c); c.pid = pid_b; c.seq = 8;
    CHECK(send_msg(PROC_A, SHZ_OP_W64_CONSOLE_ACK, SHZ_MSGF_ONEWAY, 0x300, &c, sizeof c) == 0);
    memset(pl, 0, sizeof pl); c.pid = pid_a; c.seq = 8; c.length = 4; memcpy(pl, &c, sizeof c);
    CHECK(send_msg(PROC_A, SHZ_OP_W64_CONSOLE_ACK, SHZ_MSGF_ONEWAY, 0x301, pl, sizeof c) == 0);
    memset(&junk, 0, sizeof junk); c.length = 0; c.pid = pid_b;
    junk.opcode = SHZ_OP_W64_CONSOLE_ACK; junk.flags = SHZ_MSGF_ONEWAY; junk.payload_length = sizeof c;
    junk.src_domain = SHZ_DOM_WIN98; junk.dst_domain = SHZ_DOM_KERNEL64; junk.generation = 8;
    CHECK(shz_ring_push(w98_tx, &junk, &c) == SHZ_OK);
    core_step();
    CHECK(refused == refused0 + 2 && stale_msgs == stale0 + 1 && sb->seq_acked == 0 && sa->seq_acked == 0);

    /* B consumes all 8 of its frames (A's 8 go to the stash) but dies before acknowledging: nothing is left to
     * discard. A consumes its own 8, also without ACK (A is live: its credit stays its own business). */
    for (i = 1; i <= 8; ++i) {
        CHECK(recv_into(PROC_B, &h, pl, sizeof pl) == 0 && h.opcode == SHZ_OP_W64_CONSOLE_OUTPUT);
        memcpy(&c, pl, sizeof c);
        CHECK(c.pid == pid_b && c.seq == i);
    }
    for (i = 1; i <= 8; ++i) CHECK(recv_into(PROC_A, &h, pl, sizeof pl) == 0 && h.opcode == SHZ_OP_W64_CONSOLE_OUTPUT);
    CHECK(recv_into(PROC_A, &h, 0, 0) == NTWV_ERROR_NO_MORE_ITEMS && recv_into(PROC_B, &h, 0, 0) == NTWV_ERROR_NO_MORE_ITEMS);
    ntwv_w64_owner_handle_close(PROC_B);                    /* B's last handle: identity retired */

    /* TX full: the reaper keeps the pending ACK watermark and sends nothing else (no KILL ahead of the ACK). */
    memset(&junk, 0, sizeof junk);
    junk.opcode = SHZ_OP_W64_QUERY; junk.flags = SHZ_MSGF_ONEWAY;
    junk.src_domain = SHZ_DOM_WIN98; junk.dst_domain = SHZ_DOM_KERNEL64; junk.generation = 7;
    for (pushed = 0; shz_ring_push(w98_tx, &junk, 0) == SHZ_OK; ++pushed) {}
    CHECK(recv_into(PROC_C, &h, 0, 0) == NTWV_ERROR_NO_MORE_ITEMS);
    for (popped = 0; shz_ring_pop(rx, &h, pl, sizeof pl, &reason) == SHZ_OK; ++popped)
        CHECK(h.opcode == SHZ_OP_W64_QUERY);
    CHECK(popped == pushed && pushed == 32);
    /* Next DIOC: cumulative trusted ACK(8) before the KILL, both capability 0 on generation 7. */
    CHECK(recv_into(PROC_C, &h, 0, 0) == NTWV_ERROR_NO_MORE_ITEMS);
    CHECK(shz_ring_count(rx) == 2);
    {
        const uint32_t t = rx->tail;
        shz_msg_hdr_t a, k;
        memcpy(&a, shz_ring_slot(rx, t), sizeof a);
        memcpy(&c, (const uint8_t *)shz_ring_slot(rx, t) + sizeof a, sizeof c);
        memcpy(&k, shz_ring_slot(rx, t + 1), sizeof k);
        CHECK(a.opcode == SHZ_OP_W64_CONSOLE_ACK && a.flags == SHZ_MSGF_ONEWAY && a.capability_id == 0 &&
              a.generation == 7 && c.pid == pid_b && c.seq == 8 && !c.length);
        CHECK(k.opcode == SHZ_OP_W64_KILL_PROCESS && k.capability_id == 0);
    }
    refused0 = refused;
    /* Production pump: ACK(8) returns credit, KILL terminates, frames 9..16 go out and are discarded by C's RECV;
     * the reaper acknowledges them (ACK 16), the last 640 bytes leave as frames 17..20, PROCESS_EXITED follows and
     * the trusted RELEASE frees the slot. Without the VxD ACKs the core stays at credit 8 with 2048 bytes queued. */
    rounds = poll_until_released(pid_b);
    CHECK(rounds < 16 && !slot_by_pid(pid_b) && !sb->used);
    CHECK(sb->seq_sent == 20 && sb->seq_acked == 16 && sb->exited_sent && sb->state == SHZ_W64_PS_KILLED && !sb->dropped);
    CHECK(refused == refused0 && ntwv_w64_tracked() == 1);
    CHECK(sa->used && sa->seq_sent == 8 && sa->seq_acked == 0);   /* the live owner's credit was never touched */

    /* The freed core slot is reusable: with A's still allocated, three more creations fit in W64_MAX_PROCS. */
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_B) == 0);
    for (i = 0; i < W64_MAX_PROCS - 1; ++i) (void)create_as(PROC_B, 0x400 + i);
    CHECK(used_slots() == W64_MAX_PROCS && ntwv_w64_tracked() == W64_MAX_PROCS);

    /* Second owner: A exits on its own with one buffered chunk behind a full window; A dies after consuming
     * everything (no ACK). Reaper: ACK(8) -> frame 9 -> EXITED -> discard -> RELEASE. KILL of an exited
     * process is answered OK by the production handler (idempotent). */
    process_terminate(proc_of((int)pid_a), 3, 0);
    core_step();
    CHECK(sa->reaped && !sa->exited_sent && sa->out[0].head != sa->out[0].tail);
    ntwv_w64_owner_handle_close(PROC_A);
    rounds = poll_until_released(pid_a);
    CHECK(rounds < 16 && !sa->used && sa->seq_sent == 9 && sa->seq_acked == 8 && sa->exit_code == 3);
    CHECK(refused == refused0 && ntwv_w64_tracked() == W64_MAX_PROCS - 1);
    printf("test_w64_console_reaper: %u checks, 0 failures (production bridge.c + subsys64.c console relay)\n", checks);
#endif
    return 0;
}
