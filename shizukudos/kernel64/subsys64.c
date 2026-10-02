/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 WIN64 subsystem service: the Kernel64 end of the "64-bit subsystem bridge" through which a
 * 32-bit Windows 98 program (NTW32.DLL over NTWRAP9X.VXD, in the Win98 domain) starts, feeds, watches and
 * kills Win64 PE32+ processes that run here in Long Mode. Wire format: abi/shz_ipc.h, ABI 1.1, opcodes
 * SHZ_OP_W64_* (validated with the shared shz_w64_*_check helpers before anything is acted on).
 *
 * Profiles:
 *   Supervisor  subsys64_start() binds to the channel whose peer is SHZ_DOM_WIN98 (created by the Supervisor
 *               once a Win98 domain exists) and serves it until the client sends SHUTDOWN. Not runnable here
 *               (needs Intel VMX and a Win98 domain); the code path compiles into KERNEL64.BIN.
 *   Standalone  there is no peer domain at all, so subsys64_start() builds a loopback channel in kernel
 *               memory, runs the very same service on a kernel thread and drives it from a client that
 *               speaks the wire format exactly as the VxD/DLL do. Results: "K64 subsys64 PASS/FAIL" lines
 *               and evidence slot 31 (checked by tests/run_k64_standalone.py).
 *
 * Console relay: a process created here gets a per-process "console sink" (process.console_sink, inherited by
 * its children); sysfile.c hands NtWriteFile/NtReadFile on the console objects to subsys64_console_write/read.
 * Output is queued per stream and sent as ordered CONSOLE_OUTPUT frames under a credit window
 * (SHZ_W64_CONSOLE_WINDOW unacknowledged frames); a writer whose queue is full blocks for up to
 * W64_WRITE_WAIT_MS and then drops (counted, reported in PROCESS_EXITED). Input arrives as CONSOLE_INPUT
 * frames into a bounded stdin queue; a reader blocks until data, EOF or its own termination.
 */
#include "proc_internal.h"
#include "fs.h"
#include "../abi/shz_ipc.h"
#include "../pma_bridge/service.h"

#define W64_MAX_PROCS 4
#define W64_OUT_FIFO 2048u
#define W64_IN_FIFO 1024u
#define W64_WRITE_WAIT_MS 10000u
#define W64_SHUTDOWN_WAIT_MS 5000u

extern int32_t ldr_create_process(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                                  process_t **out_proc, thread_t **out_thread);

typedef struct { uint8_t buf[W64_OUT_FIFO]; uint32_t head, tail; } w64_fifo_t;   /* head - tail = bytes queued */

typedef struct {
    int used;
    uint32_t gen;                       /* bumped on every allocation: stale process.console_sink pointers are ignored */
    int pid;
    process_t *proc;                    /* valid until reaped */
    uint32_t state;                     /* shz_w64_proc_state */
    w64_fifo_t out[2];                  /* stdout, stderr */
    uint8_t in[W64_IN_FIFO];
    uint32_t in_head, in_tail;
    int in_eof;
    uint32_t seq_sent, seq_acked, dropped;
    int reaped, exited_sent;
    int64_t exit_code;
    uint32_t fault_status;
} w64_slot_t;

static w64_slot_t slots[W64_MAX_PROCS];
static uint32_t next_gen = 1;
static process_t bridge_parent;         /* pseudo parent so ldr_create_process() attaches the sink before the thread runs */

static void *chan_base;
static size_t chan_size;
static shz_channel_hdr_t *chan;
static shz_ring_hdr_t *rx, *tx;
static uint32_t peer;
static int notify_supported = 1;
static ksem_t doorbell_sem;
static volatile int shutdown_requested;
static uint64_t shutdown_deadline;
static uint32_t served, proto_errors, refused, stale_msgs, out_frames, in_frames;
static uint64_t start_tick;
/* One service thread owns the PMA bridge state. Windows identities describe
 * the caller; they never become native scheduler threads. Accepted WAITs keep
 * a completion reservation until their reply reaches the existing channel. */
static shz_pma_service_t pma_service;
static shz_msg_hdr_t pma_inbound, pma_rejection;
static uint8_t pma_inbound_payload[SHZ_MSG_MAX_INLINE];
static int pma_inbound_pending, pma_rejection_pending;
static int channel_rx_faulted;
static uint64_t pma_full_ring_retries;

static uint64_t pma_now_ns(void)
{
    const uint64_t tick = ticks_now();
    const uint64_t unit = (uint64_t)TICK_US * 1000;
    return tick > (UINT64_MAX - 1) / unit ? UINT64_MAX - 1 : tick * unit;
}

static int pma_pump(void)
{
    const shz_pma_frame_t *frame;
    int progressed = 0;
    if (pma_service.generation != chan->generation) return 0;
    shz_pma_service_tick(&pma_service, pma_now_ns());
    while ((frame = shz_pma_service_peek(&pma_service)) != 0) {
        shz_msg_hdr_t header = frame->header;
        if (shz_ring_push(tx, &header, frame->payload) != SHZ_OK) {
            ++pma_full_ring_retries;
            break;
        }
        shz_pma_service_ack(&pma_service, header.request_id);
        progressed = 1;
    }
    if (pma_rejection_pending && shz_ring_push(tx, &pma_rejection, 0) == SHZ_OK) {
        pma_rejection_pending = 0;
        progressed = 1;
    }
    if (progressed && notify_supported && shz_notify(peer, 1) == SHZ_E_UNSUPPORTED)
        notify_supported = 0;
    return progressed;
}

static void pma_retry_inbound(void)
{
    int rc;
    if (!pma_inbound_pending || pma_rejection_pending) return;
    rc = shz_pma_service_dispatch(&pma_service, &pma_inbound, pma_inbound_payload, pma_now_ns());
    if (rc == SHZ_E_QUEUE_FULL) return; /* retry unchanged after outgoing replies drain */
    pma_inbound_pending = 0;
    if (rc == SHZ_OK) return;
    memset(&pma_rejection, 0, sizeof pma_rejection);
    pma_rejection.flags = SHZ_MSGF_REPLY;
    pma_rejection.opcode = pma_inbound.opcode;
    pma_rejection.request_id = pma_inbound.request_id;
    pma_rejection.src_domain = SHZ_DOM_KERNEL64;
    pma_rejection.dst_domain = pma_inbound.src_domain;
    pma_rejection.generation = pma_service.generation;
    pma_rejection.status = rc;
    pma_rejection_pending = 1;
}

void subsys64_doorbell(void) { sem_post(&doorbell_sem); }

/* ---------------------------------------------------------------- slots */
static w64_slot_t *slot_by_pid(uint32_t pid)
{
    unsigned i;
    for (i = 0; i < W64_MAX_PROCS; ++i)
        if (slots[i].used && (uint32_t)slots[i].pid == pid)
            return &slots[i];
    return 0;
}

static w64_slot_t *slot_alloc(void)
{
    unsigned i;
    for (i = 0; i < W64_MAX_PROCS; ++i)
        if (!slots[i].used) {
            memset(&slots[i], 0, sizeof slots[i]);
            slots[i].used = 1;
            slots[i].gen = next_gen++;
            return &slots[i];
        }
    return 0;
}

static unsigned active_count(void)
{
    unsigned i, n = 0;
    for (i = 0; i < W64_MAX_PROCS; ++i)
        if (slots[i].used && !slots[i].reaped) ++n;
    return n;
}

static w64_slot_t *sink_of(process_t *p)
{
    w64_slot_t *s = (w64_slot_t *)p->console_sink;
    if (!s || s < slots || s >= slots + W64_MAX_PROCS || !s->used || s->gen != p->console_sink_gen || s->exited_sent)
        return 0;
    return s;
}

/* ---------------------------------------------------------------- console hooks (process thread context) */
int subsys64_console_write(process_t *p, int stream, const void *data, uint64_t n)
{
    w64_slot_t *s = sink_of(p);
    w64_fifo_t *f;
    const uint8_t *src = data;
    uint32_t waited = 0;
    if (!s)
        return 0;
    f = &s->out[stream == 2 ? 1 : 0];
    while (n) {
        uint64_t fl = irq_save();
        uint32_t space = W64_OUT_FIFO - (f->head - f->tail), k;
        if (space > n) space = (uint32_t)n;
        for (k = 0; k < space; ++k)
            f->buf[(f->head + k) % W64_OUT_FIFO] = src[k];
        f->head += space;
        irq_restore(fl);
        src += space;
        n -= space;
        if (n) {
            if (p->terminated || waited++ >= W64_WRITE_WAIT_MS) {
                fl = irq_save();
                s->dropped += (uint32_t)n;                   /* the client never drained: report, do not wedge */
                irq_restore(fl);
                break;
            }
            thread_sleep_ms(1);
        }
    }
    return 1;
}

int subsys64_console_read(process_t *p, void *buf, uint64_t cap, uint64_t *got)
{
    w64_slot_t *s = sink_of(p);
    if (!s)
        return 0;
    *got = 0;
    for (;;) {
        uint64_t fl = irq_save();
        uint32_t avail = s->in_head - s->in_tail, k;
        int eof = s->in_eof;
        if (avail) {
            if (avail > cap) avail = (uint32_t)cap;
            for (k = 0; k < avail; ++k)
                ((uint8_t *)buf)[k] = s->in[(s->in_tail + k) % W64_IN_FIFO];
            s->in_tail += avail;
            irq_restore(fl);
            *got = avail;
            return 1;
        }
        irq_restore(fl);
        if (eof || p->terminated)
            return 1;                                       /* *got == 0: end of file */
        thread_sleep_ms(1);
    }
}

/* ---------------------------------------------------------------- transmit helpers */
static int push(shz_msg_hdr_t *h, const void *payload)
{
    int rc;
    unsigned spins = 0;
    for (;;) {
        /* A blocked W64 reply shares this worker with PMA. Expire accepted
         * waits and give their retained completions the first available slot. */
        pma_pump();
        rc = shz_ring_push(tx, h, payload);
        if (rc != SHZ_E_QUEUE_FULL || spins++ >= 2000 ||
            (shutdown_requested && ticks_now() >= shutdown_deadline)) break;
        thread_sleep_ms(1);                                 /* back-pressure: the client drains its ring */
    }
    if (rc == SHZ_OK && notify_supported && shz_notify(peer, 1) == SHZ_E_UNSUPPORTED)
        notify_supported = 0;                               /* standalone: no Supervisor, the client polls */
    return rc;
}

static void reply(const shz_msg_hdr_t *req, int32_t status, const void *payload, uint16_t len)
{
    shz_msg_hdr_t h;
    memset(&h, 0, sizeof h);
    h.flags = SHZ_MSGF_REPLY;
    h.opcode = req->opcode;
    h.request_id = req->request_id;
    h.src_domain = SHZ_DOM_KERNEL64;
    h.dst_domain = req->src_domain;
    h.generation = chan->generation;
    h.status = status;
    h.payload_length = len;
    h.capability_id = req->capability_id;
    if (push(&h, payload) != SHZ_OK)
        ++refused;
}

static int event(uint32_t opcode, const void *payload, uint16_t len)
{
    shz_msg_hdr_t h;
    memset(&h, 0, sizeof h);
    h.flags = SHZ_MSGF_ONEWAY;
    h.opcode = opcode;
    h.src_domain = SHZ_DOM_KERNEL64;
    h.dst_domain = (uint16_t)peer;
    h.generation = chan->generation;
    h.payload_length = len;
    return push(&h, payload);
}

static void fill_event(shz_w64_event_t *ev, const w64_slot_t *s, uint32_t state, int32_t status)
{
    memset(ev, 0, sizeof *ev);
    ev->pid = (uint32_t)s->pid;
    ev->state = state;
    ev->status = status;
    ev->fault_status = s->fault_status;
    ev->exit_code = s->exit_code;
    ev->console_seq = s->seq_sent;
    ev->console_dropped = s->dropped;
}

/* ---------------------------------------------------------------- request handlers */
static void handle_query(const shz_msg_hdr_t *m)
{
    shz_w64_info_t info;
    memset(&info, 0, sizeof info);
    info.abi_major = SHZ_ABI_MAJOR;
    info.abi_minor = SHZ_ABI_MINOR;
    info.subsystem_version = SHZ_W64_SUBSYS_VERSION;
    info.capabilities = SHZ_W64_CAP_CREATE | SHZ_W64_CAP_CONSOLE_OUTPUT | SHZ_W64_CAP_CONSOLE_INPUT | SHZ_W64_CAP_KILL |
                        SHZ_W64_CAP_POOL_ARGS;
    info.max_processes = W64_MAX_PROCS;
    info.max_args_bytes = SHZ_W64_MAX_ARGS_BYTES;
    info.console_window = SHZ_W64_CONSOLE_WINDOW;
    info.console_chunk = SHZ_W64_CONSOLE_CHUNK;
    info.active_processes = active_count();
    info.uptime_ns = (ticks_now() - start_tick) * 1000000ull;
    reply(m, SHZ_OK, &info, sizeof info);
}

static void handle_create(const shz_msg_hdr_t *m, const uint8_t *payload)
{
    shz_w64_create_t hdr;
    const uint16_t *block;
    static char path[800], cmd[2048], cwd[800];            /* UTF-8; the service thread is the only user */
    w64_slot_t *s;
    process_t *np = 0;
    thread_t *nt = 0;
    int32_t st;
    shz_w64_event_t ev;
    int rc = shz_w64_create_check(m, payload, chan, chan_base, &hdr, &block);
    if (rc != SHZ_OK) {
        ++refused;
        reply(m, rc, 0, 0);
        return;
    }
    if (utf16_to_utf8(block, hdr.path_chars, path, sizeof path) < 0 ||
        utf16_to_utf8(block + hdr.path_chars, hdr.cmdline_chars, cmd, sizeof cmd) < 0 ||
        utf16_to_utf8(block + hdr.path_chars + hdr.cmdline_chars, hdr.cwd_chars, cwd, sizeof cwd) < 0) {
        ++refused;
        reply(m, SHZ_E_RANGE, 0, 0);
        return;
    }
    s = slot_alloc();
    if (!s) {
        reply(m, SHZ_E_NOMEM, 0, 0);
        return;
    }
    bridge_parent.console_sink = s;
    bridge_parent.console_sink_gen = s->gen;
    st = ldr_create_process(&bridge_parent, path, cmd, cwd, &np, &nt);
    bridge_parent.console_sink = 0;
    if (st) {
        kprintf("K64 subsys64: create %s failed (%x)\n", path, (uint32_t)st);
        fill_event(&ev, s, SHZ_W64_PS_FAILED, st);
        s->used = 0;
        reply(m, SHZ_OK, &ev, sizeof ev);
        return;
    }
    s->proc = np;
    s->pid = np->pid;
    s->state = SHZ_W64_PS_STARTED;
    kprintf("K64 subsys64: started %s as pid %d for domain %u\n", np->name, np->pid, (unsigned)m->src_domain);
    fill_event(&ev, s, SHZ_W64_PS_STARTED, STATUS_SUCCESS);
    reply(m, SHZ_OK, &ev, sizeof ev);
}

static void handle_console_ack(const shz_msg_hdr_t *m, const uint8_t *payload)
{
    shz_w64_console_t c;
    w64_slot_t *s;
    if (shz_w64_console_check(m, payload, &c) != SHZ_OK || c.length) { ++refused; return; }
    s = slot_by_pid(c.pid);
    if (!s || c.seq > s->seq_sent) { ++refused; return; }  /* acknowledging what was never sent: hostile, ignored */
    if (c.seq > s->seq_acked)
        s->seq_acked = c.seq;
}

static void handle_console_input(const shz_msg_hdr_t *m, const uint8_t *payload)
{
    shz_w64_console_t c;
    w64_slot_t *s;
    uint64_t fl;
    uint32_t space, k;
    int rc = shz_w64_console_check(m, payload, &c);
    if (rc != SHZ_OK || c.stream != 0) { ++refused; reply(m, rc == SHZ_OK ? SHZ_E_INVALID : rc, 0, 0); return; }
    s = slot_by_pid(c.pid);
    if (!s || s->reaped) { reply(m, SHZ_E_NOENT, 0, 0); return; }
    fl = irq_save();
    space = W64_IN_FIFO - (s->in_head - s->in_tail);
    if (s->in_eof) { irq_restore(fl); reply(m, SHZ_E_INVALID, 0, 0); return; }     /* stdin already closed */
    if (c.length > space) { irq_restore(fl); reply(m, SHZ_E_QUEUE_FULL, 0, 0); return; }
    for (k = 0; k < c.length; ++k)
        s->in[(s->in_head + k) % W64_IN_FIFO] = payload[sizeof c + k];
    s->in_head += c.length;
    if (c.flags & SHZ_W64_CONF_EOF)
        s->in_eof = 1;
    irq_restore(fl);
    ++in_frames;
    reply(m, SHZ_OK, 0, 0);
}

static void handle_kill(const shz_msg_hdr_t *m, const uint8_t *payload)
{
    shz_w64_kill_t k;
    w64_slot_t *s;
    if (m->payload_length != sizeof k) { ++refused; reply(m, SHZ_E_INVALID, 0, 0); return; }
    memcpy(&k, payload, sizeof k);
    s = slot_by_pid(k.pid);
    if (!s) { reply(m, SHZ_E_NOENT, 0, 0); return; }
    if (!s->reaped && s->proc && !s->proc->terminated) {
        process_terminate(s->proc, (int64_t)k.exit_code, 0);
        s->state = SHZ_W64_PS_KILLED;
        kprintf("K64 subsys64: pid %d killed on request (exit %d)\n", s->pid, k.exit_code);
    }
    reply(m, SHZ_OK, 0, 0);                                  /* idempotent: an exited process is already "killed" */
}

static void handle_release(const shz_msg_hdr_t *m, const uint8_t *payload)
{
    shz_w64_kill_t k;
    w64_slot_t *s;
    if (m->payload_length != sizeof k) { ++refused; reply(m, SHZ_E_INVALID, 0, 0); return; }
    memcpy(&k, payload, sizeof k);
    s = slot_by_pid(k.pid);
    if (!s) { reply(m, SHZ_E_NOENT, 0, 0); return; }
    if (!s->reaped || !s->exited_sent) { reply(m, SHZ_E_BUSY, 0, 0); return; }
    s->used = 0;
    reply(m, SHZ_OK, 0, 0);
}

static void handle(const shz_msg_hdr_t *m, const uint8_t *payload)
{
    if (m->src_domain != peer) { ++refused; return; }
    if (m->generation != chan->generation || m->dst_domain != SHZ_DOM_KERNEL64) {
        ++stale_msgs;
        if (!(m->flags & SHZ_MSGF_ONEWAY))
            reply(m, SHZ_E_STALE, 0, 0);
        return;
    }
    ++served;
    switch (m->opcode) {
    case SHZ_OP_W64_QUERY: handle_query(m); break;
    case SHZ_OP_W64_CREATE_PROCESS: handle_create(m, payload); break;
    case SHZ_OP_W64_CONSOLE_ACK: handle_console_ack(m, payload); break;
    case SHZ_OP_W64_CONSOLE_INPUT: handle_console_input(m, payload); break;
    case SHZ_OP_W64_KILL_PROCESS: handle_kill(m, payload); break;
    case SHZ_OP_W64_RELEASE: handle_release(m, payload); break;
    case SHZ_OP_W64_SHUTDOWN:
        shutdown_requested = 1;
        shutdown_deadline = ticks_now() + W64_SHUTDOWN_WAIT_MS;
        KASSERT(shz_pma_service_shutdown(&pma_service) == SHZ_OK);
        reply(m, SHZ_OK, 0, 0);
        break;
    default:
        if (!(m->flags & SHZ_MSGF_ONEWAY))
            reply(m, SHZ_E_UNSUPPORTED, 0, 0);
        else
            ++refused;
    }
}

/* ---------------------------------------------------------------- output pump and reaping */
static int pump_slot(w64_slot_t *s)
{
    unsigned stream;
    int progressed = 0;
    /* The last thread drops threads_alive before releasing process resources.
     * proc_wait can block while teardown is still running, defeating the outer
     * shutdown deadline. Keep pumping until teardown makes reaping ready. */
    if (!s->reaped && s->proc && s->proc->terminated && s->proc->threads_alive == 0 &&
        s->proc->teardown == 2) {
        int64_t code = 0;
        int faulted = 0;
        if (proc_wait(s->pid, &code, &faulted) == 0) {
            s->exit_code = code;
            s->fault_status = faulted ? (uint32_t)code : 0;
            if (s->state != SHZ_W64_PS_KILLED) s->state = SHZ_W64_PS_EXITED;
            s->reaped = 1;
            s->proc = 0;
            progressed = 1;
        }
    }
    for (stream = 0; stream < 2; ++stream) {
        w64_fifo_t *f = &s->out[stream];
        while (f->head != f->tail && s->seq_sent - s->seq_acked < SHZ_W64_CONSOLE_WINDOW) {
            uint8_t pl[SHZ_MSG_MAX_INLINE];
            shz_w64_console_t c;
            uint64_t fl = irq_save();
            uint32_t n = f->head - f->tail, k;
            if (n > SHZ_W64_CONSOLE_CHUNK) n = SHZ_W64_CONSOLE_CHUNK;
            for (k = 0; k < n; ++k)
                pl[sizeof c + k] = f->buf[(f->tail + k) % W64_OUT_FIFO];
            irq_restore(fl);
            memset(&c, 0, sizeof c);
            c.pid = (uint32_t)s->pid;
            c.seq = s->seq_sent + 1;
            c.length = (uint16_t)n;
            c.stream = (uint8_t)(stream + 1);
            memcpy(pl, &c, sizeof c);
            if (event(SHZ_OP_W64_CONSOLE_OUTPUT, pl, (uint16_t)(sizeof c + n)) != SHZ_OK)
                return progressed;                          /* ring full: retry on the next pass */
            fl = irq_save();
            f->tail += n;                                   /* consume only once the frame is on the wire */
            irq_restore(fl);
            ++s->seq_sent;
            ++out_frames;
            progressed = 1;
        }
    }
    if (s->reaped && !s->exited_sent && s->out[0].head == s->out[0].tail && s->out[1].head == s->out[1].tail) {
        shz_w64_event_t ev;
        fill_event(&ev, s, s->state, STATUS_SUCCESS);
        if (event(SHZ_OP_W64_PROCESS_EXITED, &ev, sizeof ev) == SHZ_OK) {
            s->exited_sent = 1;
            progressed = 1;
            kprintf("K64 subsys64: pid %d %s, exit %d fault %x, %u console frame(s), %u dropped byte(s)\n", s->pid,
                    s->state == SHZ_W64_PS_KILLED ? "killed" : "exited", (int)s->exit_code, s->fault_status,
                    s->seq_sent, s->dropped);
        }
    }
    return progressed;
}

static void service_loop(void)
{
    while (!shutdown_requested) {
        shz_msg_hdr_t m;
        uint8_t payload[SHZ_MSG_MAX_INLINE];
        int reason, rc, busy;
        unsigned i, receive_budget = 64;
#ifndef SHZ_STANDALONE
        {   /* Native workers belong to the actual Windows domain. A failed or
             * exited owner cannot leave this service admitting work forever. */
            hcreg_t owner_state = SHZ_DS_UNUSED;
            const long owner_rc = shz_hcall(SHZ_HC_DOMAIN_STATE, peer, 0, &owner_state);
            if (owner_rc != SHZ_OK ||
                (owner_state != SHZ_DS_RUNNABLE && owner_state != SHZ_DS_WAITING)) {
                kprintf("K64 subsys64: native owner ended: status %ld state %u\n",
                        owner_rc, (unsigned)owner_state);
                shutdown_requested = 1;
                shutdown_deadline = ticks_now() + W64_SHUTDOWN_WAIT_MS;
                KASSERT(shz_pma_service_shutdown(&pma_service) == SHZ_OK);
                break;
            }
        }
#endif
        if (pma_service.generation < chan->generation) {
            /* A Supervisor-owned channel epoch fences every old identity,
             * request and reply. Never re-stamp an old completion as new. */
            pma_inbound_pending = pma_rejection_pending = 0;
            channel_rx_faulted = 0;
            KASSERT(shz_pma_service_restart(&pma_service, chan->generation) == SHZ_OK);
        }
        busy = pma_pump();
        pma_retry_inbound();
        while (receive_budget-- && !shutdown_requested && !channel_rx_faulted && !pma_inbound_pending && !pma_rejection_pending &&
               (rc = shz_ring_pop(rx, &m, payload, sizeof payload, &reason)) != SHZ_E_NOENT) {
            busy = 1;
            if (rc == SHZ_OK && m.src_domain != peer) ++refused;
            else if (rc == SHZ_OK && shz_pma_is_opcode(m.opcode)) {
                pma_inbound = m;
                memset(pma_inbound_payload, 0, sizeof pma_inbound_payload);
                memcpy(pma_inbound_payload, payload, m.payload_length);
                pma_inbound_pending = 1;
                pma_retry_inbound();
            } else if (rc == SHZ_OK) handle(&m, payload);
            else {
                ++proto_errors;                            /* malformed slot consumed and dropped, never answered */
                if (reason == SHZ_PR_HEAD_CORRUPT || rc == SHZ_E_INVALID) {
                    /* The slot was not consumed. Quarantine this receive ring
                     * until a newer Supervisor epoch; keep accepted deadlines
                     * and outgoing completion processing live. */
                    channel_rx_faulted = 1;
                    break;
                }
            }
        }
        busy |= pma_pump();
        for (i = 0; i < W64_MAX_PROCS; ++i)
            if (slots[i].used) busy |= pump_slot(&slots[i]);
        if (!busy) {
            if (notify_supported) { sem_wait_timeout(&doorbell_sem, 5); shz_doorbell_ack(); }
            else thread_sleep_ms(1);
        }
    }
    {   /* shutdown: kill what is still running, reap it, and report */
        unsigned i, rounds = 0;
        for (i = 0; i < W64_MAX_PROCS; ++i)
            if (slots[i].used && !slots[i].reaped && slots[i].proc && !slots[i].proc->terminated) {
                process_terminate(slots[i].proc, 0x102, 0);
                slots[i].state = SHZ_W64_PS_KILLED;
            }
        while (active_count() && rounds++ < W64_SHUTDOWN_WAIT_MS && ticks_now() < shutdown_deadline) {
            pma_pump();
            for (i = 0; i < W64_MAX_PROCS; ++i)
                if (slots[i].used) pump_slot(&slots[i]);
            thread_sleep_ms(1);
        }
    }
    while ((shz_pma_service_peek(&pma_service) || pma_rejection_pending) && ticks_now() < shutdown_deadline)
        if (!pma_pump()) thread_sleep_ms(1);
    if (shz_pma_service_peek(&pma_service) || pma_rejection_pending)
        kprintf("K64 subsys64: shutdown completion drain reached %u ms limit; native domain exits next\n", W64_SHUTDOWN_WAIT_MS);
    kprintf("K64 subsys64: service stopped: %u request(s), %u output frame(s), %u input frame(s), %u protocol error(s), "
            "%u refused, %u stale\n", served, out_frames, in_frames, proto_errors, refused, stale_msgs);
}

static void bind_channel(void *base, size_t bytes, uint32_t peer_domain)
{
    chan_base = base;
    chan_size = bytes;
    chan = (shz_channel_hdr_t *)base;
    KASSERT(shz_channel_valid(chan, chan_size));
    peer = peer_domain;
    rx = shz_channel_ring_rx(chan_base, chan, SHZ_DOM_KERNEL64);
    tx = shz_channel_ring_tx(chan_base, chan, SHZ_DOM_KERNEL64);
    KASSERT(shz_ring_valid(rx) && shz_ring_valid(tx));
    sem_init(&doorbell_sem, 0);
    shutdown_requested = 0;
    shutdown_deadline = 0;
    start_tick = ticks_now();
    pma_inbound_pending = pma_rejection_pending = 0;
    channel_rx_faulted = 0;
    KASSERT(shz_pma_service_init(&pma_service, SHZ_DOM_KERNEL64, peer, chan->generation) == SHZ_OK);
#ifdef SHZ_STANDALONE
    notify_supported = 0;                                   /* no Supervisor: no doorbells, the peer polls */
#endif
}

#ifndef SHZ_STANDALONE
/* Supervisor profile: serve the Win98 domain's channel until it says SHUTDOWN. Without a Win98 domain the
 * Supervisor creates no such channel and this returns at once. */
void subsys64_start(const shz_bootinfo_t *bi)
{
    unsigned c;
    for (c = 0; c < bi->channel_count; ++c) {
        if (bi->channel[c].peer_domain != SHZ_DOM_WIN98)
            continue;
        bind_channel((void *)(DIRECT_MAP + bi->channel[c].gpa), (size_t)bi->channel[c].size, bi->channel[c].peer_domain);
        if (shz_set_doorbell_vector(VEC_DOORBELL) != 0)
            notify_supported = 0;
        kprintf("K64 subsys64: serving WIN64 subsystem requests from domain %u on channel %u\n",
                (unsigned)bi->channel[c].peer_domain, (unsigned)bi->channel[c].channel_id);
        service_loop();
        return;
    }
    kprintf("K64 subsys64: no Win98 peer channel; WIN64 subsystem bridge idle\n");
}
#else
/* ================================================================== standalone loopback self-test
 * The service runs on its own kernel thread over a channel in kernel memory; this thread is the client and
 * sends byte-identical frames to what NTWRAP9X.VXD puts on the ring for NTW32.DLL. */
static uint8_t loop_chan[131072] __attribute__((aligned(4096)));
static unsigned passed, failed;
#define CHECK(name, cond) do { if (cond) { kprintf("K64 subsys64 PASS: %s\n", name); ++passed; } \
    else { kprintf("K64 subsys64 FAIL: %s\n", name); ++failed; } } while (0)

static shz_ring_hdr_t *cl_tx, *cl_rx;
static uint64_t cl_next_id = 0x4000;
static struct { shz_msg_hdr_t h; uint8_t pl[SHZ_MSG_MAX_INLINE]; } evq[64];
static unsigned evq_head, evq_tail;

static void service_thread(void *arg) { (void)arg; service_loop(); }

/* Pops one frame from the client's receive ring; replies go to the caller, one-way events are queued. */
static int cl_poll(shz_msg_hdr_t *reply_h, uint8_t *reply_pl, uint64_t want_id)
{
    shz_msg_hdr_t h;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    int reason, rc;
    while ((rc = shz_ring_pop(cl_rx, &h, pl, sizeof pl, &reason)) != SHZ_E_NOENT) {
        if (rc != SHZ_OK) continue;
        if ((h.flags & SHZ_MSGF_REPLY) && h.request_id == want_id) {
            *reply_h = h;
            memcpy(reply_pl, pl, sizeof pl);
            return 1;
        }
        if (h.flags & SHZ_MSGF_ONEWAY && evq_head - evq_tail < 64) {
            evq[evq_head % 64].h = h;
            memcpy(evq[evq_head % 64].pl, pl, sizeof pl);
            ++evq_head;
        }
    }
    return 0;
}

static int cl_call(uint32_t op, const void *pl, uint16_t len, uint64_t boff, uint32_t blen, uint32_t generation,
                   shz_msg_hdr_t *reply_h, uint8_t *reply_pl, uint32_t timeout_ms)
{
    shz_msg_hdr_t h;
    uint32_t waited = 0;
    memset(&h, 0, sizeof h);
    h.opcode = op;
    h.request_id = cl_next_id++;
    h.src_domain = SHZ_DOM_WIN98;
    h.dst_domain = SHZ_DOM_KERNEL64;
    h.generation = generation;
    h.payload_length = len;
    h.buffer_offset = boff;
    h.buffer_length = blen;
    if (blen) h.flags |= SHZ_MSGF_BUFFER;
    if (shz_ring_push(cl_tx, &h, pl) != SHZ_OK) return SHZ_E_QUEUE_FULL;
    while (!cl_poll(reply_h, reply_pl, h.request_id)) {
        if (waited++ >= timeout_ms) return SHZ_E_TIMEOUT;
        thread_sleep_ms(1);
    }
    return reply_h->status;
}

static void cl_oneway(uint32_t op, const void *pl, uint16_t len)
{
    shz_msg_hdr_t h;
    memset(&h, 0, sizeof h);
    h.flags = SHZ_MSGF_ONEWAY;
    h.opcode = op;
    h.src_domain = SHZ_DOM_WIN98;
    h.dst_domain = SHZ_DOM_KERNEL64;
    h.generation = 1;
    h.payload_length = len;
    KASSERT(shz_ring_push(cl_tx, &h, pl) == SHZ_OK);
}

static int cl_event(shz_msg_hdr_t *h, uint8_t *pl, uint32_t timeout_ms)
{
    shz_msg_hdr_t dummy;
    uint8_t dpl[SHZ_MSG_MAX_INLINE];
    uint32_t waited = 0;
    for (;;) {
        if (evq_head != evq_tail) {
            *h = evq[evq_tail % 64].h;
            memcpy(pl, evq[evq_tail % 64].pl, SHZ_MSG_MAX_INLINE);
            ++evq_tail;
            return 1;
        }
        cl_poll(&dummy, dpl, ~0ull);
        if (evq_head == evq_tail) {
            if (waited++ >= timeout_ms) return 0;
            thread_sleep_ms(1);
        }
    }
}

static void cl_ack(uint32_t pid, uint32_t seq)
{
    shz_w64_console_t c;
    memset(&c, 0, sizeof c);
    c.pid = pid; c.seq = seq;
    cl_oneway(SHZ_OP_W64_CONSOLE_ACK, &c, sizeof c);
}

static int cl_input(uint32_t pid, const char *text, uint16_t n, int eof)
{
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    shz_w64_console_t c;
    shz_msg_hdr_t rh;
    uint8_t rpl[SHZ_MSG_MAX_INLINE];
    memset(&c, 0, sizeof c);
    c.pid = pid; c.length = n; c.stream = 0; c.flags = eof ? SHZ_W64_CONF_EOF : 0;
    memcpy(pl, &c, sizeof c);
    if (n) memcpy(pl + sizeof c, text, n);
    return cl_call(SHZ_OP_W64_CONSOLE_INPUT, pl, (uint16_t)(sizeof c + n), 0, 0, 1, &rh, rpl, 2000);
}

static int cl_simple(uint32_t op, uint32_t pid, int32_t code)
{
    shz_w64_kill_t k = { pid, code };
    shz_msg_hdr_t rh;
    uint8_t rpl[SHZ_MSG_MAX_INLINE];
    return cl_call(op, &k, sizeof k, 0, 0, 1, &rh, rpl, 2000);
}

static void wstr(uint16_t *out, const char *s, uint32_t *n) { uint32_t i; for (i = 0; s[i]; ++i) out[i] = (uint8_t)s[i]; *n = i; }

/* Sends CREATE_PROCESS for `exe` with `cmdline`; returns the wire status and fills *ev on SHZ_OK. */
static int cl_create(const char *exe, const char *cmdline, shz_w64_event_t *ev, int force_pool)
{
    static uint16_t path[300], cmd[2100], cwd[64], block[2200];
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    shz_w64_create_t ch;
    shz_msg_hdr_t rh;
    uint8_t rpl[SHZ_MSG_MAX_INLINE];
    uint32_t np, nc, nw, bytes;
    int pool, rc;
    uint64_t off = 0;
    wstr(path, exe, &np);
    wstr(cmd, cmdline, &nc);
    wstr(cwd, "C:\\SHZ\\TESTS", &nw);
    bytes = shz_w64_create_pack(&ch, path, np, cmd, nc, cwd, nw, block, 2200, &pool);
    KASSERT(bytes);
    if (pool || force_pool) {
        off = shz_pool_alloc(loop_chan, (shz_channel_hdr_t *)loop_chan, SHZ_DOM_WIN98, bytes);
        KASSERT(off);
        memcpy(loop_chan + off, block, bytes);
        rc = cl_call(SHZ_OP_W64_CREATE_PROCESS, &ch, sizeof ch, off, bytes, 1, &rh, rpl, 5000);
        KASSERT(shz_pool_release(loop_chan, (shz_channel_hdr_t *)loop_chan, SHZ_DOM_WIN98, off, bytes, 0) == SHZ_OK);
    } else {
        memcpy(pl, &ch, sizeof ch);
        memcpy(pl + sizeof ch, block, bytes);
        rc = cl_call(SHZ_OP_W64_CREATE_PROCESS, pl, (uint16_t)(sizeof ch + bytes), 0, 0, 1, &rh, rpl, 5000);
    }
    if (rc == SHZ_OK && rh.payload_length == sizeof *ev) memcpy(ev, rpl, sizeof *ev);
    else memset(ev, 0, sizeof *ev);
    return rc;
}

/* Collects console frames for `pid` until PROCESS_EXITED, acknowledging as `ack_every` frames arrive (0 = never),
 * with an optional stdin script (then EOF) sent once the output contains `marker`. `already_acked` is the highest
 * sequence number acknowledged before this call. Returns 1 when EXITED arrived. */
struct run_result { uint32_t frames, bytes, err_bytes, max_unacked, gaps; char text[4096]; uint32_t text_len; shz_w64_event_t exited; int got_exit; };

static int contains(const struct run_result *r, const char *needle);

static int collect(uint32_t pid, unsigned ack_every, const char *stdin_text, const char *marker, uint32_t already_acked,
                   struct run_result *r, uint32_t timeout_ms)
{
    shz_msg_hdr_t h;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    uint32_t last_acked = already_acked, expect_seq = already_acked + 1, sent_stdin = stdin_text ? 0 : 1, silent = 0;
    memset(r, 0, sizeof *r);
    while (silent < timeout_ms) {
        shz_w64_console_t c;
        if (!cl_event(&h, pl, 20)) { silent += 20; continue; }
        silent = 0;
        if (h.opcode == SHZ_OP_W64_PROCESS_EXITED) {
            shz_w64_event_t ev;
            memcpy(&ev, pl, sizeof ev);
            if (ev.pid != pid) continue;
            r->exited = ev;
            r->got_exit = 1;
            return 1;
        }
        if (h.opcode != SHZ_OP_W64_CONSOLE_OUTPUT || shz_w64_console_check(&h, pl, &c) != SHZ_OK || c.pid != pid) continue;
        ++r->frames;
        if (c.seq != expect_seq) ++r->gaps;
        expect_seq = c.seq + 1;
        if (c.seq - last_acked > r->max_unacked) r->max_unacked = c.seq - last_acked;
        if (c.stream == 2) r->err_bytes += c.length; else r->bytes += c.length;
        if (r->text_len + c.length < sizeof r->text) { memcpy(r->text + r->text_len, pl + sizeof c, c.length); r->text_len += c.length; }
        if (ack_every && c.seq - last_acked >= ack_every) { cl_ack(pid, c.seq); last_acked = c.seq; }
        if (!sent_stdin && contains(r, marker)) {
            const uint32_t n = (uint32_t)strlen(stdin_text);
            cl_input(pid, stdin_text, (uint16_t)n, 0);
            cl_input(pid, 0, 0, 1);
            sent_stdin = 1;
        }
    }
    return 0;
}

static int contains(const struct run_result *r, const char *needle)
{
    const uint32_t n = (uint32_t)strlen(needle);
    uint32_t i;
    for (i = 0; i + n <= r->text_len; ++i)
        if (!memcmp(r->text + i, needle, n)) return 1;
    return 0;
}

/* CREATE acknowledges the process object, not execution of its user entrypoint.
 * Observe and ACK real output before a kill whose regression also requires that
 * output. An absolute tick budget stays bounded even if unrelated events arrive. */
static int wait_console_ready(uint32_t pid, const char *marker, struct run_result *r,
                              uint32_t *acked_seq, uint32_t timeout_ms)
{
    const uint64_t start = ticks_now();
    shz_msg_hdr_t h;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    memset(r, 0, sizeof *r);
    *acked_seq = 0;
    while (ticks_now() - start < timeout_ms) {
        shz_w64_console_t c;
        if (!cl_event(&h, pl, 20)) continue;
        if (h.opcode == SHZ_OP_W64_PROCESS_EXITED) {
            shz_w64_event_t ev;
            memcpy(&ev, pl, sizeof ev);
            if (ev.pid == pid) return 0;       /* exited before the readiness marker */
        }
        if (h.opcode != SHZ_OP_W64_CONSOLE_OUTPUT ||
            shz_w64_console_check(&h, pl, &c) != SHZ_OK || c.pid != pid) continue;
        if (r->text_len + c.length < sizeof r->text) {
            memcpy(r->text + r->text_len, pl + sizeof c, c.length);
            r->text_len += c.length;
        }
        cl_ack(pid, c.seq);
        *acked_seq = c.seq;
        if (contains(r, marker)) return 1;
    }
    return 0;
}

static void inject_bad_slot(int how)
{
    const uint32_t head = cl_tx->head;
    uint8_t *slot = (uint8_t *)cl_tx + sizeof *cl_tx + (size_t)(head & (cl_tx->slot_count - 1)) * SHZ_MSG_SLOT_SIZE;
    shz_msg_hdr_t h;
    memset(&h, 0, sizeof h);
    h.opcode = SHZ_OP_W64_QUERY; h.src_domain = SHZ_DOM_WIN98; h.dst_domain = SHZ_DOM_KERNEL64; h.generation = 1;
    h.request_id = 0x999;
    {   /* push publishes the head: without interrupts off, the (timer-preempted) service thread could pop the still
           valid slot before it is corrupted and answer it as a QUERY (seen once in 4 standalone runs under TCG) */
        const uint64_t fl = irq_save();
        KASSERT(shz_ring_push(cl_tx, &h, 0) == SHZ_OK);
        if (how == 0) slot[0] ^= 0xff;                      /* magic */
        else if (how == 1) slot[0x10] ^= 0x01;              /* opcode bit: checksum mismatch */
        else *(uint32_t *)(slot + 0x0c) = 3000;             /* message_size */
        irq_restore(fl);
    }
}

#define T_HELLO "\\SHZ\\TESTS\\T_HELLO.EXE"
#define T_CON "\\SHZ\\TESTS\\T_W64CON.EXE"

/* PMA fixtures use the actual channel and a separately scheduled service, so
 * SIGNAL may complete WAIT before its own reply. Keep unrelated replies rather
 * than discarding asynchronous completions as a synchronous client would. */
static struct { int used; uint64_t order; shz_msg_hdr_t h; uint8_t pl[SHZ_MSG_MAX_INLINE]; } pma_replies[64];
static unsigned pma_passed, pma_failed;
static uint64_t pma_received_order, pma_taken_order;
#define PMA_CHECK(name, cond) do { if (cond) { ++pma_passed; ++passed; kprintf("K64 PMA bridge PASS: %s\n", name); } \
    else { ++pma_failed; ++failed; kprintf("K64 PMA bridge FAIL: %s\n", name); } } while (0)

static shz_pma_request_t pma_request(uint32_t pid, uint32_t tid)
{
    shz_pma_request_t r;
    memset(&r, 0, sizeof r);
    r.magic = SHZ_PMA_MAGIC;
    r.abi_major = SHZ_PMA_ABI_MAJOR;
    r.abi_minor = SHZ_PMA_ABI_MINOR;
    r.size = sizeof r;
    r.domain = SHZ_DOM_WIN98;
    r.pid = pid; r.tid = tid;
    r.owner_generation = r.thread_generation = 1;
    return r;
}

static uint64_t pma_send(uint32_t op, const shz_pma_request_t *r, uint64_t id, uint32_t generation)
{
    shz_msg_hdr_t h;
    unsigned waited = 0;
    int rc;
    memset(&h, 0, sizeof h);
    h.opcode = op;
    h.request_id = id ? id : cl_next_id++;
    h.src_domain = SHZ_DOM_WIN98;
    h.dst_domain = SHZ_DOM_KERNEL64;
    h.generation = generation;
    h.payload_length = sizeof *r;
    while ((rc = shz_ring_push(cl_tx, &h, r)) == SHZ_E_QUEUE_FULL) {
        if (++waited > 500) return 0;
        thread_sleep_ms(1);
    }
    return rc == SHZ_OK ? h.request_id : 0;
}

static int pma_take(uint64_t id, shz_msg_hdr_t *h, uint8_t *pl, unsigned timeout_ms)
{
    uint64_t start = ticks_now();
    unsigned i;
    if (!id) return 0;
    for (i = 0; i < 64; ++i)
        if (pma_replies[i].used && pma_replies[i].h.request_id == id) {
            *h = pma_replies[i].h;
            memcpy(pl, pma_replies[i].pl, SHZ_MSG_MAX_INLINE);
            pma_taken_order = pma_replies[i].order;
            pma_replies[i].used = 0;
            return 1;
        }
    for (;;) {
        shz_msg_hdr_t next;
        uint8_t data[SHZ_MSG_MAX_INLINE];
        int reason, rc;
        while ((rc = shz_ring_pop(cl_rx, &next, data, sizeof data, &reason)) != SHZ_E_NOENT) {
            if (rc != SHZ_OK) continue;
            if (!(next.flags & SHZ_MSGF_REPLY)) continue;
            ++pma_received_order;
            if (next.request_id == id) {
                *h = next; memcpy(pl, data, sizeof data);
                pma_taken_order = pma_received_order;
                return 1;
            }
            for (i = 0; i < 64; ++i) if (!pma_replies[i].used) break;
            KASSERT(i < 64);
            pma_replies[i].used = 1;
            pma_replies[i].order = pma_received_order;
            pma_replies[i].h = next;
            memcpy(pma_replies[i].pl, data, sizeof data);
        }
        if (ticks_now() - start >= timeout_ms) return 0;
        thread_sleep_ms(1);
    }
}

static int pma_result(uint64_t id, int32_t status, shz_pma_completion_t *out)
{
    shz_msg_hdr_t h;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    if (!pma_take(id, &h, pl, 2000) || h.status != status || h.flags != SHZ_MSGF_REPLY ||
        h.src_domain != SHZ_DOM_KERNEL64 || h.dst_domain != SHZ_DOM_WIN98 || h.generation != 1) return 0;
    if (h.payload_length == sizeof(shz_pma_completion_t)) {
        shz_pma_completion_t c;
        memcpy(&c, pl, sizeof c);
        if (c.magic != SHZ_PMA_MAGIC || c.size != sizeof c || c.sequence != id || c.status != status) return 0;
        if (out) *out = c;
    } else if (out) return 0;
    return 1;
}

static int pma_call(uint32_t op, shz_pma_request_t *r, int32_t status, shz_pma_completion_t *out)
{
    return pma_result(pma_send(op, r, 0, 1), status, out);
}

static uint64_t pma_wait(uint32_t object, uint32_t tid, uint64_t deadline)
{
    shz_pma_request_t r = pma_request(600, tid);
    r.object = object; r.deadline_ns = deadline;
    return pma_send(SHZ_OP_PMA_EVENT_WAIT, &r, 0, 1);
}

static void pma_selftest(void)
{
    shz_pma_request_t r = pma_request(600, 1);
    shz_pma_completion_t c;
    shz_msg_hdr_t h;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    uint32_t automatic = 0, manual = 0;
    uint64_t a, b, op, before;
    int ok;
    shz_pma_info_t info;

    a = pma_send(SHZ_OP_PMA_QUERY, &r, 0, 1);
    memset(&info, 0, sizeof info);
    ok = pma_take(a, &h, pl, 2000) && h.status == SHZ_OK && h.payload_length == sizeof info;
    if (ok) memcpy(&info, pl, sizeof info);
    r.required_features = UINT64_C(1) << 63;
    ok &= pma_call(SHZ_OP_PMA_QUERY, &r, SHZ_E_UNSUPPORTED, 0);
    r.required_features = 0; r.abi_major = 2;
    ok &= pma_call(SHZ_OP_PMA_QUERY, &r, SHZ_E_UNSUPPORTED, 0);
    r.abi_major = SHZ_PMA_ABI_MAJOR; r.abi_minor = 2;
    b = pma_send(SHZ_OP_PMA_QUERY, &r, 0, 1);
    ok &= pma_take(b, &h, pl, 2000) && h.status == SHZ_OK;
    r.abi_minor = SHZ_PMA_ABI_MINOR;
    PMA_CHECK("query negotiation", ok && info.magic == SHZ_PMA_MAGIC && info.abi_major == 1 &&
              info.features == 31 && info.max_waits > 0 && info.max_completions > info.max_waits &&
              info.now_ns > 0 && info.now_ns <= pma_now_ns() && info.generation == 1 && info.self_domain == SHZ_DOM_KERNEL64 &&
              info.peer_domain == SHZ_DOM_WIN98);

    memset(&c, 0, sizeof c);
    ok = pma_call(SHZ_OP_PMA_EVENT_CREATE, &r, SHZ_OK, &c);
    automatic = c.object;
    a = pma_wait(automatic, 2, UINT64_MAX);
    thread_sleep_ms(10);
    ok &= !pma_take(a, &h, pl, 0); /* an unsignaled WAIT has no immediate success reply */
    r.object = automatic;
    ok &= pma_call(SHZ_OP_PMA_EVENT_SIGNAL, &r, SHZ_OK, 0) && pma_result(a, SHZ_OK, 0);
    b = pma_wait(automatic, 2, 0);
    ok &= pma_result(b, SHZ_E_TIMEOUT, 0);
    PMA_CHECK("auto-reset deferred wait", ok && automatic != 0);

    r.object = 0; r.flags = SHZ_PMA_EVENT_MANUAL_RESET;
    memset(&c, 0, sizeof c);
    ok = pma_call(SHZ_OP_PMA_EVENT_CREATE, &r, SHZ_OK, &c);
    manual = c.object; r.flags = 0; r.object = manual;
    a = pma_wait(manual, 2, UINT64_MAX); b = pma_wait(manual, 3, UINT64_MAX);
    thread_sleep_ms(5);
    ok &= !pma_take(a, &h, pl, 0) && !pma_take(b, &h, pl, 0);
    ok &= pma_call(SHZ_OP_PMA_EVENT_SIGNAL, &r, SHZ_OK, 0);
    ok &= pma_result(a, SHZ_OK, 0) && pma_result(b, SHZ_OK, 0);
    ok &= pma_result(pma_wait(manual, 2, 0), SHZ_OK, 0);
    ok &= pma_call(SHZ_OP_PMA_EVENT_RESET, &r, SHZ_OK, 0);
    ok &= pma_result(pma_wait(manual, 2, 0), SHZ_E_TIMEOUT, 0);
    PMA_CHECK("manual-reset broadcast", ok && manual != 0);

    r = pma_request(600, 1);
    b = pma_send(SHZ_OP_PMA_QUERY, &r, 0, 1);
    ok = pma_take(b, &h, pl, 2000) && h.status == SHZ_OK && h.payload_length == sizeof info;
    memcpy(&info, pl, sizeof info);
    before = ticks_now();
    b = info.now_ns + UINT64_C(15000000);
    a = pma_wait(automatic, 2, b);
    ok &= pma_result(a, SHZ_E_TIMEOUT, 0);
    PMA_CHECK("timeout", ok && pma_now_ns() >= b && ticks_now() - before < 2000);

    a = pma_wait(automatic, 2, UINT64_MAX);
    r = pma_request(600, 2); r.target_sequence = a;
    ok = pma_call(SHZ_OP_PMA_CANCEL, &r, SHZ_OK, 0) && pma_result(a, SHZ_E_CANCELLED, 0);
    PMA_CHECK("cancellation", ok);

    r = pma_request(600, 1); r.object = automatic;
    a = pma_send(SHZ_OP_PMA_EVENT_SIGNAL, &r, 0, 9);
    PMA_CHECK("stale generation", pma_result(a, SHZ_E_STALE, 0) &&
              pma_result(pma_wait(automatic, 2, 0), SHZ_E_TIMEOUT, 0));

    op = pma_send(SHZ_OP_PMA_EVENT_SIGNAL, &r, 0, 1);
    ok = pma_result(op, SHZ_OK, 0) && pma_result(pma_wait(automatic, 2, 0), SHZ_OK, 0);
    ok &= pma_send(SHZ_OP_PMA_EVENT_SIGNAL, &r, op, 1) == op && pma_result(op, SHZ_E_STALE, 0);
    ok &= pma_result(pma_wait(automatic, 2, 0), SHZ_E_TIMEOUT, 0);
    PMA_CHECK("duplicate request", ok);

    a = pma_wait(automatic, 4, UINT64_MAX);
    r = pma_request(600, 4);
    ok = pma_call(SHZ_OP_PMA_THREAD_EXIT, &r, SHZ_OK, 0) && pma_result(a, SHZ_E_CANCELLED, 0);
    r.object = automatic;
    ok &= pma_call(SHZ_OP_PMA_EVENT_WAIT, &r, SHZ_E_STALE, 0);
    r.thread_generation = 2; r.deadline_ns = 0;
    ok &= pma_call(SHZ_OP_PMA_EVENT_WAIT, &r, SHZ_E_TIMEOUT, 0);
    PMA_CHECK("thread cleanup", ok);

    /* Fill the real reply ring without consuming replies. A timeout completion
     * must remain queued, then appear once after the peer drains the ring. */
    {
        uint64_t ids[32], retries = pma_full_ring_retries;
        unsigned i;
        a = pma_wait(automatic, 2, pma_now_ns() + UINT64_C(30000000));
        r = pma_request(600, 1);
        for (i = 0; i < 32; ++i) ids[i] = pma_send(SHZ_OP_PMA_QUERY, &r, 0, 1);
        thread_sleep_ms(60);
        ok = cl_rx->head - cl_rx->tail == 32 && pma_full_ring_retries > retries;
        for (i = 0; i < 32; ++i)
            ok &= pma_take(ids[i], &h, pl, 2000) && h.status == SHZ_OK && h.payload_length == sizeof info;
        ok &= pma_result(a, SHZ_E_TIMEOUT, 0) && !pma_take(a, &h, pl, 5);
        PMA_CHECK("full-ring completion retention", ok);
    }

    /* A W64 reply under back-pressure must not monopolize the worker and
     * postpone an already accepted PMA deadline. Decode wire arrival order. */
    {
        uint64_t ids[32], legacy, timeout_order;
        unsigned i;
        shz_msg_hdr_t request;
        r = pma_request(600, 1);
        b = pma_send(SHZ_OP_PMA_QUERY, &r, 0, 1);
        ok = pma_take(b, &h, pl, 2000) && h.status == SHZ_OK && h.payload_length == sizeof info;
        memcpy(&info, pl, sizeof info);
        a = pma_wait(automatic, 2, info.now_ns + UINT64_C(30000000));
        for (i = 0; i < 32; ++i) ids[i] = pma_send(SHZ_OP_PMA_QUERY, &r, 0, 1);
        thread_sleep_ms(5);
        ok &= cl_rx->head - cl_rx->tail == 32;
        memset(&request, 0, sizeof request);
        request.opcode = SHZ_OP_W64_QUERY; request.request_id = legacy = cl_next_id++;
        request.src_domain = SHZ_DOM_WIN98; request.dst_domain = SHZ_DOM_KERNEL64; request.generation = 1;
        ok &= shz_ring_push(cl_tx, &request, 0) == SHZ_OK;
        thread_sleep_ms(60);
        for (i = 0; i < 32; ++i) ok &= pma_take(ids[i], &h, pl, 2000) && h.status == SHZ_OK;
        ok &= pma_result(a, SHZ_E_TIMEOUT, 0);
        timeout_order = pma_taken_order;
        ok &= pma_take(legacy, &h, pl, 2000) && h.status == SHZ_OK && h.opcode == SHZ_OP_W64_QUERY;
        PMA_CHECK("mixed W64 backpressure deadline", ok && timeout_order < pma_taken_order);
    }

    a = pma_wait(automatic, 2, UINT64_MAX);
    r = pma_request(600, 1);
    ok = pma_call(SHZ_OP_PMA_PROCESS_EXIT, &r, SHZ_OK, 0) && pma_result(a, SHZ_E_CANCELLED, 0);
    ok &= pma_call(SHZ_OP_PMA_EVENT_CREATE, &r, SHZ_E_STALE, 0);
    r.owner_generation = 2;
    memset(&c, 0, sizeof c);
    ok &= pma_call(SHZ_OP_PMA_EVENT_CREATE, &r, SHZ_OK, &c) && c.object != automatic;
    r.object = automatic;
    ok &= pma_call(SHZ_OP_PMA_EVENT_SIGNAL, &r, SHZ_E_NOENT, 0);
    r.object = c.object;
    ok &= pma_call(SHZ_OP_PMA_EVENT_CLOSE, &r, SHZ_OK, 0);
    PMA_CHECK("process cleanup", ok);

    {
        uint32_t object;
        r = pma_request(601, 1);
        memset(&c, 0, sizeof c);
        ok = pma_call(SHZ_OP_PMA_EVENT_CREATE, &r, SHZ_OK, &c);
        object = c.object;
        r.object = object; r.deadline_ns = UINT64_MAX;
        a = pma_send(SHZ_OP_PMA_EVENT_WAIT, &r, 0, 1);
        r.object = 0; r.deadline_ns = 0;
        ok &= pma_call(SHZ_OP_PMA_THREAD_EXIT, &r, SHZ_OK, 0) && pma_result(a, SHZ_E_CANCELLED, 0);
        /* VMM process teardown may run after its last caller thread is dead. */
        ok &= pma_call(SHZ_OP_PMA_PROCESS_EXIT, &r, SHZ_OK, 0);
        r.tid = 2;
        ok &= pma_call(SHZ_OP_PMA_EVENT_CREATE, &r, SHZ_E_STALE, 0);
        r.owner_generation = 2;
        memset(&c, 0, sizeof c);
        ok &= pma_call(SHZ_OP_PMA_EVENT_CREATE, &r, SHZ_OK, &c) && c.object != object;
        r.object = object;
        ok &= pma_call(SHZ_OP_PMA_EVENT_SIGNAL, &r, SHZ_E_NOENT, 0);
        r.object = c.object;
        ok &= pma_call(SHZ_OP_PMA_EVENT_CLOSE, &r, SHZ_OK, 0);
        PMA_CHECK("process cleanup after thread exit", ok);
    }

    /* A corrupt producer index is quarantined once. The native worker must
     * still expire and transmit accepted waits, rather than spin on the slot. */
    r = pma_request(600, 1); r.owner_generation = 2;
    memset(&c, 0, sizeof c);
    ok = pma_call(SHZ_OP_PMA_EVENT_CREATE, &r, SHZ_OK, &c);
    r.object = c.object; r.deadline_ns = pma_now_ns() + UINT64_C(30000000);
    a = pma_send(SHZ_OP_PMA_EVENT_WAIT, &r, 0, 1);
    thread_sleep_ms(5);
    {
        uint32_t head = cl_tx->head, errors = proto_errors;
        const uint64_t f = irq_save();
        cl_tx->head = cl_tx->tail + cl_tx->slot_count + 1;
        irq_restore(f);
        thread_sleep_ms(40);
        ok &= pma_result(a, SHZ_E_TIMEOUT, 0) && proto_errors == errors + 1;
        { const uint64_t restore = irq_save(); cl_tx->head = head; irq_restore(restore); }
    }
    PMA_CHECK("corrupt-ring quarantine", ok);

    /* Supervisor epochs may change while a WAIT is outstanding. Only fresh
     * requests belong to the restarted peer; the obsolete WAIT is discarded. */
    { const uint64_t f = irq_save(); chan->generation = 2; irq_restore(f); }
    r = pma_request(600, 1);
    b = pma_send(SHZ_OP_PMA_QUERY, &r, 0, 2);
    ok = pma_take(b, &h, pl, 2000) && h.status == SHZ_OK && h.generation == 2;
    /* Ring metadata validation failures are also nonconsuming. Quarantine
     * those once, keep native deadlines live, and recover in a fresh epoch. */
    r.object = 0;
    memset(&c, 0, sizeof c);
    b = pma_send(SHZ_OP_PMA_EVENT_CREATE, &r, 0, 2);
    ok &= pma_take(b, &h, pl, 2000) && h.status == SHZ_OK && h.payload_length == sizeof c;
    memcpy(&c, pl, sizeof c);
    r.object = c.object; r.deadline_ns = pma_now_ns() + UINT64_C(30000000);
    a = pma_send(SHZ_OP_PMA_EVENT_WAIT, &r, 0, 2);
    thread_sleep_ms(5);
    {
        uint32_t errors = proto_errors, magic = cl_tx->magic;
        const uint64_t f = irq_save(); cl_tx->magic = 0; irq_restore(f);
        thread_sleep_ms(40);
        ok &= pma_take(a, &h, pl, 2000) && h.status == SHZ_E_TIMEOUT && h.generation == 2 && proto_errors == errors + 1;
        { const uint64_t restore = irq_save(); cl_tx->magic = magic; irq_restore(restore); }
    }
    PMA_CHECK("invalid-ring metadata quarantine", ok);

    /* Reuse the next epoch for the outstanding-wait restart itself. */
    { const uint64_t f = irq_save(); chan->generation = 3; irq_restore(f); }
    r = pma_request(600, 1);
    b = pma_send(SHZ_OP_PMA_QUERY, &r, 0, 3);
    ok = pma_take(b, &h, pl, 2000) && h.status == SHZ_OK && h.generation == 3;
    b = pma_send(SHZ_OP_PMA_EVENT_CREATE, &r, 0, 3);
    ok &= pma_take(b, &h, pl, 2000) && h.status == SHZ_OK && h.payload_length == sizeof c;
    memcpy(&c, pl, sizeof c);
    r.object = c.object; r.deadline_ns = UINT64_MAX;
    a = pma_send(SHZ_OP_PMA_EVENT_WAIT, &r, 0, 3);
    thread_sleep_ms(5);
    ok &= !pma_take(a, &h, pl, 0);
    { const uint64_t f = irq_save(); chan->generation = 4; irq_restore(f); }
    r = pma_request(600, 1);
    b = pma_send(SHZ_OP_PMA_QUERY, &r, 0, 4);
    ok &= pma_take(b, &h, pl, 2000) && h.status == SHZ_OK && h.generation == 4 && h.payload_length == sizeof info;
    memcpy(&info, pl, sizeof info);
    ok &= info.generation == 4 && !pma_take(a, &h, pl, 5);
    b = pma_send(SHZ_OP_PMA_QUERY, &r, 0, 1);
    ok &= pma_take(b, &h, pl, 2000) && h.status == SHZ_E_STALE && h.generation == 4;
    PMA_CHECK("domain restart", ok);
}

static int pma_shutdown_selftest(thread_t *svc)
{
    shz_pma_request_t r = pma_request(600, 1);
    shz_pma_completion_t c;
    shz_msg_hdr_t h, shutdown;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    uint64_t ids[32], waiting, trailing, stop;
    unsigned i;
    int ok;
    const uint32_t epoch = chan->generation;
    uint64_t id = pma_send(SHZ_OP_PMA_EVENT_CREATE, &r, 0, epoch);
    ok = pma_take(id, &h, pl, 2000) && h.status == SHZ_OK && h.payload_length == sizeof c;
    memcpy(&c, pl, sizeof c);
    r.object = c.object; r.deadline_ns = UINT64_MAX;
    waiting = pma_send(SHZ_OP_PMA_EVENT_WAIT, &r, 0, epoch);
    r.object = 0; r.deadline_ns = 0;
    for (i = 0; i < 32; ++i) ids[i] = pma_send(SHZ_OP_PMA_QUERY, &r, 0, epoch);
    thread_sleep_ms(5);
    ok &= cl_rx->head - cl_rx->tail == 32;
    memset(&shutdown, 0, sizeof shutdown);
    shutdown.opcode = SHZ_OP_W64_SHUTDOWN; shutdown.request_id = stop = cl_next_id++;
    shutdown.src_domain = SHZ_DOM_WIN98; shutdown.dst_domain = SHZ_DOM_KERNEL64; shutdown.generation = epoch;
    r.object = c.object; r.deadline_ns = UINT64_MAX;
    {
        const uint64_t f = irq_save();
        ok &= shz_ring_push(cl_tx, &shutdown, 0) == SHZ_OK;
        trailing = pma_send(SHZ_OP_PMA_EVENT_WAIT, &r, 0, epoch);
        irq_restore(f);
    }
    thread_sleep_ms(10);
    for (i = 0; i < 32; ++i) ok &= pma_take(ids[i], &h, pl, 2000) && h.status == SHZ_OK;
    ok &= pma_take(waiting, &h, pl, 2000) && h.status == SHZ_E_CANCELLED && h.generation == epoch;
    ok &= pma_take(stop, &h, pl, 2000) && h.status == SHZ_OK && h.opcode == SHZ_OP_W64_SHUTDOWN;
    thread_join(svc);
    ok &= !pma_take(trailing, &h, pl, 5) && shz_ring_count(cl_tx) == 1 && !shz_pma_service_peek(&pma_service);
    PMA_CHECK("shutdown cancels waits and stops admission", ok && shutdown_requested);
    return ok ? SHZ_OK : SHZ_E_PROTO;
}

static void selftest(void)
{
    thread_t *svc;
    shz_msg_hdr_t rh;
    uint8_t rpl[SHZ_MSG_MAX_INLINE];
    shz_w64_event_t ev;
    struct run_result rr;
    int rc;
    uint32_t pid;
    const uint64_t free_before = pmm_free_count();

    KASSERT(shz_channel_init(loop_chan, sizeof loop_chan, 2, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, 1) == SHZ_OK);
    bind_channel(loop_chan, sizeof loop_chan, SHZ_DOM_WIN98);
    cl_tx = shz_channel_ring_tx(loop_chan, chan, SHZ_DOM_WIN98);
    cl_rx = shz_channel_ring_rx(loop_chan, chan, SHZ_DOM_WIN98);
    svc = thread_create("w64svc", service_thread, 0);
    KASSERT(svc);
    kprintf("K64 subsys64: loopback self-test (no peer domain in the standalone profile)\n");

    /* 1. capabilities */
    rc = cl_call(SHZ_OP_W64_QUERY, 0, 0, 0, 0, 1, &rh, rpl, 2000);
    {
        shz_w64_info_t info;
        memcpy(&info, rpl, sizeof info);
        CHECK("QUERY reports ABI 1.1, subsystem 1.0, every capability, 4 slots, window 8, chunk 176",
              rc == SHZ_OK && rh.payload_length == sizeof info && info.abi_major == 1 && info.abi_minor == 1 &&
              info.subsystem_version == SHZ_W64_SUBSYS_VERSION && info.capabilities == 31 && info.max_processes == W64_MAX_PROCS &&
              info.console_window == 8 && info.console_chunk == 176 && info.active_processes == 0);
    }

    /* 2. malformed / failing creation */
    {
        uint8_t pl[SHZ_MSG_MAX_INLINE];
        shz_w64_create_t bad;
        memset(&bad, 0, sizeof bad);
        bad.path_chars = 3; bad.block_bytes = 8;
        memcpy(pl, &bad, sizeof bad); memset(pl + sizeof bad, 'A', 8);
        rc = cl_call(SHZ_OP_W64_CREATE_PROCESS, pl, sizeof bad + 8, 0, 0, 1, &rh, rpl, 2000);
        CHECK("CREATE with disagreeing lengths is INVALID", rc == SHZ_E_INVALID);
        rc = cl_call(SHZ_OP_W64_CREATE_PROCESS, pl, 4, 0, 0, 1, &rh, rpl, 2000);
        CHECK("CREATE with a truncated header is PROTO", rc == SHZ_E_PROTO);
        memset(&bad, 0, sizeof bad);
        bad.path_chars = 1; bad.block_bytes = 2;
        rc = cl_call(SHZ_OP_W64_CREATE_PROCESS, &bad, sizeof bad, chan->pool_offset, 2, 1, &rh, rpl, 2000);
        CHECK("CREATE referencing an unowned pool block is DENIED", rc == SHZ_E_DENIED);
    }
    rc = cl_create("\\SHZ\\TESTS\\NOPE.EXE", "NOPE.EXE", &ev, 0);
    CHECK("CREATE of a missing image answers a FAILED event with STATUS_OBJECT_NAME_NOT_FOUND",
          rc == SHZ_OK && ev.state == SHZ_W64_PS_FAILED && ev.status == STATUS_OBJECT_NAME_NOT_FOUND && ev.pid == 0);

    /* 3. T_HELLO.EXE end to end: STARTED, ordered output, EXITED with exit code 7 */
    rc = cl_create(T_HELLO, "T_HELLO.EXE first", &ev, 0);
    pid = ev.pid;
    CHECK("CREATE T_HELLO.EXE answers STARTED with a pid", rc == SHZ_OK && ev.state == SHZ_W64_PS_STARTED && ev.status == 0 && pid != 0);
    collect(pid, 1, 0, 0, 0, &rr, 10000);
    CHECK("T_HELLO.EXE console output relayed in order and EXITED reports exit code 7, no fault",
          rr.got_exit && rr.exited.state == SHZ_W64_PS_EXITED && rr.exited.exit_code == 7 && rr.exited.fault_status == 0 &&
          rr.gaps == 0 && rr.frames >= 1 && rr.exited.console_seq == rr.frames && rr.exited.console_dropped == 0 &&
          contains(&rr, "hello from Win64 PE32+") && contains(&rr, "PROCESSOR_ARCHITECTURE=AMD64"));
    CHECK("RELEASE frees the slot once, then reports NOENT", cl_simple(SHZ_OP_W64_RELEASE, pid, 0) == SHZ_OK &&
          cl_simple(SHZ_OP_W64_RELEASE, pid, 0) == SHZ_E_NOENT);

    /* 4. T_W64CON.EXE: flow control window, stderr stream, stdin echo and EOF */
    rc = cl_create(T_CON, "T_W64CON.EXE", &ev, 0);
    pid = ev.pid;
    CHECK("CREATE T_W64CON.EXE answers STARTED", rc == SHZ_OK && ev.state == SHZ_W64_PS_STARTED && pid != 0);
    {
        /* do not acknowledge for a while: at most SHZ_W64_CONSOLE_WINDOW frames may arrive */
        shz_msg_hdr_t h;
        uint8_t pl[SHZ_MSG_MAX_INLINE];
        unsigned got = 0, waited;
        uint32_t highest = 0;
        for (waited = 0; waited < 40; ++waited) {
            while (cl_event(&h, pl, 1)) {
                shz_w64_console_t c;
                if (h.opcode == SHZ_OP_W64_CONSOLE_OUTPUT && shz_w64_console_check(&h, pl, &c) == SHZ_OK && c.pid == pid) {
                    ++got;
                    highest = c.seq;
                }
            }
            thread_sleep_ms(10);
        }
        CHECK("without CONSOLE_ACK the service stops after exactly the window of 8 frames", got == SHZ_W64_CONSOLE_WINDOW && highest == 8);
        cl_ack(pid, highest);
    }
    collect(pid, 3, "ping\n", "argc=", 8, &rr, 10000);
    CHECK("T_W64CON.EXE: 3000 stdout bytes + echo of stdin, stderr marker on stream 2, EOF ends it, exit 0",
          rr.got_exit && rr.exited.exit_code == 0 && rr.exited.fault_status == 0 && rr.gaps == 0 && rr.err_bytes == 24 &&
          rr.max_unacked <= SHZ_W64_CONSOLE_WINDOW && rr.exited.console_dropped == 0 &&
          contains(&rr, "line 29 ") && contains(&rr, "cmdline=12 chars argc=1") && contains(&rr, "echo:ping") &&
          contains(&rr, "stdin closed after 5 bytes"));
    kprintf("K64 subsys64: T_W64CON relay: %u frames, %u stdout bytes, %u stderr bytes, max unacked %u\n", rr.frames + 8,
            rr.bytes, rr.err_bytes, rr.max_unacked);
    CHECK("RELEASE after EXITED", cl_simple(SHZ_OP_W64_RELEASE, pid, 0) == SHZ_OK);

    /* 5. argument block through the pool (too long for one slot) */
    {
        static char longcmd[300];
        unsigned i;
        memcpy(longcmd, "T_W64CON.EXE ", 13);
        for (i = 13; i < 263; ++i) longcmd[i] = (char)('a' + i % 26);
        longcmd[263] = 0;
        rc = cl_create(T_CON, longcmd, &ev, 0);
        pid = ev.pid;
        CHECK("CREATE with a 596-byte argument block travels through the shared pool and starts", rc == SHZ_OK && ev.state == SHZ_W64_PS_STARTED);
        collect(pid, 1, "", "argc=", 0, &rr, 10000);
        CHECK("the pool-carried command line reached the process intact (263 chars)", rr.got_exit && rr.exited.exit_code == 0 &&
              contains(&rr, "cmdline=263 chars argc=2"));
        cl_simple(SHZ_OP_W64_RELEASE, pid, 0);
    }

    /* 6. KILL_PROCESS and the RELEASE / INPUT / KILL error cases */
    rc = cl_create(T_CON, "T_W64CON.EXE hang", &ev, 0);
    pid = ev.pid;
    CHECK("CREATE of the hanging probe starts", rc == SHZ_OK && ev.state == SHZ_W64_PS_STARTED);
    CHECK("RELEASE of a live process is BUSY", cl_simple(SHZ_OP_W64_RELEASE, pid, 0) == SHZ_E_BUSY);
    {
        unsigned k;
        int last = SHZ_OK, full = 0;
        char chunk[SHZ_W64_CONSOLE_CHUNK];
        memset(chunk, 'z', sizeof chunk);
        for (k = 0; k < 7; ++k) {                           /* 7 x 176 = 1232 > the 1024-byte stdin queue */
            last = cl_input(pid, chunk, sizeof chunk, 0);
            if (last == SHZ_E_QUEUE_FULL) { full = 1; break; }
        }
        CHECK("CONSOLE_INPUT beyond the 1024-byte stdin queue is QUEUE_FULL, earlier chunks accepted", full && k == 5);
    }
    struct run_result ready;
    uint32_t ready_acked;
    CHECK("hanging probe produced its real readiness banner before KILL_PROCESS",
          wait_console_ready(pid, "hanging until killed", &ready, &ready_acked, 10000));
    CHECK("KILL_PROCESS with exit code 0x77 is accepted", cl_simple(SHZ_OP_W64_KILL_PROCESS, pid, 0x77) == SHZ_OK);
    collect(pid, 1, 0, 0, ready_acked, &rr, 10000);
    CHECK("killed process reports KILLED, exit code 0x77, no fault", rr.got_exit && rr.exited.state == SHZ_W64_PS_KILLED &&
          rr.exited.exit_code == 0x77 && rr.exited.fault_status == 0 && contains(&ready, "hanging until killed"));
    CHECK("KILL of an already exited process is OK, of an unknown pid NOENT",
          cl_simple(SHZ_OP_W64_KILL_PROCESS, pid, 1) == SHZ_OK && cl_simple(SHZ_OP_W64_KILL_PROCESS, 0x7777, 1) == SHZ_E_NOENT);
    CHECK("CONSOLE_INPUT to an unknown pid is NOENT", cl_input(0x7777, "x", 1, 0) == SHZ_E_NOENT);
    cl_simple(SHZ_OP_W64_RELEASE, pid, 0);

    /* 7. capacity: four slots, the fifth is NOMEM, then everything is killed and reaped */
    {
        uint32_t pids[W64_MAX_PROCS];
        unsigned i, started = 0, exited = 0;
        for (i = 0; i < W64_MAX_PROCS; ++i) {
            rc = cl_create(T_CON, "T_W64CON.EXE hang", &ev, 0);
            pids[i] = ev.pid;
            if (rc == SHZ_OK && ev.state == SHZ_W64_PS_STARTED) ++started;
        }
        rc = cl_create(T_CON, "T_W64CON.EXE hang", &ev, 0);
        CHECK("four bridged processes run at once; the fifth CREATE is NOMEM", started == W64_MAX_PROCS && rc == SHZ_E_NOMEM);
        rc = cl_call(SHZ_OP_W64_QUERY, 0, 0, 0, 0, 1, &rh, rpl, 2000);
        { shz_w64_info_t info; memcpy(&info, rpl, sizeof info); CHECK("QUERY counts the four active processes", rc == SHZ_OK && info.active_processes == 4); }
        for (i = 0; i < W64_MAX_PROCS; ++i) cl_simple(SHZ_OP_W64_KILL_PROCESS, pids[i], 3);
        for (i = 0; i < W64_MAX_PROCS; ++i) {
            shz_msg_hdr_t h; uint8_t pl[SHZ_MSG_MAX_INLINE];
            uint32_t waited = 0;
            while (waited < 10000 && cl_event(&h, pl, 50)) {
                if (h.opcode == SHZ_OP_W64_PROCESS_EXITED) { ++exited; break; }
                waited += 50;
            }
        }
        for (i = 0; i < W64_MAX_PROCS; ++i) cl_simple(SHZ_OP_W64_RELEASE, pids[i], 0);
        CHECK("all four killed processes report EXITED and release", exited == W64_MAX_PROCS &&
              cl_simple(SHZ_OP_W64_RELEASE, pids[0], 0) == SHZ_E_NOENT);
    }

    /* 8. protocol robustness */
    rc = cl_call(SHZ_OP_W64_QUERY, 0, 0, 0, 0, 5, &rh, rpl, 2000);
    CHECK("stale generation is rejected with STALE", rc == SHZ_E_STALE);
    rc = cl_call(0x2ff, 0, 0, 0, 0, 1, &rh, rpl, 2000);
    CHECK("unknown WIN64 opcode is UNSUPPORTED", rc == SHZ_E_UNSUPPORTED);
    rc = cl_call(0x100, 0, 0, 0, 0, 1, &rh, rpl, 2000);
    CHECK("a Kernel32-family opcode is UNSUPPORTED on this channel", rc == SHZ_E_UNSUPPORTED);
    inject_bad_slot(0); inject_bad_slot(1); inject_bad_slot(2);
    rc = cl_call(SHZ_OP_W64_QUERY, 0, 0, 0, 0, 1, &rh, rpl, 2000);
    CHECK("three malformed slots are dropped and the service still answers", rc == SHZ_OK && proto_errors == 3);
    {
        shz_w64_console_t c;
        memset(&c, 0, sizeof c);
        c.pid = 1; c.seq = 5000;
        cl_oneway(SHZ_OP_W64_CONSOLE_ACK, &c, sizeof c);      /* hostile ack for a pid that never existed */
        rc = cl_call(SHZ_OP_W64_QUERY, 0, 0, 0, 0, 1, &rh, rpl, 2000);
        CHECK("a CONSOLE_ACK for an unknown process is ignored", rc == SHZ_OK);
    }

    {
        shz_msg_hdr_t hostile;
        memset(&hostile, 0, sizeof hostile);
        hostile.opcode = SHZ_OP_W64_SHUTDOWN;
        hostile.request_id = cl_next_id++;
        hostile.src_domain = SHZ_DOM_KERNEL32;
        hostile.dst_domain = SHZ_DOM_KERNEL64;
        hostile.generation = chan->generation;
        KASSERT(shz_ring_push(cl_tx, &hostile, 0) == SHZ_OK);
        rc = cl_call(SHZ_OP_W64_QUERY, 0, 0, 0, 0, chan->generation, &rh, rpl, 2000);
        CHECK("hostile source cannot SHUTDOWN the service; the real peer still receives QUERY", rc == SHZ_OK && !shutdown_requested);
    }

    /* 9. PMA requests share the same live channel and service thread. */
    pma_selftest();

    /* 10. shutdown */
    rc = pma_shutdown_selftest(svc);
    CHECK("SHUTDOWN stops the service thread", rc == SHZ_OK && shutdown_requested);
    kprintf("K64 subsys64: physical pages: %llu free before, %llu after (heap warm-up may keep some)\n", free_before, pmm_free_count());
    kprintf("K64 subsys64: loopback self-test %u passed, %u failed\n", passed, failed);
    kprintf("K64 PMA bridge: %u passed, %u failed\n", pma_passed, pma_failed);
    KASSERT(passed <= 255 && failed <= 255);
    shz_evidence(31, 0x57340000ull | ((uint64_t)passed << 8) | failed);
}

void subsys64_start(const shz_bootinfo_t *bi)
{
    (void)bi;
    if (!fs_lookup(T_HELLO) || !fs_lookup(T_CON)) {
        kprintf("K64 subsys64: test images missing, loopback self-test skipped\n");
        shz_evidence(31, 0x57340000ull);
        return;
    }
    selftest();
}
#endif
