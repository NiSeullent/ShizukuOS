/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 audio service: syscall NtShzSound (0xda, ABI ../abi/shz_audio.h), PCM conversion, one exclusive
 * process-owned output stream and a bounded 32-descriptor ring over a hardware backend (audio.h; AC97 in audio_ac97.c).
 *
 * Authority: the caller's process_t* comes from the syscall dispatcher; the stream records process pointer, pid and
 * create_tick and pins the process object (ob_ref) until audio_process_teardown() (called from process_teardown())
 * stops the engine. Caller-supplied ids are never credentials; the 64-bit handle is only a generation check.
 * Lock order: audio_lock only. The interrupt handler (backend) touches hardware registers and a counter, nothing else.
 * Completion: slots retire only when the hardware position (CIV/DCH) proves the DMA consumed them.
 */
#include "proc_internal.h"
#include "audio.h"
#include "../abi/shz_audio.h"

#define COMP_CAP 96u                            /* completed-cookie ring; admission reserves a terminal entry per accepted cookie */
#define HW_RATE 48000u

typedef struct {
    int used, started, hw_run, paused, fault, underrun_latched;
    uint64_t handle;
    process_t *owner;
    int pid;
    uint64_t create_tick;
    kobject_t *object;
    uint32_t channels, bits, rate, vol_l, vol_r, acc;
    uint32_t head, queued;
    uint32_t slot_frames[AUDIO_RING_SLOTS];
    uint64_t slot_cookie[AUDIO_RING_SLOTS];
    uint64_t played_bytes, submitted_bytes;
    uint32_t underruns;
    shz_snd_cookie comp[COMP_CAP];
    uint32_t comp_head, comp_count;
} stream_t;

static kmutex_t audio_lock;
static stream_t st;
static uint64_t gen_counter;
static int dev_faulted;
static uint32_t output_left=0xffff,output_right=0xffff,output_muted;
extern int shz_auth_sound_control_allowed(process_t *);
static const audio_backend *be;
extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);

static void comp_push(uint64_t cookie, uint32_t flags)
{
    shz_snd_cookie *c;
    KASSERT(st.comp_count < COMP_CAP);
    c = &st.comp[(st.comp_head + st.comp_count++) % COMP_CAP];
    c->cookie = cookie; c->flags = flags; c->reserved = 0;
}

/* Moves slots the hardware proved consumed from the queue to the completed state; *pos gets the last hardware sample. */
static void retire(audio_hw_pos *pos)
{
    uint32_t d, done;
    pos->sr = AUDIO_SR_DCH; pos->civ = 0; pos->picb = 0;
    if (!st.started) return;
    be->position(pos);
    if (!st.queued) return;
    d = (pos->civ - st.head) % AUDIO_RING_SLOTS;
    done = d;
    /* Halt after the last valid buffer: DCH alone is not consumption (pause/error also halt). Require CELV, CIV at the
     * last queued slot and PICB==0 (nothing left in the buffer). */
    if ((pos->sr & AUDIO_SR_DCH) && (pos->sr & AUDIO_SR_CELV) && pos->picb == 0 &&
        pos->civ == (st.head + st.queued - 1) % AUDIO_RING_SLOTS) done = st.queued;
    if (done > st.queued) done = st.queued;
    while (done) {
        const uint32_t s = st.head;
        if (st.slot_cookie[s]) comp_push(st.slot_cookie[s], 0);
        st.played_bytes += (uint64_t)st.slot_frames[s] * 4u;
        st.slot_cookie[s] = 0; st.slot_frames[s] = 0;
        st.head = (st.head + 1) % AUDIO_RING_SLOTS;
        --st.queued; --done;
    }
}

/* Cookies queued but not yet terminal: each already owns a reserved completed-ring entry (comp_count + this <= COMP_CAP). */
static uint32_t queued_cookies(void)
{
    uint32_t i, n = 0;
    for (i = 0; i < AUDIO_RING_SLOTS; ++i) if (st.slot_cookie[i]) ++n;
    return n;
}

static int stop_stream(void);
static int ensure_running(uint32_t lvi)
{
    int rc;
    if (!st.started) {
        st.started = 1;                                 /* attempted start: engine state unknown until proven stopped */
        rc = be->start(lvi);
        if (!rc) st.hw_run = 1;
    } else if (!st.hw_run) {
        rc = be->extend(lvi);
        if (!rc) rc = be->pause(0);
        if (!rc) st.hw_run = 1;
    } else {
        rc = be->extend(lvi);
    }
    if (rc) { (void)stop_stream(); st.fault = 1; }      /* stop/prove; unproven stop quarantines (dev_faulted), pages never reused */
    return rc;
}

/* Halts the engine and proves it inactive; unplayed cookies complete as ABORTED. Returns 0 when inactive is proven. */
static int stop_stream(void)
{
    int rc = st.started ? be->stop() : 0;
    while (st.queued) {
        const uint32_t s = st.head;
        if (st.slot_cookie[s]) comp_push(st.slot_cookie[s], SHZ_SND_COOKIEF_ABORTED);
        st.slot_cookie[s] = 0; st.slot_frames[s] = 0;
        st.head = (st.head + 1) % AUDIO_RING_SLOTS;
        --st.queued;
    }
    st.head = 0; st.acc = 0; st.hw_run = 0; st.paused = 0; st.underrun_latched = 0;
    if (rc) { dev_faulted = 1; st.fault = 1; }            /* engine not proven halted: nothing is ever reused */
    else { st.started = 0; }
    return rc;
}

static void release_stream(void)
{
    if (be->irq_detach) be->irq_detach();
    if (st.object) ob_deref(st.object);
    memset(&st, 0, sizeof st);
}

static int owner_live(process_t *p)
{
    return p && p->used && !p->teardown && !p->terminated;
}

static stream_t *find_stream(process_t *p, uint64_t handle)
{
    if (!st.used || !handle || st.handle != handle) return 0;
    if (st.owner != p || st.pid != p->pid || st.create_tick != p->create_tick) return 0;
    return &st;
}

/* ---------------------------------------------------------------- PCM conversion + queueing */
static uint32_t frame_size(uint32_t ch, uint32_t bits) { return ch * (bits / 8u); }

static int16_t apply_vol(int32_t v, uint32_t vol) { return (int16_t)(((int64_t)v * (int64_t)vol) / 0xffff); }

static int32_t do_write(const shz_snd_write_in *in, shz_snd_write_out *out)
{
    const uint32_t fs = frame_size(st.channels, st.bits), prod = (st.head + st.queued) % AUDIO_RING_SLOTS;
    const uint32_t freeslots = AUDIO_MAX_INFLIGHT - st.queued;
    uint32_t nslots = 0, frames[AUDIO_MAX_INFLIGHT], acc = st.acc, consumed = 0, i;
    uint8_t chunk[256];
    int full = 0;
    uint64_t total_frames = 0;
    memset(frames, 0, sizeof frames);
    while (consumed < in->length && !full) {
        const uint32_t n = in->length - consumed < sizeof chunk ? in->length - consumed : (uint32_t)sizeof chunk;
        uint32_t off;
        if (copy_from_user(st.owner, chunk, in->data + consumed, n)) return STATUS_ACCESS_VIOLATION;   /* nothing committed */
        for (off = 0; off + fs <= n; off += fs) {
            const uint32_t k = (acc + HW_RATE) / st.rate;
            const uint32_t room = (nslots ? AUDIO_SLOT_FRAMES - frames[nslots - 1] : 0) + (freeslots - nslots) * AUDIO_SLOT_FRAMES;
            int32_t l, r;
            uint32_t j;
            if (room < k) { full = 1; break; }
            if (st.bits == 8) {
                l = ((int32_t)chunk[off] - 128) * 256;
                r = st.channels == 2 ? ((int32_t)chunk[off + 1] - 128) * 256 : l;
            } else {
                l = (int16_t)(chunk[off] | (chunk[off + 1] << 8));
                r = st.channels == 2 ? (int16_t)(chunk[off + 2] | (chunk[off + 3] << 8)) : l;
            }
            l = output_muted?0:apply_vol(apply_vol(l, st.vol_l), output_left);
            r = output_muted?0:apply_vol(apply_vol(r, st.vol_r), output_right);
            for (j = 0; j < k; ++j) {
                int16_t *page;
                if (!nslots || frames[nslots - 1] == AUDIO_SLOT_FRAMES) frames[nslots++] = 0;
                page = (int16_t *)be->slot_cpu((prod + nslots - 1) % AUDIO_RING_SLOTS);
                page[frames[nslots - 1] * 2] = (int16_t)l;
                page[frames[nslots - 1] * 2 + 1] = (int16_t)r;
                ++frames[nslots - 1]; ++total_frames;
            }
            acc = (acc + HW_RATE) % st.rate;
            consumed += fs;
        }
    }
    out->size = sizeof *out;
    out->free_slots = freeslots;
    if (!consumed) { out->accepted_bytes = 0; out->flags = SHZ_SND_WRITEF_QUEUE_FULL; return STATUS_DEVICE_BUSY; }
    /* Commit: descriptors are written (and counted busy in the queue) before LVI is published. */
    for (i = 0; i < nslots; ++i) {
        const uint32_t s = (prod + i) % AUDIO_RING_SLOTS;
        st.slot_frames[s] = frames[i];
        st.slot_cookie[s] = i + 1 == nslots ? in->cookie : 0;
        be->slot_program(s, frames[i] * 2u);
    }
    st.queued += nslots;
    st.acc = acc;
    st.submitted_bytes += total_frames * 4u;
    st.underrun_latched = 0;
    out->accepted_bytes = consumed;
    out->flags = consumed < in->length ? SHZ_SND_WRITEF_QUEUE_FULL : 0;
    out->free_slots = freeslots - nslots;
    if (!st.paused && ensure_running((prod + nslots - 1) % AUDIO_RING_SLOTS)) return STATUS_UNSUCCESSFUL;
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- syscall surface */
static int32_t put_out(process_t *cur, uint64_t uout, uint64_t out_len, uint64_t uret, const void *src, uint32_t n)
{
    if (!uout || out_len < n) {
        if (uret && copy_to_user(cur, uret, &n, 4)) return STATUS_ACCESS_VIOLATION;
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (copy_to_user(cur, uout, src, n)) return STATUS_ACCESS_VIOLATION;
    if (uret && copy_to_user(cur, uret, &n, 4)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

static void fill_caps(shz_snd_caps *c, int present, const audio_hw_info *hi)
{
    memset(c, 0, sizeof *c);
    c->size = sizeof *c; c->abi_version = SHZ_SND_ABI_VERSION;
    c->irq_line = 0xffffffffu;
    if (!present) return;
    c->present = 1; c->backend = SHZ_SND_BACKEND_AC97;
    c->flags = (st.used ? SHZ_SND_CAPF_STREAM_OPEN : 0) | (hi->irq_line != 0xffffffffu ? SHZ_SND_CAPF_IRQ : 0) |
               (dev_faulted ? SHZ_SND_CAPF_FAULTED : 0);
    c->bits_mask = SHZ_SND_FMT_8BIT | SHZ_SND_FMT_16BIT;
    c->rate_mask = SHZ_SND_RATE_11025 | SHZ_SND_RATE_22050 | SHZ_SND_RATE_44100 | SHZ_SND_RATE_48000;
    c->max_channels = 2; c->hw_rate = HW_RATE; c->ring_slots = AUDIO_RING_SLOTS;
    c->queue_bytes = AUDIO_MAX_INFLIGHT * AUDIO_SLOT_BYTES;
    c->pci_vendor = hi->vendor; c->pci_device = hi->device; c->irq_line = hi->irq_line;
}

static int backend_ready(audio_hw_info *hi)
{
    if (!be) be = audio_backend_get();
    if (!be) return 0;
    return be->probe(hi) == 0;
}

static int32_t op_open(process_t *cur, uint64_t uin, uint32_t in_len, uint64_t uout, uint64_t out_len, uint64_t uret)
{
    shz_snd_open_in in;
    shz_snd_open_out out;
    audio_hw_info hi;
    int32_t s;
    if (in_len != sizeof in) return STATUS_INFO_LENGTH_MISMATCH;
    if (copy_from_user(cur, &in, uin, sizeof in)) return STATUS_ACCESS_VIOLATION;
    if (in.size != sizeof in || in.reserved || in.volume_left > 0xffff || in.volume_right > 0xffff ||
        (in.channels != 1 && in.channels != 2) || (in.bits != 8 && in.bits != 16) ||
        (in.rate != 11025 && in.rate != 22050 && in.rate != 44100 && in.rate != 48000)) return STATUS_INVALID_PARAMETER;
    if (!owner_live(cur) || !cur->object) return STATUS_PROCESS_IS_TERMINATING;
    if (!backend_ready(&hi) || dev_faulted) return STATUS_DEVICE_NOT_READY;
    if (st.used) return STATUS_DEVICE_BUSY;
    memset(&st, 0, sizeof st);
    st.used = 1; st.owner = cur; st.pid = cur->pid; st.create_tick = cur->create_tick;
    st.object = cur->object; ob_ref(st.object);
    st.channels = in.channels; st.bits = in.bits; st.rate = in.rate; st.vol_l = in.volume_left; st.vol_r = in.volume_right;
    st.handle = ((++gen_counter) << 8) | 0xa5u;
    be->irq_attach();                                  /* optional: polled when the line is not safely shareable */
    memset(&out, 0, sizeof out);
    out.size = sizeof out; out.handle = st.handle; out.hw_rate = HW_RATE; out.queue_bytes = AUDIO_MAX_INFLIGHT * AUDIO_SLOT_BYTES;
    s = put_out(cur, uout, out_len, uret, &out, sizeof out);
    if (s) { stop_stream(); release_stream(); }       /* output copy failed: the stream never existed for the caller */
    return s;
}

static int32_t op_status(process_t *cur, stream_t *s, uint64_t uout, uint64_t out_len, uint64_t uret)
{
    shz_snd_status o;
    audio_hw_pos pos;
    uint32_t n = 0;
    retire(&pos);
    memset(&o, 0, sizeof o);
    o.size = sizeof o;
    o.flags = (s->hw_run ? SHZ_SND_STF_RUNNING : 0) | (s->paused ? SHZ_SND_STF_PAUSED : 0) | (s->fault ? SHZ_SND_STF_FAULT : 0);
    if (s->started && s->hw_run && !s->queued && (pos.sr & AUDIO_SR_DCH)) {
        if (!s->underrun_latched) { s->underrun_latched = 1; ++s->underruns; }
        o.flags |= SHZ_SND_STF_UNDERRUN;
    }
    o.played_bytes = s->played_bytes;
    if (s->started && s->queued && pos.civ == s->head && s->slot_frames[s->head] * 2u >= pos.picb)
        o.played_bytes += (uint64_t)(s->slot_frames[s->head] * 2u - pos.picb) * 2u;    /* partial current buffer */
    o.submitted_bytes = s->submitted_bytes;
    o.queued_slots = s->queued; o.free_slots = AUDIO_MAX_INFLIGHT - s->queued;
    o.underruns = s->underruns; o.irq_count = be->irq_count ? be->irq_count() : 0;
    while (n < SHZ_SND_MAX_COOKIES && n < s->comp_count) {
        o.cookies[n] = s->comp[(s->comp_head + n) % COMP_CAP]; ++n;
    }
    o.cookie_count = n;
    if (s->comp_count > n) o.flags |= SHZ_SND_STF_MORE_COOKIES;
    { const int32_t r = put_out(cur, uout, out_len, uret, &o, sizeof o);
      if (r == STATUS_SUCCESS) { s->comp_head = (s->comp_head + n) % COMP_CAP; s->comp_count -= n; }   /* commit only after both copies */
      return r; }
}

static int32_t sound_locked(process_t *cur, uint32_t op, uint64_t uin, uint32_t in_len, uint64_t uout, uint64_t out_len, uint64_t uret)
{
    audio_hw_info hi;
    union { shz_snd_handle_in h; shz_snd_write_in w; shz_snd_pause_in p; shz_snd_volume_in v; } in;
    shz_snd_write_out wo;
    stream_t *s;
    uint64_t handle;
    uint32_t want;
    int32_t r;
    if (op == SHZ_SND_OP_QUERY) {
        shz_snd_caps c;
        const int present = backend_ready(&hi);
        fill_caps(&c, present, &hi);
        if (!uout) return present ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
        r = put_out(cur, uout, out_len, uret, &c, sizeof c);
        return r ? r : (present ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY);
    }
    if(op==SHZ_SND_OP_OUTPUT_GET||op==SHZ_SND_OP_OUTPUT_SET) {
        shz_snd_output value={sizeof value,output_left,output_right,output_muted};
        if(!owner_live(cur))return STATUS_PROCESS_IS_TERMINATING;
        if(!backend_ready(&hi)||dev_faulted)return STATUS_DEVICE_NOT_READY;
        if(op==SHZ_SND_OP_OUTPUT_GET) {
            if(uin||in_len)return STATUS_INVALID_PARAMETER;
            return put_out(cur,uout,out_len,uret,&value,sizeof value);
        }
        if(!shz_auth_sound_control_allowed(cur))return STATUS_ACCESS_DENIED;
        if(in_len!=sizeof value)return STATUS_INFO_LENGTH_MISMATCH;
        if(copy_from_user(cur,&value,uin,sizeof value))return STATUS_ACCESS_VIOLATION;
        if(value.size!=sizeof value||value.volume_left>0xffff||value.volume_right>0xffff||value.muted>1)return STATUS_INVALID_PARAMETER;
        /* Copyout precedes the mutation. A failing/undersized reply cannot
         * leave an undocumented gain change. No hardware callback runs here. */
        r=put_out(cur,uout,out_len,uret,&value,sizeof value);
        if(r)return r;
        output_left=value.volume_left;output_right=value.volume_right;output_muted=value.muted;
        return STATUS_SUCCESS;
    }
    if (op == SHZ_SND_OP_OPEN) return op_open(cur, uin, in_len, uout, out_len, uret);
    if (op > SHZ_SND_OP_VOLUME) return STATUS_INVALID_PARAMETER;
    if (!be) return STATUS_DEVICE_NOT_READY;
    want = op == SHZ_SND_OP_WRITE ? sizeof in.w : op == SHZ_SND_OP_PAUSE ? sizeof in.p :
           op == SHZ_SND_OP_VOLUME ? sizeof in.v : sizeof in.h;
    if (in_len != want) return STATUS_INFO_LENGTH_MISMATCH;
    memset(&in, 0, sizeof in);
    if (copy_from_user(cur, &in, uin, want)) return STATUS_ACCESS_VIOLATION;
    if (in.h.size != want) return STATUS_INVALID_PARAMETER;                 /* every struct starts with size */
    handle = op == SHZ_SND_OP_WRITE ? in.w.handle : op == SHZ_SND_OP_PAUSE ? in.p.handle :
             op == SHZ_SND_OP_VOLUME ? in.v.handle : in.h.handle;
    s = find_stream(cur, handle);
    if (!s) return STATUS_INVALID_HANDLE;
    if (!owner_live(cur)) return STATUS_PROCESS_IS_TERMINATING;
    switch (op) {
    case SHZ_SND_OP_WRITE:
        if (s->fault || dev_faulted) return STATUS_DEVICE_NOT_READY;
        if (!in.w.data || !in.w.length || in.w.length > SHZ_SND_MAX_WRITE_BYTES || in.w.length % frame_size(s->channels, s->bits) ||
            in.w.reserved || in.w.reserved2) return STATUS_INVALID_PARAMETER;
        { audio_hw_pos pos; retire(&pos); }
        if (in.w.cookie && st.comp_count + queued_cookies() >= COMP_CAP) {   /* backpressure: owner must drain STATUS */
            memset(&wo, 0, sizeof wo);
            wo.size = sizeof wo; wo.flags = SHZ_SND_WRITEF_QUEUE_FULL; wo.free_slots = AUDIO_MAX_INFLIGHT - st.queued;
            put_out(cur, uout, out_len, uret, &wo, sizeof wo);
            return STATUS_DEVICE_BUSY;
        }
        r = do_write(&in.w, &wo);
        if (r == STATUS_SUCCESS || r == STATUS_DEVICE_BUSY) {
            const int32_t c = put_out(cur, uout, out_len, uret, &wo, sizeof wo);
            if (c && r == STATUS_SUCCESS) return c;     /* data is queued: the caller learns via STATUS/cookie */
        }
        return r;
    case SHZ_SND_OP_STATUS: return op_status(cur, s, uout, out_len, uret);
    case SHZ_SND_OP_PAUSE:
        if (in.p.pause > 1) return STATUS_INVALID_PARAMETER;
        if (s->fault) return STATUS_DEVICE_NOT_READY;
        if (in.p.pause && !s->paused) {
            { audio_hw_pos pp; retire(&pp); }           /* account an EOF halt before the gate so resume never replays it */
            if (s->started && s->hw_run) { if (be->pause(1)) { s->fault = 1; return STATUS_UNSUCCESSFUL; } s->hw_run = 0; }
            s->paused = 1;
        } else if (!in.p.pause && s->paused) {
            audio_hw_pos pos;
            s->paused = 0;
            retire(&pos);
            if (s->queued && ensure_running((s->head + s->queued - 1) % AUDIO_RING_SLOTS)) return STATUS_UNSUCCESSFUL;
        }
        return STATUS_SUCCESS;
    case SHZ_SND_OP_RESET:
        return stop_stream() ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
    case SHZ_SND_OP_VOLUME:
        if (in.v.volume_left > 0xffff || in.v.volume_right > 0xffff || in.v.reserved) return STATUS_INVALID_PARAMETER;
        s->vol_l = in.v.volume_left; s->vol_r = in.v.volume_right;
        return STATUS_SUCCESS;
    case SHZ_SND_OP_CLOSE:
        r = stop_stream();
        release_stream();                               /* pages are never freed, so a failed proof only quarantines the device */
        return r ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
    default: return STATUS_INVALID_PARAMETER;
    }
}

int32_t sys_ext_audio(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    int32_t s;
    uint64_t out_len, uret;
    if (num != SYS_NtShzSound) return STATUS_INVALID_SYSTEM_SERVICE;
    if (a1 > 0xff || a3 > 0xffffffffull) return STATUS_INVALID_PARAMETER;
    out_len = (uint32_t)stack_arg(cur, r, 5);
    uret = (uint64_t)stack_arg(cur, r, 6);
    mutex_lock(&audio_lock);
    s = sound_locked(cur, (uint32_t)a1, a2, (uint32_t)a3, a4, out_len, uret);
    mutex_unlock(&audio_lock);
    return s;
}

/* process_teardown(): the owner is dying (teardown flag already set). Stops DMA before the slot/address space is reused. */
void audio_process_teardown(process_t *p)
{
    mutex_lock(&audio_lock);
    if (st.used && st.owner == p) {
        stop_stream();
        release_stream();
    }
    mutex_unlock(&audio_lock);
}
