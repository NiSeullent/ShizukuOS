/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded synchronous VxD adapter. See REFERENCES.md for ABI facts.
 *
 * Two request families share the same user-buffer discipline (validate, pin, check PTEs under cli, copy):
 *   NTWV_IOCTL_QUERY       the original 32-byte version query (unchanged code path);
 *   NTWV_IOCTL_W64_*       the WIN64 subsystem bridge: the Win98 domain's end of the ShizukuDOS ABI 1.1
 *                          channel to Kernel64 (shizukudos/abi/shz_ipc.h), exposed to NTW32.DLL.
 */
#include "bridge.h"

static void ntwv_copy(void *d, const void *s, size_t n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; }
static void ntwv_fill(void *d, int c, size_t n) { uint8_t *a = d; while (n--) *a++ = (uint8_t)c; }
#define SHZ_IPC_MEMCPY(d, s, n) ntwv_copy((d), (s), (n))
#define SHZ_IPC_MEMSET(d, c, n) ntwv_fill((d), (c), (n))
#include "../../shizukudos/abi/shz_ipc.h"

_Static_assert(sizeof(struct ntwv_dioc) == 48, "VWIN32 DIOC ABI");
_Static_assert(sizeof(struct ntwv_query) == 32, "query wire ABI");
_Static_assert(sizeof(struct ntwv_w64_open) == 64, "W64 open wire ABI");
static struct ntw_context context;
/* Readiness/query flags may be observed outside W64 admission. Keep every
 * access atomic; this does not permit concurrent context initialization. */
static uint32_t live, selftest;
/* One owner for the SPSC endpoints, pending table and request scratch. Never
 * spin or sleep here: a preempting/reentrant caller must let the owner finish. */
static uint32_t w64_admitted;

static int w64_enter(void)
{
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&w64_admitted, &expected, 1, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static void w64_leave(void) { __atomic_store_n(&w64_admitted, 0, __ATOMIC_RELEASE); }

int ntwv_initialize(const struct ntw_lock_ops *ops)
{
    ntw_handle handle;
    if (__atomic_load_n(&live, __ATOMIC_ACQUIRE) || ntw_initialize(&context, ops) != NTW_OK)
        return 0;
    /* Real object behavior, before exposing any request interface. */
    if (ntw_event_create(&context, 0, 0, NTW_EVENT_ALL, &handle) != NTW_OK)
        goto failed;
    if (ntw_event_try_wait(&context, handle) != NTW_PENDING ||
        ntw_event_set(&context, handle, 0) != NTW_OK ||
        ntw_event_try_wait(&context, handle) != NTW_OK ||
        ntw_event_try_wait(&context, handle) != NTW_PENDING) {
        (void)ntw_close(&context, handle);
        goto failed;
    }
    if (ntw_close(&context, handle) != NTW_OK)
        goto failed;
    __atomic_store_n(&selftest, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&live, 1, __ATOMIC_RELEASE);
    return 1;
failed:
    (void)ntw_shutdown(&context);
    return 0;
}

int ntwv_shutdown(void)
{
    if (!w64_enter())
        return 0;
    if (!__atomic_load_n(&live, __ATOMIC_ACQUIRE) || ntw_shutdown(&context) != NTW_OK) {
        w64_leave();
        return 0;
    }
    __atomic_store_n(&live, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&selftest, 0, __ATOMIC_RELAXED);
    w64_leave();
    return 1;
}

struct pinned {
    uint32_t original_page, count, alias, offset;
};

static int user_range(uint32_t address, uint32_t bytes)
{
    /* This initial ABI accepts only the Win32 private arena. Shared/system,
     * low DOS mappings, overflow and zero-length requests are excluded. */
    return bytes != 0 && address >= 0x00400000u && address < 0x80000000u &&
           bytes <= 0x80000000u - address;
}

static int pin(const struct ntwv_pages *ops, uint32_t address, uint32_t bytes,
               struct pinned *range)
{
    uint32_t alias;
    range->original_page = address >> 12;
    range->offset = address & 4095u;
    range->count = (range->offset + bytes + 4095u) >> 12;
    range->alias = 0;
    if (ops->check(range->original_page, range->count, 0) != range->count)
        return 0;
    alias = ops->lock(range->original_page, range->count, NTWV_MAP_GLOBAL);
    if (!alias)
        return 0;
    /* The service contract returns a page-aligned system alias. */
    if (alias < 0x80000000u || (alias & 4095u) != 0 ||
        range->count > ((UINT32_MAX - alias) >> 12) + 1) {
        (void)ops->unlock(alias >> 12, range->count, NTWV_MAP_GLOBAL);
        return 0;
    }
    range->alias = alias;
    return 1;
}

/* Present/user original pages (writable too when `write`), present alias pages referring to exactly the
 * same pinned physical frames. */
static int alias_ok(const struct ntwv_pages *ops, const struct pinned *range, int write)
{
    uint32_t original[2], alias[2], i;
    const uint32_t need = write ? 7u : 5u;
    if (range->count > 2 ||
        !ops->ptes(range->original_page, range->count, original, 0) ||
        !ops->ptes(range->alias >> 12, range->count, alias, 0))
        return 0;
    for (i = 0; i < range->count; ++i) {
        if ((original[i] & need) != need || (alias[i] & (write ? 3u : 1u)) != (write ? 3u : 1u) ||
            (original[i] & 0xfffff000u) != (alias[i] & 0xfffff000u))
            return 0;
    }
    return 1;
}

static int writable_alias(const struct ntwv_pages *ops, const struct pinned *range) { return alias_ok(ops, range, 1); }

static uint32_t dioc_query(const struct ntwv_dioc *request, const struct ntwv_pages *ops)
{
    struct ntwv_query reply = { NTWV_QUERY_MAGIC, sizeof(struct ntwv_query),
        1, NTW_ABI_VERSION, NTW_MAX_OBJECTS, 1, 0, 0 };
    struct pinned output, returned;
    uint32_t bytes = sizeof(reply), result = NTWV_ERROR_NOACCESS;
    uintptr_t saved;
    if (request->input || request->input_bytes || request->overlapped)
        return NTWV_ERROR_INVALID_PARAMETER;
    if (request->output_bytes < bytes)
        return NTWV_ERROR_INSUFFICIENT_BUFFER;
    if (!user_range(request->output, bytes) || !user_range(request->returned, 4) ||
        (request->output < request->returned + 4 && request->returned < request->output + bytes))
        return NTWV_ERROR_INVALID_PARAMETER;
    if (!ops || !ops->check || !ops->lock || !ops->unlock || !ops->ptes ||
        !ops->enter || !ops->leave || !ops->write)
        return NTWV_ERROR_NOT_SUPPORTED;
    if (!pin(ops, request->output, bytes, &output))
        return NTWV_ERROR_NOACCESS;
    if (!pin(ops, request->returned, 4, &returned)) {
        (void)ops->unlock(output.alias >> 12, output.count, NTWV_MAP_GLOBAL);
        return NTWV_ERROR_NOACCESS;
    }
    /* Win98 uniprocessor, synchronous callback only. Both aliases are pinned
     * before disabling IRQs. No blocking calls, user pointers or allocations
     * occur inside the bounded PTE-validation / 36-byte-copy interval. */
    saved = ops->enter(0);
    if (writable_alias(ops, &output) && writable_alias(ops, &returned)) {
        reply.initialized = __atomic_load_n(&live, __ATOMIC_ACQUIRE);
        reply.selftest = __atomic_load_n(&selftest, __ATOMIC_ACQUIRE);
        ops->write(output.alias + output.offset, &reply, bytes);
        ops->write(returned.alias + returned.offset, &bytes, 4);
        result = 0;
    }
    ops->leave(0, saved);
    if (!ops->unlock(returned.alias >> 12, returned.count, NTWV_MAP_GLOBAL))
        result = NTWV_ERROR_NOACCESS;
    if (!ops->unlock(output.alias >> 12, output.count, NTWV_MAP_GLOBAL))
        result = NTWV_ERROR_NOACCESS;
    return result;
}

/* ------------------------------------------------------------------ WIN64 subsystem bridge */
static struct {
    int open;
    uint8_t *base;
    uint32_t bytes;
    shz_channel_hdr_t *hdr;
    shz_channel_hdr_t layout;              /* Supervisor-owned layout captured at OPEN */
    shz_ring_hdr_t *tx, *rx;
    uint32_t channel_id, self, peer, generation, abi;
    uint32_t sent, received, proto_errors, notify_errors;
    struct { int used; uint64_t request_id, offset; uint32_t length, opcode; } pending[NTWV_W64_PENDING_POOL];
} w64;
static uint8_t w64_in[NTWV_W64_SEND_MAX], w64_out[SHZ_MSG_SLOT_SIZE];   /* protected by w64_admitted */

void ntwv_w64_reset(void)
{
    if (!w64_enter())
        return;                            /* an admitted operation still owns the mapping */
    /* The VMM keeps the physical mapping. Outstanding pool blocks must stay
     * allocated: the peer may still consume their queued requests. There is no
     * cancellation/rundown acknowledgement in this transport revision. */
    ntwv_fill(&w64, 0, sizeof w64);
    w64_leave();
}

static int w64_layout_valid(const shz_channel_hdr_t *c, uint32_t channel_id)
{
    uint64_t ring_bytes, table_bytes;
    if (c->magic != SHZ_CHANNEL_MAGIC || c->abi_major != SHZ_ABI_MAJOR ||
        c->channel_id != channel_id || !c->generation ||
        !((c->domain_a == SHZ_DOM_WIN98 && c->domain_b == SHZ_DOM_KERNEL64) ||
          (c->domain_b == SHZ_DOM_WIN98 && c->domain_a == SHZ_DOM_KERNEL64)) ||
        c->slot_count < 2 || (c->slot_count & (c->slot_count - 1)) ||
        c->slot_count > (SHZ_IPC_REGION_SIZE - sizeof *c - 2 * sizeof(shz_ring_hdr_t)) /
                        (2 * SHZ_MSG_SLOT_SIZE) ||
        !c->pool_size || (c->pool_size % SHZ_POOL_BLOCK) || (c->pool_offset % SHZ_POOL_BLOCK) ||
        (c->ring_ab_offset % 64) || (c->ring_ba_offset % 64))
        return 0;
    ring_bytes = shz_ring_bytes(c->slot_count);
    table_bytes = (c->pool_size / SHZ_POOL_BLOCK + 63) & ~UINT64_C(63);
    /* Keep header/owner table, both rings and pool disjoint and in the mapped
     * window. Bound the slot count before the size_t arithmetic above. */
    /* c is only a copied header, never a mapped channel window. The shared
     * channel validator now also dereferences ring headers, so it cannot run
     * on this snapshot. Validate its bounded geometry here; OPEN/live check
     * the actual mapped ring headers separately before any transport use. */
    return shz_range_ok(c->pool_offset, c->pool_size, SHZ_IPC_REGION_SIZE) &&
           shz_range_ok(sizeof *c, table_bytes, c->ring_ab_offset) &&
           shz_range_ok(c->ring_ab_offset, ring_bytes, c->ring_ba_offset) &&
           shz_range_ok(c->ring_ba_offset, ring_bytes, c->pool_offset);
}

static uint32_t w64_live(void)
{
    shz_channel_hdr_t now;
    const shz_channel_hdr_t *opened = &w64.layout;
    if (!w64.open)
        return NTWV_ERROR_NOT_READY;
    ntwv_copy(&now, w64.hdr, sizeof now);
    if (now.generation != w64.generation)
        return NTWV_ERROR_DEV_NOT_EXIST;      /* explicit reset/reopen required after restart */
    if (!w64_layout_valid(&now, w64.channel_id) ||
        now.abi_minor != opened->abi_minor || now.domain_a != opened->domain_a || now.domain_b != opened->domain_b ||
        now.ring_ab_offset != opened->ring_ab_offset || now.ring_ba_offset != opened->ring_ba_offset ||
        now.pool_offset != opened->pool_offset || now.pool_size != opened->pool_size || now.slot_count != opened->slot_count ||
        !shz_ring_valid(w64.tx) || !shz_ring_valid(w64.rx) ||
        w64.tx->slot_count != opened->slot_count || w64.rx->slot_count != opened->slot_count)
        return NTWV_ERROR_GEN_FAILURE;
    return 0;
}

static uint32_t pending_count(void)
{
    uint32_t i, n = 0;
    for (i = 0; i < NTWV_W64_PENDING_POOL; ++i)
        n += w64.pending[i].used ? 1u : 0u;
    return n;
}

static void fill_open(struct ntwv_w64_open *o)
{
    ntwv_fill(o, 0, sizeof *o);
    o->magic = NTWV_W64_MAGIC;
    o->size = sizeof *o;
    o->abi_major = w64.abi >> 16;
    o->abi_minor = w64.abi & 0xffffu;
    o->channel_id = w64.channel_id;
    o->self_domain = w64.self;
    o->peer_domain = w64.peer;
    o->generation = w64.generation;
    o->slot_count = w64.open ? w64.layout.slot_count : 0;
    o->pool_bytes = w64.open ? (uint32_t)w64.layout.pool_size : 0;
    o->sent = w64.sent;
    o->received = w64.received;
    o->proto_errors = w64.proto_errors;
    o->notify_errors = w64.notify_errors;
    o->pending_pool = pending_count();
}

static uint32_t w64_open(const struct ntwv_hv *hv)
{
    uint32_t ver = 0, c;
    if (w64.open)
        return w64_live();
    if (!hv->hypervisor_present())
        return NTWV_ERROR_NOT_SUPPORTED;            /* no Shizuku Supervisor: VMCALL must never run */
    if (hv->hcall(SHZ_HC_ABI_VERSION, 0, 0, &ver, 0) != SHZ_OK)
        return NTWV_ERROR_GEN_FAILURE;
    if ((ver >> 16) != SHZ_ABI_MAJOR)
        return NTWV_ERROR_REVISION_MISMATCH;
    for (c = 0; c < SHZ_MAX_CHANNELS; ++c) {
        uint32_t gpa = 0, peer = 0;
        shz_channel_hdr_t *hdr;
        if (hv->hcall(SHZ_HC_CHANNEL_INFO, c, 0, &gpa, &peer) != SHZ_OK || peer != SHZ_DOM_KERNEL64)
            continue;
        hdr = hv->map_phys(gpa, SHZ_IPC_REGION_SIZE);
        if (!hdr)
            return NTWV_ERROR_NOT_ENOUGH_MEMORY;
        ntwv_copy(&w64.layout, hdr, sizeof w64.layout);
        if (!w64_layout_valid(&w64.layout, c))
            return NTWV_ERROR_GEN_FAILURE;        /* the Supervisor named a channel that is not ours */
        w64.base = (uint8_t *)hdr;
        w64.bytes = SHZ_IPC_REGION_SIZE;
        w64.hdr = hdr;
        w64.self = SHZ_DOM_WIN98;
        w64.peer = SHZ_DOM_KERNEL64;
        w64.tx = shz_channel_ring_tx(w64.base, &w64.layout, w64.self);
        w64.rx = shz_channel_ring_rx(w64.base, &w64.layout, w64.self);
        if (!shz_ring_valid(w64.tx) || !shz_ring_valid(w64.rx) ||
            w64.tx->slot_count != w64.layout.slot_count || w64.rx->slot_count != w64.layout.slot_count)
            return NTWV_ERROR_GEN_FAILURE;
        w64.channel_id = w64.layout.channel_id;
        w64.generation = w64.layout.generation;
        w64.abi = ver;
        w64.open = 1;
        return 0;
    }
    return NTWV_ERROR_DEV_NOT_EXIST;
}

static int pending_reply_matches(const shz_msg_hdr_t *h)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_PENDING_POOL; ++i)
        if (w64.pending[i].used && w64.pending[i].request_id == h->request_id)
            return w64.pending[i].opcode == h->opcode;
    return 1;                               /* inline requests have no pool lease here */
}

static void release_pending(const shz_msg_hdr_t *h)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_PENDING_POOL; ++i)
        if (w64.pending[i].used && w64.pending[i].request_id == h->request_id && w64.pending[i].opcode == h->opcode) {
            if (shz_pool_release(w64.base, &w64.layout, w64.self, w64.pending[i].offset, w64.pending[i].length, 0) == SHZ_OK)
                w64.pending[i].used = 0;
        }
}

static uint32_t w64_send(const struct ntwv_hv *hv, uint32_t in_bytes, uint32_t *out_len)
{
    shz_msg_hdr_t h;
    uint32_t extra, slot = NTWV_W64_PENDING_POOL, i;
    uint64_t off = 0;
    int32_t status;
    int rc;
    const uint32_t live_result = w64_live();
    if (live_result)
        return live_result;
    ntwv_copy(&h, w64_in, sizeof h);
    if (h.payload_length > SHZ_MSG_MAX_INLINE || in_bytes < sizeof h + h.payload_length)
        return NTWV_ERROR_INVALID_PARAMETER;
    for (i = 0; i < NTWV_W64_PENDING_POOL; ++i)
        if (w64.pending[i].used && w64.pending[i].request_id == h.request_id)
            return NTWV_ERROR_BUSY;           /* one completion cannot retire two buffers */
    extra = in_bytes - (uint32_t)sizeof h - h.payload_length;
    /* The VxD, not the application, names the endpoints and the generation; a buffer reference only
     * ever comes from data the application handed over in this same request. */
    h.src_domain = (uint16_t)w64.self;
    h.dst_domain = (uint16_t)w64.peer;
    h.generation = w64.generation;
    h.flags = (uint16_t)(h.flags & ~(uint16_t)SHZ_MSGF_BUFFER);
    h.buffer_offset = 0;
    h.buffer_length = 0;
    if (extra) {
        for (i = 0; i < NTWV_W64_PENDING_POOL; ++i)
            if (!w64.pending[i].used) { slot = i; break; }
        if (slot == NTWV_W64_PENDING_POOL || (h.flags & SHZ_MSGF_ONEWAY))
            return NTWV_ERROR_BUSY;             /* pool blocks are freed by the matching reply */
        off = shz_pool_alloc(w64.base, &w64.layout, w64.self, extra);
        if (!off)
            return NTWV_ERROR_NOT_ENOUGH_MEMORY;
        ntwv_copy(w64.base + off, w64_in + sizeof h + h.payload_length, extra);
        h.buffer_offset = off;
        h.buffer_length = extra;
        h.flags = (uint16_t)(h.flags | SHZ_MSGF_BUFFER);
    }
    rc = shz_ring_push(w64.tx, &h, w64_in + sizeof h);
    if (rc != SHZ_OK) {
        if (extra)
            (void)shz_pool_release(w64.base, &w64.layout, w64.self, off, extra, 0);
        return rc == SHZ_E_QUEUE_FULL ? NTWV_ERROR_BUSY : NTWV_ERROR_INVALID_PARAMETER;
    }
    if (extra) {
        w64.pending[slot].used = 1;
        w64.pending[slot].request_id = h.request_id;
        w64.pending[slot].offset = off;
        w64.pending[slot].length = extra;
        w64.pending[slot].opcode = h.opcode;
    }
    ++w64.sent;
    if (hv->hcall(SHZ_HC_NOTIFY, w64.peer, 1, 0, 0) != SHZ_OK)
        ++w64.notify_errors;
    status = SHZ_OK;
    ntwv_copy(w64_out, &status, sizeof status);
    *out_len = sizeof status;
    return 0;
}

static uint32_t w64_recv(uint32_t *out_len)
{
    shz_msg_hdr_t h;
    int rc, reason;
    uint32_t budget, live_result = w64_live();
    if (live_result)
        return live_result;
    for (budget = 0; budget < w64.layout.slot_count; ++budget) {
        rc = shz_ring_pop(w64.rx, &h, w64_out + sizeof h, SHZ_MSG_MAX_INLINE, &reason);
        if (rc == SHZ_E_NOENT)
            return NTWV_ERROR_NO_MORE_ITEMS;
        if (rc != SHZ_OK) {
            ++w64.proto_errors;
            /* A corrupt head cannot be consumed. Never retry it indefinitely. */
            if (rc != SHZ_E_PROTO || reason == SHZ_PR_HEAD_CORRUPT)
                return NTWV_ERROR_GEN_FAILURE;
            continue;
        }
        live_result = w64_live();
        if (live_result)
            return live_result;
        if (h.src_domain != w64.peer || h.dst_domain != w64.self || h.generation != w64.generation ||
            (h.flags != SHZ_MSGF_REPLY && h.flags != SHZ_MSGF_ONEWAY) || h.buffer_length || h.buffer_offset ||
            ((h.flags & SHZ_MSGF_REPLY) && !pending_reply_matches(&h))) {
            ++w64.proto_errors;
            continue;                         /* no delivery or pool retirement for a foreign response */
        }
        ntwv_copy(w64_out, &h, sizeof h);
        if (h.payload_length < SHZ_MSG_MAX_INLINE)
            ntwv_fill(w64_out + sizeof h + h.payload_length, 0, SHZ_MSG_MAX_INLINE - h.payload_length);
        if (h.flags & SHZ_MSGF_REPLY)
            release_pending(&h);
        ++w64.received;
        *out_len = SHZ_MSG_SLOT_SIZE;
        return 0;
    }
    return NTWV_ERROR_NO_MORE_ITEMS;           /* bounded drain even if the peer keeps producing garbage */
}

static uint32_t w64_wait(const struct ntwv_hv *hv, uint32_t *out_len)
{
    uint32_t mask = 0;
    const uint32_t live_result = w64_live();
    if (live_result)
        return live_result;
    /* Non-blocking in this revision: the doorbell state is acknowledged and reported; NTW32.DLL polls with
     * Sleep(1) between RECV calls. Blocking on the doorbell needs a VPICD-hooked vector (see the README). */
    if (hv->hcall(SHZ_HC_DOORBELL_ACK, 0, 0, &mask, 0) != SHZ_OK)
        mask = 0;
    ntwv_copy(w64_out, &mask, sizeof mask);
    *out_len = sizeof mask;
    return 0;
}

static uint32_t w64_handle(const struct ntwv_hv *hv, uint32_t code, uint32_t in_bytes, uint32_t *out_len)
{
    switch (code) {
    case NTWV_IOCTL_W64_OPEN: {
        const uint32_t result = w64_open(hv);
        if (result)
            return result;
        fill_open((struct ntwv_w64_open *)w64_out);
        *out_len = sizeof(struct ntwv_w64_open);
        return 0;
    }
    case NTWV_IOCTL_W64_SEND: return w64_send(hv, in_bytes, out_len);
    case NTWV_IOCTL_W64_RECV: return w64_recv(out_len);
    case NTWV_IOCTL_W64_WAIT: return w64_wait(hv, out_len);
    default: return NTWV_ERROR_NOT_SUPPORTED;
    }
}

static int ranges_overlap(uint32_t a, uint32_t a_bytes, uint32_t b, uint32_t b_bytes)
{
    return a_bytes && b_bytes && a < b + b_bytes && b < a + a_bytes;
}

static uint32_t dioc_w64(const struct ntwv_dioc *request, const struct ntwv_pages *ops, const struct ntwv_hv *hv)
{
    uint32_t in_min = 0, in_max = 0, out_need = 0, out_len = 0, result = NTWV_ERROR_NOACCESS;
    struct pinned input, output, returned;
    uintptr_t saved;
    int ok;
    switch (request->code) {
    case NTWV_IOCTL_W64_OPEN: out_need = sizeof(struct ntwv_w64_open); break;
    case NTWV_IOCTL_W64_SEND: in_min = 64; in_max = NTWV_W64_SEND_MAX; out_need = 4; break;
    case NTWV_IOCTL_W64_RECV: out_need = SHZ_MSG_SLOT_SIZE; break;
    case NTWV_IOCTL_W64_WAIT: in_min = in_max = 4; out_need = 4; break;
    default: return NTWV_ERROR_NOT_SUPPORTED;
    }
    if (request->overlapped || request->input_bytes < in_min || request->input_bytes > in_max ||
        (request->input_bytes ? !user_range(request->input, request->input_bytes) : request->input != 0))
        return NTWV_ERROR_INVALID_PARAMETER;
    if (request->output_bytes < out_need)
        return NTWV_ERROR_INSUFFICIENT_BUFFER;
    if (!user_range(request->output, out_need) || !user_range(request->returned, 4) ||
        ranges_overlap(request->output, out_need, request->returned, 4) ||
        ranges_overlap(request->input, request->input_bytes, request->output, out_need) ||
        ranges_overlap(request->input, request->input_bytes, request->returned, 4))
        return NTWV_ERROR_INVALID_PARAMETER;
    if (!ops || !ops->check || !ops->lock || !ops->unlock || !ops->ptes || !ops->enter || !ops->leave ||
        !ops->write || !ops->read || !hv || !hv->hypervisor_present || !hv->hcall || !hv->map_phys)
        return NTWV_ERROR_NOT_SUPPORTED;
    input.alias = input.count = 0;
    if (request->input_bytes && !pin(ops, request->input, request->input_bytes, &input))
        return NTWV_ERROR_NOACCESS;
    if (!pin(ops, request->output, out_need, &output)) {
        if (input.alias) (void)ops->unlock(input.alias >> 12, input.count, NTWV_MAP_GLOBAL);
        return NTWV_ERROR_NOACCESS;
    }
    if (!pin(ops, request->returned, 4, &returned)) {
        (void)ops->unlock(output.alias >> 12, output.count, NTWV_MAP_GLOBAL);
        if (input.alias) (void)ops->unlock(input.alias >> 12, input.count, NTWV_MAP_GLOBAL);
        return NTWV_ERROR_NOACCESS;
    }
    /* Bounded interval 1: validate every alias and copy the input into kernel memory. */
    saved = ops->enter(0);
    ok = (!input.alias || alias_ok(ops, &input, 0)) && writable_alias(ops, &output) && writable_alias(ops, &returned);
    if (ok && input.alias)
        ops->read(w64_in, input.alias + input.offset, request->input_bytes);
    ops->leave(0, saved);
    if (ok) {
        /* Ring and hypercall work happens with the caller's interrupt state: it never touches user memory. */
        result = w64_handle(hv, request->code, request->input_bytes, &out_len);
        if (result == 0) {
            /* Bounded interval 2: re-validate (pages stayed pinned) and copy the reply out. */
            saved = ops->enter(0);
            if (writable_alias(ops, &output) && writable_alias(ops, &returned)) {
                ops->write(output.alias + output.offset, w64_out, out_len);
                ops->write(returned.alias + returned.offset, &out_len, 4);
            } else {
                result = NTWV_ERROR_NOACCESS;
            }
            ops->leave(0, saved);
        }
    }
    if (!ops->unlock(returned.alias >> 12, returned.count, NTWV_MAP_GLOBAL))
        result = NTWV_ERROR_NOACCESS;
    if (!ops->unlock(output.alias >> 12, output.count, NTWV_MAP_GLOBAL))
        result = NTWV_ERROR_NOACCESS;
    if (input.alias && !ops->unlock(input.alias >> 12, input.count, NTWV_MAP_GLOBAL))
        result = NTWV_ERROR_NOACCESS;
    return result;
}

uint32_t ntwv_dioc_ex(const struct ntwv_dioc *request, const struct ntwv_pages *ops, const struct ntwv_hv *hv)
{
    if (!request)
        return NTWV_ERROR_INVALID_PARAMETER;
    if (!__atomic_load_n(&live, __ATOMIC_ACQUIRE))
        return NTWV_ERROR_NOT_READY;
    if (request->code == 0)
        return 0; /* DIOC_OPEN/GETVERSION handshake; no user buffer access. */
    if (request->code == UINT32_MAX)
        return 1; /* DIOC_CLOSEHANDLE: documented VXD_SUCCESS. */
    if (request->code == NTWV_IOCTL_QUERY)
        return dioc_query(request, ops);
    if (request->code >= NTWV_IOCTL_W64_OPEN && request->code <= NTWV_IOCTL_W64_WAIT) {
        uint32_t result;
        if (!hv)
            return NTWV_ERROR_NOT_SUPPORTED;
        if (!w64_enter())
            return NTWV_ERROR_BUSY;
        /* Recheck after admission: dynamic shutdown takes the same gate. */
        result = __atomic_load_n(&live, __ATOMIC_ACQUIRE) ? dioc_w64(request, ops, hv) : NTWV_ERROR_NOT_READY;
        w64_leave();
        return result;
    }
    return NTWV_ERROR_NOT_SUPPORTED;
}

uint32_t ntwv_dioc(const struct ntwv_dioc *request, const struct ntwv_pages *ops)
{
    return ntwv_dioc_ex(request, ops, 0);
}
