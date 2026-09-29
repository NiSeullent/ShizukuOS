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
static uint32_t live, selftest;

int ntwv_initialize(const struct ntw_lock_ops *ops)
{
    ntw_handle handle;
    if (live || ntw_initialize(&context, ops) != NTW_OK)
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
    selftest = live = 1;
    return 1;
failed:
    (void)ntw_shutdown(&context);
    return 0;
}

int ntwv_shutdown(void)
{
    if (!live || ntw_shutdown(&context) != NTW_OK)
        return 0;
    live = selftest = 0;
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
        reply.initialized = live;
        reply.selftest = selftest;
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
    shz_ring_hdr_t *tx, *rx;
    uint32_t channel_id, self, peer, generation, abi;
    uint32_t sent, received, proto_errors, notify_errors;
    struct { int used; uint64_t request_id, offset; uint32_t length; } pending[NTWV_W64_PENDING_POOL];
} w64;
static uint8_t w64_in[NTWV_W64_SEND_MAX], w64_out[SHZ_MSG_SLOT_SIZE];   /* UP synchronous: one request at a time */

void ntwv_w64_reset(void)
{
    ntwv_fill(&w64, 0, sizeof w64);         /* the VMM keeps the physical mapping; nothing else to release */
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
    o->slot_count = w64.open ? w64.hdr->slot_count : 0;
    o->pool_bytes = w64.open ? (uint32_t)w64.hdr->pool_size : 0;
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
        return 0;
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
        if (!shz_channel_valid(hdr, SHZ_IPC_REGION_SIZE) ||
            !((hdr->domain_a == SHZ_DOM_WIN98 && hdr->domain_b == SHZ_DOM_KERNEL64) ||
              (hdr->domain_b == SHZ_DOM_WIN98 && hdr->domain_a == SHZ_DOM_KERNEL64)))
            return NTWV_ERROR_GEN_FAILURE;        /* the Supervisor named a channel that is not ours */
        w64.base = (uint8_t *)hdr;
        w64.bytes = SHZ_IPC_REGION_SIZE;
        w64.hdr = hdr;
        w64.self = SHZ_DOM_WIN98;
        w64.peer = SHZ_DOM_KERNEL64;
        w64.tx = shz_channel_ring_tx(w64.base, hdr, w64.self);
        w64.rx = shz_channel_ring_rx(w64.base, hdr, w64.self);
        if (!shz_ring_valid(w64.tx) || !shz_ring_valid(w64.rx))
            return NTWV_ERROR_GEN_FAILURE;
        w64.channel_id = hdr->channel_id;
        w64.generation = hdr->generation;
        w64.abi = ver;
        w64.open = 1;
        return 0;
    }
    return NTWV_ERROR_DEV_NOT_EXIST;
}

static void release_pending(uint64_t request_id)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_PENDING_POOL; ++i)
        if (w64.pending[i].used && w64.pending[i].request_id == request_id) {
            (void)shz_pool_release(w64.base, w64.hdr, w64.self, w64.pending[i].offset, w64.pending[i].length, 0);
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
    if (!w64.open)
        return NTWV_ERROR_NOT_READY;
    ntwv_copy(&h, w64_in, sizeof h);
    if (h.payload_length > SHZ_MSG_MAX_INLINE || in_bytes < sizeof h + h.payload_length)
        return NTWV_ERROR_INVALID_PARAMETER;
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
        off = shz_pool_alloc(w64.base, w64.hdr, w64.self, extra);
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
            (void)shz_pool_release(w64.base, w64.hdr, w64.self, off, extra, 0);
        return rc == SHZ_E_QUEUE_FULL ? NTWV_ERROR_BUSY : NTWV_ERROR_INVALID_PARAMETER;
    }
    if (extra) {
        w64.pending[slot].used = 1;
        w64.pending[slot].request_id = h.request_id;
        w64.pending[slot].offset = off;
        w64.pending[slot].length = extra;
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
    if (!w64.open)
        return NTWV_ERROR_NOT_READY;
    for (;;) {
        rc = shz_ring_pop(w64.rx, &h, w64_out + sizeof h, SHZ_MSG_MAX_INLINE, &reason);
        if (rc == SHZ_E_NOENT)
            return NTWV_ERROR_NO_MORE_ITEMS;
        if (rc == SHZ_OK)
            break;
        ++w64.proto_errors;                     /* malformed slot: consumed, never shown to the application */
    }
    ntwv_copy(w64_out, &h, sizeof h);
    if (h.payload_length < SHZ_MSG_MAX_INLINE)
        ntwv_fill(w64_out + sizeof h + h.payload_length, 0, SHZ_MSG_MAX_INLINE - h.payload_length);
    if (h.flags & SHZ_MSGF_REPLY)
        release_pending(h.request_id);
    ++w64.received;
    *out_len = SHZ_MSG_SLOT_SIZE;
    return 0;
}

static uint32_t w64_wait(const struct ntwv_hv *hv, uint32_t *out_len)
{
    uint32_t mask = 0;
    if (!w64.open)
        return NTWV_ERROR_NOT_READY;
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
    if (!live)
        return NTWV_ERROR_NOT_READY;
    if (request->code == 0)
        return 0; /* DIOC_OPEN/GETVERSION handshake; no user buffer access. */
    if (request->code == UINT32_MAX)
        return 1; /* DIOC_CLOSEHANDLE: documented VXD_SUCCESS. */
    if (request->code == NTWV_IOCTL_QUERY)
        return dioc_query(request, ops);
    if (request->code >= NTWV_IOCTL_W64_OPEN && request->code <= NTWV_IOCTL_W64_WAIT)
        return hv ? dioc_w64(request, ops, hv) : NTWV_ERROR_NOT_SUPPORTED;
    return NTWV_ERROR_NOT_SUPPORTED;
}

uint32_t ntwv_dioc(const struct ntwv_dioc *request, const struct ntwv_pages *ops)
{
    return ntwv_dioc_ex(request, ops, 0);
}
