/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded synchronous VxD adapter. See REFERENCES.md for ABI facts.
 *
 * Two request families share the same user-buffer discipline (validate, pin, check PTEs under cli, copy):
 *   NTWV_IOCTL_QUERY       the original 32-byte version query (unchanged code path);
 *   NTWV_IOCTL_W64_*       the WIN64 subsystem bridge: the Win98 domain's end of the ShizukuDOS ABI 1.1
 *                          channel to Kernel64 (shizukudos/abi/shz_ipc.h), exposed to NTW32.DLL.
 */
#include "bridge.h"
#include "pma_endpoint.h"

static void ntwv_copy(void *d, const void *s, size_t n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; }
static void ntwv_fill(void *d, int c, size_t n) { uint8_t *a = d; while (n--) *a++ = (uint8_t)c; }
#define SHZ_IPC_MEMCPY(d, s, n) ntwv_copy((d), (s), (n))
#define SHZ_IPC_MEMSET(d, c, n) ntwv_fill((d), (c), (n))
#include "../../shizukudos/abi/shz_ipc.h"
#include "../../shizukudos/abi/shz_w64_owner.h"
#include "w64_owner.h"

_Static_assert(sizeof(struct ntwv_dioc) == 48, "VWIN32 DIOC ABI");
_Static_assert(sizeof(struct ntwv_query) == 32, "query wire ABI");
_Static_assert(sizeof(struct ntwv_w64_open) == 64, "W64 open wire ABI");
static struct ntw_context context;
/* Readiness/query flags may be observed outside W64 admission. Keep every
 * access atomic; this does not permit concurrent context initialization. */
static uint32_t live, selftest;
/* One owner for the SPSC endpoints, pending table and request scratch. Never
 * spin or sleep here: a preempting/reentrant caller must let the owner finish. */
static uint32_t w64_admitted, endpoint_leased, legacy_opened;
/* One buffered DIOC acquires at most input/output/returned aliases. Failed
 * unlocks remain owned across calls, using the exact service/alias/count. */
#define NTWV_ALIAS_RECORDS 3u
static uint32_t page_admitted, page_owned, page_retained, endpoint_abort_pending;
static struct {
    uint32_t alias_page, count, held, failed;
    uint32_t (*unlock)(uint32_t, uint32_t, uint32_t);
} alias_records[NTWV_ALIAS_RECORDS];
static int page_drain(void);
static uint32_t pending_count(void);
static int page_enter(void)
{
    uint32_t expected=0;
    return __atomic_compare_exchange_n(&page_admitted,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED);
}
static void page_leave(void) { __atomic_store_n(&page_admitted,0,__ATOMIC_RELEASE); }

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
    if (__atomic_load_n(&page_admitted, __ATOMIC_ACQUIRE) || __atomic_load_n(&page_owned, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&live, __ATOMIC_ACQUIRE) || ntw_initialize(&context, ops) != NTW_OK)
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
    if (!page_enter())
        return 0;
    if (!page_drain() || !w64_enter()) { page_leave(); return 0; }
    if (endpoint_leased || !__atomic_load_n(&live, __ATOMIC_ACQUIRE) || ntw_shutdown(&context) != NTW_OK) {
        w64_leave();
        page_leave();
        return 0;
    }
    __atomic_store_n(&live, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&selftest, 0, __ATOMIC_RELAXED);
    w64_leave();
    page_leave();
    return 1;
}

struct pinned {
    uint32_t original_page, count, alias, offset, record;
};

static int release_alias(uint32_t at)
{
    if(!alias_records[at].held) return 1;
    if(!alias_records[at].unlock(alias_records[at].alias_page,alias_records[at].count,NTWV_MAP_GLOBAL)) {
        if(!alias_records[at].failed) {
            alias_records[at].failed=1;
            __atomic_add_fetch(&page_retained,1,__ATOMIC_RELEASE);
        }
        return 0;
    }
    if(alias_records[at].failed) __atomic_sub_fetch(&page_retained,1,__ATOMIC_RELEASE);
    alias_records[at].held=alias_records[at].failed=0;
    __atomic_sub_fetch(&page_owned,1,__ATOMIC_RELEASE);
    return 1;
}
static int page_drain(void)
{
    int complete=1;
    /* At most three original aliases, one attempt each; no new lock/admission
     * can occur until all failures have actually released their records. */
    for(uint32_t at=0;at<NTWV_ALIAS_RECORDS;++at)
        if(alias_records[at].held && !release_alias(at)) complete=0;
    if(complete && __atomic_load_n(&endpoint_abort_pending,__ATOMIC_ACQUIRE)) {
        if(!w64_enter()) return 0;
        if(pending_count()) complete=0;
        else {
            endpoint_leased=0;
            __atomic_store_n(&endpoint_abort_pending,0,__ATOMIC_RELEASE);
        }
        w64_leave();
    }
    return complete;
}
static int unpin(struct pinned *range) { return release_alias(range->record); }

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
    uint32_t alias, at;
    range->original_page = address >> 12;
    range->offset = address & 4095u;
    range->count = (range->offset + bytes + 4095u) >> 12;
    range->alias = 0;
    for(at=0;at<NTWV_ALIAS_RECORDS && alias_records[at].held;++at) { }
    if(at==NTWV_ALIAS_RECORDS) return 0;
    if (ops->check(range->original_page, range->count, 0) != range->count)
        return 0;
    alias = ops->lock(range->original_page, range->count, NTWV_MAP_GLOBAL);
    if (!alias)
        return 0;
    range->record=at;
    alias_records[at].alias_page=alias>>12;
    alias_records[at].count=range->count;
    alias_records[at].unlock=ops->unlock;
    alias_records[at].held=1; alias_records[at].failed=0;
    __atomic_add_fetch(&page_owned,1,__ATOMIC_RELEASE);
    /* The service contract returns a page-aligned system alias. */
    if (alias < 0x80000000u || (alias & 4095u) != 0 ||
        range->count > ((UINT32_MAX - alias) >> 12) + 1) {
        (void)unpin(range);
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
        (void)unpin(&output);
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
    if (!unpin(&returned))
        result = NTWV_ERROR_NOACCESS;
    if (!unpin(&output))
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
    struct { int used; uint64_t request_id, offset; uint32_t length, opcode, owner; } pending[NTWV_W64_PENDING_POOL];
} w64;
static uint8_t w64_in[NTWV_W64_SEND_MAX], w64_out[SHZ_MSG_SLOT_SIZE];   /* protected by w64_admitted */

/* ------------------------------------------------------------------ native endpoint owners (shz_w64_owner.h)
 * Raw DIOC W64 callers are separated by a generational owner the VxD derives from the VWIN32 DIOC context
 * (VM handle, hDevice, tagProcess). The table and generations survive ntwv_w64_reset so ids are never reused.
 * Every frame popped from the shared rx ring is routed into the mailbox of the owner its capability_id names;
 * RECV hands out only the caller's own mailbox head and consumes it only after the protected copy and all
 * unpins succeeded. The leased PMA endpoint keeps its exclusive raw route (no owner routing). All state below
 * is protected by w64_admitted, except `depart`, which lifecycle callbacks set atomically. */
#define NTWV_OWNER_NONE_SLOT SHZ_W64_OWNER_MAX
#define NTWV_OWNER_INFLIGHT_MAX (SHZ_W64_OWNER_MAILBOX_DEPTH - SHZ_W64_CONSOLE_WINDOW - 1u)
#define NTWV_OWNER_CTL_ID_BASE UINT64_C(0x5357000000000000)   /* VxD-originated OWNER_CONTROL request ids */
static shz_w64_owner_table_t owners;
static struct {
    uint32_t vm, device, process;           /* exact VWIN32 context of the bound owner */
    uint32_t depart, depart_gen;            /* departure reason/generation set by lifecycle callbacks */
    uint32_t head, count, inflight;         /* retained mailbox ring and outstanding non-oneway requests */
    uint32_t auth_pending;                  /* one typed broker request (0x20A..0x20C) outstanding */
    uint64_t auth_request_id;
    uint8_t slot[SHZ_W64_OWNER_MAILBOX_DEPTH][SHZ_MSG_SLOT_SIZE];
} octx[SHZ_W64_OWNER_MAX];
static struct { uint32_t used; uint8_t frame[SHZ_MSG_SLOT_SIZE]; } stash;   /* one routed frame awaiting room */
static uint8_t w64_pump[SHZ_MSG_SLOT_SIZE];
static uint64_t ctl_next;
static uint32_t owner_discards, recv_slot = NTWV_OWNER_NONE_SLOT;
/* Credential hygiene: VxD-owned validation scratch, and the transmit ring indices of pushed auth frames. Core wipes
 * the slot it consumes; the VxD scrubs the same slot again once the consumer index passed it (the slot is then
 * producer-owned, i.e. ours, and is scrubbed before any later push can reuse it). */
static shz_w64_auth_req_t auth_scratch;
static struct { uint32_t used, index; } auth_tx[SHZ_W64_OWNER_MAX];

static void mailbox_clear(uint32_t i)
{
    octx[i].head = octx[i].count = octx[i].inflight = 0;
    octx[i].auth_pending = 0;
    octx[i].auth_request_id = 0;
}

/* Discard (count + scrub) everything an owner still retains; nobody else may receive it. */
static void mailbox_discard(uint32_t i)
{
    owner_discards += octx[i].count;
    ntwv_wipe(octx[i].slot, sizeof octx[i].slot);
    mailbox_clear(i);
}

static void stash_discard(void)
{
    if (stash.used) {
        stash.used = 0;
        ++owner_discards;
    }
    ntwv_wipe(stash.frame, sizeof stash.frame);
}

/* Scrub transmitted auth slots the consumer has passed (or all of them when `force`, after an epoch change).
 * Returns the number of records still awaiting consumption. */
static uint32_t auth_tx_scrub(int force)
{
    uint32_t i, left = 0, head, tail;
    if (!w64.tx)
        return 0;
    head = w64.tx->head;
    tail = __atomic_load_n(&w64.tx->tail, __ATOMIC_ACQUIRE);
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i) {
        if (!auth_tx[i].used)
            continue;
        /* A later push into the same physical slot (head advanced more than slot_count past the record) already
         * zero-filled it before writing its own frame: drop the record, never wipe the newer frame. */
        if ((uint32_t)(head - auth_tx[i].index) > w64.tx->slot_count) {
            auth_tx[i].used = 0;
            continue;
        }
        /* Unconsumed iff the index lies in [tail, head); wrap-safe on the free-running indices. */
        if (!force && (uint32_t)(auth_tx[i].index - tail) < (uint32_t)(head - tail)) {
            ++left;
            continue;
        }
        ntwv_wipe(shz_ring_slot(w64.tx, auth_tx[i].index), SHZ_MSG_SLOT_SIZE);
        auth_tx[i].used = 0;
    }
    return left;
}

static int auth_tx_record(uint32_t index)
{
    uint32_t i;
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i)
        if (!auth_tx[i].used) {
            auth_tx[i].used = 1;
            auth_tx[i].index = index;
            return 1;
        }
    return 0;
}

static int auth_tx_room(void)
{
    uint32_t i;
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i)
        if (!auth_tx[i].used)
            return 1;
    return 0;
}

static int owners_busy(void)
{
    uint32_t i;
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i)
        if (owners.rec[i].state == SHZ_W64_OWNER_LIVE || owners.rec[i].state == SHZ_W64_OWNER_REVOKING)
            return 1;
    return stash.used != 0;
}

/* Exact-context lookup under the current channel epoch (the context key alone is only a hint). */
static uint32_t owner_find(const struct ntwv_dioc *request)
{
    uint32_t i;
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i) {
        const shz_w64_owner_rec_t *r = &owners.rec[i];
        if (r->state == SHZ_W64_OWNER_LIVE && r->channel_generation == w64.generation &&
            octx[i].vm == request->vm && octx[i].device == request->device && octx[i].process == request->process)
            return shz_w64_owner_make(i, r->generation);
    }
    return SHZ_W64_OWNER_NONE;
}

static uint32_t owner_derive(const struct ntwv_dioc *request, int bind)
{
    uint64_t key;
    uint32_t id, i;
    if (!request->vm || !request->device || !request->process)
        return SHZ_W64_OWNER_NONE;            /* not a VWIN32 Win32 DIOC context */
    id = owner_find(request);
    if (id || !bind)
        return id;
    key = ((uint64_t)request->process << 32) | (uint64_t)(request->vm ^ (request->device * 0x9e3779b1u));
    if (!key)
        key = 1;
    id = shz_w64_owner_bind(&owners, key, w64.generation);
    if (!id)
        return SHZ_W64_OWNER_NONE;            /* table full: caller gets BUSY, nobody is evicted */
    i = shz_w64_owner_slot(id);
    octx[i].vm = request->vm;
    octx[i].device = request->device;
    octx[i].process = request->process;
    __atomic_store_n(&octx[i].depart, 0, __ATOMIC_RELEASE);
    mailbox_clear(i);
    return id;
}

static void owner_retire(uint32_t i)
{
    mailbox_discard(i);
    octx[i].vm = octx[i].device = octx[i].process = 0;
    __atomic_store_n(&octx[i].depart, 0, __ATOMIC_RELEASE);
    shz_w64_owner_finish(&owners.rec[i]);
}

/* Channel epoch change: implicitly revoke every owner of the older epoch (no control message). */
static void owners_epoch(uint32_t new_generation)
{
    uint32_t i;
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i) {
        shz_w64_owner_rec_t *r = &owners.rec[i];
        if ((r->state == SHZ_W64_OWNER_LIVE || r->state == SHZ_W64_OWNER_REVOKING) &&
            r->channel_generation != new_generation) {
            mailbox_discard(i);
            octx[i].vm = octx[i].device = octx[i].process = 0;
            __atomic_store_n(&octx[i].depart, 0, __ATOMIC_RELEASE);
        }
    }
    (void)shz_w64_owner_epoch_revoke(&owners, new_generation);
    stash_discard();
    (void)auth_tx_scrub(1);                     /* the old epoch's transmit ring is never consumed again */
}

/* Apply recorded departures (LIVE -> REVOKING) and push any outstanding OWNER_CONTROL(REVOKE). A full ring
 * leaves revoke_request_id 0 so the push is retried by the next admitted W64 operation; nothing is dropped. */
static void owners_service(const struct ntwv_hv *hv)
{
    uint32_t i, pushed = 0;
    (void)auth_tx_scrub(0);
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i) {
        shz_w64_owner_rec_t *r = &owners.rec[i];
        const uint32_t reason = __atomic_load_n(&octx[i].depart, __ATOMIC_ACQUIRE);
        if (reason) {
            __atomic_store_n(&octx[i].depart, 0, __ATOMIC_RELEASE);
            if (r->state == SHZ_W64_OWNER_LIVE && octx[i].depart_gen == r->generation)
                (void)shz_w64_owner_begin_revoke(&owners, shz_w64_owner_make(i, r->generation), reason);
        }
        if (r->state == SHZ_W64_OWNER_REVOKING && !r->revoke_request_id && r->channel_generation == w64.generation) {
            shz_msg_hdr_t h;
            shz_w64_owner_ctl_t c;
            const uint32_t id = shz_w64_owner_make(i, r->generation);
            /* Nobody receives for a departed owner: its retained frames are counted, scrubbed and discarded. */
            mailbox_discard(i);
            shz_w64_owner_ctl_build(&c, id, r->revoke_reason, w64.generation);
            ntwv_fill(&h, 0, sizeof h);
            h.opcode = SHZ_OP_W64_OWNER_CONTROL;
            h.request_id = NTWV_OWNER_CTL_ID_BASE | ++ctl_next;
            h.payload_length = (uint32_t)sizeof c;
            h.capability_id = id;
            h.src_domain = (uint16_t)w64.self;
            h.dst_domain = (uint16_t)w64.peer;
            h.generation = w64.generation;
            if (shz_ring_push(w64.tx, &h, &c) != SHZ_OK)
                break;                          /* retry later; slot and mailbox stay retained */
            r->revoke_request_id = h.request_id;
            ++w64.sent;
            pushed = 1;
        }
    }
    if (pushed && hv && hv->hcall(SHZ_HC_NOTIFY, w64.peer, 1, 0, 0) != SHZ_OK)
        ++w64.notify_errors;
}

static void owner_ctl_reply(const shz_msg_hdr_t *h, const uint8_t *payload)
{
    shz_w64_owner_rec_t *r = shz_w64_owner_get(&owners, h->capability_id, 1);
    shz_w64_owner_ctl_t c;
    shz_w64_owner_ctl_reply_t out;
    if (!r || r->state != SHZ_W64_OWNER_REVOKING || !r->revoke_request_id || r->revoke_request_id != h->request_id) {
        ++w64.proto_errors;
        return;
    }
    shz_w64_owner_ctl_build(&c, h->capability_id, r->revoke_reason, r->channel_generation);
    if (shz_w64_owner_ctl_reply_check(h, payload, &c, r->revoke_request_id, &out) == SHZ_OK)
        owner_retire(shz_w64_owner_slot(h->capability_id));
    else
        r->revoke_request_id = 0;               /* not acknowledged: retain and push again */
}

/* Route one validated frame. Returns 0 when the owner's mailbox is full (caller keeps it in the stash). */
static int owner_route(const uint8_t *frame)
{
    shz_msg_hdr_t h;
    shz_w64_owner_rec_t *r;
    uint32_t i;
    ntwv_copy(&h, frame, sizeof h);
    if (h.opcode == SHZ_OP_W64_OWNER_CONTROL) {
        if (h.flags == SHZ_MSGF_REPLY)
            owner_ctl_reply(&h, frame + sizeof h);
        else
            ++w64.proto_errors;
        return 1;
    }
    r = shz_w64_owner_get(&owners, h.capability_id, 1);
    if (!r || r->channel_generation != w64.generation || r->state != SHZ_W64_OWNER_LIVE) {
        ++owner_discards;                       /* unowned, departed or stale owner: no global receive */
        return 1;
    }
    i = shz_w64_owner_slot(h.capability_id);
    if (shz_w64_auth_op(h.opcode) &&
        (h.flags != SHZ_MSGF_REPLY || !octx[i].auth_pending || octx[i].auth_request_id != h.request_id)) {
        ++w64.proto_errors;                     /* no event form, and no reply for a request this owner did not send */
        return 1;
    }
    if (octx[i].count == SHZ_W64_OWNER_MAILBOX_DEPTH)
        return 0;
    {
        uint8_t *dst = octx[i].slot[(octx[i].head + octx[i].count) % SHZ_W64_OWNER_MAILBOX_DEPTH];
        ntwv_copy(dst, frame, SHZ_MSG_SLOT_SIZE);
        if (shz_w64_auth_op(h.opcode)) {
            /* Terminal reply to the accepted auth request: deliver, but never forward a malformed body. */
            if (!ntwv_w64_auth_reply_ok(&h, frame + sizeof h)) {
                ++w64.proto_errors;
                ntwv_w64_auth_reply_sanitize(dst);
            }
            octx[i].auth_pending = 0;
            octx[i].auth_request_id = 0;
        }
    }
    ++octx[i].count;
    if ((h.flags & SHZ_MSGF_REPLY) && octx[i].inflight)
        --octx[i].inflight;
    return 1;
}

void ntwv_w64_reset(void)
{
    if (!w64_enter())
        return;                            /* an admitted operation still owns the mapping */
    if (endpoint_leased || __atomic_load_n(&page_retained,__ATOMIC_ACQUIRE) || owners_busy() ||
        (w64.open && auth_tx_scrub(0))) {
        w64_leave();
        return;                            /* native endpoint or a native owner still owns replies, or an
                                            * unconsumed credential frame still has to be scrubbed */
    }
    {
        uint32_t i;
        for (i = 0; i < SHZ_W64_OWNER_MAX; ++i)
            auth_tx[i].used = 0;           /* without an open mapping nothing is left to scrub */
    }
    /* The VMM keeps the physical mapping. Outstanding pool blocks must stay
     * allocated: the peer may still consume their queued requests. There is no
     * cancellation/rundown acknowledgement in this transport revision. */
    ntwv_fill(&w64, 0, sizeof w64);
    legacy_opened = 0;
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
    if (now.generation != w64.generation) {
        owners_epoch(now.generation);         /* old-epoch owners are implicitly revoked on both sides */
        return NTWV_ERROR_DEV_NOT_EXIST;
    }      /* explicit reset/reopen required after restart */
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
        if (w64.pending[i].used && w64.pending[i].request_id == h->request_id &&
            (!w64.pending[i].owner || w64.pending[i].owner == h->capability_id))
            return w64.pending[i].opcode == h->opcode;
    return 1;                               /* inline requests have no pool lease here */
}

static void release_pending(const shz_msg_hdr_t *h)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_PENDING_POOL; ++i)
        if (w64.pending[i].used && w64.pending[i].request_id == h->request_id && w64.pending[i].opcode == h->opcode &&
            (!w64.pending[i].owner || w64.pending[i].owner == h->capability_id)) {
            if (shz_pool_release(w64.base, &w64.layout, w64.self, w64.pending[i].offset, w64.pending[i].length, 0) == SHZ_OK)
                w64.pending[i].used = 0;
        }
}

static uint32_t w64_send(const struct ntwv_hv *hv, uint32_t in_bytes, uint32_t *out_len, uint32_t owner)
{
    shz_msg_hdr_t h;
    uint32_t extra, slot = NTWV_W64_PENDING_POOL, i;
    uint64_t off = 0;
    int32_t status;
    int rc;
    const uint32_t live_result = w64_live();
    if (live_result)
        return live_result;
    (void)auth_tx_scrub(0);                   /* also on the leased route: consumed credential slots are ours */
    ntwv_copy(&h, w64_in, sizeof h);
    if (h.payload_length > SHZ_MSG_MAX_INLINE || in_bytes < sizeof h + h.payload_length)
        return NTWV_ERROR_INVALID_PARAMETER;
    for (i = 0; i < NTWV_W64_PENDING_POOL; ++i)
        if (w64.pending[i].used && w64.pending[i].request_id == h.request_id && w64.pending[i].owner == owner)
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
        w64.pending[slot].owner = owner;
    }
    ++w64.sent;
    if (hv->hcall(SHZ_HC_NOTIFY, w64.peer, 1, 0, 0) != SHZ_OK)
        ++w64.notify_errors;
    status = SHZ_OK;
    ntwv_copy(w64_out, &status, sizeof status);
    *out_len = sizeof status;
    return 0;
}

/* Leased PMA endpoint only: exclusive raw route over the same channel. */
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

/* Drain the shared rx ring into owner mailboxes (bounded by the ring depth). A frame whose LIVE owner's mailbox
 * is full stays in the one-frame stash and stops the drain: it is retained, never dropped. */
static uint32_t owners_pump_drain(void);
static uint32_t owners_pump(void)
{
    const uint32_t result = owners_pump_drain();
    ntwv_wipe(w64_pump, sizeof w64_pump);       /* routed copies live only in mailboxes / the stash */
    return result;
}

static uint32_t owners_pump_drain(void)
{
    shz_msg_hdr_t h;
    int rc, reason;
    uint32_t budget, live_result;
    if (stash.used) {
        if (!owner_route(stash.frame))
            return 0;
        stash.used = 0;
        ntwv_wipe(stash.frame, sizeof stash.frame);
    }
    for (budget = 0; budget < w64.layout.slot_count; ++budget) {
        rc = shz_ring_pop(w64.rx, &h, w64_pump + sizeof h, SHZ_MSG_MAX_INLINE, &reason);
        if (rc == SHZ_E_NOENT)
            return 0;
        if (rc != SHZ_OK) {
            ++w64.proto_errors;
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
            continue;
        }
        ntwv_copy(w64_pump, &h, sizeof h);
        if (h.payload_length < SHZ_MSG_MAX_INLINE)
            ntwv_fill(w64_pump + sizeof h + h.payload_length, 0, SHZ_MSG_MAX_INLINE - h.payload_length);
        if (h.flags & SHZ_MSGF_REPLY)
            release_pending(&h);              /* the peer finished with the pool block */
        ++w64.received;
        if (!owner_route(w64_pump)) {
            ntwv_copy(stash.frame, w64_pump, SHZ_MSG_SLOT_SIZE);
            stash.used = 1;
            return 0;
        }
    }
    return 0;
}

static uint32_t w64_owner_send(const struct ntwv_hv *hv, const struct ntwv_dioc *request, uint32_t in_bytes,
                               uint32_t *out_len)
{
    shz_msg_hdr_t h;
    uint32_t id, i, result, at = 0;
    int auth;
    const uint32_t live_result = w64_live();
    if (live_result)
        return live_result;
    owners_service(hv);
    ntwv_copy(&h, w64_in, sizeof h);
    if (h.payload_length > SHZ_MSG_MAX_INLINE || in_bytes < sizeof h + h.payload_length)
        return NTWV_ERROR_INVALID_PARAMETER;
    /* Agreed raw allowlist: never SHUTDOWN, OWNER_CONTROL, server events, PMA 0x300..0x3ff, GUI (disabled); the
     * typed broker requests 0x20A..0x20C only with flags 0 and strict inline validation below. */
    if (!ntwv_w64_owner_op_allowed(h.opcode, h.flags))
        return NTWV_ERROR_ACCESS_DENIED;
    if (in_bytes != sizeof h + h.payload_length && !shz_w64_endpoint_pool_allowed(h.opcode))
        return NTWV_ERROR_INVALID_PARAMETER;
    id = owner_derive(request, 1);
    if (!id)
        return NTWV_ERROR_BUSY;
    i = shz_w64_owner_slot(id);
    auth = shz_w64_auth_op(h.opcode);
    if (auth) {
        /* Validate the whole frame before anything is forwarded; the scratch copy is wiped inside. */
        result = ntwv_w64_auth_admit(&h, w64_in + sizeof h, in_bytes, id, &auth_scratch);
        if (result)
            return result;
        if (octx[i].auth_pending || !auth_tx_room())
            return NTWV_ERROR_BUSY;           /* one credential request per owner; bounded scrub records */
    }
    if (!(h.flags & SHZ_MSGF_ONEWAY) && octx[i].count + octx[i].inflight >= NTWV_OWNER_INFLIGHT_MAX)
        return NTWV_ERROR_BUSY;               /* bound replies so this owner cannot fill its own mailbox */
    /* Forged capability rewrite: the application value is never trusted; the VxD never emits a privileged id. */
    h.capability_id = id;
    ntwv_copy(w64_in, &h, sizeof h);
    if (auth)
        at = w64.tx->head;                    /* w64_send pushes exactly this one frame */
    result = w64_send(hv, in_bytes, out_len, id);
    if (!result && !(h.flags & SHZ_MSGF_ONEWAY))
        ++octx[i].inflight;
    if (!result && auth) {
        octx[i].auth_pending = 1;
        octx[i].auth_request_id = h.request_id;
        (void)auth_tx_record(at);             /* room was checked above under the same gate */
    }
    return result;
}

static uint32_t w64_owner_recv(const struct ntwv_hv *hv, const struct ntwv_dioc *request, uint32_t *out_len)
{
    uint32_t id, i, result;
    const uint32_t live_result = w64_live();
    if (live_result)
        return live_result;
    owners_service(hv);
    id = owner_derive(request, 0);
    if (!id)
        return NTWV_ERROR_NO_MORE_ITEMS;      /* no owner, nothing addressed to this caller */
    result = owners_pump();
    i = shz_w64_owner_slot(id);
    if (!octx[i].count)
        return result ? result : NTWV_ERROR_NO_MORE_ITEMS;
    /* Hand out the head without consuming it: dioc_w64 acknowledges after copy-out and all unpins. */
    ntwv_copy(w64_out, octx[i].slot[octx[i].head], SHZ_MSG_SLOT_SIZE);
    recv_slot = i;
    *out_len = SHZ_MSG_SLOT_SIZE;
    return 0;
}

static void w64_owner_recv_ack(void)
{
    const uint32_t i = recv_slot;
    recv_slot = NTWV_OWNER_NONE_SLOT;
    if (i >= SHZ_W64_OWNER_MAX || !octx[i].count)
        return;
    ntwv_wipe(octx[i].slot[octx[i].head], SHZ_MSG_SLOT_SIZE);   /* delivered and acknowledged: scrub the copy */
    octx[i].head = (octx[i].head + 1u) % SHZ_W64_OWNER_MAILBOX_DEPTH;
    --octx[i].count;
}

static uint32_t w64_wait(const struct ntwv_hv *hv, const struct ntwv_dioc *request, uint32_t *out_len)
{
    uint32_t id;
    uint32_t mask = 0;
    const uint32_t live_result = w64_live();
    if (live_result)
        return live_result;
    /* Non-blocking in this revision: the doorbell state is acknowledged and reported; NTW32.DLL polls with
     * Sleep(1) between RECV calls. Blocking on the doorbell needs a VPICD-hooked vector (see the README). */
    owners_service(hv);
    if (hv->hcall(SHZ_HC_DOORBELL_ACK, 0, 0, &mask, 0) != SHZ_OK)
        mask = 0;
    /* The doorbell is shared: drain into mailboxes so other owners' frames stay retained for them, and report
     * the caller's own retained work as a peer bit. */
    (void)owners_pump();
    id = owner_derive(request, 0);
    if (id && octx[shz_w64_owner_slot(id)].count)
        mask |= 1u << (w64.peer & 31u);
    ntwv_copy(w64_out, &mask, sizeof mask);
    *out_len = sizeof mask;
    return 0;
}

static uint32_t w64_handle(const struct ntwv_hv *hv, const struct ntwv_dioc *request, uint32_t in_bytes,
                           uint32_t *out_len)
{
    if (w64.open)
        legacy_opened = 1;
    switch (request->code) {
    case NTWV_IOCTL_W64_OPEN: {
        uint32_t id, result = w64_open(hv);
        if (result)
            return result;
        legacy_opened = 1;
        owners_service(hv);
        id = owner_derive(request, 1);
        if (!id)
            return NTWV_ERROR_BUSY;
        fill_open((struct ntwv_w64_open *)w64_out);
        ((struct ntwv_w64_open *)w64_out)->owner_id = id;
        *out_len = sizeof(struct ntwv_w64_open);
        return 0;
    }
    case NTWV_IOCTL_W64_SEND: return w64_owner_send(hv, request, in_bytes, out_len);
    case NTWV_IOCTL_W64_RECV: return w64_owner_recv(hv, request, out_len);
    case NTWV_IOCTL_W64_WAIT: return w64_wait(hv, request, out_len);
    default: return NTWV_ERROR_NOT_SUPPORTED;
    }
}

uint32_t ntwv_endpoint_acquire(const struct ntwv_hv *hv, struct ntwv_w64_open *info)
{
    uint32_t result;
    if (!hv || !hv->hypervisor_present || !hv->hcall || !hv->map_phys || !info)
        return NTWV_ERROR_INVALID_PARAMETER;
    if (!w64_enter())
        return NTWV_ERROR_BUSY;
    if (!__atomic_load_n(&live, __ATOMIC_ACQUIRE))
        result = NTWV_ERROR_NOT_READY;
    else if (endpoint_leased || legacy_opened || __atomic_load_n(&page_retained,__ATOMIC_ACQUIRE))
        result = NTWV_ERROR_BUSY;
    else {
        result = w64_open(hv);
        if (!result) {
            /* A lease must not inherit another client's queued work. */
            if (__atomic_load_n(&w64.tx->head, __ATOMIC_ACQUIRE) !=
                    __atomic_load_n(&w64.tx->tail, __ATOMIC_ACQUIRE) ||
                __atomic_load_n(&w64.rx->head, __ATOMIC_ACQUIRE) !=
                    __atomic_load_n(&w64.rx->tail, __ATOMIC_ACQUIRE) || pending_count())
                result = NTWV_ERROR_BUSY;
            else {
                endpoint_leased = 1;
                fill_open(info);
            }
        }
    }
    w64_leave();
    return result;
}

uint32_t ntwv_endpoint_send(const struct ntwv_hv *hv, const shz_msg_hdr_t *header, const void *payload)
{
    uint32_t result, bytes = 0;
    if (!header || !payload || header->payload_length > SHZ_MSG_MAX_INLINE || !hv)
        return NTWV_ERROR_INVALID_PARAMETER;
    if (!w64_enter())
        return NTWV_ERROR_BUSY;
    if (!endpoint_leased || !__atomic_load_n(&live, __ATOMIC_ACQUIRE))
        result = NTWV_ERROR_NOT_READY;
    else {
        ntwv_copy(w64_in, header, sizeof *header);
        ntwv_copy(w64_in + sizeof *header, payload, header->payload_length);
        result = w64_send(hv, (uint32_t)sizeof *header + header->payload_length, &bytes, 0);
        ntwv_wipe(w64_in, sizeof *header + header->payload_length);
    }
    w64_leave();
    return result;
}

uint32_t ntwv_endpoint_recv(void *slot)
{
    uint32_t result, bytes = 0;
    if (!slot)
        return NTWV_ERROR_INVALID_PARAMETER;
    if (!w64_enter())
        return NTWV_ERROR_BUSY;
    result = endpoint_leased && __atomic_load_n(&live, __ATOMIC_ACQUIRE) ?
        w64_recv(&bytes) : NTWV_ERROR_NOT_READY;
    if (!result)
        ntwv_copy(slot, w64_out, bytes);
    ntwv_wipe(w64_out, sizeof w64_out);
    w64_leave();
    return result;
}

uint32_t ntwv_endpoint_release(void)
{
    uint32_t result = 0;
    /* A lifecycle callback can retry failed aliases too, but it must not
     * interfere with a DIOC currently pinning/copying/unpinning them. */
    if(__atomic_load_n(&page_owned,__ATOMIC_ACQUIRE)) {
        if(!page_enter()) return NTWV_ERROR_BUSY;
        result=page_drain() ? 0u : NTWV_ERROR_BUSY;
        page_leave();
        if(result) return result;
    }
    if (!w64_enter())
        return NTWV_ERROR_BUSY;
    if (!endpoint_leased || pending_count() || __atomic_load_n(&page_owned,__ATOMIC_ACQUIRE))
        result = NTWV_ERROR_BUSY;
    else
        endpoint_leased = 0;
    w64_leave();
    return result;
}
void ntwv_endpoint_abort_registration(void)
{
    /* Registration publishes no backend work. Queue its transport rollback;
     * the caller's aliases still have to release before the lease can end. */
    __atomic_store_n(&endpoint_abort_pending,1,__ATOMIC_RELEASE);
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
        if (input.alias) (void)unpin(&input);
        return NTWV_ERROR_NOACCESS;
    }
    if (!pin(ops, request->returned, 4, &returned)) {
        (void)unpin(&output);
        if (input.alias) (void)unpin(&input);
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
        recv_slot = NTWV_OWNER_NONE_SLOT;
        result = w64_handle(hv, request, request->input_bytes, &out_len);
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
    if (!unpin(&returned))
        result = NTWV_ERROR_NOACCESS;
    if (!unpin(&output))
        result = NTWV_ERROR_NOACCESS;
    if (input.alias && !unpin(&input))
        result = NTWV_ERROR_NOACCESS;
    /* Consume the delivered mailbox head only after the protected copy and every unpin succeeded. */
    if (!result && request->code == NTWV_IOCTL_W64_RECV)
        w64_owner_recv_ack();
    recv_slot = NTWV_OWNER_NONE_SLOT;
    /* The kernel copies may have carried credentials (auth SEND) or a delivered reply: scrub them on every path
     * (forwarded, rejected, failed copy-out). A retained mailbox head keeps its own copy until acknowledged. */
    ntwv_wipe(w64_in, sizeof w64_in);
    ntwv_wipe(w64_out, sizeof w64_out);
    return result;
}

void ntwv_w64_owner_departed(const struct ntwv_hv *hv, uint32_t vm, uint32_t device, uint32_t process, uint32_t reason)
{
    uint32_t i;
    if ((!vm && !device && !process) || !reason || reason > SHZ_W64_REVOKE_REASON_MAX ||
        reason == SHZ_W64_REVOKE_CHANNEL_EPOCH)
        return;
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i) {
        const shz_w64_owner_rec_t *r = &owners.rec[i];
        if (__atomic_load_n(&r->state, __ATOMIC_ACQUIRE) != SHZ_W64_OWNER_LIVE ||
            (vm && octx[i].vm != vm) || (device && octx[i].device != device) ||
            (process && octx[i].process != process))
            continue;
        octx[i].depart_gen = r->generation;
        __atomic_store_n(&octx[i].depart, reason, __ATOMIC_RELEASE);
    }
    /* Apply now when no W64 operation is admitted; otherwise the next admitted W64 DIOC applies it. */
    if (!w64_enter())
        return;
    if (!endpoint_leased && !w64_live())
        owners_service(hv);
    w64_leave();
}

static uint32_t dioc_pma(const struct ntwv_dioc *request, const struct ntwv_pages *ops)
{
    uint8_t input_data[sizeof(struct ntwv_pma_registration)] = { 0 };
    uint8_t output_data[sizeof(struct ntwv_pma_event_result)] = { 0 };
    struct pinned input = { 0 }, output, returned;
    uint32_t in_need = 0, out_need = 0, out_len = 0, result = NTWV_ERROR_NOACCESS;
    uintptr_t saved;
    int ok;
    switch (request->code) {
    case NTWV_IOCTL_PMA_REGISTER: in_need = sizeof(struct ntwv_pma_registration); out_need = sizeof(struct ntwv_pma_owner); break;
    case NTWV_IOCTL_PMA_QUERY: out_need = sizeof(struct ntwv_pma_ticket); break;
    case NTWV_IOCTL_PMA_TAKE: out_need = sizeof(struct ntwv_pma_result); break;
    case NTWV_IOCTL_PMA_CLOSE: out_need = 4; break;
    case NTWV_IOCTL_PMA_EVENT_CREATE:
    case NTWV_IOCTL_PMA_EVENT_WAIT:
    case NTWV_IOCTL_PMA_EVENT_SIGNAL:
    case NTWV_IOCTL_PMA_EVENT_RESET:
    case NTWV_IOCTL_PMA_EVENT_CLOSE: in_need = sizeof(struct ntwv_pma_event_request); out_need = sizeof(struct ntwv_pma_ticket); break;
    case NTWV_IOCTL_PMA_EVENT_TAKE: out_need = sizeof(struct ntwv_pma_event_result); break;
    default: return NTWV_ERROR_NOT_SUPPORTED;
    }
    if (request->overlapped || request->input_bytes != in_need ||
        (in_need ? !user_range(request->input, in_need) : request->input != 0) ||
        !user_range(request->output, out_need) || !user_range(request->returned, 4) ||
        ranges_overlap(request->output, out_need, request->returned, 4) ||
        ranges_overlap(request->input, in_need, request->output, out_need) ||
        ranges_overlap(request->input, in_need, request->returned, 4))
        return NTWV_ERROR_INVALID_PARAMETER;
    if (request->output_bytes < out_need)
        return NTWV_ERROR_INSUFFICIENT_BUFFER;
    if (!ops || !ops->check || !ops->lock || !ops->unlock || !ops->ptes || !ops->enter ||
        !ops->leave || !ops->write || !ops->read)
        return NTWV_ERROR_NOT_SUPPORTED;
    if (in_need && !pin(ops, request->input, in_need, &input))
        return NTWV_ERROR_NOACCESS;
    if (!pin(ops, request->output, out_need, &output)) {
        if (input.alias) (void)unpin(&input);
        return NTWV_ERROR_NOACCESS;
    }
    if (!pin(ops, request->returned, 4, &returned)) {
        (void)unpin(&output);
        if (input.alias) (void)unpin(&input);
        return NTWV_ERROR_NOACCESS;
    }
    saved = ops->enter(0);
    ok = (!input.alias || alias_ok(ops, &input, 0)) && writable_alias(ops, &output) && writable_alias(ops, &returned);
    if (ok && input.alias)
        ops->read(input_data, input.alias + input.offset, in_need);
    ops->leave(0, saved);
    if (ok) {
        result = ntwv_pma_dispatch(request, input_data, output_data, &out_len);
        if (!result) {
            saved = ops->enter(0);
            if (out_len <= out_need && writable_alias(ops, &output) && writable_alias(ops, &returned)) {
                ops->write(output.alias + output.offset, output_data, out_len);
                ops->write(returned.alias + returned.offset, &out_len, 4);
            } else
                result = NTWV_ERROR_NOACCESS;
            ops->leave(0, saved);
        }
    }
    if (!unpin(&returned)) result = NTWV_ERROR_NOACCESS;
    if (!unpin(&output)) result = NTWV_ERROR_NOACCESS;
    if (input.alias && !unpin(&input)) result = NTWV_ERROR_NOACCESS;
    if (!result && (request->code == NTWV_IOCTL_PMA_TAKE || request->code == NTWV_IOCTL_PMA_EVENT_TAKE)) {
        struct ntwv_pma_result taken;
        ntwv_copy(&taken, output_data, sizeof taken);
        result = ntwv_pma_take_ack(request, taken.request_id);
    }
    if (!result && request->code == NTWV_IOCTL_PMA_CLOSE)
        result = ntwv_pma_close_ack(request);
    return result;
}

static uint32_t dispatch_dioc(const struct ntwv_dioc *request, const struct ntwv_pages *ops, const struct ntwv_hv *hv)
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
    if (request->code >= NTWV_IOCTL_PMA_REGISTER && request->code <= NTWV_IOCTL_PMA_EVENT_RESET)
        return dioc_pma(request, ops);
    if (request->code >= NTWV_IOCTL_W64_OPEN && request->code <= NTWV_IOCTL_W64_WAIT) {
        uint32_t result;
        if (!hv)
            return NTWV_ERROR_NOT_SUPPORTED;
        if (!w64_enter())
            return NTWV_ERROR_BUSY;
        /* Recheck after admission: dynamic shutdown takes the same gate. */
        result = !__atomic_load_n(&live, __ATOMIC_ACQUIRE) ? NTWV_ERROR_NOT_READY :
            endpoint_leased ? NTWV_ERROR_BUSY : dioc_w64(request, ops, hv);
        w64_leave();
        return result;
    }
    return NTWV_ERROR_NOT_SUPPORTED;
}

uint32_t ntwv_dioc_ex(const struct ntwv_dioc *request, const struct ntwv_pages *ops, const struct ntwv_hv *hv)
{
    uint32_t result;
    if(!request) return NTWV_ERROR_INVALID_PARAMETER;
    if(!__atomic_load_n(&live,__ATOMIC_ACQUIRE)) return NTWV_ERROR_NOT_READY;
    if(request->code!=NTWV_IOCTL_QUERY &&
       !(request->code>=NTWV_IOCTL_W64_OPEN && request->code<=NTWV_IOCTL_W64_WAIT) &&
       !(request->code>=NTWV_IOCTL_PMA_REGISTER && request->code<=NTWV_IOCTL_PMA_EVENT_RESET))
        return dispatch_dioc(request,ops,hv);
    if(!page_enter()) return NTWV_ERROR_BUSY;
    result=!__atomic_load_n(&live,__ATOMIC_ACQUIRE) ? NTWV_ERROR_NOT_READY :
           !page_drain() ? NTWV_ERROR_NOACCESS : dispatch_dioc(request,ops,hv);
    if(!__atomic_load_n(&page_owned,__ATOMIC_ACQUIRE) &&
       __atomic_load_n(&endpoint_abort_pending,__ATOMIC_ACQUIRE) && !page_drain())
        result=NTWV_ERROR_NOACCESS;
    page_leave(); return result;
}

uint32_t ntwv_dioc(const struct ntwv_dioc *request, const struct ntwv_pages *ops)
{
    return ntwv_dioc_ex(request, ops, 0);
}
