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
#ifdef NTWV_W64_DERIVED_OWNER
#include "w64_owner.h"
/* Set only inside dioc_w64 under the W64 admission token: a user SEND is stamped with the VxD-derived owner. */
static int w64_stamp;
static uint32_t w64_stamp_cap;
/* RECV demultiplex: K64 replies echo the request capability_id and events carry the creator's owner_cap, so a
 * message is delivered only to the Win98 process holding that derived identity. A message popped by another
 * process waits here (bounded); an owner that retired drops its messages. Protected by w64_admitted.
 * Every stashed message records a non-wrapping 64-bit arrival number; an owner always receives its OLDEST stashed
 * message first (slot reuse order is irrelevant), so per-process console sequence order is preserved. */
#define NTWV_W64_STASH 8u
struct w64_stashed { uint32_t cap; uint64_t arrival; uint8_t slot[SHZ_MSG_SLOT_SIZE]; };
static struct w64_stashed w64_stash[NTWV_W64_STASH];
static uint64_t w64_arrival;
static uint32_t w64_orphans;
/* Remote process custody (P1-C). Every CREATE_PROCESS the VxD forwards for a derived owner reserves an entry
 * (owner capability + request id); only the matching reply turns it into (owner, K64 pid), so a foreign or forged
 * reply can never make the VxD kill a process. A full table refuses the CREATE (fail closed, nothing leaks). When that owner retires (last NTWRAP9X handle closed) before releasing it, the
 * VxD itself sends a trusted (DERIVED bit clear) KILL_PROCESS, waits for PROCESS_EXITED, then sends RELEASE.
 * Bounded: work happens only inside admitted W64 DIOCs of other processes; table overflow is counted. */
#define NTWV_W64_TRACKED 32u
enum { TR_FREE = 0, TR_CREATE_SENT, TR_RUNNING, TR_EXITED, TR_KILL_SENT, TR_RELEASE_SENT };
/* out_seen: highest CONSOLE_OUTPUT seq K64 sent for this (owner, pid) and this VxD popped (delivered, stashed or
 * discarded); out_acked: highest seq the VxD itself acknowledged after the owner retired. K64 holds a process's
 * PROCESS_EXITED until its output FIFOs drain, and drains only under console credit, so a retired owner's unacked
 * window must be acknowledged here or the slot never reaches EXITED/RELEASE. */
struct w64_tracked_proc { uint32_t cap, pid, state, user_release, out_seen, out_acked; uint64_t user_req, vxd_req; };
static struct w64_tracked_proc w64_tracked[NTWV_W64_TRACKED];
static uint64_t w64_vxd_request = UINT64_C(0x8000000000000000);   /* VxD-originated ids; client ids start low */
static uint32_t w64_untracked;
/* Same LE-packer constraint as w64_owner.c owner_at(): keep element addresses computed from the array base. */
static struct w64_stashed *stash_at(uint32_t i) { struct w64_stashed *s = &w64_stash[i]; __asm__("" : "+r"(s)); return s; }
static struct w64_tracked_proc *tracked_at(uint32_t i)
{ struct w64_tracked_proc *t = &w64_tracked[i]; __asm__("" : "+r"(t)); return t; }
#endif

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

static uint32_t dioc_clock(const struct ntwv_dioc *request, const struct ntwv_pages *ops,
                           const struct ntwv_hv *hv)
{
    shz_clock_reply_t reply = { SHZ_CLOCK_MAGIC, sizeof(shz_clock_reply_t),
                                SHZ_CLOCK_VERSION, 0, 0, SHZ_CLOCK_FREQUENCY };
    struct pinned output, returned;
    uint32_t bytes = sizeof(reply), version = 0, low = 0, high = 0;
    uint32_t result = NTWV_ERROR_NOACCESS;
    int32_t status;
    uintptr_t saved;
    if (request->input || request->input_bytes || request->overlapped)
        return NTWV_ERROR_INVALID_PARAMETER;
    if (request->output_bytes < bytes) return NTWV_ERROR_INSUFFICIENT_BUFFER;
    if (!user_range(request->output, bytes) || !user_range(request->returned, 4) ||
        (request->output < request->returned + 4 && request->returned < request->output + bytes))
        return NTWV_ERROR_INVALID_PARAMETER;
    if (!ops || !ops->check || !ops->lock || !ops->unlock || !ops->ptes ||
        !ops->enter || !ops->leave || !ops->write ||
        !hv || !hv->hypervisor_present || !hv->hcall)
        return NTWV_ERROR_NOT_SUPPORTED;
    if (!hv->hypervisor_present()) return NTWV_ERROR_NOT_SUPPORTED;
    status = hv->hcall(SHZ_HC_ABI_VERSION, 0, 0, &version, 0);
    if (status != SHZ_OK) return NTWV_ERROR_GEN_FAILURE;
    if ((version >> 16) != SHZ_ABI_MAJOR) return NTWV_ERROR_REVISION_MISMATCH;
    if (!pin(ops, request->output, bytes, &output)) return NTWV_ERROR_NOACCESS;
    if (!pin(ops, request->returned, 4, &returned)) {
        (void)unpin(&output);
        return NTWV_ERROR_NOACCESS;
    }
    /* One admitted, readonly hypercall. Only local scalars go to VMCALL. An
     * old Supervisor's unsupported response never falls back to HC_TIME. */
    status = hv->hcall(SHZ_HC_CLOCK_SPLIT, SHZ_CLOCK_VERSION, 0, &low, &high);
    if (status == SHZ_E_UNSUPPORTED) result = NTWV_ERROR_NOT_SUPPORTED;
    else if (status == SHZ_E_DENIED) result = 5; /* ERROR_ACCESS_DENIED */
    else if (status != SHZ_OK) result = NTWV_ERROR_GEN_FAILURE;
    else if (high & 0x80000000u) result = NTWV_ERROR_GEN_FAILURE;
    else {
        reply.counter = ((uint64_t)high << 32) | low;
        saved = ops->enter(0);
        if (writable_alias(ops, &output) && writable_alias(ops, &returned)) {
            ops->write(output.alias + output.offset, &reply, bytes);
            ops->write(returned.alias + returned.offset, &bytes, 4);
            result = 0;
        }
        ops->leave(0, saved);
    }
    /* Always release both leases. Preserve an earlier Core error if cleanup
     * also fails; retained aliases still block subsequent page admission. */
    if (!unpin(&returned) && !result) result = NTWV_ERROR_NOACCESS;
    if (!unpin(&output) && !result) result = NTWV_ERROR_NOACCESS;
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
    uint32_t sent, received, proto_errors, notify_errors, attested;
    /* Pool custody keyed by (stamped owner capability, request id, opcode, channel generation): every NTW32
     * instance numbers its requests from the same base, so the id alone never identifies a request. */
    struct { int used; uint64_t request_id, offset; uint32_t length, opcode, cap, generation; } pending[NTWV_W64_PENDING_POOL];
} w64;
static uint8_t w64_in[NTWV_W64_SEND_MAX], w64_out[SHZ_MSG_SLOT_SIZE];   /* protected by w64_admitted */

void ntwv_w64_reset(void)
{
    if (!w64_enter())
        return;                            /* an admitted operation still owns the mapping */
    if (endpoint_leased || __atomic_load_n(&page_retained,__ATOMIC_ACQUIRE)) {
        w64_leave();
        return;                            /* native endpoint still owns replies */
    }
    /* The VMM keeps the physical mapping. Outstanding pool blocks must stay
     * allocated: the peer may still consume their queued requests. There is no
     * cancellation/rundown acknowledgement in this transport revision. */
    ntwv_fill(&w64, 0, sizeof w64);
#ifdef NTWV_W64_DERIVED_OWNER
    ntwv_w64_owner_reset_locked();
    ntwv_fill(w64_stash, 0, sizeof w64_stash);
    /* A reset channel's pids belong to the old generation: never KILL them on a reopened (possibly restarted)
     * peer where the same pid may name another process. Gap: a reset without a peer restart leaks them. */
    ntwv_fill(w64_tracked, 0, sizeof w64_tracked);
#endif
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
    o->attested = w64.attested;
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
#ifdef NTWV_W64_DERIVED_OWNER
        /* This build stamps every user SEND (w64_owner.c): declare it to the Supervisor for exactly this channel
         * generation, before the first send. An old Supervisor (E_UNSUPPORTED) or a missing EDX hypercall leaves
         * the channel unattested: K64 then refuses GUI and keeps only its legacy console route. Any other refusal
         * means the Supervisor disagrees about this bind, so the channel is not used at all (fail closed). */
        w64.attested = 0;
        if (hv->hcall3) {
            uint32_t recorded = 0;
            const int32_t rc = hv->hcall3(SHZ_HC_CHANNEL_ATTEST, c, w64.generation,
                                          SHZ_CHAN_ATTEST_W64_DERIVED_OWNER, &recorded, 0);
            if (rc == SHZ_OK && recorded == SHZ_CHAN_ATTEST_W64_DERIVED_OWNER)
                w64.attested = recorded;
            else if (rc != SHZ_E_UNSUPPORTED) {
                ntwv_fill(&w64, 0, sizeof w64);
                return NTWV_ERROR_GEN_FAILURE;
            }
        }
#endif
        w64.open = 1;
        return 0;
    }
    return NTWV_ERROR_DEV_NOT_EXIST;
}

/* The pool lease of (owner, request id) on this generation; NTWV_W64_PENDING_POOL when none. At most one exists:
 * w64_send refuses a second request with the same owner/id while one is outstanding. */
static uint32_t pending_find(uint32_t cap, uint64_t request_id, uint32_t generation)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_PENDING_POOL; ++i)
        if (w64.pending[i].used && w64.pending[i].cap == cap && w64.pending[i].request_id == request_id &&
            w64.pending[i].generation == generation)
            return i;
    return NTWV_W64_PENDING_POOL;
}

static int pending_reply_matches(const shz_msg_hdr_t *h)
{
    const uint32_t i = pending_find(h->capability_id, h->request_id, h->generation);
    /* Another owner's lease with the same id is irrelevant; inline requests have no pool lease here. */
    return i == NTWV_W64_PENDING_POOL || w64.pending[i].opcode == h->opcode;
}

/* Only the entry's own terminal reply (same owner, id, opcode, generation) retires its pool block. */
static void release_pending(const shz_msg_hdr_t *h)
{
    const uint32_t i = pending_find(h->capability_id, h->request_id, h->generation);
    if (i != NTWV_W64_PENDING_POOL && w64.pending[i].opcode == h->opcode &&
        shz_pool_release(w64.base, &w64.layout, w64.self, w64.pending[i].offset, w64.pending[i].length, 0) == SHZ_OK)
        w64.pending[i].used = 0;
}

#ifdef NTWV_W64_DERIVED_OWNER
static uint32_t tracked_find(uint32_t cap, uint32_t pid)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_TRACKED; ++i)
        if (tracked_at(i)->state > TR_CREATE_SENT && tracked_at(i)->cap == cap && tracked_at(i)->pid == pid)
            return i;
    return NTWV_W64_TRACKED;
}
/* The outstanding forwarded CREATE (owner, request id), or NTWV_W64_TRACKED. */
static uint32_t tracked_create(uint32_t cap, uint64_t request_id)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_TRACKED; ++i)
        if (tracked_at(i)->state == TR_CREATE_SENT && tracked_at(i)->cap == cap && tracked_at(i)->user_req == request_id)
            return i;
    return NTWV_W64_TRACKED;
}
static uint32_t tracked_free(void)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_TRACKED; ++i)
        if (tracked_at(i)->state == TR_FREE)
            return i;
    return NTWV_W64_TRACKED;
}

/* Locked. A validated K64 message (before routing): record/advance remote process custody. */
static void track_observe(const shz_msg_hdr_t *h, const uint8_t *payload)
{
    shz_w64_event_t ev;
    uint32_t i;
    if (h->opcode == SHZ_OP_W64_CREATE_PROCESS && h->flags == SHZ_MSGF_REPLY) {
        if ((i = tracked_create(h->capability_id, h->request_id)) == NTWV_W64_TRACKED)
            return;                           /* not a CREATE this VxD forwarded: never gains custody */
        if (h->status == SHZ_OK && h->payload_length == sizeof ev) {
            ntwv_copy(&ev, payload, sizeof ev);
            if (ev.pid && ev.state == SHZ_W64_PS_STARTED && tracked_find(h->capability_id, ev.pid) == NTWV_W64_TRACKED) {
                tracked_at(i)->pid = ev.pid;
                tracked_at(i)->state = TR_RUNNING;
                return;
            }
            if (ev.pid && ev.state == SHZ_W64_PS_STARTED)
                ++w64_untracked;              /* duplicate (owner, pid): K64 contract breach, keep the first */
        }
        tracked_at(i)->state = TR_FREE;       /* creation failed: no remote slot */
        return;
    }
    if (h->opcode == SHZ_OP_W64_CONSOLE_OUTPUT) {
        shz_w64_console_t c;
        struct w64_tracked_proc *t;
        /* Credit custody only from a well-formed one-way stdout/stderr frame of a tracked (K64-stamped owner, pid)
         * process; the client's request id never names anything here. Bounded jump: K64 numbers frames 1, 2, ...
         * per process and never runs more than one window ahead of an acknowledgement. */
        if (h->flags != SHZ_MSGF_ONEWAY || !shz_w64_owner_cap_derived(h->capability_id) ||
            shz_w64_console_check(h, payload, &c) != SHZ_OK || (c.stream != 1 && c.stream != 2) ||
            (i = tracked_find(h->capability_id, c.pid)) == NTWV_W64_TRACKED)
            return;
        t = tracked_at(i);
        if ((t->state == TR_RUNNING || t->state == TR_KILL_SENT) && c.seq - t->out_seen - 1u < SHZ_W64_CONSOLE_WINDOW)
            t->out_seen = c.seq;
        return;
    }
    if (h->opcode == SHZ_OP_W64_PROCESS_EXITED && h->flags == SHZ_MSGF_ONEWAY && h->payload_length == sizeof ev) {
        ntwv_copy(&ev, payload, sizeof ev);
        i = tracked_find(h->capability_id, ev.pid);
        if (i != NTWV_W64_TRACKED && (tracked_at(i)->state == TR_RUNNING || tracked_at(i)->state == TR_KILL_SENT))
            tracked_at(i)->state = TR_EXITED;
        return;
    }
    if (h->flags != SHZ_MSGF_REPLY || (h->opcode != SHZ_OP_W64_KILL_PROCESS && h->opcode != SHZ_OP_W64_RELEASE))
        return;
    for (i = 0; i < NTWV_W64_TRACKED; ++i) {
        struct w64_tracked_proc *t = tracked_at(i);
        if (t->state == TR_FREE)
            continue;
        if (shz_w64_owner_cap_derived(h->capability_id)) {
            /* The owner's own RELEASE: its slot is gone (NOENT: already gone), else it keeps custody. */
            if (h->opcode == SHZ_OP_W64_RELEASE && t->user_release && t->cap == h->capability_id &&
                t->user_req == h->request_id) {
                if (h->status == SHZ_OK || h->status == SHZ_E_NOENT)
                    t->state = TR_FREE;
                t->user_release = 0;
            }
        } else if (h->capability_id == 0 && t->vxd_req == h->request_id) {
            if (h->opcode == SHZ_OP_W64_KILL_PROCESS && t->state == TR_KILL_SENT && h->status == SHZ_E_NOENT)
                t->state = TR_FREE;          /* nothing left to release */
            else if (h->opcode == SHZ_OP_W64_RELEASE && t->state == TR_RELEASE_SENT)
                t->state = h->status == SHZ_OK || h->status == SHZ_E_NOENT ? TR_FREE : TR_EXITED;
        }
    }
}

/* Locked. A trusted in-VxD message (capability 0: never DERIVED, never a client's capability) on the bound
 * channel generation. 0 when queued; the request id is consumed only then. */
static int vxd_push(const struct ntwv_hv *hv, uint32_t opcode, uint16_t flags, const void *payload, uint16_t length,
                    uint64_t *request_id)
{
    shz_msg_hdr_t h;
    ntwv_fill(&h, 0, sizeof h);
    h.opcode = opcode;
    h.flags = flags;
    h.request_id = w64_vxd_request;
    h.src_domain = (uint16_t)w64.self;
    h.dst_domain = (uint16_t)w64.peer;
    h.generation = w64.generation;
    h.payload_length = length;
    ntwv_w64_owner_stamp(&h, 0, 0);
    if (shz_ring_push(w64.tx, &h, payload) != SHZ_OK)
        return 1;
    ++w64_vxd_request;
    if (request_id)
        *request_id = h.request_id;
    ++w64.sent;
    if (hv->hcall(SHZ_HC_NOTIFY, w64.peer, 1, 0, 0) != SHZ_OK)
        ++w64.notify_errors;
    return 0;
}

/* Locked. A trusted KILL/RELEASE of a tracked pid; its reply is matched by *request_id. */
static int vxd_send(const struct ntwv_hv *hv, uint32_t opcode, uint32_t pid, uint64_t *request_id)
{
    shz_w64_kill_t k;
    k.pid = pid;
    k.exit_code = -1;
    return vxd_push(hv, opcode, 0, &k, sizeof k, request_id);
}

/* Locked. A trusted cumulative CONSOLE_ACK (one-way, no reply) for a retired owner's tracked process. */
static int vxd_console_ack(const struct ntwv_hv *hv, uint32_t pid, uint32_t seq)
{
    shz_w64_console_t c;
    ntwv_fill(&c, 0, sizeof c);
    c.pid = pid;
    c.seq = seq;
    return vxd_push(hv, SHZ_OP_W64_CONSOLE_ACK, SHZ_MSGF_ONEWAY, &c, sizeof c, 0);
}

/* Locked, live channel. Reclaim K64 processes of retired owners: acknowledge every console frame K64 sent them
 * (the owner can no longer consume or ACK it; without credit K64 never drains and never reports EXITED), KILL,
 * then RELEASE after PROCESS_EXITED. Frames that arrive later are discarded by RECV and acknowledged here again. */
static void w64_reap(const struct ntwv_hv *hv)
{
    uint32_t i, op, next;
    for (i = 0; i < NTWV_W64_TRACKED; ++i) {
        struct w64_tracked_proc *t = tracked_at(i);
        if (t->state == TR_FREE || t->user_release || ntwv_w64_owner_cap_live(t->cap))
            continue;
        if ((t->state == TR_RUNNING || t->state == TR_KILL_SENT) && t->out_seen != t->out_acked) {
            if (vxd_console_ack(hv, t->pid, t->out_seen))
                return;                       /* ring full: the watermark stays pending for a later DIOC */
            t->out_acked = t->out_seen;
        }
        if (t->state == TR_RUNNING) { op = SHZ_OP_W64_KILL_PROCESS; next = TR_KILL_SENT; }
        else if (t->state == TR_EXITED) { op = SHZ_OP_W64_RELEASE; next = TR_RELEASE_SENT; }
        else continue;
        if (vxd_send(hv, op, t->pid, &t->vxd_req))
            return;                           /* ring full: retry on a later DIOC */
        t->state = next;
    }
}

uint32_t ntwv_w64_tracked(void)
{
    uint32_t i, n = 0;
    for (i = 0; i < NTWV_W64_TRACKED; ++i)
        n += tracked_at(i)->state != TR_FREE;
    return n;
}
#endif

static uint32_t w64_send(const struct ntwv_hv *hv, uint32_t in_bytes, uint32_t *out_len)
{
    shz_msg_hdr_t h;
    uint32_t extra, slot = NTWV_W64_PENDING_POOL, i;
#ifdef NTWV_W64_DERIVED_OWNER
    uint32_t track;
#endif
    uint64_t off = 0;
    int32_t status;
    int rc;
    const uint32_t live_result = w64_live();
    if (live_result)
        return live_result;
    ntwv_copy(&h, w64_in, sizeof h);
    if (h.payload_length > SHZ_MSG_MAX_INLINE || in_bytes < sizeof h + h.payload_length)
        return NTWV_ERROR_INVALID_PARAMETER;
    extra = in_bytes - (uint32_t)sizeof h - h.payload_length;
    /* The VxD, not the application, names the endpoints and the generation; a buffer reference only
     * ever comes from data the application handed over in this same request. */
    h.src_domain = (uint16_t)w64.self;
    h.dst_domain = (uint16_t)w64.peer;
    h.generation = w64.generation;
#ifdef NTWV_W64_DERIVED_OWNER
    ntwv_w64_owner_stamp(&h, w64_stamp, w64_stamp_cap);   /* the application's capability_id is never forwarded */
#endif
    /* One completion cannot retire two buffers: the same owner may not reuse an id with a pool lease. */
    if (pending_find(h.capability_id, h.request_id, h.generation) != NTWV_W64_PENDING_POOL)
        return NTWV_ERROR_BUSY;
#ifdef NTWV_W64_DERIVED_OWNER
    track = NTWV_W64_TRACKED;
    if (w64_stamp && h.opcode == SHZ_OP_W64_CREATE_PROCESS) {
        if (tracked_create(h.capability_id, h.request_id) != NTWV_W64_TRACKED)
            return NTWV_ERROR_BUSY;
        if ((track = tracked_free()) == NTWV_W64_TRACKED)
            return NTWV_ERROR_NOT_ENOUGH_MEMORY;   /* no custody record: refuse rather than risk an orphan */
    }
#endif
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
        w64.pending[slot].cap = h.capability_id;
        w64.pending[slot].generation = h.generation;
    }
#ifdef NTWV_W64_DERIVED_OWNER
    if (track != NTWV_W64_TRACKED) {
        ntwv_fill(tracked_at(track), 0, sizeof *tracked_at(track));
        tracked_at(track)->cap = h.capability_id;
        tracked_at(track)->user_req = h.request_id;
        tracked_at(track)->state = TR_CREATE_SENT;
    }
    if (w64_stamp && h.opcode == SHZ_OP_W64_RELEASE && h.payload_length >= sizeof(shz_w64_kill_t)) {
        shz_w64_kill_t k;
        ntwv_copy(&k, w64_in + sizeof h, sizeof k);
        i = tracked_find(h.capability_id, k.pid);
        if (i != NTWV_W64_TRACKED) {          /* the owner releases its own slot: custody ends on its OK reply */
            tracked_at(i)->user_release = 1;
            tracked_at(i)->user_req = h.request_id;
        }
    }
#endif
    ++w64.sent;
    if (hv->hcall(SHZ_HC_NOTIFY, w64.peer, 1, 0, 0) != SHZ_OK)
        ++w64.notify_errors;
    status = SHZ_OK;
    ntwv_copy(w64_out, &status, sizeof status);
    *out_len = sizeof status;
    return 0;
}

#ifdef NTWV_W64_DERIVED_OWNER
/* Locked. Deliver the OLDEST stashed message for `cap` (lowest arrival number, independent of slot index). */
static int stash_take(uint32_t cap, uint32_t *out_len)
{
    uint32_t i, best = NTWV_W64_STASH;
    for (i = 0; i < NTWV_W64_STASH; ++i)
        if (stash_at(i)->cap && stash_at(i)->cap == cap &&
            (best == NTWV_W64_STASH || stash_at(i)->arrival < stash_at(best)->arrival))
            best = i;
    if (best == NTWV_W64_STASH)
        return 0;
    ntwv_copy(w64_out, stash_at(best)->slot, SHZ_MSG_SLOT_SIZE);
    stash_at(best)->cap = 0;
    ++w64.received;
    *out_len = SHZ_MSG_SLOT_SIZE;
    return 1;
}
/* Locked. A free stash slot, after dropping retired owners' messages; NTWV_W64_STASH when full. */
static uint32_t stash_free_slot(void)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_STASH; ++i)
        if (stash_at(i)->cap && !ntwv_w64_owner_cap_live(stash_at(i)->cap)) {
            stash_at(i)->cap = 0;                /* owner's last handle closed / channel reset: undeliverable */
            ++w64_orphans;
        }
    for (i = 0; i < NTWV_W64_STASH; ++i)
        if (!stash_at(i)->cap)
            return i;
    return NTWV_W64_STASH;
}
/* Locked. 1 when the unconsumed ring head belongs to ANOTHER live derived owner, i.e. popping it would need a
 * stash slot. Advisory peek of the peer-written slot: the popped (CRC-checked) header still decides routing. An
 * empty or corrupt ring returns 0 so shz_ring_pop reports it. */
static int rx_head_for_other(uint32_t cap)
{
    shz_msg_hdr_t peek;
    const uint32_t tail = w64.rx->tail, head = __atomic_load_n(&w64.rx->head, __ATOMIC_ACQUIRE);
    if (head == tail || head - tail > w64.rx->slot_count)
        return 0;
    ntwv_copy(&peek, shz_ring_slot(w64.rx, tail), sizeof peek);
    return peek.capability_id != cap && shz_w64_owner_cap_derived(peek.capability_id) &&
           ntwv_w64_owner_cap_live(peek.capability_id);
}
#endif

/* cap: the caller's derived identity (0 = unfiltered: the in-VxD endpoint or a forwarding build). */
static uint32_t w64_recv(uint32_t *out_len, uint32_t cap)
{
    shz_msg_hdr_t h;
    int rc, reason;
    uint32_t budget, live_result = w64_live();
#ifdef NTWV_W64_DERIVED_OWNER
    uint32_t spare = NTWV_W64_STASH;
#else
    (void)cap;
#endif
    if (live_result)
        return live_result;
#ifdef NTWV_W64_DERIVED_OWNER
    if (cap && stash_take(cap, out_len))
        return 0;
#endif
    for (budget = 0; budget < w64.layout.slot_count; ++budget) {
#ifdef NTWV_W64_DERIVED_OWNER
        /* Never pop a message that could be neither delivered nor kept: with the stash full only a head that is
         * the caller's own (or undeliverable to anyone) may be consumed; another live owner's head stays queued. */
        if (cap && (spare = stash_free_slot()) == NTWV_W64_STASH && rx_head_for_other(cap))
            return NTWV_ERROR_BUSY;
#endif
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
#ifdef NTWV_W64_DERIVED_OWNER
        track_observe(&h, w64_out + sizeof h);
        if (cap && h.capability_id != cap) {
            if (shz_w64_owner_cap_derived(h.capability_id) && ntwv_w64_owner_cap_live(h.capability_id)) {
                if (spare == NTWV_W64_STASH) {            /* peer rewrote the head after the peek (SPSC breach) */
                    ++w64.proto_errors;
                    ++w64_orphans;
                } else {                                  /* another live Win98 process's reply/event */
                    stash_at(spare)->cap = h.capability_id;
                    stash_at(spare)->arrival = w64_arrival++;
                    ntwv_copy(stash_at(spare)->slot, w64_out, SHZ_MSG_SLOT_SIZE);
                }
            } else {
                ++w64_orphans;                            /* no live owner: never shown to this caller */
            }
            ntwv_fill(w64_out, 0, SHZ_MSG_SLOT_SIZE);
            continue;
        }
#endif
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

static uint32_t w64_handle(const struct ntwv_hv *hv, uint32_t code, uint32_t in_bytes, uint32_t *out_len, uint32_t cap)
{
    if (w64.open)
        legacy_opened = 1;
    switch (code) {
    case NTWV_IOCTL_W64_OPEN: {
        const uint32_t result = w64_open(hv);
        if (result)
            return result;
        legacy_opened = 1;
        fill_open((struct ntwv_w64_open *)w64_out);
        *out_len = sizeof(struct ntwv_w64_open);
        return 0;
    }
    case NTWV_IOCTL_W64_SEND: return w64_send(hv, in_bytes, out_len);
    case NTWV_IOCTL_W64_RECV: return w64_recv(out_len, cap);
    case NTWV_IOCTL_W64_WAIT: return w64_wait(hv, out_len);
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
        result = w64_send(hv, (uint32_t)sizeof *header + header->payload_length, &bytes);
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
        w64_recv(&bytes, 0) : NTWV_ERROR_NOT_READY;
    if (!result)
        ntwv_copy(slot, w64_out, bytes);
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
#ifdef NTWV_W64_DERIVED_OWNER
        /* Owner = VWIN32 DIOCParams (VMHandle, tagProcess) + live channel generation, never request bytes. */
        /* SEND is stamped with it; RECV only sees messages carrying it. OPEN/WAIT expose no per-process data. */
        result = 0;
        /* Reclaim retired owners' K64 processes first (trusted VxD sends; touches neither w64_in nor w64_out). */
        if (w64.open && !w64_live())
            w64_reap(hv);
        w64_stamp = request->code == NTWV_IOCTL_W64_SEND;
        w64_stamp_cap = 0;
        if ((w64_stamp || request->code == NTWV_IOCTL_W64_RECV) && w64.open)
            result = ntwv_w64_owner_derive(request->vm, request->process, w64.generation, &w64_stamp_cap);
        if (!result)
            result = w64_handle(hv, request->code, request->input_bytes, &out_len, w64_stamp_cap);
#else
        result = w64_handle(hv, request->code, request->input_bytes, &out_len, 0);
#endif
#ifdef NTWV_W64_DERIVED_OWNER
        w64_stamp = 0;
        w64_stamp_cap = 0;
#endif
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
    return result;
}

static uint32_t dioc_pma(const struct ntwv_dioc *request, const struct ntwv_pages *ops)
{
    uint8_t input_data[sizeof(struct ntwv_pma_registration)] = { 0 };
    uint8_t output_data[sizeof(struct ntwv_pma_result)] = { 0 };
    struct pinned input = { 0 }, output, returned;
    uint32_t in_need = 0, out_need = 0, out_len = 0, result = NTWV_ERROR_NOACCESS;
    uintptr_t saved;
    int ok;
    switch (request->code) {
    case NTWV_IOCTL_PMA_REGISTER: in_need = sizeof(struct ntwv_pma_registration); out_need = sizeof(struct ntwv_pma_owner); break;
    case NTWV_IOCTL_PMA_QUERY: out_need = sizeof(struct ntwv_pma_ticket); break;
    case NTWV_IOCTL_PMA_TAKE: out_need = sizeof(struct ntwv_pma_result); break;
    case NTWV_IOCTL_PMA_CLOSE: out_need = 4; break;
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
    if (!result && request->code == NTWV_IOCTL_PMA_TAKE) {
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
    if (request->code == NTWV_IOCTL_CLOCK)
        return dioc_clock(request, ops, hv);
    if (request->code >= NTWV_IOCTL_PMA_REGISTER && request->code <= NTWV_IOCTL_PMA_CLOSE)
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
    if(request->code!=NTWV_IOCTL_QUERY && request->code!=NTWV_IOCTL_CLOCK &&
       !(request->code>=NTWV_IOCTL_W64_OPEN && request->code<=NTWV_IOCTL_W64_WAIT) &&
       !(request->code>=NTWV_IOCTL_PMA_REGISTER && request->code<=NTWV_IOCTL_PMA_CLOSE))
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
