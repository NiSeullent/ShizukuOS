/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS WIN64 subsystem: generational native endpoint owner contract.
 *
 * Shared, pointer-free, freestanding (stdint/stddef only via shz_ipc.h). Consumed by
 * NTWRAP9X.VXD (ntwrapper/vxd, owner derivation/mailbox routing), Kernel64 subsys64
 * (slot binding/revocation) and NTW32 (reads only, never forges). Wire layouts of
 * shz_ipc.h/shz_abi.h are unchanged; this header only gives meaning to the existing
 * shz_msg_hdr_t.capability_id (u32 at 0x38) for the W64 family 0x200..0x2ff and adds one
 * W64-range opcode (SHZ_OP_W64_OWNER_CONTROL = 0x209).
 *
 * Owner id (capability_id) packing, 32 bits:
 *     bit 31     : 0 for endpoint owners. 1 only in SHZ_W64_OWNER_PRIVILEGED_ID.
 *     bits 30..8 : generation, 1..SHZ_W64_OWNER_GEN_MAX (23 bits, never 0, never wraps)
 *     bits 7..0  : owner slot index, < SHZ_W64_OWNER_MAX
 *   0 = no owner (legacy/unowned): Core refuses owner-bound W64 ops carrying it.
 *
 * Derivation (VxD): the VxD derives the owner from the actual VWIN32 DIOC context (VM handle,
 * device/DIOC context, VWIN32 process) into an opaque u64 context key; the application never
 * supplies it. On every W64 SEND the VxD OVERWRITES capability_id with that owner id (as it
 * already overwrites src/dst/generation). On RECV it delivers only messages whose
 * capability_id equals the caller's owner id, from that owner's bounded mailbox; there is no
 * global receive. This is a routing lifetime, NOT a Core SID/login token: account admission
 * stays effective in Core independently of the owner id.
 *
 * Revocation (both sides MUST agree):
 *   - Reasons: device close, VWIN32 process departure, channel epoch change, generation
 *     exhaustion (slot retired, never reused).
 *   - VxD: on device close / process departure, the slot enters REVOKING, stops accepting
 *     SENDs from that owner, and sends one OWNER_CONTROL(REVOKE) request carrying
 *     capability_id == owner id (VxD-originated; endpoints may never send 0x209). The slot and
 *     its mailbox stay retained until the matching SHZ_OK reply or a channel epoch change;
 *     a full ring / failed push is retried, never dropped. Then the generation advances
 *     (or the slot retires when exhausted) and messages for the old id are counted and
 *     discarded (owner is gone; nothing else may receive them).
 *   - Core: on OWNER_CONTROL(REVOKE) for id X, for every slot bound to X: revoke GUI views
 *     and snapshots, clear held input state, refuse further console input, terminate live
 *     processes with SHZ_W64_OWNER_REVOKE_EXIT_CODE, reap privately once teardown completes
 *     (no PROCESS_EXITED owed to the departed owner), then reply SHZ_OK with counts. Idempotent:
 *     a repeated REVOKE for an already revoked id replies SHZ_OK with zero counts.
 *   - Channel epoch change (chan->generation differs from the bound epoch): both sides
 *     implicitly revoke every owner bound to the old epoch without a control message.
 *   - Core binding: CREATE_PROCESS binds the slot to (owner id, channel generation, admitted
 *     live slot generation + process pointer). Every later slot lookup (KILL, RELEASE,
 *     CONSOLE_ACK/INPUT, GUI ops) requires the same owner id and channel generation, else
 *     SHZ_E_NOENT (no disclosure of other owners' pids). Core sets capability_id on every
 *     reply (echo) AND every event (CONSOLE_OUTPUT/PROCESS_EXITED) to the slot owner id.
 *
 * Privileged authority: distinct from endpoint owners. SHUTDOWN (0x208) is never allowed to
 * an endpoint owner. Only SHZ_W64_OWNER_PRIVILEGED_ID, which the VxD DIOC SEND path never
 * emits, plus Core-local configuration that enables a privileged peer, may stop the service.
 * Leased-PMA opcodes (0x300..0x3ff) are never accepted on the W64 raw SEND path.
 */
#ifndef SHZ_W64_OWNER_H
#define SHZ_W64_OWNER_H
#include <stddef.h>
#include <stdint.h>
#include "shz_ipc.h"

/* ------------------------------------------------------------------ bounds */
#define SHZ_W64_OWNER_MAX 16u               /* owner table slots in the VxD; Core bound tables use the same */
#define SHZ_W64_OWNER_MAILBOX_DEPTH 16u     /* retained 256-byte slots per owner (>= CONSOLE_WINDOW + replies + EXITED) */
#define SHZ_W64_OWNER_SLOT_BITS 8u
#define SHZ_W64_OWNER_SLOT_MASK 0xffu
#define SHZ_W64_OWNER_GEN_SHIFT 8u
#define SHZ_W64_OWNER_GEN_MAX 0x7fffffu     /* 23-bit generation; reaching it retires the slot */
#define SHZ_W64_OWNER_PRIV_BIT 0x80000000u
#define SHZ_W64_OWNER_NONE 0u
#define SHZ_W64_OWNER_PRIVILEGED_ID 0x80000000u   /* never produced by the endpoint DIOC SEND path */
#define SHZ_W64_OWNER_REVOKE_EXIT_CODE ((int32_t)0xc000013au)  /* STATUS_CONTROL_C_EXIT */

_Static_assert(SHZ_W64_OWNER_MAX <= SHZ_W64_OWNER_SLOT_MASK + 1u, "owner slot fits slot bits");
_Static_assert(SHZ_W64_OWNER_MAILBOX_DEPTH >= SHZ_W64_CONSOLE_WINDOW + 2u, "mailbox holds console window + reply + EXITED");
_Static_assert(((SHZ_W64_OWNER_GEN_MAX << SHZ_W64_OWNER_GEN_SHIFT) & SHZ_W64_OWNER_PRIV_BIT) == 0, "generation never sets priv bit");

/* ------------------------------------------------------------------ states / reasons / authority */
enum shz_w64_owner_state {
    SHZ_W64_OWNER_FREE = 0,       /* reusable; next allocation uses generation + 1 */
    SHZ_W64_OWNER_LIVE = 1,       /* bound to a DIOC context, SEND/RECV permitted */
    SHZ_W64_OWNER_REVOKING = 2,   /* departure seen; SEND refused, mailbox retained until Core acknowledges */
    SHZ_W64_OWNER_RETIRED = 3     /* generation exhausted; slot is never reused */
};

enum shz_w64_owner_revoke_reason {
    SHZ_W64_REVOKE_DEVICE_CLOSE = 1,
    SHZ_W64_REVOKE_PROCESS_DEPARTURE = 2,
    SHZ_W64_REVOKE_CHANNEL_EPOCH = 3,
    SHZ_W64_REVOKE_GEN_EXHAUSTED = 4
};
#define SHZ_W64_REVOKE_REASON_MAX 4u

enum shz_w64_authority {
    SHZ_W64_AUTH_NONE = 0,        /* capability_id 0 / malformed / stale: owner-bound ops refused */
    SHZ_W64_AUTH_ENDPOINT = 1,    /* valid endpoint owner id */
    SHZ_W64_AUTH_PRIVILEGED = 2   /* SHZ_W64_OWNER_PRIVILEGED_ID and Core enabled it */
};

/* ------------------------------------------------------------------ owner id */
SHZ_IPC_INLINE uint32_t shz_w64_owner_make(uint32_t slot, uint32_t generation)
{
    if (slot >= SHZ_W64_OWNER_MAX || generation == 0 || generation > SHZ_W64_OWNER_GEN_MAX)
        return SHZ_W64_OWNER_NONE;
    return (generation << SHZ_W64_OWNER_GEN_SHIFT) | slot;
}
SHZ_IPC_INLINE uint32_t shz_w64_owner_slot(uint32_t id) { return id & SHZ_W64_OWNER_SLOT_MASK; }
SHZ_IPC_INLINE uint32_t shz_w64_owner_gen(uint32_t id) { return (id & ~SHZ_W64_OWNER_PRIV_BIT) >> SHZ_W64_OWNER_GEN_SHIFT; }

/* Structurally valid endpoint owner id (not NONE, not privileged, slot in bound, gen nonzero). */
SHZ_IPC_INLINE int shz_w64_owner_id_valid(uint32_t id)
{
    return id != SHZ_W64_OWNER_NONE && !(id & SHZ_W64_OWNER_PRIV_BIT) &&
           shz_w64_owner_slot(id) < SHZ_W64_OWNER_MAX && shz_w64_owner_gen(id) != 0;
}

/* Next generation for a freed slot; 0 means exhausted: the slot must become RETIRED. */
SHZ_IPC_INLINE uint32_t shz_w64_owner_next_gen(uint32_t gen)
{
    return gen >= SHZ_W64_OWNER_GEN_MAX ? 0u : gen + 1u;
}

/* Core-side classification of an inbound W64 header. `privileged_enabled` is Core-local
 * configuration (default 0); it is never derived from payload content. */
SHZ_IPC_INLINE int shz_w64_authority_of(uint32_t capability_id, int privileged_enabled)
{
    if (capability_id == SHZ_W64_OWNER_PRIVILEGED_ID)
        return privileged_enabled ? SHZ_W64_AUTH_PRIVILEGED : SHZ_W64_AUTH_NONE;
    return shz_w64_owner_id_valid(capability_id) ? SHZ_W64_AUTH_ENDPOINT : SHZ_W64_AUTH_NONE;
}

/* ------------------------------------------------------------------ control opcode */
#define SHZ_OP_W64_OWNER_CONTROL 0x209u     /* VxD -> K64 request; reply echoes opcode */
_Static_assert(SHZ_OP_W64_OWNER_CONTROL > SHZ_OP_W64_SHUTDOWN && SHZ_OP_W64_OWNER_CONTROL <= SHZ_W64_OP_LAST,
               "owner control is additive in the W64 range");
#define SHZ_W64_OWNER_CTL_VERSION 1u
enum shz_w64_owner_ctl_action { SHZ_W64_OWNER_CTL_REVOKE = 1 };

typedef struct {
    uint32_t size;                      /* 0x00 sizeof(shz_w64_owner_ctl_t) */
    uint32_t version;                   /* 0x04 SHZ_W64_OWNER_CTL_VERSION */
    uint32_t owner_id;                  /* 0x08 == header capability_id */
    uint32_t action;                    /* 0x0c SHZ_W64_OWNER_CTL_REVOKE */
    uint32_t reason;                    /* 0x10 shz_w64_owner_revoke_reason (not CHANNEL_EPOCH: implicit) */
    uint32_t expected_channel_generation; /* 0x14 == header generation */
    uint32_t reserved[2];               /* 0x18 zero */
} shz_w64_owner_ctl_t;

typedef struct {
    uint32_t size;                      /* 0x00 sizeof(shz_w64_owner_ctl_reply_t) */
    uint32_t version;                   /* 0x04 */
    uint32_t owner_id;                  /* 0x08 echo */
    uint32_t reason;                    /* 0x0c echo */
    uint32_t revoked_processes;         /* 0x10 slots unbound (terminated or already exited) */
    uint32_t revoked_views;             /* 0x14 GUI views revoked */
    uint32_t revoked_snapshots;         /* 0x18 GUI snapshots freed */
    uint32_t reserved;                  /* 0x1c zero */
} shz_w64_owner_ctl_reply_t;

_Static_assert(sizeof(shz_w64_owner_ctl_t) == 32, "owner ctl layout");
_Static_assert(sizeof(shz_w64_owner_ctl_reply_t) == 32, "owner ctl reply layout");
_Static_assert(__builtin_offsetof(shz_w64_owner_ctl_t, expected_channel_generation) == 0x14, "owner ctl offset");

/* ------------------------------------------------------------------ op allowlists */
#define SHZ_W64_GUI_OP_FIRST 0x240u          /* see shz_w64_gui.h (isolated candidate) */
#define SHZ_W64_GUI_OP_LAST 0x245u

/* VxD: may a native endpoint's raw DIOC SEND carry this opcode with these flags?
 * `flags` are the application's header flags BEFORE the VxD strips SHZ_MSGF_BUFFER.
 * gui_enabled must be nonzero only when every production GUI hook exists. */
SHZ_IPC_INLINE int shz_w64_endpoint_op_allowed(uint32_t opcode, uint16_t flags, int gui_enabled)
{
    const uint16_t f = (uint16_t)(flags & ~(uint16_t)SHZ_MSGF_BUFFER);
    if (flags & (SHZ_MSGF_REPLY | SHZ_MSGF_CANCEL))
        return 0;
    switch (opcode) {
    case SHZ_OP_W64_CONSOLE_ACK:
        return f == SHZ_MSGF_ONEWAY;
    case SHZ_OP_W64_QUERY:
    case SHZ_OP_W64_CREATE_PROCESS:
    case SHZ_OP_W64_CONSOLE_INPUT:
    case SHZ_OP_W64_KILL_PROCESS:
    case SHZ_OP_W64_RELEASE:
        return f == 0;
    default:
        /* SHUTDOWN, OWNER_CONTROL, server events, PMA 0x300..0x3ff and unknown ids: never. */
        return gui_enabled && opcode >= SHZ_W64_GUI_OP_FIRST && opcode <= SHZ_W64_GUI_OP_LAST && flags == 0;
    }
}

/* VxD: does the raw SEND carry pool data (bytes beyond header+payload)? Only CREATE_PROCESS may. */
SHZ_IPC_INLINE int shz_w64_endpoint_pool_allowed(uint32_t opcode) { return opcode == SHZ_OP_W64_CREATE_PROCESS; }

/* Core: may a request with this authority perform this opcode? Pair with shz_w64_authority_of.
 * OWNER_CONTROL additionally needs shz_w64_owner_ctl_check. */
SHZ_IPC_INLINE int shz_w64_core_op_allowed(uint32_t opcode, int authority, int gui_enabled)
{
    if (opcode == SHZ_OP_W64_SHUTDOWN)
        return authority == SHZ_W64_AUTH_PRIVILEGED;
    if (authority != SHZ_W64_AUTH_ENDPOINT)
        return 0;
    switch (opcode) {
    case SHZ_OP_W64_QUERY: case SHZ_OP_W64_CREATE_PROCESS: case SHZ_OP_W64_CONSOLE_ACK:
    case SHZ_OP_W64_CONSOLE_INPUT: case SHZ_OP_W64_KILL_PROCESS: case SHZ_OP_W64_RELEASE:
    case SHZ_OP_W64_OWNER_CONTROL:
        return 1;
    default:
        return gui_enabled && opcode >= SHZ_W64_GUI_OP_FIRST && opcode <= SHZ_W64_GUI_OP_LAST;
    }
}

/* ------------------------------------------------------------------ control validators */
SHZ_IPC_INLINE void shz_w64_owner_ctl_build(shz_w64_owner_ctl_t *c, uint32_t owner_id, uint32_t reason,
                                            uint32_t channel_generation)
{
    SHZ_IPC_MEMSET(c, 0, sizeof *c);
    c->size = (uint32_t)sizeof *c;
    c->version = SHZ_W64_OWNER_CTL_VERSION;
    c->owner_id = owner_id;
    c->action = SHZ_W64_OWNER_CTL_REVOKE;
    c->reason = reason;
    c->expected_channel_generation = channel_generation;
}

/* Core: strict request check. `channel_generation` is the live chan->generation. */
SHZ_IPC_INLINE int shz_w64_owner_ctl_check(const shz_msg_hdr_t *m, const void *payload, uint32_t channel_generation,
                                           shz_w64_owner_ctl_t *out)
{
    shz_w64_owner_ctl_t c;
    if (!m || !payload || !out || m->opcode != SHZ_OP_W64_OWNER_CONTROL || m->payload_length != sizeof c)
        return SHZ_E_PROTO;
    if (m->flags != 0 || m->buffer_length || m->buffer_offset)
        return SHZ_E_INVALID;
    SHZ_IPC_MEMCPY(&c, payload, sizeof c);
    if (c.size != sizeof c || c.version != SHZ_W64_OWNER_CTL_VERSION || c.action != SHZ_W64_OWNER_CTL_REVOKE ||
        c.reserved[0] || c.reserved[1] || c.reason == 0 || c.reason > SHZ_W64_REVOKE_REASON_MAX ||
        c.reason == SHZ_W64_REVOKE_CHANNEL_EPOCH)
        return SHZ_E_INVALID;
    if (!shz_w64_owner_id_valid(c.owner_id) || c.owner_id != m->capability_id)
        return SHZ_E_DENIED;
    if (c.expected_channel_generation != channel_generation || m->generation != channel_generation)
        return SHZ_E_STALE;
    *out = c;
    return SHZ_OK;
}

/* VxD: strict reply check against the request it sent. */
SHZ_IPC_INLINE int shz_w64_owner_ctl_reply_check(const shz_msg_hdr_t *m, const void *payload,
                                                 const shz_w64_owner_ctl_t *req, uint64_t request_id,
                                                 shz_w64_owner_ctl_reply_t *out)
{
    shz_w64_owner_ctl_reply_t r;
    if (!m || !req || !out || m->opcode != SHZ_OP_W64_OWNER_CONTROL || m->flags != SHZ_MSGF_REPLY ||
        m->request_id != request_id || m->capability_id != req->owner_id || m->buffer_length || m->buffer_offset)
        return SHZ_E_PROTO;
    if (m->status != SHZ_OK)
        return m->payload_length == 0 ? m->status : SHZ_E_PROTO;
    if (!payload || m->payload_length != sizeof r)
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&r, payload, sizeof r);
    if (r.size != sizeof r || r.version != SHZ_W64_OWNER_CTL_VERSION || r.owner_id != req->owner_id ||
        r.reason != req->reason || r.reserved)
        return SHZ_E_PROTO;
    *out = r;
    return SHZ_OK;
}

/* ------------------------------------------------------------------ VxD owner table (pointer-free) */
typedef struct {
    uint64_t context_key;       /* opaque key derived by the VxD from VM/device/VWIN32 process; 0 = none */
    uint32_t state;             /* shz_w64_owner_state */
    uint32_t generation;        /* current generation of this slot (valid while LIVE/REVOKING) */
    uint32_t channel_generation;/* epoch the owner was bound under */
    uint32_t revoke_reason;     /* set on REVOKING */
    uint64_t revoke_request_id; /* OWNER_CONTROL request id while REVOKING, 0 = not yet pushed */
} shz_w64_owner_rec_t;

typedef struct {
    shz_w64_owner_rec_t rec[SHZ_W64_OWNER_MAX];
} shz_w64_owner_table_t;

_Static_assert(sizeof(shz_w64_owner_rec_t) == 32, "owner record layout");

/* Live lookup by context key under the current epoch; returns owner id or NONE. */
SHZ_IPC_INLINE uint32_t shz_w64_owner_lookup(const shz_w64_owner_table_t *t, uint64_t key, uint32_t chan_gen)
{
    unsigned i;
    if (!t || !key)
        return SHZ_W64_OWNER_NONE;
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i)
        if (t->rec[i].state == SHZ_W64_OWNER_LIVE && t->rec[i].context_key == key &&
            t->rec[i].channel_generation == chan_gen)
            return shz_w64_owner_make(i, t->rec[i].generation);
    return SHZ_W64_OWNER_NONE;
}

/* Bind a new owner for `key` (caller looked it up first). Returns owner id, or NONE when the
 * table is full (caller fails the DIOC with BUSY; never evicts a LIVE/REVOKING owner). */
SHZ_IPC_INLINE uint32_t shz_w64_owner_bind(shz_w64_owner_table_t *t, uint64_t key, uint32_t chan_gen)
{
    unsigned i;
    if (!t || !key)
        return SHZ_W64_OWNER_NONE;
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i) {
        shz_w64_owner_rec_t *r = &t->rec[i];
        uint32_t g;
        if (r->state != SHZ_W64_OWNER_FREE)
            continue;
        g = shz_w64_owner_next_gen(r->generation);
        if (!g) { r->state = SHZ_W64_OWNER_RETIRED; continue; }
        r->generation = g;
        r->context_key = key;
        r->channel_generation = chan_gen;
        r->revoke_reason = 0;
        r->revoke_request_id = 0;
        r->state = SHZ_W64_OWNER_LIVE;
        return shz_w64_owner_make(i, g);
    }
    return SHZ_W64_OWNER_NONE;
}

/* Exact-id match of a LIVE owner (SEND path) or LIVE/REVOKING owner (mailbox routing). */
SHZ_IPC_INLINE shz_w64_owner_rec_t *shz_w64_owner_get(shz_w64_owner_table_t *t, uint32_t id, int allow_revoking)
{
    shz_w64_owner_rec_t *r;
    if (!t || !shz_w64_owner_id_valid(id))
        return 0;
    r = &t->rec[shz_w64_owner_slot(id)];
    if (r->generation != shz_w64_owner_gen(id))
        return 0;
    if (r->state == SHZ_W64_OWNER_LIVE || (allow_revoking && r->state == SHZ_W64_OWNER_REVOKING))
        return r;
    return 0;
}

/* Departure: LIVE -> REVOKING. Caller then pushes OWNER_CONTROL and records revoke_request_id. */
SHZ_IPC_INLINE int shz_w64_owner_begin_revoke(shz_w64_owner_table_t *t, uint32_t id, uint32_t reason)
{
    shz_w64_owner_rec_t *r = shz_w64_owner_get(t, id, 0);
    if (!r)
        return SHZ_E_NOENT;
    if (reason == 0 || reason > SHZ_W64_REVOKE_REASON_MAX || reason == SHZ_W64_REVOKE_CHANNEL_EPOCH)
        return SHZ_E_INVALID;
    r->state = SHZ_W64_OWNER_REVOKING;
    r->revoke_reason = reason;
    r->revoke_request_id = 0;
    return SHZ_OK;
}

/* Core acknowledged (validated reply) or epoch changed: free the slot (generation kept so the
 * next bind advances it; exhaustion retires the slot). Caller discards the owner's mailbox. */
SHZ_IPC_INLINE void shz_w64_owner_finish(shz_w64_owner_rec_t *r)
{
    r->context_key = 0;
    r->revoke_request_id = 0;
    r->state = shz_w64_owner_next_gen(r->generation) ? SHZ_W64_OWNER_FREE : SHZ_W64_OWNER_RETIRED;
}

/* Channel epoch change: every LIVE/REVOKING owner of an older epoch is implicitly revoked. Returns count. */
SHZ_IPC_INLINE unsigned shz_w64_owner_epoch_revoke(shz_w64_owner_table_t *t, uint32_t new_chan_gen)
{
    unsigned i, n = 0;
    for (i = 0; i < SHZ_W64_OWNER_MAX; ++i) {
        shz_w64_owner_rec_t *r = &t->rec[i];
        if ((r->state == SHZ_W64_OWNER_LIVE || r->state == SHZ_W64_OWNER_REVOKING) &&
            r->channel_generation != new_chan_gen) {
            r->revoke_reason = SHZ_W64_REVOKE_CHANNEL_EPOCH;
            shz_w64_owner_finish(r);
            ++n;
        }
    }
    return n;
}

/* ------------------------------------------------------------------ C6 typed broker requests (routing02, additive)
 * Endpoint -> Core requests carrying credentials for the authenticated endpoint broker. Owner = header
 * capability_id (endpoint owner rules above; NONE/privileged never valid here). flags 0, no pool buffer.
 * Core copies the payload ONCE into a bounded local (shz_w64_auth_req_check), calls the broker, and scrubs the
 * local copy and the consumed ring slot on every path. Replies never echo user or secret; credentials and their
 * lengths are never logged. These opcodes are NOT in shz_w64_endpoint_op_allowed: the VxD allowlist extension is a
 * separate change (native clients cannot deliver them until it lands). */
#define SHZ_OP_W64_AUTH_LOGIN 0x20Au
#define SHZ_OP_W64_AUTH_REGISTER 0x20Bu
#define SHZ_OP_W64_AUTH_CONFIRM_ELEVATION 0x20Cu
#define SHZ_W64_AUTH_VERSION 1u
#define SHZ_W64_AUTH_USER_MAX 32u
#define SHZ_W64_AUTH_SECRET_MAX 128u
_Static_assert(SHZ_OP_W64_AUTH_LOGIN > SHZ_OP_W64_OWNER_CONTROL && SHZ_OP_W64_AUTH_CONFIRM_ELEVATION < SHZ_W64_GUI_OP_FIRST,
               "auth opcodes are additive in the W64 range");

typedef struct {
    uint32_t size;          /* 0x00 sizeof */
    uint16_t version;       /* 0x04 SHZ_W64_AUTH_VERSION */
    uint16_t flags;         /* 0x06 0 */
    uint32_t user_len;      /* 0x08 1..31, no NUL inside, user[user_len]==0, rest zero */
    uint32_t secret_len;    /* 0x0c 1..128, secret bytes past secret_len zero */
    uint32_t roles;         /* 0x10 REGISTER only (validated by broker); else 0 */
    uint32_t reserved;      /* 0x14 0 */
    char user[SHZ_W64_AUTH_USER_MAX];           /* 0x18 */
    uint8_t secret[SHZ_W64_AUTH_SECRET_MAX];    /* 0x38 */
} shz_w64_auth_req_t;

typedef struct {
    uint32_t size;          /* 0x00 sizeof */
    int32_t status;         /* 0x04 shz_status (same as header status) */
    uint64_t auth_epoch;    /* 0x08 broker login epoch on success, else 0 */
    uint32_t subject_flags; /* 0x10 bound subject flags on success, else 0 */
    uint32_t reserved;      /* 0x14 0 */
} shz_w64_auth_reply_t;

_Static_assert(sizeof(shz_w64_auth_req_t) == 184 && sizeof(shz_w64_auth_req_t) <= SHZ_MSG_MAX_INLINE, "auth req layout");
_Static_assert(__builtin_offsetof(shz_w64_auth_req_t, secret) == 0x38, "auth req secret offset");
_Static_assert(sizeof(shz_w64_auth_reply_t) == 24, "auth reply layout");

SHZ_IPC_INLINE int shz_w64_auth_op(uint32_t opcode)
{
    return opcode >= SHZ_OP_W64_AUTH_LOGIN && opcode <= SHZ_OP_W64_AUTH_CONFIRM_ELEVATION;
}

/* Core: strict request check. Copies the payload exactly once into *out (only after the envelope is proven to
 * carry exactly sizeof *out bytes); the caller MUST scrub *out with a non-elidable wipe on every path, including
 * any error returned here. Privileged/NONE owners are refused (SHZ_E_DENIED). */
SHZ_IPC_INLINE int shz_w64_auth_req_check(const shz_msg_hdr_t *m, const void *payload, shz_w64_auth_req_t *out)
{
    uint32_t i;
    if (!m || !out || !shz_w64_auth_op(m->opcode) || !payload || m->payload_length != sizeof *out)
        return SHZ_E_PROTO;
    if (m->flags != 0 || m->buffer_length || m->buffer_offset)
        return SHZ_E_INVALID;
    if (!shz_w64_owner_id_valid(m->capability_id))
        return SHZ_E_DENIED;
    SHZ_IPC_MEMCPY(out, payload, sizeof *out);
    if (out->size != sizeof *out || out->version != SHZ_W64_AUTH_VERSION || out->flags || out->reserved ||
        out->user_len == 0 || out->user_len >= SHZ_W64_AUTH_USER_MAX ||
        out->secret_len == 0 || out->secret_len > SHZ_W64_AUTH_SECRET_MAX ||
        (m->opcode != SHZ_OP_W64_AUTH_REGISTER && out->roles))
        return SHZ_E_INVALID;
    for (i = 0; i < SHZ_W64_AUTH_USER_MAX; ++i)
        if ((i < out->user_len) != (out->user[i] != 0))
            return SHZ_E_INVALID;
    for (i = out->secret_len; i < SHZ_W64_AUTH_SECRET_MAX; ++i)
        if (out->secret[i])
            return SHZ_E_INVALID;
    return SHZ_OK;
}
#endif
