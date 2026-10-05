/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS WIN64 subsystem: native GUI view protocol v1 -- ISOLATED SOURCE CANDIDATE.
 *
 * Draft opcodes 0x240..0x245 and capability bit 0x20 per
 * build/claude-shizuku-dispatch-20261003/native-gui-v1-proposal.md. NOT a declared feature:
 * Kernel64 MUST NOT set SHZ_W64_CAP_GUI_CANDIDATE in shz_w64_info_t.capabilities, and the
 * VxD/Core allowlists (shz_w64_owner.h, gui_enabled=0) refuse these opcodes, until the
 * production hooks exist (derived owner route, admitted slot binding, WM capture/input,
 * NTW32 entry points, native presenter). Until then the server answers SHZ_E_UNSUPPORTED.
 *
 * Transport: the existing W64 channel and CRC'd shz_msg_hdr_t only. Requests: flags 0,
 * buffer_length/offset 0, exact payload_length. Replies: flags == SHZ_MSGF_REPLY, same
 * opcode/request_id/capability_id; status SHZ_OK carries the exact reply payload, any other
 * status carries payload_length 0. capability_id is the VxD-derived owner (shz_w64_owner.h);
 * the payload pid is an advisory selector, never an identity. All fields little-endian,
 * pointer-free; window_id is the opaque 64-bit WM generational id (not an HWND/pointer).
 */
#ifndef SHZ_W64_GUI_H
#define SHZ_W64_GUI_H
#include <stddef.h>
#include <stdint.h>
#include "shz_ipc.h"
#include "shz_w64_owner.h"

/* ------------------------------------------------------------------ ids / limits */
#define SHZ_W64_CAP_GUI_CANDIDATE 0x20u     /* distinct from existing caps 1|2|4|8|16 */
_Static_assert((SHZ_W64_CAP_GUI_CANDIDATE & (SHZ_W64_CAP_CREATE | SHZ_W64_CAP_CONSOLE_OUTPUT | SHZ_W64_CAP_CONSOLE_INPUT |
                                             SHZ_W64_CAP_KILL | SHZ_W64_CAP_POOL_ARGS)) == 0, "gui cap bit is new");

enum shz_w64_gui_opcode {
    SHZ_OP_W64_GUI_QUERY_VIEW = 0x240,
    SHZ_OP_W64_GUI_FRAME_ACQUIRE = 0x241,
    SHZ_OP_W64_GUI_FRAME_READ = 0x242,
    SHZ_OP_W64_GUI_FRAME_RELEASE = 0x243,
    SHZ_OP_W64_GUI_INPUT = 0x244,
    SHZ_OP_W64_GUI_CLOSE_VIEW = 0x245
};
_Static_assert(SHZ_OP_W64_GUI_QUERY_VIEW == SHZ_W64_GUI_OP_FIRST && SHZ_OP_W64_GUI_CLOSE_VIEW == SHZ_W64_GUI_OP_LAST,
               "gui op range agrees with owner allowlist");

#define SHZ_W64_GUI_VERSION 1u
#define SHZ_W64_GUI_MAX_WIDTH 1024u
#define SHZ_W64_GUI_MAX_HEIGHT 768u
#define SHZ_W64_GUI_MAX_FRAME_BYTES 3145728u        /* 1024 * 768 * 4 */
#define SHZ_W64_GUI_CHUNK 128u                      /* FRAME_READ data bytes per reply */
#define SHZ_W64_GUI_SNAPSHOT_LEASE_MS 10000u
#define SHZ_W64_GUI_TRANSFER_DEADLINE_MS 5000u      /* client aggregate, < lease */
#define SHZ_W64_GUI_VIEWS_PER_PROCESS 1u
#define SHZ_W64_GUI_SNAPSHOTS_PER_VIEW 1u
#define SHZ_W64_GUI_COORD_LIMIT 32767               /* |x|,|y| bound for client coordinates */
#define SHZ_W64_GUI_BPP_BYTES 4u
_Static_assert(SHZ_W64_GUI_MAX_FRAME_BYTES == SHZ_W64_GUI_MAX_WIDTH * SHZ_W64_GUI_MAX_HEIGHT * 4u, "frame limit");
_Static_assert(SHZ_W64_GUI_TRANSFER_DEADLINE_MS < SHZ_W64_GUI_SNAPSHOT_LEASE_MS, "transfer within lease");

enum shz_w64_gui_pixel_format { SHZ_W64_GUI_PF_BGRX32 = 1 };   /* top-down, B,G,R,X bytes, X ignored */
enum shz_w64_gui_view_caps { SHZ_W64_GUI_VCAP_FRAME = 1, SHZ_W64_GUI_VCAP_INPUT = 2 };
#define SHZ_W64_GUI_VCAP_ALL 3u
enum shz_w64_gui_acquire_flags { SHZ_W64_GUI_AF_CLIENT_ONLY = 1 };
#define SHZ_W64_GUI_AF_ALL 1u

enum shz_w64_gui_input_kind {
    SHZ_W64_GUI_IN_POINTER_MOVE = 1,
    SHZ_W64_GUI_IN_LBUTTON_DOWN = 2,
    SHZ_W64_GUI_IN_LBUTTON_UP = 3,
    SHZ_W64_GUI_IN_RBUTTON_DOWN = 4,
    SHZ_W64_GUI_IN_RBUTTON_UP = 5,
    SHZ_W64_GUI_IN_KEY_DOWN = 6,
    SHZ_W64_GUI_IN_KEY_UP = 7,
    SHZ_W64_GUI_IN_CLOSE = 8          /* posts actual WM_CLOSE to that owned window */
};
#define SHZ_W64_GUI_IN_KIND_MAX 8u
enum shz_w64_gui_input_flags { SHZ_W64_GUI_INF_EXTENDED = 1 };   /* key kinds only: extended scancode */

/* ------------------------------------------------------------------ packets */
typedef struct {
    uint32_t size;                          /* 0x00 24 */
    uint32_t version;                       /* 0x04 SHZ_W64_GUI_VERSION */
    uint32_t pid;                           /* 0x08 advisory selector (nonzero) */
    uint32_t expected_channel_generation;   /* 0x0c */
    uint32_t reserved[2];                   /* 0x10 zero */
} shz_w64_gui_query_req_t;

typedef struct {
    uint32_t size;                          /* 0x00 64 */
    uint32_t version;                       /* 0x04 */
    uint32_t pid;                           /* 0x08 echo */
    uint32_t process_generation;            /* 0x0c admitted slot generation, nonzero */
    uint64_t view_id;                       /* 0x10 monotonic nonzero, never wraps */
    uint32_t channel_generation;            /* 0x18 */
    uint32_t capabilities;                  /* 0x1c shz_w64_gui_view_caps */
    uint32_t max_width, max_height;         /* 0x20 */
    uint32_t max_frame_bytes;               /* 0x28 */
    uint32_t max_chunk_bytes;               /* 0x2c == SHZ_W64_GUI_CHUNK */
    uint32_t snapshot_lease_ms;             /* 0x30 */
    uint32_t reserved;                      /* 0x34 zero */
    uint64_t default_window_id;             /* 0x38 0 = process has no window yet */
} shz_w64_gui_view_info_t;

typedef struct {
    uint32_t size;                          /* 0x00 whole packet size of this op/direction */
    uint32_t version;                       /* 0x04 */
    uint32_t pid;                           /* 0x08 */
    uint32_t process_generation;            /* 0x0c */
    uint64_t window_id;                     /* 0x10 */
    uint64_t view_id;                       /* 0x18 */
    uint64_t snapshot_id;                   /* 0x20 */
    uint32_t expected_channel_generation;   /* 0x28 */
    uint32_t sequence;                      /* 0x2c per-view, nonzero; strictly increasing for INPUT */
} shz_w64_gui_prefix_t;

typedef struct {
    shz_w64_gui_prefix_t p;                 /* window 0 allowed (first owned visible top-level); snapshot 0 */
    uint64_t previous_snapshot_id;          /* 0x30 advisory */
    uint32_t flags;                         /* 0x38 SHZ_W64_GUI_AF_* */
    uint32_t reserved;                      /* 0x3c zero */
} shz_w64_gui_acquire_req_t;

typedef struct {
    shz_w64_gui_prefix_t p;                 /* full window id; new nonzero snapshot id */
    uint32_t width, height;                 /* 0x30 */
    uint32_t stride;                        /* 0x38 width * 4 */
    uint32_t byte_length;                   /* 0x3c stride * height */
    uint32_t pixel_format;                  /* 0x40 SHZ_W64_GUI_PF_BGRX32 */
    uint32_t pixels_crc32;                  /* 0x44 shz_crc32 over all byte_length bytes */
    uint32_t lease_ms;                      /* 0x48 */
    uint32_t flags;                         /* 0x4c echo of request flags */
} shz_w64_gui_acquire_reply_t;

typedef struct {
    shz_w64_gui_prefix_t p;
    uint32_t offset, length;                /* 0x30 */
    uint32_t reserved[2];                   /* 0x38 zero */
} shz_w64_gui_read_req_t;

typedef struct {
    shz_w64_gui_prefix_t p;
    uint32_t offset, length;                /* 0x30 echo */
    uint32_t reserved[2];                   /* 0x38 zero */
    uint8_t data[SHZ_W64_GUI_CHUNK];        /* 0x40 length bytes, zero tail */
} shz_w64_gui_read_reply_t;

typedef struct {
    shz_w64_gui_prefix_t p;
    uint32_t kind;                          /* 0x30 shz_w64_gui_input_kind */
    uint32_t flags;                         /* 0x34 shz_w64_gui_input_flags */
    int32_t x, y;                           /* 0x38 client coordinates */
    uint32_t key;                           /* 0x40 VK 1..254 for key kinds, else 0 */
    uint32_t scancode;                      /* 0x44 0..0xff for key kinds, else 0 */
    uint32_t clock_ms;                      /* 0x48 client timestamp, informational */
    uint32_t reserved;                      /* 0x4c zero */
} shz_w64_gui_input_req_t;

/* RELEASE request/reply, CLOSE_VIEW request/reply and INPUT reply are a bare prefix (48). */

_Static_assert(sizeof(shz_w64_gui_query_req_t) == 24, "gui query req");
_Static_assert(sizeof(shz_w64_gui_view_info_t) == 64, "gui view info");
_Static_assert(__builtin_offsetof(shz_w64_gui_view_info_t, default_window_id) == 0x38, "gui view info tail");
_Static_assert(sizeof(shz_w64_gui_prefix_t) == 48, "gui prefix");
_Static_assert(sizeof(shz_w64_gui_acquire_req_t) == 64, "gui acquire req");
_Static_assert(sizeof(shz_w64_gui_acquire_reply_t) == 80, "gui acquire reply");
_Static_assert(sizeof(shz_w64_gui_read_req_t) == 64, "gui read req");
_Static_assert(sizeof(shz_w64_gui_read_reply_t) == 192, "gui read reply");
_Static_assert(sizeof(shz_w64_gui_read_reply_t) <= SHZ_MSG_MAX_INLINE, "gui read reply inline");
_Static_assert(sizeof(shz_w64_gui_input_req_t) == 80, "gui input req");

/* Exact payload sizes per opcode/direction; 0 = not a GUI op. */
SHZ_IPC_INLINE uint32_t shz_w64_gui_req_size(uint32_t op)
{
    switch (op) {
    case SHZ_OP_W64_GUI_QUERY_VIEW: return sizeof(shz_w64_gui_query_req_t);
    case SHZ_OP_W64_GUI_FRAME_ACQUIRE: return sizeof(shz_w64_gui_acquire_req_t);
    case SHZ_OP_W64_GUI_FRAME_READ: return sizeof(shz_w64_gui_read_req_t);
    case SHZ_OP_W64_GUI_FRAME_RELEASE: case SHZ_OP_W64_GUI_CLOSE_VIEW: return sizeof(shz_w64_gui_prefix_t);
    case SHZ_OP_W64_GUI_INPUT: return sizeof(shz_w64_gui_input_req_t);
    default: return 0;
    }
}
SHZ_IPC_INLINE uint32_t shz_w64_gui_reply_size(uint32_t op)
{
    switch (op) {
    case SHZ_OP_W64_GUI_QUERY_VIEW: return sizeof(shz_w64_gui_view_info_t);
    case SHZ_OP_W64_GUI_FRAME_ACQUIRE: return sizeof(shz_w64_gui_acquire_reply_t);
    case SHZ_OP_W64_GUI_FRAME_READ: return sizeof(shz_w64_gui_read_reply_t);
    case SHZ_OP_W64_GUI_FRAME_RELEASE: case SHZ_OP_W64_GUI_CLOSE_VIEW: case SHZ_OP_W64_GUI_INPUT:
        return sizeof(shz_w64_gui_prefix_t);
    default: return 0;
    }
}

/* ------------------------------------------------------------------ header checks */
/* Core: request header. Owner/authority/allowlist is checked separately (shz_w64_owner.h). */
SHZ_IPC_INLINE int shz_w64_gui_req_hdr_check(const shz_msg_hdr_t *m, uint32_t channel_generation)
{
    const uint32_t need = m ? shz_w64_gui_req_size(m->opcode) : 0;
    if (!need)
        return SHZ_E_PROTO;
    if (m->flags != 0 || m->buffer_length || m->buffer_offset || m->payload_length != need)
        return SHZ_E_INVALID;
    if (!shz_w64_owner_id_valid(m->capability_id))
        return SHZ_E_DENIED;
    if (m->generation != channel_generation)
        return SHZ_E_STALE;
    return SHZ_OK;
}

/* Client: reply header for request (op, request_id, owner). Returns SHZ_OK when a full payload
 * follows, the server's negative status for a well-formed empty error reply, else SHZ_E_PROTO. */
SHZ_IPC_INLINE int shz_w64_gui_reply_hdr_check(const shz_msg_hdr_t *m, uint32_t op, uint64_t request_id, uint32_t owner_id)
{
    const uint32_t need = shz_w64_gui_reply_size(op);
    if (!m || !need || m->opcode != op || m->flags != SHZ_MSGF_REPLY || m->request_id != request_id ||
        m->capability_id != owner_id || m->buffer_length || m->buffer_offset)
        return SHZ_E_PROTO;
    if (m->status != SHZ_OK)
        return (m->payload_length == 0 && m->status < 0) ? m->status : SHZ_E_PROTO;
    return m->payload_length == need ? SHZ_OK : SHZ_E_PROTO;
}

/* ------------------------------------------------------------------ request validators (Core) */
SHZ_IPC_INLINE int shz_w64_gui_query_check(const void *payload, uint32_t channel_generation, shz_w64_gui_query_req_t *out)
{
    shz_w64_gui_query_req_t q;
    if (!payload || !out)
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&q, payload, sizeof q);
    if (q.size != sizeof q || q.version != SHZ_W64_GUI_VERSION || q.pid == 0 || q.reserved[0] || q.reserved[1])
        return SHZ_E_INVALID;
    if (q.expected_channel_generation != channel_generation)
        return SHZ_E_STALE;
    *out = q;
    return SHZ_OK;
}

/* Common prefix rules for a request of `op` (not QUERY_VIEW). */
SHZ_IPC_INLINE int shz_w64_gui_prefix_req_check(const shz_w64_gui_prefix_t *p, uint32_t op, uint32_t channel_generation)
{
    const uint32_t need = shz_w64_gui_req_size(op);
    if (!need || op == SHZ_OP_W64_GUI_QUERY_VIEW)
        return SHZ_E_PROTO;
    if (p->size != need || p->version != SHZ_W64_GUI_VERSION || p->pid == 0 || p->process_generation == 0 ||
        p->view_id == 0 || p->sequence == 0)
        return SHZ_E_INVALID;
    if (op != SHZ_OP_W64_GUI_FRAME_ACQUIRE && p->window_id == 0)
        return SHZ_E_INVALID;                       /* window 0 only selects for ACQUIRE */
    if ((op == SHZ_OP_W64_GUI_FRAME_READ || op == SHZ_OP_W64_GUI_FRAME_RELEASE) ? p->snapshot_id == 0
                                                                                : p->snapshot_id != 0)
        return SHZ_E_INVALID;
    if (p->expected_channel_generation != channel_generation)
        return SHZ_E_STALE;
    return SHZ_OK;
}

SHZ_IPC_INLINE int shz_w64_gui_acquire_check(const void *payload, uint32_t channel_generation, shz_w64_gui_acquire_req_t *out)
{
    shz_w64_gui_acquire_req_t a;
    int rc;
    if (!payload || !out)
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&a, payload, sizeof a);
    if ((rc = shz_w64_gui_prefix_req_check(&a.p, SHZ_OP_W64_GUI_FRAME_ACQUIRE, channel_generation)) != SHZ_OK)
        return rc;
    if ((a.flags & ~SHZ_W64_GUI_AF_ALL) || a.reserved)
        return SHZ_E_INVALID;
    *out = a;
    return SHZ_OK;
}

SHZ_IPC_INLINE int shz_w64_gui_read_check(const void *payload, uint32_t channel_generation, shz_w64_gui_read_req_t *out)
{
    shz_w64_gui_read_req_t r;
    int rc;
    if (!payload || !out)
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&r, payload, sizeof r);
    if ((rc = shz_w64_gui_prefix_req_check(&r.p, SHZ_OP_W64_GUI_FRAME_READ, channel_generation)) != SHZ_OK)
        return rc;
    if (r.reserved[0] || r.reserved[1] || r.length == 0 || r.length > SHZ_W64_GUI_CHUNK ||
        (r.offset & 3u) || (r.length & 3u))
        return SHZ_E_INVALID;
    *out = r;
    return SHZ_OK;
}

/* Core, after locating the held snapshot: overflow-safe range check against its byte_length. */
SHZ_IPC_INLINE int shz_w64_gui_read_range_check(uint32_t offset, uint32_t length, uint32_t byte_length)
{
    return (offset <= byte_length && length <= byte_length - offset) ? SHZ_OK : SHZ_E_RANGE;
}

/* RELEASE and CLOSE_VIEW: bare prefix. */
SHZ_IPC_INLINE int shz_w64_gui_prefix_only_check(const void *payload, uint32_t op, uint32_t channel_generation,
                                                 shz_w64_gui_prefix_t *out)
{
    shz_w64_gui_prefix_t p;
    int rc;
    if (!payload || !out || (op != SHZ_OP_W64_GUI_FRAME_RELEASE && op != SHZ_OP_W64_GUI_CLOSE_VIEW))
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&p, payload, sizeof p);
    if ((rc = shz_w64_gui_prefix_req_check(&p, op, channel_generation)) != SHZ_OK)
        return rc;
    *out = p;
    return SHZ_OK;
}

SHZ_IPC_INLINE int shz_w64_gui_input_check(const void *payload, uint32_t channel_generation, shz_w64_gui_input_req_t *out)
{
    shz_w64_gui_input_req_t in;
    int rc;
    if (!payload || !out)
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&in, payload, sizeof in);
    if ((rc = shz_w64_gui_prefix_req_check(&in.p, SHZ_OP_W64_GUI_INPUT, channel_generation)) != SHZ_OK)
        return rc;
    if (in.reserved || in.kind == 0 || in.kind > SHZ_W64_GUI_IN_KIND_MAX)
        return SHZ_E_INVALID;
    switch (in.kind) {
    case SHZ_W64_GUI_IN_KEY_DOWN: case SHZ_W64_GUI_IN_KEY_UP:
        if ((in.flags & ~(uint32_t)SHZ_W64_GUI_INF_EXTENDED) || in.key == 0 || in.key > 254u || in.scancode > 0xffu ||
            in.x || in.y)
            return SHZ_E_INVALID;
        break;
    case SHZ_W64_GUI_IN_CLOSE:
        if (in.flags || in.key || in.scancode || in.x || in.y)
            return SHZ_E_INVALID;
        break;
    default: /* pointer kinds */
        if (in.flags || in.key || in.scancode || in.x > SHZ_W64_GUI_COORD_LIMIT || in.x < -SHZ_W64_GUI_COORD_LIMIT ||
            in.y > SHZ_W64_GUI_COORD_LIMIT || in.y < -SHZ_W64_GUI_COORD_LIMIT)
            return SHZ_E_INVALID;
    }
    *out = in;
    return SHZ_OK;
}

/* ------------------------------------------------------------------ reply validators (client) */
/* Reply prefix must repeat the request tuple. ACQUIRE may resolve window 0 and must return a
 * new nonzero snapshot; READ/RELEASE echo the snapshot; INPUT/CLOSE echo snapshot 0. */
SHZ_IPC_INLINE int shz_w64_gui_prefix_reply_check(const shz_w64_gui_prefix_t *rep, const shz_w64_gui_prefix_t *req, uint32_t op)
{
    const uint32_t need = shz_w64_gui_reply_size(op);
    if (!need || op == SHZ_OP_W64_GUI_QUERY_VIEW || rep->size != need || rep->version != SHZ_W64_GUI_VERSION ||
        rep->pid != req->pid || rep->process_generation != req->process_generation || rep->view_id != req->view_id ||
        rep->expected_channel_generation != req->expected_channel_generation || rep->sequence != req->sequence)
        return SHZ_E_PROTO;
    if (op == SHZ_OP_W64_GUI_FRAME_ACQUIRE) {
        if (rep->window_id == 0 || (req->window_id && rep->window_id != req->window_id) || rep->snapshot_id == 0)
            return SHZ_E_PROTO;
    } else if (rep->window_id != req->window_id || rep->snapshot_id != req->snapshot_id) {
        return SHZ_E_PROTO;
    }
    return SHZ_OK;
}

SHZ_IPC_INLINE int shz_w64_gui_view_info_check(const void *payload, const shz_w64_gui_query_req_t *req,
                                               shz_w64_gui_view_info_t *out)
{
    shz_w64_gui_view_info_t v;
    if (!payload || !req || !out)
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&v, payload, sizeof v);
    if (v.size != sizeof v || v.version != SHZ_W64_GUI_VERSION || v.pid != req->pid || v.process_generation == 0 ||
        v.view_id == 0 || v.channel_generation != req->expected_channel_generation || v.reserved ||
        !(v.capabilities & SHZ_W64_GUI_VCAP_FRAME) || (v.capabilities & ~SHZ_W64_GUI_VCAP_ALL) ||
        v.max_width == 0 || v.max_width > SHZ_W64_GUI_MAX_WIDTH || v.max_height == 0 ||
        v.max_height > SHZ_W64_GUI_MAX_HEIGHT || v.max_frame_bytes == 0 ||
        (uint64_t)v.max_frame_bytes > (uint64_t)v.max_width * v.max_height * 4u ||
        v.max_chunk_bytes != SHZ_W64_GUI_CHUNK || v.snapshot_lease_ms == 0 ||
        v.snapshot_lease_ms > SHZ_W64_GUI_SNAPSHOT_LEASE_MS || v.snapshot_lease_ms <= SHZ_W64_GUI_TRANSFER_DEADLINE_MS)
        return SHZ_E_PROTO;
    *out = v;
    return SHZ_OK;
}

SHZ_IPC_INLINE int shz_w64_gui_acquire_reply_check(const void *payload, const shz_w64_gui_acquire_req_t *req,
                                                   const shz_w64_gui_view_info_t *view, shz_w64_gui_acquire_reply_t *out)
{
    shz_w64_gui_acquire_reply_t a;
    uint64_t bytes;
    if (!payload || !req || !view || !out)
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&a, payload, sizeof a);
    if (shz_w64_gui_prefix_reply_check(&a.p, &req->p, SHZ_OP_W64_GUI_FRAME_ACQUIRE) != SHZ_OK)
        return SHZ_E_PROTO;
    bytes = (uint64_t)a.width * 4u * a.height;
    if (a.width == 0 || a.width > view->max_width || a.height == 0 || a.height > view->max_height ||
        a.stride != a.width * 4u || bytes != a.byte_length || bytes > view->max_frame_bytes ||
        a.pixel_format != SHZ_W64_GUI_PF_BGRX32 || a.lease_ms == 0 || a.lease_ms > view->snapshot_lease_ms ||
        a.flags != req->flags)
        return SHZ_E_PROTO;
    *out = a;
    return SHZ_OK;
}

SHZ_IPC_INLINE int shz_w64_gui_read_reply_check(const void *payload, const shz_w64_gui_read_req_t *req,
                                                shz_w64_gui_read_reply_t *out)
{
    unsigned i;
    if (!payload || !req || !out)
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(out, payload, sizeof *out);
    if (shz_w64_gui_prefix_reply_check(&out->p, &req->p, SHZ_OP_W64_GUI_FRAME_READ) != SHZ_OK ||
        out->offset != req->offset || out->length != req->length || out->reserved[0] || out->reserved[1])
        return SHZ_E_PROTO;
    for (i = out->length; i < SHZ_W64_GUI_CHUNK; ++i)
        if (out->data[i])
            return SHZ_E_PROTO;
    return SHZ_OK;
}

/* RELEASE, CLOSE_VIEW and INPUT replies: bare prefix echo. */
SHZ_IPC_INLINE int shz_w64_gui_ack_reply_check(const void *payload, const shz_w64_gui_prefix_t *req, uint32_t op)
{
    shz_w64_gui_prefix_t p;
    if (!payload || !req || (op != SHZ_OP_W64_GUI_FRAME_RELEASE && op != SHZ_OP_W64_GUI_CLOSE_VIEW &&
                             op != SHZ_OP_W64_GUI_INPUT))
        return SHZ_E_PROTO;
    SHZ_IPC_MEMCPY(&p, payload, sizeof p);
    return shz_w64_gui_prefix_reply_check(&p, req, op);
}
#endif
