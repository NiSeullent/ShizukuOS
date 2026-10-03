/* SPDX-License-Identifier: GPL-2.0-only
 * NTW32 native Win64 GUI frame-pull client. Original code; stock Win98 imports only (SetLastError), no CRT.
 * Per process handle it keeps the server tuple (process generation, channel generation, view, window, snapshot,
 * input sequence). Every reply must repeat the exact tuple, sequence, offset and length before any byte is
 * published to the caller; a failed transport keeps the held tuple so a later RELEASE/CLOSE can retry. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include "ntw64.h"
#include "ntw64_gui.h"
#include "../../ntwrapper/vxd/bridge.h"
#include "../../shizukudos/abi/shz_w64_gui.h"

#define GUI_MAX 8u
struct gui_state {
    HANDLE handle;
    uint32_t pid, process_gen, channel_gen, next_seq, byte_length;
    uint64_t view_id, window_id, snapshot_id;
};
static struct gui_state gs[GUI_MAX];

static BOOL gfail(DWORD e) { SetLastError(e); return FALSE; }
static struct gui_state *find(HANDLE h)
{
    unsigned i;
    for (i = 0; h && i < GUI_MAX; ++i) if (gs[i].handle == h) return &gs[i];
    return 0;
}
static void prefix(shz_w64_gui_prefix_t *p, const struct gui_state *s, uint32_t size, uint64_t snap, uint32_t seq)
{
    shz_w64_gui_zero(p, sizeof *p);
    p->size = size; p->version = SHZ_W64_GUI_VERSION; p->pid = s->pid; p->process_generation = s->process_gen;
    p->window_id = s->window_id; p->view_id = s->view_id; p->snapshot_id = snap;
    p->expected_channel_generation = s->channel_gen; p->sequence = seq;
}
/* Reply prefix must repeat the request tuple; ACQUIRE with window 0 may return the selected window. */
static int same(const shz_w64_gui_prefix_t *q, const shz_w64_gui_prefix_t *r, uint32_t reply_size, int any_snap)
{
    return r->size == reply_size && r->version == SHZ_W64_GUI_VERSION && r->pid == q->pid &&
        r->process_generation == q->process_generation && r->view_id == q->view_id &&
        r->expected_channel_generation == q->expected_channel_generation && r->sequence == q->sequence &&
        (q->window_id ? r->window_id == q->window_id : r->window_id != 0) &&
        (any_snap ? r->snapshot_id != 0 : r->snapshot_id == q->snapshot_id);
}

BOOL WINAPI NtwQueryGui64(HANDLE process, NTW64_GUI_VIEW *view)
{
    shz_w64_gui_query_t q;
    shz_w64_gui_view_t v;
    uint8_t reply[SHZ_MSG_MAX_INLINE];
    int32_t st;
    struct gui_state *s = find(process);
    unsigned i;
    ntw64_info_t info;
    if (!view) return gfail(ERROR_INVALID_PARAMETER);
    if (s && s->view_id) return gfail(ERROR_BUSY);               /* one view per process: NtwCloseGui64 first */
    if (!NtwQuerySubsystem64(&info)) return FALSE;
    if (!(info.capabilities & SHZ_W64_CAP_GUI)) return gfail(ERROR_NOT_SUPPORTED);   /* no fallback */
    for (i = 0; !s && i < GUI_MAX; ++i) if (!gs[i].handle) s = &gs[i];
    if (!s) return gfail(ERROR_TOO_MANY_OPEN_FILES);
    shz_w64_gui_zero(&q, sizeof q);
    q.size = sizeof q; q.version = SHZ_W64_GUI_VERSION; q.expected_channel_generation = info.generation;
    if (!ntw64_gui_transact(process, SHZ_OP_W64_GUI_QUERY_VIEW, (uint8_t *)&q, sizeof q, reply, sizeof v, &st))
        return FALSE;
    shz_w64_gui_copy(&v, reply, sizeof v);
    if (v.size != sizeof v || v.version != SHZ_W64_GUI_VERSION || v.pid != q.pid || !v.view_id ||
        !shz_w64_gui_display_valid(v.display_backend) ||
        v.channel_generation != q.expected_channel_generation || !(v.capabilities & SHZ_W64_CAP_GUI) ||
        v.max_chunk_bytes != SHZ_W64_GUI_CHUNK || !v.max_width || v.max_width > SHZ_W64_GUI_MAX_WIDTH ||
        !v.max_height || v.max_height > SHZ_W64_GUI_MAX_HEIGHT || v.max_frame_bytes > SHZ_W64_GUI_MAX_FRAME_BYTES)
        return gfail(ERROR_INVALID_DATA);
    shz_w64_gui_zero(s, sizeof *s);
    s->handle = process; s->pid = v.pid; s->process_gen = v.process_generation; s->channel_gen = v.channel_generation;
    s->view_id = v.view_id; s->next_seq = 1;
    view->view_id = v.view_id; view->default_window_id = v.default_window_id; view->max_width = v.max_width;
    view->max_height = v.max_height; view->max_frame_bytes = v.max_frame_bytes; view->max_chunk = v.max_chunk_bytes;
    view->lease_ms = v.snapshot_lease_ms;
    view->display_backend = v.display_backend;   /* SCANOUT or HOSTED_PRIVATE; never acceleration */
    return TRUE;
}

BOOL WINAPI NtwAcquireGuiFrame64(HANDLE process, NTW64_GUI_FRAME *frame)
{
    struct gui_state *s = find(process);
    shz_w64_gui_acquire_t a;
    shz_w64_gui_snapshot_t o;
    uint8_t reply[SHZ_MSG_MAX_INLINE];
    int32_t st;
    if (!s || !s->view_id) return gfail(NTW64_ERROR_INVALID_HANDLE);
    if (!frame) return gfail(ERROR_INVALID_PARAMETER);
    if (s->snapshot_id) return gfail(ERROR_BUSY);                /* release the held snapshot first */
    shz_w64_gui_zero(&a, sizeof a);
    prefix(&a.p, s, sizeof a, 0, 0);
    a.flags = SHZ_W64_GUI_ACQ_CLIENT_ONLY;
    if (!ntw64_gui_transact(process, SHZ_OP_W64_GUI_FRAME_ACQUIRE, (uint8_t *)&a, sizeof a, reply, sizeof o, &st))
        return FALSE;
    shz_w64_gui_copy(&o, reply, sizeof o);
    if (!same(&a.p, &o.p, sizeof o, 1) || o.pixel_format != SHZ_W64_GUI_FMT_BGRX32 || o.stride != o.width * 4u ||
        !shz_w64_gui_frame_bytes(o.width, o.height) || o.byte_length != shz_w64_gui_frame_bytes(o.width, o.height) ||
        o.flags)
        return gfail(ERROR_INVALID_DATA);
    s->window_id = o.p.window_id; s->snapshot_id = o.p.snapshot_id; s->byte_length = o.byte_length;
    frame->snapshot_id = o.p.snapshot_id; frame->window_id = o.p.window_id; frame->width = o.width;
    frame->height = o.height; frame->stride = o.stride; frame->byte_length = o.byte_length;
    frame->pixel_format = o.pixel_format; frame->pixels_crc32 = o.pixels_crc32;
    return TRUE;
}

BOOL WINAPI NtwReadGuiFrame64(HANDLE process, ULONGLONG snapshot_id, DWORD offset, DWORD length, void *out)
{
    struct gui_state *s = find(process);
    shz_w64_gui_read_t r;
    shz_w64_gui_chunk_t o;
    uint8_t reply[SHZ_MSG_MAX_INLINE];
    int32_t st;
    uint32_t i;
    if (!s || !s->snapshot_id || snapshot_id != s->snapshot_id) return gfail(NTW64_ERROR_INVALID_HANDLE);
    if (!out || shz_w64_gui_read_bounds(s->byte_length, offset, length)) return gfail(ERROR_INVALID_PARAMETER);
    shz_w64_gui_zero(&r, sizeof r);
    prefix(&r.p, s, sizeof r, s->snapshot_id, 0);
    r.offset = offset; r.length = length;
    if (!ntw64_gui_transact(process, SHZ_OP_W64_GUI_FRAME_READ, (uint8_t *)&r, sizeof r, reply, sizeof o, &st))
        return FALSE;
    shz_w64_gui_copy(&o, reply, sizeof o);
    if (!same(&r.p, &o.r.p, sizeof o, 0) || o.r.offset != offset || o.r.length != length || o.r.reserved[0] ||
        o.r.reserved[1])
        return gfail(ERROR_INVALID_DATA);
    for (i = length; i < SHZ_W64_GUI_CHUNK; ++i) if (o.data[i]) return gfail(ERROR_INVALID_DATA);   /* zero tail */
    shz_w64_gui_copy(out, o.data, length);
    return TRUE;
}

static BOOL simple(HANDLE process, struct gui_state *s, uint32_t opcode, uint64_t snap)
{
    shz_w64_gui_prefix_t p, o;
    uint8_t reply[SHZ_MSG_MAX_INLINE];
    int32_t st;
    prefix(&p, s, sizeof p, snap, 0);
    if (!ntw64_gui_transact(process, opcode, (uint8_t *)&p, sizeof p, reply, sizeof o, &st)) return FALSE;
    shz_w64_gui_copy(&o, reply, sizeof o);
    return same(&p, &o, sizeof o, 0) ? TRUE : gfail(ERROR_INVALID_DATA);
}

BOOL WINAPI NtwReleaseGuiFrame64(HANDLE process, ULONGLONG snapshot_id)
{
    struct gui_state *s = find(process);
    if (!s || !snapshot_id || snapshot_id != s->snapshot_id) return gfail(NTW64_ERROR_INVALID_HANDLE);
    if (!simple(process, s, SHZ_OP_W64_GUI_FRAME_RELEASE, snapshot_id)) return FALSE;   /* tuple retained */
    s->snapshot_id = 0; s->byte_length = 0;
    return TRUE;
}

BOOL WINAPI NtwSendGuiInput64(HANDLE process, const NTW64_GUI_INPUT *in, DWORD *sequence)
{
    struct gui_state *s = find(process);
    shz_w64_gui_input_t e;
    shz_w64_gui_prefix_t o;
    uint8_t reply[SHZ_MSG_MAX_INLINE];
    int32_t st;
    if (!s || !s->view_id || !s->window_id) return gfail(NTW64_ERROR_INVALID_HANDLE);
    if (!in || in->kind < SHZ_W64_GUI_IN_MOVE || in->kind > SHZ_W64_GUI_IN_CLOSE || (in->flags & ~SHZ_W64_GUI_INF_KNOWN))
        return gfail(ERROR_INVALID_PARAMETER);
    if (s->next_seq == 0) return gfail(ERROR_TOO_MANY_OPEN_FILES);   /* sequence space exhausted: never wraps */
    shz_w64_gui_zero(&e, sizeof e);
    prefix(&e.p, s, sizeof e, 0, s->next_seq);
    e.kind = in->kind; e.flags = in->flags; e.x = in->x; e.y = in->y; e.key = in->key; e.scancode = in->scancode;
    e.clock_ms = in->clock_ms;
    if (!ntw64_gui_transact(process, SHZ_OP_W64_GUI_INPUT, (uint8_t *)&e, sizeof e, reply, sizeof o, &st)) {
        /* Transport failure: the same sequence is retried later (server ACKs an identical duplicate once). */
        return FALSE;
    }
    shz_w64_gui_copy(&o, reply, sizeof o);
    if (!same(&e.p, &o, sizeof o, 0)) return gfail(ERROR_INVALID_DATA);
    if (sequence) *sequence = s->next_seq;
    ++s->next_seq;
    return TRUE;
}

BOOL WINAPI NtwCloseGui64(HANDLE process)
{
    struct gui_state *s = find(process);
    if (!s) return gfail(NTW64_ERROR_INVALID_HANDLE);
    if (s->snapshot_id && !NtwReleaseGuiFrame64(process, s->snapshot_id)) return FALSE;   /* retained for retry */
    if (!simple(process, s, SHZ_OP_W64_GUI_CLOSE_VIEW, 0)) return FALSE;
    shz_w64_gui_zero(s, sizeof *s);
    return TRUE;
}
