/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 WIN64 native GUI frame-pull service (see w64_gui_service.h, abi/shz_w64_gui.h). Original code.
 *
 * Authority: the subject (slot pid/generation, kernel process_t, creator capability id, channel generation) is
 * supplied by subsys64 from its own tables. A view binds to all of them; every request re-checks the binding,
 * the process liveness, the owned top-level window (w->pid, w->q->proc == subject process, gfx_auth_window on that
 * actual subject). Window 0 is accepted only by ACQUIRE and selects the topmost visible owned top-level window,
 * never the desktop or another process's window.
 *
 * Frames: ACQUIRE copies the window's client surface plus visible owned child surfaces (bottom-to-top) under
 * gfx_lock into private page-allocated storage; READ serves 128-byte slices of that immutable copy only; the
 * snapshot lives until RELEASE, CLOSE_VIEW, revoke or the advertised lease expiry. One view and one held
 * snapshot per process. Identifiers are monotonic 64-bit and never wrap (exhaustion refuses).
 *
 * Input: per-view monotonic sequence; an identical duplicate of the last accepted event ACKs without applying
 * twice. Events are posted into the owning thread's existing input queue (gq_post_input) with the same message
 * layout gfx_input.c produces; CLOSE posts WM_CLOSE to the owned window. Held keys/buttons are released on revoke.
 *
 * Enablement: served only where the caller identity is not application-chosen: the standalone profile (in-kernel
 * loopback client, no foreign peer) or the supervised profile while the Supervisor attests (SHZ_HC_CHANNEL_ATTESTED,
 * SHZ_CHAN_ATTEST_W64_DERIVED_OWNER, current channel generation) that the NTWRAP9X VxD built with NTWV_W64_DERIVED_OWNER
 * (ntwrapper/vxd/w64_owner.c) stamps capability_id from the VWIN32 DIOC tagProcess + system VM + channel generation;
 * every op then requires shz_w64_gui_subject_ok(.., 1, attested). Unattested: SHZ_E_DENIED.
 * There is no anonymous enable: the former SHZ_W64_GUI_DEV_ANON flag is a build error.
 * Display: QUERY_VIEW first runs the lazy gfx_fb_init() (authorized+attested only), then is refused unless gfx_fb runs
 * a real scanout backend or the w64-hosted private buffer. */
#include "w64_gui_service.h"
#include "gfx_auth.h"

#define W64G_MAX_VIEWS 4u
#define W64G_WM_CLOSE 0x0010u
#define W64G_WM_KEYDOWN 0x0100u
#define W64G_WM_KEYUP 0x0101u
#define W64G_WM_MOUSEMOVE 0x0200u
#define W64G_WM_LBUTTONDOWN 0x0201u
#define W64G_WM_LBUTTONUP 0x0202u
#define W64G_WM_RBUTTONDOWN 0x0204u
#define W64G_WM_RBUTTONUP 0x0205u
#define W64G_MK_LBUTTON 1u
#define W64G_MK_RBUTTON 2u
#define W64G_MK_SHIFT 4u
#define W64G_MK_CONTROL 8u
#define W64G_MAX_DEPTH 8

typedef struct {
    int used, closed;
    uint32_t pid, slot_gen, channel_gen, owner_cap;
    process_t *proc;
    uint64_t view_id, window_id;
    uint32_t *snap;                                 /* immutable copy, snap_alloc bytes from gfx_pages_alloc */
    uint64_t snap_alloc, snap_id, last_released, lease_deadline;
    uint32_t width, height, bytes, crc;
    uint32_t in_seq;                                /* last accepted input sequence */
    shz_w64_gui_input_t last_in;                    /* for idempotent duplicate ACK */
    uint32_t buttons;                               /* MK_LBUTTON/MK_RBUTTON held through this view */
    uint32_t keys[8];                               /* VKs held down through this view */
} w64g_view_t;

static w64g_view_t views[W64G_MAX_VIEWS];
static uint64_t next_view_id = 1, next_snap_id = 1;
static uint64_t hosted_presents;

#if defined(SHZ_W64_GUI_DEV_ANON)
#error "SHZ_W64_GUI_DEV_ANON removed: anonymous Win98 callers are never served; build SHZ_W64_GUI_DERIVED_OWNER + NTWV_W64_DERIVED_OWNER VxD"
#endif
/* Supervised profile: always derived-owner + attested channel (wire b5); -DSHZ_W64_GUI_DERIVED_OWNER is redundant. */
#if !defined(SHZ_STANDALONE)
#define W64G_DERIVED_REQUIRED 1
#else
#define W64G_DERIVED_REQUIRED 0
#endif

int w64_gui_enabled(void)
{
#if defined(SHZ_STANDALONE)
    return 1;
#else
    return subsys64_channel_attested();
#endif
}

/* ---------------------------------------------------------------- hosted software display */
static int hosted_probe(gfx_fb_t *fb)
{
    if (!w64_gui_enabled()) return -1;
    fb->lfb = 0;
    fb->lfb_pa = 0;
    kprintf("K64 gfx: hosted software display %ux%u (no scanout; W64 GUI frame pull only)\n", fb->width, fb->height);
    return 0;
}
static void hosted_present(int x, int y, int w, int h) { (void)x; (void)y; (void)w; (void)h; ++hosted_presents; }
const gfx_backend_t gfx_backend_w64_hosted = { "w64-hosted", SHZ_GPU_BACKEND_NONE, hosted_probe, hosted_present };

/* 0 when no real display exists (gfx_fb_init failed / NO_SUCH_DEVICE): the GUI route then refuses, no fallback. */
static uint32_t display_backend(void)
{
    if (!g_fb.ready || !g_fb.back || !g_fb.backend || !g_fb.width || !g_fb.height) return 0;
    if (g_fb.backend == &gfx_backend_w64_hosted) return SHZ_W64_GUI_DISPLAY_HOSTED_PRIVATE;
    return g_fb.backend->id != SHZ_GPU_BACKEND_NONE ? SHZ_W64_GUI_DISPLAY_SCANOUT : 0u;
}

/* ---------------------------------------------------------------- view table */
static void snap_free(w64g_view_t *v)
{
    if (v->snap) gfx_pages_free(v->snap, v->snap_alloc);
    v->snap = 0;
    v->snap_alloc = 0;
    v->snap_id = 0;
    v->bytes = v->width = v->height = v->crc = 0;
}

static int32_t client_wh(const gwin_t *w, int32_t *cw, int32_t *ch)
{
    *cw = w->w - w->ncl - w->ncr;
    *ch = w->h - w->nct - w->ncb;
    return *cw > 0 && *ch > 0;
}

/* Lock held. The window must be a live, visible, top-level window of exactly this subject process. */
static gwin_t *owned_window(process_t *p, uint64_t id)
{
    gwin_t *w;
    if (!g_win || !p || !id) return 0;
    w = wm_lookup(id);
    if (!w || w == wm_desktop() || w->destroying || w->msgonly || w->parent != wm_desktop()) return 0;
    if (w->pid != (uint32_t)p->pid || !w->q || w->q->proc != p || !gfx_auth_window(p, w) || !wm_is_visible(w)) return 0;
    return w;
}

/* Lock held: topmost visible owned top-level window, 0 when none. */
static gwin_t *first_owned(process_t *p)
{
    gwin_t *d, *w;
    if (!g_win || !(d = wm_desktop())) return 0;
    for (w = d->child; w; w = w->next)
        if (owned_window(p, w->handle) == w) return w;
    return 0;
}

static void release_held(w64g_view_t *v)
{
    gwin_t *w;
    unsigned k;
    if (!v->buttons && !(v->keys[0] | v->keys[1] | v->keys[2] | v->keys[3] | v->keys[4] | v->keys[5] | v->keys[6] |
                         v->keys[7])) return;
    if (g_win) {
        mutex_lock(&gfx_lock);
        w = (v->proc && v->window_id) ? owned_window(v->proc, v->window_id) : 0;
        if (w) {
            shz_msg_t m;
            memset(&m, 0, sizeof m);
            m.hwnd = w->handle;
            m.time = gq_time();
            m.pad0 = SHZ_MSGF_INPUT;
            for (k = 0; k < 256; ++k)
                if (v->keys[k >> 5] & (1u << (k & 31))) {
                    m.message = W64G_WM_KEYUP;
                    m.wparam = k;
                    m.lparam = (int64_t)(uint64_t)(1u | (1u << 30) | (1u << 31));
                    (void)gq_post_input(w->q, &m, 0);
                }
            if (v->buttons & W64G_MK_LBUTTON) { m.message = W64G_WM_LBUTTONUP; m.wparam = 0; m.lparam = 0; m.pad0 |= SHZ_MSGF_MOUSE;
                                                (void)gq_post_input(w->q, &m, 0); }
            if (v->buttons & W64G_MK_RBUTTON) { m.message = W64G_WM_RBUTTONUP; m.wparam = 0; m.lparam = 0; m.pad0 |= SHZ_MSGF_MOUSE;
                                                (void)gq_post_input(w->q, &m, 0); }
        }
        mutex_unlock(&gfx_lock);
    }
    v->buttons = 0;
    memset(v->keys, 0, sizeof v->keys);
}

static void view_revoke(w64g_view_t *v)
{
    release_held(v);
    snap_free(v);
    memset(v, 0, sizeof *v);
}

void w64_gui_revoke(uint32_t pid, uint32_t slot_gen)
{
    unsigned i;
    for (i = 0; i < W64G_MAX_VIEWS; ++i)
        if (views[i].used && views[i].pid == pid && views[i].slot_gen == slot_gen) view_revoke(&views[i]);
}

void w64_gui_revoke_all(void)
{
    unsigned i;
    for (i = 0; i < W64G_MAX_VIEWS; ++i)
        if (views[i].used) view_revoke(&views[i]);
}

/* Lazy housekeeping on every request: channel epoch change and lease expiry. */
static void expire(uint32_t channel_gen)
{
    const uint64_t now = ticks_now();
    unsigned i;
    for (i = 0; i < W64G_MAX_VIEWS; ++i) {
        w64g_view_t *v = &views[i];
        if (!v->used) continue;
        if (v->channel_gen != channel_gen) { view_revoke(v); continue; }
        if (v->snap && now >= v->lease_deadline) snap_free(v);
    }
}

static w64g_view_t *view_of(const w64_gui_subject_t *s)
{
    unsigned i;
    for (i = 0; i < W64G_MAX_VIEWS; ++i)
        if (views[i].used && views[i].pid == s->pid && views[i].slot_gen == s->slot_gen) return &views[i];
    return 0;
}

static int subject_live(const w64_gui_subject_t *s)
{
    process_t *p = s->proc;
    return p && p->used && !p->terminated && (uint32_t)p->pid == s->pid;
}

/* ---------------------------------------------------------------- capture */
/* Lock held: copy `w`'s client surface at (ox, oy) of the destination, then its visible owned children from the
 * bottom of the z-order up. */
static void copy_tree(process_t *p, gwin_t *w, uint32_t *dst, int32_t dw, int32_t dh, int32_t ox, int32_t oy,
                      int32_t bx, int32_t by, int depth)
{
    int32_t cw, ch, y;
    gwin_t *c, *last = 0;
    if (!client_wh(w, &cw, &ch)) return;
    if (w->surf && w->sw > 0 && w->sh > 0) {
        const int32_t sw = cw < w->sw ? cw : w->sw, sh = ch < w->sh ? ch : w->sh;
        for (y = 0; y < sh; ++y) {
            const int32_t ty = oy + y;
            int32_t x0 = ox, x1 = ox + sw;
            if (ty < 0 || ty >= dh) continue;
            if (x0 < 0) x0 = 0;
            if (x1 > dw) x1 = dw;
            if (x1 > x0)
                memcpy(dst + (uint64_t)ty * (uint32_t)dw + x0, w->surf + (uint64_t)y * (uint32_t)w->sw + (x0 - ox),
                       (uint64_t)(x1 - x0) * 4u);
        }
    }
    if (depth >= W64G_MAX_DEPTH) return;
    for (c = w->child; c; c = c->next) last = c;
    for (c = last; c; c = c->prev) {
        int32_t sx, sy;
        if (c->destroying || c->msgonly || !(c->style & SHZ_WS_VISIBLE) || (c->style & SHZ_WS_MINIMIZE) ||
            c->pid != (uint32_t)p->pid || !gfx_auth_window(p, c)) continue;
        wm_client_origin(c, &sx, &sy);
        copy_tree(p, c, dst, dw, dh, sx - bx, sy - by, bx, by, depth + 1);
    }
}

static int32_t capture(w64g_view_t *v, gwin_t **unused, uint64_t window_id, uint64_t *selected)
{
    int32_t cw = 0, ch = 0, attempt;
    (void)unused;
    for (attempt = 0; attempt < 2; ++attempt) {
        uint32_t bytes;
        uint64_t alloc;
        uint32_t *buf;
        gwin_t *w;
        int32_t bx, by;
        mutex_lock(&gfx_lock);
        w = window_id ? owned_window(v->proc, window_id) : first_owned(v->proc);
        if (!w || !client_wh(w, &cw, &ch)) { mutex_unlock(&gfx_lock); return SHZ_E_NOENT; }
        mutex_unlock(&gfx_lock);
        if ((uint32_t)cw > SHZ_W64_GUI_MAX_WIDTH || (uint32_t)ch > SHZ_W64_GUI_MAX_HEIGHT) return SHZ_E_RANGE;
        bytes = shz_w64_gui_frame_bytes((uint32_t)cw, (uint32_t)ch);
        alloc = ((uint64_t)bytes + 4095u) & ~4095ull;
        buf = gfx_pages_alloc(alloc);              /* zeroed; outside gfx_lock */
        if (!buf) return SHZ_E_NOMEM;
        mutex_lock(&gfx_lock);
        w = window_id ? owned_window(v->proc, window_id) : first_owned(v->proc);
        if (w) {
            int32_t nw, nh;
            if (client_wh(w, &nw, &nh) && nw == cw && nh == ch) {
                wm_client_origin(w, &bx, &by);
                copy_tree(v->proc, w, buf, cw, ch, 0, 0, bx, by, 0);
                *selected = w->handle;
                mutex_unlock(&gfx_lock);
                snap_free(v);
                v->snap = buf;
                v->snap_alloc = alloc;
                v->width = (uint32_t)cw;
                v->height = (uint32_t)ch;
                v->bytes = bytes;
                v->crc = shz_w64_gui_crc32(0, buf, bytes);
                return SHZ_OK;
            }
        }
        mutex_unlock(&gfx_lock);
        gfx_pages_free(buf, alloc);
        if (!w) return SHZ_E_NOENT;               /* destroyed meanwhile; resized: retry once */
    }
    return SHZ_E_BUSY;
}

/* ---------------------------------------------------------------- input */
static int32_t inject(w64g_view_t *v, const shz_w64_gui_input_t *in)
{
    gwin_t *w, *t;
    shz_msg_t m;
    int32_t cw, ch, sx, sy;
    int32_t st = STATUS_SUCCESS;
    const uint32_t mods = ((in->flags & SHZ_W64_GUI_INF_SHIFT) ? W64G_MK_SHIFT : 0) |
                          ((in->flags & SHZ_W64_GUI_INF_CTRL) ? W64G_MK_CONTROL : 0);
    mutex_lock(&gfx_lock);
    w = owned_window(v->proc, v->window_id);
    if (!w || !client_wh(w, &cw, &ch)) { mutex_unlock(&gfx_lock); return SHZ_E_NOENT; }
    memset(&m, 0, sizeof m);
    m.time = gq_time();
    m.pad0 = SHZ_MSGF_INPUT;
    m.pad1 = 0;
    switch (in->kind) {
    case SHZ_W64_GUI_IN_CLOSE:
        st = gq_post(w->q, w->handle, W64G_WM_CLOSE, 0, 0);
        mutex_unlock(&gfx_lock);
        return st == STATUS_SUCCESS ? SHZ_OK : SHZ_E_QUEUE_FULL;
    case SHZ_W64_GUI_IN_KEYDOWN: case SHZ_W64_GUI_IN_KEYUP: {
        const int up = in->kind == SHZ_W64_GUI_IN_KEYUP;
        t = w->q->focus ? wm_lookup(w->q->focus) : 0;
        if (!t || !wm_is_descendant(w, t) || !gfx_auth_window(v->proc, t)) t = w;   /* focus never leaves the view */
        m.hwnd = t->handle;
        m.message = up ? W64G_WM_KEYUP : W64G_WM_KEYDOWN;
        m.wparam = in->key;
        m.lparam = (int64_t)(uint64_t)(1u | ((in->scancode & 0x1ffu) << 16) | (up ? (1u << 30) | (1u << 31) : 0));
        st = gq_post_input(w->q, &m, 0);
        if (st == STATUS_SUCCESS) {
            if (up) v->keys[in->key >> 5] &= ~(1u << (in->key & 31));
            else v->keys[in->key >> 5] |= 1u << (in->key & 31);
        }
        break;
    }
    default: {
        uint32_t msg = W64G_WM_MOUSEMOVE, held = v->buttons;
        if (in->x < 0 || in->y < 0 || in->x >= cw || in->y >= ch) { mutex_unlock(&gfx_lock); return SHZ_E_RANGE; }
        if (in->kind == SHZ_W64_GUI_IN_LDOWN) { msg = W64G_WM_LBUTTONDOWN; held |= W64G_MK_LBUTTON; }
        else if (in->kind == SHZ_W64_GUI_IN_LUP) { msg = W64G_WM_LBUTTONUP; held &= ~W64G_MK_LBUTTON; }
        else if (in->kind == SHZ_W64_GUI_IN_RDOWN) { msg = W64G_WM_RBUTTONDOWN; held |= W64G_MK_RBUTTON; }
        else if (in->kind == SHZ_W64_GUI_IN_RUP) { msg = W64G_WM_RBUTTONUP; held &= ~W64G_MK_RBUTTON; }
        wm_client_origin(w, &sx, &sy);
        sx += in->x;
        sy += in->y;
        t = wm_input_hit(sx, sy);                   /* deepest window at the point; must stay inside this view */
        if (!t || !wm_is_descendant(w, t) || !gfx_auth_window(v->proc, t)) t = w;
        m.hwnd = t->handle;
        m.message = msg;
        m.wparam = held | mods;
        m.lparam = (int64_t)(uint64_t)(((uint32_t)(uint16_t)sx) | ((uint32_t)(uint16_t)sy << 16));  /* screen, like gfx_input.c */
        m.pt.x = sx;
        m.pt.y = sy;
        m.pad0 |= SHZ_MSGF_MOUSE;
        st = gq_post_input(w->q, &m, msg == W64G_WM_MOUSEMOVE);
        if (st == STATUS_SUCCESS) v->buttons = held;
    }
    }
    mutex_unlock(&gfx_lock);
    return st == STATUS_SUCCESS ? SHZ_OK : SHZ_E_QUEUE_FULL;
}

/* ---------------------------------------------------------------- request handling */
static void fill_prefix(shz_w64_gui_prefix_t *o, const w64g_view_t *v, uint32_t size, uint32_t seq)
{
    memset(o, 0, sizeof *o);
    o->size = size;
    o->version = SHZ_W64_GUI_VERSION;
    o->pid = v->pid;
    o->process_generation = v->slot_gen;
    o->window_id = v->window_id;
    o->view_id = v->view_id;
    o->snapshot_id = v->snap_id;
    o->expected_channel_generation = v->channel_gen;
    o->sequence = seq;
}

/* Common prefix validation against the view. Window 0 only when `allow_window0`. */
static int32_t check_prefix(const shz_w64_gui_prefix_t *p, uint32_t size, const w64_gui_subject_t *s, w64g_view_t **out,
                            int allow_window0)
{
    w64g_view_t *v;
    if (p->size != size || p->version != SHZ_W64_GUI_VERSION || p->pid != s->pid) return SHZ_E_INVALID;
    if (p->process_generation != s->slot_gen || p->expected_channel_generation != s->channel_gen) return SHZ_E_STALE;
    v = view_of(s);
    if (!v || !p->view_id || p->view_id != v->view_id) return SHZ_E_STALE;
    if (!shz_w64_gui_subject_ok(v->owner_cap, s->request_cap, W64G_DERIVED_REQUIRED, s->channel_attested) || v->proc != s->proc)
        return SHZ_E_DENIED;
    if (v->closed) return SHZ_E_STALE;
    if (!p->window_id ? !allow_window0 : (v->window_id && p->window_id != v->window_id)) return SHZ_E_DENIED;
    *out = v;
    return SHZ_OK;
}

int32_t w64_gui_handle(uint32_t opcode, const uint8_t *payload, uint32_t length, const w64_gui_subject_t *s,
                       uint8_t *reply, uint16_t *reply_len)
{
    w64g_view_t *v = 0;
    int32_t st;
    *reply_len = 0;
    if (!w64_gui_enabled()) {
        if (W64G_DERIVED_REQUIRED) w64_gui_revoke_all();          /* attestation gone: no view outlives it */
        return W64G_DERIVED_REQUIRED ? SHZ_E_DENIED : SHZ_E_UNSUPPORTED;
    }
    if (!shz_w64_gui_request_size(opcode)) return SHZ_E_UNSUPPORTED;
    if (!payload || length != shz_w64_gui_request_size(opcode)) return SHZ_E_INVALID;
    if (!s) return SHZ_E_NOENT;
    expire(s->channel_gen);
    if (!shz_w64_gui_subject_ok(s->owner_cap, s->request_cap, W64G_DERIVED_REQUIRED, s->channel_attested))
        return SHZ_E_DENIED;                                       /* not the slot's creator endpoint */

    if (opcode == SHZ_OP_W64_GUI_QUERY_VIEW) {
        shz_w64_gui_query_t q;
        shz_w64_gui_view_t o;
        unsigned i;
        memcpy(&q, payload, sizeof q);
        if (q.size != sizeof q || q.version != SHZ_W64_GUI_VERSION || q.pid != s->pid || q.reserved[0] || q.reserved[1])
            return SHZ_E_INVALID;
        if (q.expected_channel_generation != s->channel_gen) return SHZ_E_STALE;
        if (!subject_live(s)) return SHZ_E_NOENT;
        if (!display_backend()) {
            /* Authorized + attested QUERY performs the real lazy display init (GOP grant, else the w64-hosted
             * private buffer) instead of racing the remote app's first USER/GDI call. Still no fallback: a
             * genuine refusal stays UNSUPPORTED, an allocation failure NOMEM. No window yet -> window 0 below. */
            const int st_init = gfx_fb_init();
            if (st_init == STATUS_NO_MEMORY) return SHZ_E_NOMEM;
            if (st_init || !display_backend()) return SHZ_E_UNSUPPORTED;
        }
        if ((v = view_of(s)) != 0) {
            if (!v->closed) return SHZ_E_BUSY;     /* one view per process; CLOSE_VIEW first */
            view_revoke(v);
        }
        for (i = 0; i < W64G_MAX_VIEWS && !v; ++i)
            if (!views[i].used) v = &views[i];
        if (!v) return SHZ_E_NOMEM;
        if (next_view_id == UINT64_MAX) return SHZ_E_NOMEM;       /* retire instead of wrapping */
        memset(v, 0, sizeof *v);
        v->used = 1;
        v->pid = s->pid;
        v->slot_gen = s->slot_gen;
        v->channel_gen = s->channel_gen;
        v->owner_cap = s->owner_cap;
        v->proc = s->proc;
        v->view_id = next_view_id++;
        memset(&o, 0, sizeof o);
        o.size = sizeof o;
        o.version = SHZ_W64_GUI_VERSION;
        o.pid = s->pid;
        o.process_generation = s->slot_gen;
        o.view_id = v->view_id;
        o.channel_generation = s->channel_gen;
        o.capabilities = SHZ_W64_CAP_GUI;
        o.display_backend = display_backend();
        o.max_width = SHZ_W64_GUI_MAX_WIDTH;
        o.max_height = SHZ_W64_GUI_MAX_HEIGHT;
        o.max_frame_bytes = SHZ_W64_GUI_MAX_FRAME_BYTES;
        o.max_chunk_bytes = SHZ_W64_GUI_CHUNK;
        o.snapshot_lease_ms = SHZ_W64_GUI_LEASE_MS;
        if (g_win) {
            gwin_t *w;
            mutex_lock(&gfx_lock);
            w = first_owned(s->proc);
            o.default_window_id = w ? w->handle : 0;
            mutex_unlock(&gfx_lock);
        }
        memcpy(reply, &o, sizeof o);
        *reply_len = sizeof o;
        return SHZ_OK;
    }

    if (opcode == SHZ_OP_W64_GUI_CLOSE_VIEW) {
        shz_w64_gui_prefix_t p, o;
        memcpy(&p, payload, sizeof p);
        if (p.size != sizeof p || p.version != SHZ_W64_GUI_VERSION || p.pid != s->pid || p.snapshot_id) return SHZ_E_INVALID;
        if (p.process_generation != s->slot_gen || p.expected_channel_generation != s->channel_gen) return SHZ_E_STALE;
        v = view_of(s);
        if (!v || p.view_id != v->view_id) return SHZ_E_STALE;
        if (!shz_w64_gui_subject_ok(v->owner_cap, s->request_cap, W64G_DERIVED_REQUIRED, s->channel_attested)) return SHZ_E_DENIED;
        if (!v->closed) { release_held(v); snap_free(v); v->closed = 1; }   /* the app window stays as it is */
        fill_prefix(&o, v, sizeof o, p.sequence);
        o.window_id = p.window_id;
        memcpy(reply, &o, sizeof o);
        *reply_len = sizeof o;
        return SHZ_OK;
    }

    if (!subject_live(s)) return SHZ_E_NOENT;

    if (opcode == SHZ_OP_W64_GUI_FRAME_ACQUIRE) {
        shz_w64_gui_acquire_t a;
        shz_w64_gui_snapshot_t o;
        uint64_t selected = 0;
        memcpy(&a, payload, sizeof a);
        if ((st = check_prefix(&a.p, sizeof a, s, &v, 1)) != SHZ_OK) return st;
        if (a.p.snapshot_id || a.reserved || (a.flags & ~SHZ_W64_GUI_ACQ_CLIENT_ONLY)) return SHZ_E_INVALID;
        if (v->snap) return SHZ_E_BUSY;            /* one held snapshot per view: RELEASE first */
        if (next_snap_id == UINT64_MAX) return SHZ_E_NOMEM;
        if ((st = capture(v, 0, a.p.window_id ? a.p.window_id : v->window_id, &selected)) != SHZ_OK) return st;
        if (v->window_id && selected != v->window_id) { snap_free(v); return SHZ_E_DENIED; }
        v->window_id = selected;
        v->snap_id = next_snap_id++;
        v->lease_deadline = ticks_now() + SHZ_W64_GUI_LEASE_MS;
        memset(&o, 0, sizeof o);
        fill_prefix(&o.p, v, sizeof o, a.p.sequence);
        o.width = v->width;
        o.height = v->height;
        o.stride = v->width * 4u;
        o.byte_length = v->bytes;
        o.pixel_format = SHZ_W64_GUI_FMT_BGRX32;
        o.pixels_crc32 = v->crc;
        o.lease_ms = SHZ_W64_GUI_LEASE_MS;
        memcpy(reply, &o, sizeof o);
        *reply_len = sizeof o;
        return SHZ_OK;
    }

    if (opcode == SHZ_OP_W64_GUI_FRAME_READ) {
        shz_w64_gui_read_t r;
        shz_w64_gui_chunk_t o;
        memcpy(&r, payload, sizeof r);
        if ((st = check_prefix(&r.p, sizeof r, s, &v, 0)) != SHZ_OK) return st;
        if (r.reserved[0] || r.reserved[1]) return SHZ_E_INVALID;
        if (!v->snap || !r.p.snapshot_id || r.p.snapshot_id != v->snap_id) return SHZ_E_STALE;
        if (shz_w64_gui_read_bounds(v->bytes, r.offset, r.length)) return SHZ_E_RANGE;
        memset(&o, 0, sizeof o);
        fill_prefix(&o.r.p, v, sizeof o, r.p.sequence);
        o.r.offset = r.offset;
        o.r.length = r.length;
        memcpy(o.data, (const uint8_t *)v->snap + r.offset, r.length);
        memcpy(reply, &o, sizeof o);
        *reply_len = sizeof o;
        return SHZ_OK;
    }

    if (opcode == SHZ_OP_W64_GUI_FRAME_RELEASE) {
        shz_w64_gui_prefix_t p, o;
        memcpy(&p, payload, sizeof p);
        if ((st = check_prefix(&p, sizeof p, s, &v, 0)) != SHZ_OK) return st;
        if (!p.snapshot_id) return SHZ_E_INVALID;
        if (v->snap && p.snapshot_id == v->snap_id) {
            v->last_released = v->snap_id;
            snap_free(v);
        } else if (p.snapshot_id != v->last_released) return SHZ_E_STALE;   /* idempotent only for the last one */
        fill_prefix(&o, v, sizeof o, p.sequence);
        o.snapshot_id = p.snapshot_id;
        memcpy(reply, &o, sizeof o);
        *reply_len = sizeof o;
        return SHZ_OK;
    }

    /* INPUT */
    {
        shz_w64_gui_input_t in;
        shz_w64_gui_prefix_t o;
        memcpy(&in, payload, sizeof in);
        if ((st = check_prefix(&in.p, sizeof in, s, &v, 0)) != SHZ_OK) return st;
        if (in.p.snapshot_id || in.reserved || (in.flags & ~SHZ_W64_GUI_INF_KNOWN) || in.kind < SHZ_W64_GUI_IN_MOVE ||
            in.kind > SHZ_W64_GUI_IN_CLOSE || in.key > 255u || in.scancode > 0x1ffu ||
            ((in.kind == SHZ_W64_GUI_IN_KEYDOWN || in.kind == SHZ_W64_GUI_IN_KEYUP) ? !in.key : (in.key || in.scancode)))
            return SHZ_E_INVALID;
        if (!v->window_id) return SHZ_E_NOENT;     /* ACQUIRE selects the window first */
        if (in.p.sequence == v->in_seq && v->in_seq && !memcmp(&in, &v->last_in, sizeof in)) {
            /* identical duplicate of the accepted event: ACK, do not apply twice */
        } else {
            if (v->in_seq == UINT32_MAX || in.p.sequence != v->in_seq + 1u) return SHZ_E_STALE;
            if ((st = inject(v, &in)) != SHZ_OK) return st;
            v->in_seq = in.p.sequence;
            v->last_in = in;
        }
        fill_prefix(&o, v, sizeof o, in.p.sequence);
        o.snapshot_id = 0;
        memcpy(reply, &o, sizeof o);
        *reply_len = sizeof o;
        return SHZ_OK;
    }
}
